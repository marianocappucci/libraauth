"""
Recuperacion de contrasena por correo (v0.5.0).

Flujo: el usuario pide un reset con su username o su email -> se genera un
token de un solo uso con vencimiento y se le manda por mail un link al
producto -> el usuario abre el link y elige contrasena nueva.

**Tres decisiones que hacen al diseno y conviene no deshacer sin pensarlo:**

1. **No se revela si el usuario existe.** `request_reset()` devuelve la
   cantidad de mails mandados, pero el router **siempre** responde lo mismo:
   un atacante no puede usar este endpoint para averiguar que usernames o
   emails estan dados de alta.
2. **De la base no sale ningun token usable**: se guarda solo su sha256.
3. **El reloj se inyecta** (`now=`). Los tests de la familia ya se comieron
   dos casos de fallas dependientes de la hora real; con `now` inyectable, el
   vencimiento se prueba sin dormir ni depender del reloj de la maquina.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .email_sender import SmtpConfig, enviar_email
from .hashing import hash_password
from .models import PasswordResetToken, Usuario


class InvalidResetToken(Exception):
    """El token no existe, ya se uso o vencio.

    Es **uno solo** para los tres casos a proposito: distinguirlos le diria a
    quien prueba tokens al azar cual de sus intentos estuvo cerca.
    """


class EmailNotConfigured(Exception):
    """La instancia no tiene SMTP configurado, asi que no puede mandar el
    mail. Se chequea **antes** de mirar si el usuario existe, para que el
    error no dependa de eso."""


def _utcnow() -> datetime:
    # Naive en UTC, para comparar contra columnas DateTime sin timezone
    # (que es lo que escribe `server_default=func.now()` en SQLite).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class PasswordResetService:
    """`session_factory` es el mismo del `UserRepository` del producto — el
    que apunta a la base donde vive `usuarios`.

    `reset_url_base` es la pantalla del producto que recibe el token, sin
    query string (ej. `https://dev.gestiolibra.com.ar/reset-password`); el
    servicio le agrega `?token=...`.

    `send_email` permite inyectar otro transporte (los tests le pasan uno que
    acumula en memoria). Por defecto usa el SMTP propio del motor.
    """

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        product_name: str,
        reset_url_base: str,
        ttl_minutes: int = 60,
        smtp_config: "SmtpConfig | Callable[[], SmtpConfig] | None" = None,
        send_email: Callable[..., None] | None = None,
        min_password_length: int = 6,
        now: Callable[[], datetime] = _utcnow,
    ):
        self.session_factory = session_factory
        self.product_name = product_name
        self.reset_url_base = reset_url_base.rstrip("?&")
        self.ttl_minutes = ttl_minutes
        # Se guarda la FUENTE, no el valor. Ver `smtp_config` mas abajo.
        self._smtp_config_source = (
            smtp_config if smtp_config is not None else SmtpConfig.from_env
        )
        self._send_email = send_email
        self.min_password_length = min_password_length
        self._now = now

    @property
    def smtp_config(self) -> SmtpConfig:
        """Se resuelve **en cada uso**, no una vez al construir el servicio.

        Es lo que hace util a la config editable por backoffice (v0.6.0): si
        se resolviera al arrancar, guardar el SMTP por pantalla no tendria
        efecto hasta recrear el contenedor — el mismo problema que se venia a
        resolver. Sigue aceptando un `SmtpConfig` fijo (lo que hacian los
        consumidores hasta la v0.5.0) y ahora tambien un callable que lo
        devuelva, como `lambda: resolver_smtp_config(session_factory)`.
        """
        fuente = self._smtp_config_source
        return fuente() if callable(fuente) else fuente

    # ── Paso 1: pedir el reset ──────────────────────────────────────────────

    def request_reset(self, identificador: str) -> int:
        """Genera un token y manda el mail. Devuelve cuantos mails salieron
        (0 si no hay ningun usuario activo con ese username/email, o si el
        que hay no tiene email cargado).

        **El valor de retorno es para el log y los tests, no para la
        respuesta HTTP** — ver la nota de arriba sobre no revelar existencia.

        Un mismo email puede estar en mas de un usuario (la columna no es
        unica), asi que se manda uno por cada uno, nombrando el username en el
        cuerpo: si no, quien comparte casilla no sabria cual cuenta esta
        recuperando.
        """
        # Se resuelve UNA vez por pedido y se pasa hacia abajo: con la config
        # en base, leerla de nuevo por cada destinatario serian N consultas
        # para un valor que no puede cambiar en el medio.
        smtp = self.smtp_config
        if not smtp.configurado:
            raise EmailNotConfigured(
                "Falta configurar el SMTP del motor de auth "
                "(por backoffice, o LIBRAAUTH_SMTP_HOST y "
                "LIBRAAUTH_SMTP_FROM_EMAIL en el entorno)."
            )

        ident = (identificador or "").strip()
        if not ident:
            return 0

        with self.session_factory() as session:
            usuarios = list(
                session.execute(
                    select(Usuario).where(
                        Usuario.activo == True,  # noqa: E712
                        or_(
                            Usuario.username == ident,
                            # El mail se compara sin distinguir mayusculas: la
                            # gente lo escribe como se le ocurre y un reset que
                            # "no llega nunca" por eso es indistinguible de un
                            # usuario inexistente.
                            Usuario.email.ilike(ident),
                        ),
                    )
                ).scalars()
            )
            destinatarios = []
            for u in usuarios:
                if not u.email:
                    continue
                token = secrets.token_urlsafe(32)
                session.add(
                    PasswordResetToken(
                        user_id=u.id,
                        token_hash=_hash_token(token),
                        expires_at=self._now() + timedelta(minutes=self.ttl_minutes),
                    )
                )
                destinatarios.append((u.email, u.username, u.nombre, token))
            session.commit()

        for email, username, nombre, token in destinatarios:
            self._enviar(smtp, email=email, username=username, nombre=nombre, token=token)
        return len(destinatarios)

    def _enviar(
        self, smtp: SmtpConfig, *, email: str, username: str, nombre: str, token: str
    ) -> None:
        link = f"{self.reset_url_base}?token={token}"
        asunto = f"Recuperar la contraseña de {self.product_name}"
        cuerpo = (
            f"Hola {nombre or username},\n\n"
            f"Recibimos un pedido para restablecer la contraseña de la cuenta "
            f"'{username}' en {self.product_name}.\n\n"
            f"Para elegir una contraseña nueva, entrá acá:\n{link}\n\n"
            f"El enlace vence en {self.ttl_minutes} minutos y se puede usar una "
            f"sola vez.\n\n"
            f"Si no pediste esto, ignorá este mensaje: tu contraseña actual "
            f"sigue funcionando.\n"
        )
        if self._send_email is not None:
            self._send_email(to_email=email, asunto=asunto, cuerpo=cuerpo)
        else:
            enviar_email(smtp, to_email=email, asunto=asunto, cuerpo=cuerpo)

    # ── Paso 2: usar el token ───────────────────────────────────────────────

    def reset(self, token: str, new_password: str) -> dict:
        """Cambia la contrasena y quema el token. Devuelve
        `{'id', 'username'}` del usuario afectado.

        Lanza `InvalidResetToken` si el token no sirve y `ValueError` si la
        contrasena nueva es mas corta que el minimo.
        """
        if len(new_password or "") < self.min_password_length:
            raise ValueError(
                f"la contraseña debe tener al menos {self.min_password_length} caracteres"
            )

        with self.session_factory() as session:
            fila = session.execute(
                select(PasswordResetToken).where(
                    PasswordResetToken.token_hash == _hash_token(token or "")
                )
            ).scalar_one_or_none()
            if fila is None or fila.used_at is not None or fila.expires_at <= self._now():
                raise InvalidResetToken()

            usuario = session.get(Usuario, fila.user_id)
            # El usuario pudo darse de baja entre el pedido y el uso del token.
            if usuario is None or not usuario.activo:
                raise InvalidResetToken()

            usuario.password_hash = hash_password(new_password)
            ahora = self._now()
            fila.used_at = ahora
            # Los demas tokens pendientes del mismo usuario se queman tambien:
            # si alguien pidio varios resets (o un atacante forzo uno), despues
            # de un cambio exitoso ninguno de los viejos deberia seguir sirviendo.
            for otro in session.execute(
                select(PasswordResetToken).where(
                    PasswordResetToken.user_id == usuario.id,
                    PasswordResetToken.used_at.is_(None),
                )
            ).scalars():
                otro.used_at = ahora
            session.commit()
            return {"id": str(usuario.id), "username": usuario.username}

    def purgar_vencidos(self) -> int:
        """Borra tokens vencidos o ya usados. Opcional — nada depende de que
        se llame; existe para que una instancia vieja no acumule filas
        muertas."""
        with self.session_factory() as session:
            filas = list(
                session.execute(
                    select(PasswordResetToken).where(
                        or_(
                            PasswordResetToken.expires_at <= self._now(),
                            PasswordResetToken.used_at.is_not(None),
                        )
                    )
                ).scalars()
            )
            for f in filas:
                session.delete(f)
            session.commit()
            return len(filas)
