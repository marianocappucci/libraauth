"""
Configuracion SMTP persistida y editable por backoffice (v0.6.0).

**El problema que resuelve.** Hasta la v0.5.0 el SMTP salia solo de
`LIBRAAUTH_SMTP_*`, asi que cambiarle el remitente a una instancia obligaba a
editar su compose **en el VPS** y recrear el contenedor. Es la razon por la
que `/auth/forgot-password` respondia `503` en las instancias donde nadie
habia hecho eso.

**Como se resuelve el valor efectivo** (`resolver_smtp_config`): si hay fila
en la base, gana la base; si no, cae al entorno. Esa precedencia importa —
una instancia que ya tenia las variables sigue funcionando **exactamente
igual** hasta que alguien guarde algo por pantalla, asi que adoptar esta
version no cambia el comportamiento de nadie.

**La contrasena se guarda cifrada**, con una clave que vive en el entorno
(ver `crypto.py`). Esto es la mitigacion de la decision del 2026-08-01 de que
la config viva entera en la base del cliente: sin cifrar, el backup de esa
instancia alcanzaria para mandar correo en su nombre.

**Lo que NUNCA sale de aca**: la contrasena en claro hacia una respuesta HTTP.
`estado()` devuelve solo si hay una cargada; el valor descifrado se usa
unicamente para armar el `SmtpConfig` que consume `enviar_email`.
"""
from contextlib import AbstractContextManager
from typing import Callable

from sqlalchemy.orm import Session

from .crypto import SecretoIndescifrable, cifrar, descifrar
from .email_sender import SmtpConfig
from .models import SmtpSettings

# La tabla tiene una sola fila y su id es fijo. Un `id` autoincremental
# permitiria que un bug dejara dos configuraciones y que la app usara
# cualquiera de las dos segun el orden de lectura.
FILA_UNICA = 1

# Centinela para distinguir "no me mandes la contrasena, dejala como esta" de
# "borrala". `None` no alcanza: un formulario que no toca el campo y uno que
# lo vacia mandan cosas distintas y las dos son legitimas.
SIN_CAMBIOS = object()


class SmtpSettingsRepository:
    """`session_factory` es el mismo del `UserRepository` del producto — el
    que apunta a la base donde este motor crea sus tablas."""

    def __init__(self, session_factory: Callable[[], AbstractContextManager[Session]]):
        self.session_factory = session_factory

    # ── Lectura ─────────────────────────────────────────────────────────────

    def get(self) -> SmtpConfig | None:
        """La config guardada, con la contrasena ya descifrada, o `None` si
        nunca se guardo nada.

        Si hay una contrasena que no se puede descifrar **no lanza**: devuelve
        la config con `password_indescifrable=True` y la contrasena vacia. El
        motivo es que esto se llama al resolver la config de un envio, y una
        instancia con el `SECRET_KEY` rotado tiene que seguir levantando y
        respondiendo `503` (que es "no configurado", y es la verdad) en vez de
        romper con un 500.
        """
        with self.session_factory() as session:
            fila = session.get(SmtpSettings, FILA_UNICA)
            if fila is None:
                return None
            try:
                password = descifrar(fila.password_cifrada)
                rota = False
            except SecretoIndescifrable:
                password, rota = "", True
            return SmtpConfig(
                host=fila.host,
                port=fila.port,
                user=fila.user,
                password=password,
                from_email=fila.from_email,
                from_name=fila.from_name,
                password_indescifrable=rota,
            )

    def estado(self) -> dict:
        """Lo que se le puede mostrar a un humano **sin filtrar el secreto**.

        `password_definida` dice si hay algo guardado; el valor no se
        devuelve nunca, ni enmascarado con su largo real (eso ya seria filtrar
        cuantos caracteres tiene).
        """
        cfg = self.get()
        if cfg is None:
            return {
                "origen": "entorno",
                "host": "", "port": 587, "user": "",
                "from_email": "", "from_name": "",
                "password_definida": False,
                "password_indescifrable": False,
                "configurado": SmtpConfig.from_env().configurado,
            }
        with self.session_factory() as session:
            fila = session.get(SmtpSettings, FILA_UNICA)
            tiene_password = bool(fila.password_cifrada)
        return {
            "origen": "base",
            "host": cfg.host, "port": cfg.port, "user": cfg.user,
            "from_email": cfg.from_email, "from_name": cfg.from_name,
            "password_definida": tiene_password,
            "password_indescifrable": cfg.password_indescifrable,
            "configurado": cfg.configurado,
        }

    # ── Escritura ───────────────────────────────────────────────────────────

    def save(
        self,
        *,
        host: str,
        port: int = 587,
        user: str = "",
        password: str | object = SIN_CAMBIOS,
        from_email: str = "",
        from_name: str = "",
    ) -> SmtpConfig:
        """Crea o actualiza la fila unica. Devuelve la config resultante.

        `password=SIN_CAMBIOS` (el default) conserva la que ya estaba: editar
        el host o el remitente **no** obliga a volver a tipear la contrasena,
        que es lo que en la practica lleva a que alguien la deje en un papel
        para poder repetirla. `password=""` la borra.

        `from_email` vacio cae al `user`, igual que hace `from_env()`: la
        mayoria de los proveedores exige que el remitente coincida con la
        cuenta autenticada.
        """
        host = (host or "").strip()
        if not host:
            raise ValueError("El servidor SMTP (host) no puede estar vacio.")
        # `port or 587` seria un bug: convertiria un 0 explicito en 587 en vez
        # de rechazarlo. Solo "no vino nada" cae al default.
        port = 587 if port in (None, "") else int(port)
        if not (1 <= port <= 65535):
            raise ValueError(f"Puerto SMTP invalido: {port}.")
        user = (user or "").strip()
        from_email = (from_email or "").strip() or user
        from_name = (from_name or "").strip()

        with self.session_factory() as session:
            fila = session.get(SmtpSettings, FILA_UNICA)
            if fila is None:
                fila = SmtpSettings(id=FILA_UNICA)
                session.add(fila)
            fila.host = host
            fila.port = port
            fila.user = user
            fila.from_email = from_email
            fila.from_name = from_name
            if password is not SIN_CAMBIOS:
                # `cifrar` lanza `ClaveDeCifradoAusente` si la instancia no
                # tiene ni SECRET_KEY ni LIBRAAUTH_ENCRYPTION_KEY. Se deja
                # propagar a proposito: guardar la contrasena en claro
                # "porque no habia clave" seria justo lo que este modulo
                # existe para impedir.
                fila.password_cifrada = cifrar(str(password))
            session.commit()

        return self.get()

    def delete(self) -> bool:
        """Borra la config guardada y devuelve si habia algo que borrar.

        Es la vuelta atras: sin fila, `resolver_smtp_config` cae al entorno,
        que es como funcionaban todas las instancias antes de la v0.6.0.
        """
        with self.session_factory() as session:
            fila = session.get(SmtpSettings, FILA_UNICA)
            if fila is None:
                return False
            session.delete(fila)
            session.commit()
            return True


def resolver_smtp_config(
    session_factory: Callable[[], AbstractContextManager[Session]],
) -> SmtpConfig:
    """El valor efectivo: la base si hay algo guardado, el entorno si no.

    Pensada para pasarse **como callable** a `PasswordResetService`
    (`smtp_config=lambda: resolver_smtp_config(sf)`), no para llamarse una vez
    al arrancar: si se resolviera al construir el servicio, editar la config
    por backoffice no tendria efecto hasta reiniciar el contenedor — o sea,
    exactamente el problema que esta version viene a resolver.
    """
    guardada = SmtpSettingsRepository(session_factory).get()
    if guardada is not None:
        return guardada
    return SmtpConfig.from_env()
