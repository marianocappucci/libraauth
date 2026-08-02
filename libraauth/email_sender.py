"""
Envio de mail propio del motor de auth (SMTP + STARTTLS).

**Por que no reusa `libracore.email_sender`**: libraauth existe justamente
para que un producto que no factura (LibraDesk) no tenga que arrastrar
LibraCore — hacerlo depender de el para mandar un mail de recuperacion
reintroduciria esa dependencia por la ventana. El costo asumido es un poco
de codigo parecido al de LibraCore; la alternativa era peor.

La config sale de variables de entorno con prefijo `LIBRAAUTH_SMTP_*`, y no
de las del producto, para que un producto pueda mandar los mails de auth por
una cuenta distinta de la que usa para comprobantes. `SmtpConfig.from_env()`
**no falla si falta algo**: devuelve una config incompleta que
`PasswordResetService` detecta, para que una instancia sin SMTP configurado
siga levantando y solo no pueda mandar el mail (ver ahi que se hace con eso).
"""
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage


@dataclass(frozen=True)
class SmtpConfig:
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    from_email: str = ""
    from_name: str = ""
    # Solo lo pone `smtp_settings.SmtpSettingsRepository`, cuando hay una
    # contrasena guardada que NO se puede descifrar con la clave actual
    # (tipicamente, porque se roto el SECRET_KEY de la instancia). Se
    # arrastra hasta aca en vez de resolverse alla para que `configurado`
    # pueda dar False: si no, la config pareceria completa y el fallo
    # aparecia recien como un error de login contra el servidor SMTP, mucho
    # mas lejos de la causa. Ver `crypto.SecretoIndescifrable`.
    password_indescifrable: bool = False

    @classmethod
    def from_env(cls) -> "SmtpConfig":
        return cls(
            host=os.environ.get("LIBRAAUTH_SMTP_HOST", ""),
            port=int(os.environ.get("LIBRAAUTH_SMTP_PORT", "587") or "587"),
            user=os.environ.get("LIBRAAUTH_SMTP_USER", ""),
            password=os.environ.get("LIBRAAUTH_SMTP_PASSWORD", ""),
            # Si no se declara un remitente propio, se usa el usuario SMTP,
            # que es lo que la mayoria de los proveedores exige que coincida.
            from_email=os.environ.get("LIBRAAUTH_SMTP_FROM_EMAIL", "")
            or os.environ.get("LIBRAAUTH_SMTP_USER", ""),
            from_name=os.environ.get("LIBRAAUTH_SMTP_FROM_NAME", ""),
        )

    @property
    def configurado(self) -> bool:
        """Minimo indispensable para poder mandar: servidor y remitente.

        Una contrasena guardada que no se puede descifrar cuenta como **no
        configurado**: mandar el mail fallaria igual, pero mucho mas tarde y
        con un error del servidor SMTP que no dice nada de la causa real.
        """
        if self.password_indescifrable:
            return False
        return bool(self.host and self.from_email)


def enviar_email(config: SmtpConfig, *, to_email: str, asunto: str, cuerpo: str) -> None:
    """Manda un mail de texto plano. Lanza si el SMTP falla — quien llama
    decide si eso se traduce en error visible o se traga (ver
    `PasswordResetService`)."""
    msg = EmailMessage()
    msg["Subject"] = asunto
    msg["From"] = f"{config.from_name} <{config.from_email}>" if config.from_name else config.from_email
    msg["To"] = to_email
    msg.set_content(cuerpo)

    with smtplib.SMTP(config.host, config.port, timeout=20) as smtp:
        smtp.starttls()
        # Hay relays internos que no piden credenciales; con `user` vacio
        # intentar `login()` seria un error innecesario.
        if config.user:
            smtp.login(config.user, config.password)
        smtp.send_message(msg)
