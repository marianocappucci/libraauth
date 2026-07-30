"""Tests del envio SMTP propio del motor.

Existen porque el resto de la suite inyecta un transporte falso: sin esto, el
camino que corre **en produccion** (`enviar_email` de verdad) no lo ejercitaba
nadie. No se abre ninguna conexion real — se sustituye `smtplib.SMTP` por un
doble que registra que se le pidio.
"""
import pytest

from libraauth import email_sender
from libraauth.email_sender import SmtpConfig, enviar_email


class SmtpFalso:
    """Doble de `smtplib.SMTP` que registra la conversacion."""

    instancias = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.starttls_llamado = False
        self.login_con = None
        self.mensajes = []
        SmtpFalso.instancias.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.starttls_llamado = True

    def login(self, user, password):
        self.login_con = (user, password)

    def send_message(self, msg):
        self.mensajes.append(msg)


@pytest.fixture
def smtp(monkeypatch):
    SmtpFalso.instancias = []
    monkeypatch.setattr(email_sender.smtplib, "SMTP", SmtpFalso)
    return SmtpFalso


def test_manda_con_starttls_y_login(smtp):
    cfg = SmtpConfig(host="smtp.test", port=587, user="cuenta", password="clave",
                     from_email="no-reply@test", from_name="Gestiolibra")
    enviar_email(cfg, to_email="ana@empresa.com", asunto="Asunto", cuerpo="Cuerpo")

    conexion = smtp.instancias[0]
    assert (conexion.host, conexion.port) == ("smtp.test", 587)
    assert conexion.starttls_llamado is True
    assert conexion.login_con == ("cuenta", "clave")
    msg = conexion.mensajes[0]
    assert msg["To"] == "ana@empresa.com"
    assert msg["Subject"] == "Asunto"
    assert msg["From"] == "Gestiolibra <no-reply@test>"
    assert msg.get_content().strip() == "Cuerpo"


def test_sin_usuario_no_intenta_login(smtp):
    """Hay relays internos que no piden credenciales; llamar `login()` con
    usuario vacio seria un error innecesario."""
    cfg = SmtpConfig(host="relay.interno", from_email="no-reply@test")
    enviar_email(cfg, to_email="ana@empresa.com", asunto="A", cuerpo="C")

    assert smtp.instancias[0].login_con is None


def test_sin_nombre_de_remitente_usa_solo_el_mail(smtp):
    cfg = SmtpConfig(host="smtp.test", from_email="no-reply@test")
    enviar_email(cfg, to_email="ana@empresa.com", asunto="A", cuerpo="C")

    assert smtp.instancias[0].mensajes[0]["From"] == "no-reply@test"


# ── Config desde el entorno ─────────────────────────────────────────────────

def test_from_env_lee_las_variables(monkeypatch):
    monkeypatch.setenv("LIBRAAUTH_SMTP_HOST", "smtp.empresa.com")
    monkeypatch.setenv("LIBRAAUTH_SMTP_PORT", "2525")
    monkeypatch.setenv("LIBRAAUTH_SMTP_USER", "cuenta")
    monkeypatch.setenv("LIBRAAUTH_SMTP_PASSWORD", "clave")
    monkeypatch.setenv("LIBRAAUTH_SMTP_FROM_NAME", "Soporte")

    cfg = SmtpConfig.from_env()

    assert (cfg.host, cfg.port, cfg.user, cfg.password) == (
        "smtp.empresa.com", 2525, "cuenta", "clave")
    # Sin FROM_EMAIL propio cae al usuario SMTP, que es lo que la mayoria de
    # los proveedores exige que coincida con el remitente.
    assert cfg.from_email == "cuenta"
    assert cfg.from_name == "Soporte"
    assert cfg.configurado is True


def test_from_env_sin_nada_devuelve_config_incompleta_en_vez_de_fallar(monkeypatch):
    """Una instancia sin SMTP tiene que poder levantar igual; el que avisa es
    `PasswordResetService`, recien cuando alguien pide un reset."""
    for v in ("LIBRAAUTH_SMTP_HOST", "LIBRAAUTH_SMTP_USER",
              "LIBRAAUTH_SMTP_FROM_EMAIL", "LIBRAAUTH_SMTP_PORT"):
        monkeypatch.delenv(v, raising=False)

    cfg = SmtpConfig.from_env()

    assert cfg.configurado is False
    assert cfg.port == 587


def test_puerto_vacio_no_rompe_el_arranque(monkeypatch):
    """Un `LIBRAAUTH_SMTP_PORT=` en el compose (variable declarada y vacia) es
    un caso real en esta familia: sin el fallback, `int("")` tiraba al
    importar la config y la app no levantaba."""
    monkeypatch.setenv("LIBRAAUTH_SMTP_PORT", "")

    assert SmtpConfig.from_env().port == 587
