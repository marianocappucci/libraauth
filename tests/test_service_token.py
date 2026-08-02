"""
Token de servicio (v0.7.0) — el guard que le permite al backoffice de la suite
administrar varias instancias sin ser usuario de ninguna.

Lo que estos tests fijan, en orden de importancia:

1. **Sin `LIBRA_SERVICE_TOKEN` no cambia nada.** Es la condicion para poder
   actualizar las instancias en produccion sin tocarles el compose.
2. Un token equivocado no entra, y tampoco entra un header vacio.
3. Con el token correcto se entra **sin cookie de sesion**, que es la unica
   forma en que el backoffice puede llegar.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth.models import Base
from libraauth.session_auth import (
    SERVICE_TOKEN_ENV,
    SERVICE_TOKEN_HEADER,
    build_smtp_settings_router,
)
from libraauth.smtp_settings import SmtpSettingsRepository

TOKEN = "un-token-de-servicio-largo-y-aleatorio"


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 64)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv(SERVICE_TOKEN_ENV, raising=False)


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/token_test.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


class _UsersFalso:
    def __init__(self, user):
        self._user = user

    def get_by_username(self, username):
        return self._user


class _SessionAuthFalso:
    def __init__(self, username):
        self._username = username

    def get_current_user(self, request):
        return self._username


def _cliente(session_factory, *, logueado=False, rol="admin"):
    app = FastAPI()
    app.state.smtp_settings = SmtpSettingsRepository(session_factory)
    app.state.session_auth = _SessionAuthFalso("admin1" if logueado else None)
    app.state.users = _UsersFalso(
        {"id": "1", "username": "admin1", "name": "Admin", "role": rol, "active": True}
    )
    app.include_router(build_smtp_settings_router())
    return TestClient(app)


# ── Sin la variable: comportamiento de v0.6.x, intacto ──────────────────────

def test_sin_variable_el_header_no_sirve_para_nada(session_factory):
    """La garantia de adopcion: una instancia que actualiza y no toca su
    compose se comporta exactamente como antes."""
    r = _cliente(session_factory).get("/admin/smtp", headers={SERVICE_TOKEN_HEADER: TOKEN})
    assert r.status_code == 401


def test_sin_variable_la_sesion_admin_sigue_entrando(session_factory):
    assert _cliente(session_factory, logueado=True).get("/admin/smtp").status_code == 200


def test_sin_variable_un_usuario_no_admin_sigue_sin_entrar(session_factory):
    r = _cliente(session_factory, logueado=True, rol="staff").get("/admin/smtp")
    assert r.status_code == 403


# ── Con la variable definida ────────────────────────────────────────────────

def test_token_correcto_entra_sin_cookie(session_factory, monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    r = _cliente(session_factory).get("/admin/smtp", headers={SERVICE_TOKEN_HEADER: TOKEN})
    assert r.status_code == 200
    assert r.json()["origen"] == "entorno"


def test_token_incorrecto_no_entra(session_factory, monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    r = _cliente(session_factory).get("/admin/smtp", headers={SERVICE_TOKEN_HEADER: "otro"})
    assert r.status_code == 401


def test_header_vacio_no_entra(session_factory, monkeypatch):
    """Un token esperado vacio ya lo cubre la guarda de la variable; este es el
    caso inverso, el header presente pero vacio."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    r = _cliente(session_factory).get("/admin/smtp", headers={SERVICE_TOKEN_HEADER: ""})
    assert r.status_code == 401


def test_sin_header_y_sin_sesion_no_entra(session_factory, monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    assert _cliente(session_factory).get("/admin/smtp").status_code == 401


def test_con_token_se_puede_escribir(session_factory, monkeypatch):
    """El caso de uso real: el backoffice le configura el correo a una
    instancia. Y la instancia lo guarda cifrado con SU clave, que es todo el
    punto de hacerlo por HTTP y no abriendole la base."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    r = _cliente(session_factory).put(
        "/admin/smtp",
        headers={SERVICE_TOKEN_HEADER: TOKEN},
        json={"host": "smtp.test", "user": "cuenta", "password": "hunter2",
              "from_email": "a@b.com"},
    )
    assert r.status_code == 200
    assert "hunter2" not in r.text
    assert SmtpSettingsRepository(session_factory).get().password == "hunter2"


def test_la_sesion_admin_sigue_funcionando_con_la_variable_puesta(session_factory, monkeypatch):
    """El token se suma, no reemplaza: los admins del cliente siguen entrando."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    assert _cliente(session_factory, logueado=True).get("/admin/smtp").status_code == 200
