"""La marca `Secure` de la cookie de sesion, configurable por entorno (ADR-026).

Lo que se fija:

- **sin la variable, `Secure`**: en la nube no cambia nada;
- con un "falso" explicito (`0`, `false`, `no`, `off`, sin importar mayusculas ni
  espacios), la cookie sale sin `Secure` y la sesion funciona de punta a punta
  por **http** (el caso del nodo de LibraEdge en la LAN);
- cualquier otro valor -- vacio, `1`, un error de tipeo -- deja `Secure`: un
  error de configuracion no puede sacar la seguridad;
- la renovacion deslizante re-emite la cookie con la misma marca que el login;
- el aviso del log nombra la variable y nunca dice mas que eso.
"""
import logging

import pytest
from fastapi import Depends, FastAPI, Response
from fastapi.testclient import TestClient
from starlette.requests import Request

import libraauth.session_auth as sa
from libraauth.session_auth import (
    COOKIE_SECURE_ENV,
    SessionAuth,
    build_json_api_auth_router,
    cookie_secure,
)

_ADMIN = {"id": "1", "username": "admin", "name": "Admin", "role": "admin", "active": True}


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "secreto-de-test-cookie-secure")
    monkeypatch.delenv(COOKIE_SECURE_ENV, raising=False)
    # Los avisos son una vez por proceso: cada test arranca sin ninguno dado.
    monkeypatch.setattr(sa, "_avisos_cookie", set())


class _Users:
    def check_credentials(self, username, password):
        return dict(_ADMIN) if (username, password) == ("admin", "correcta") else None

    def get_by_username(self, username):
        return dict(_ADMIN) if username == "admin" else None


def _session_auth() -> SessionAuth:
    users = _Users()
    return SessionAuth(
        dev_secret_fallback="no-se-usa",
        get_user_by_username=users.get_by_username,
        check_credentials=users.check_credentials,
    )


def _app() -> FastAPI:
    """El router JSON real (`/api/login`, `/api/me`), como lo montan ContaLibra y
    RestoLibra, con `SessionAuth` de verdad."""
    app = FastAPI()
    app.state.users = _Users()
    app.state.session_auth = _session_auth()
    app.include_router(build_json_api_auth_router(prefix="/api", max_intentos_fallidos=0))
    return app


def _login(cliente: TestClient):
    r = cliente.post("/api/login", json={"username": "admin", "password": "correcta"})
    assert r.status_code == 200, r.text
    return r


def _atributos(set_cookie: str) -> set[str]:
    return {parte.strip().split("=", 1)[0].lower() for parte in set_cookie.split(";")[1:]}


# ── El valor de la variable ──────────────────────────────────────────────────


def test_sin_variable_es_secure():
    assert cookie_secure() is True


@pytest.mark.parametrize("valor", ["0", "false", "FALSE", "False", "no", "NO", "off", " 0 ", "false\n"])
def test_falsos_explicitos_la_apagan(monkeypatch, valor):
    monkeypatch.setenv(COOKIE_SECURE_ENV, valor)
    assert cookie_secure() is False


@pytest.mark.parametrize(
    "valor",
    ["", "   ", "1", "true", "yes", "si", "on",
     # Errores de tipeo y valores raros: nunca apagan la seguridad.
     "falso", "flase", "f", "n", "0.0", "nope", "false0", "00", "-1", "none", "null", "disabled"],
)
def test_cualquier_otro_valor_deja_secure(monkeypatch, valor):
    monkeypatch.setenv(COOKIE_SECURE_ENV, valor)
    assert cookie_secure() is True


# ── La cookie que sale ───────────────────────────────────────────────────────


def test_login_por_https_sin_variable_sale_secure():
    r = _login(TestClient(_app(), base_url="https://testserver"))
    atributos = _atributos(r.headers["set-cookie"])
    assert {"secure", "httponly", "samesite"} <= atributos


def test_login_con_valor_raro_sigue_secure(monkeypatch):
    monkeypatch.setenv(COOKIE_SECURE_ENV, "falso")
    r = _login(TestClient(_app(), base_url="https://testserver"))
    assert "secure" in _atributos(r.headers["set-cookie"])


def test_apagada_sale_sin_secure_y_conserva_lo_demas(monkeypatch):
    monkeypatch.setenv(COOKIE_SECURE_ENV, "0")
    r = _login(TestClient(_app(), base_url="http://testserver"))
    set_cookie = r.headers["set-cookie"]
    atributos = _atributos(set_cookie)
    assert "secure" not in atributos
    # HttpOnly y SameSite=Lax no dependen de la variable.
    assert "httponly" in atributos
    assert "samesite=lax" in set_cookie.lower()


def test_apagada_la_sesion_anda_por_http(monkeypatch):
    """El caso del nodo: login y despues un pedido autenticado, todo por http."""
    monkeypatch.setenv(COOKIE_SECURE_ENV, "false")
    cliente = TestClient(_app(), base_url="http://192.168.0.10:8000")
    _login(cliente)
    r = cliente.get("/api/me")
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "admin"


def test_sin_variable_por_http_el_cliente_no_la_devuelve():
    """Lo que pasaba en el nodo: el login da 200, pero el cliente no guarda una
    cookie `Secure` que llego por http y el pedido siguiente es 401. Fija que
    el default sigue siendo ese (el arreglo es la variable, no aflojar el default)."""
    cliente = TestClient(_app(), base_url="http://192.168.0.10:8000")
    _login(cliente)
    assert cliente.get("/api/me").status_code == 401


def test_la_lectura_de_la_sesion_no_exige_https(monkeypatch):
    """Leer la sesion no mira el esquema: una cookie valida por http identifica
    al usuario igual que por https."""
    auth = _session_auth()
    app = FastAPI()

    @app.get("/quien")
    def quien(request: Request, response: Response, user: str = Depends(auth.require_auth)):
        return {"user": user}

    @app.post("/entrar")
    def entrar(response: Response):
        auth.create_session_cookie(response, "admin")
        return {}

    monkeypatch.setenv(COOKIE_SECURE_ENV, "0")
    cliente = TestClient(app, base_url="http://localhost:8000")
    cliente.post("/entrar")
    r = cliente.get("/quien")
    assert r.status_code == 200
    assert r.json() == {"user": "admin"}


def test_la_renovacion_respeta_la_variable(monkeypatch):
    """La renovacion deslizante re-emite con `create_session_cookie`, asi que
    sale con la misma marca que el login."""
    auth = _session_auth()
    monkeypatch.setenv(COOKIE_SECURE_ENV, "off")
    respuesta = Response()
    auth.create_session_cookie(respuesta, "admin")
    assert "secure" not in _atributos(respuesta.headers["set-cookie"])
    monkeypatch.delenv(COOKIE_SECURE_ENV)
    respuesta = Response()
    auth.create_session_cookie(respuesta, "admin")
    assert "secure" in _atributos(respuesta.headers["set-cookie"])


def test_logout_borra_la_cookie_por_http(monkeypatch):
    monkeypatch.setenv(COOKIE_SECURE_ENV, "0")
    cliente = TestClient(_app(), base_url="http://localhost:8000")
    _login(cliente)
    assert cliente.post("/api/logout").status_code == 200
    assert cliente.get("/api/me").status_code == 401


# ── El aviso del log ─────────────────────────────────────────────────────────


def test_avisa_una_vez_cuando_esta_apagada(monkeypatch, caplog):
    monkeypatch.setenv(COOKIE_SECURE_ENV, "0")
    with caplog.at_level(logging.WARNING, logger="libraauth.session_auth"):
        cookie_secure()
        cookie_secure()
    avisos = [r for r in caplog.records if COOKIE_SECURE_ENV in r.getMessage()]
    assert len(avisos) == 1
    assert "sin Secure" in avisos[0].getMessage()


def test_avisa_que_ignora_un_valor_desconocido(monkeypatch, caplog):
    monkeypatch.setenv(COOKIE_SECURE_ENV, "falso")
    with caplog.at_level(logging.WARNING, logger="libraauth.session_auth"):
        assert cookie_secure() is True
    mensajes = [r.getMessage() for r in caplog.records]
    assert any("no se reconoce" in m for m in mensajes)
    # El aviso no repite el valor (no es un secreto, pero el criterio es el mismo).
    assert not any("falso" in m for m in mensajes)


def test_sin_variable_no_avisa(caplog):
    with caplog.at_level(logging.WARNING, logger="libraauth.session_auth"):
        cookie_secure()
    assert not [r for r in caplog.records if COOKIE_SECURE_ENV in r.getMessage()]


def test_el_backoffice_no_lee_la_variable():
    """`AdminAuth` (backoffice de superadmin) no se sirve en nodos: su cookie
    sigue siendo `Secure` siempre, sin depender de esta variable."""
    import inspect

    import libraauth.admin_auth as admin_auth

    assert "cookie_secure" not in inspect.getsource(admin_auth)
    assert COOKIE_SECURE_ENV not in inspect.getsource(admin_auth)
