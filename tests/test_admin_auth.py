"""Tests de `AdminAuth`, portados junto con el codigo desde
`libracore.auth` el 2026-07-30. Cubren sobre todo las formas de FALLAR, que es
lo que importa en un backoffice de superadmin."""
import time

import pytest
from starlette.requests import Request
from starlette.responses import Response

from libraauth.admin_auth import AdminAuth


@pytest.fixture(autouse=True)
def entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ADMIN_PANEL_USER", "superadmin")
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "clave-del-panel")


def _auth(**kw):
    return AdminAuth(dev_secret_fallback="dev-only", **kw)


def _request_con_cookie(nombre, valor):
    scope = {
        "type": "http", "method": "GET", "path": "/", "headers":
        [(b"cookie", f"{nombre}={valor}".encode())],
    }
    return Request(scope)


# ── credenciales ─────────────────────────────────────────────────────────

def test_credenciales_correctas():
    assert _auth().check_credentials("superadmin", "clave-del-panel") is True


@pytest.mark.parametrize("user,password", [
    ("superadmin", "otra"),
    ("otro", "clave-del-panel"),
    ("", ""),
    ("superadmin", ""),
])
def test_credenciales_incorrectas(user, password):
    assert _auth().check_credentials(user, password) is False


def test_sin_password_configurada_rechaza_todo(monkeypatch):
    """Fail-closed: una instancia mal configurada no debe dejar entrar a nadie,
    ni siquiera mandando la password vacia que tiene seteada."""
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "")
    a = _auth()
    assert a.check_credentials("superadmin", "") is False
    assert a.check_credentials("superadmin", "cualquiera") is False


def test_sin_SECRET_KEY_fuera_de_development_no_arranca(monkeypatch):
    """Sin esto, cualquiera puede forjar la cookie con el secreto de dev, que
    esta en el codigo."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        _auth()


# ── cookie de sesion ─────────────────────────────────────────────────────

def test_cookie_ida_y_vuelta():
    a = _auth()
    r = Response()
    a.create_session_cookie(r, "superadmin")
    valor = r.headers["set-cookie"].split("=", 1)[1].split(";")[0]
    assert a.current_user(_request_con_cookie(a.cookie_name, valor)) == "superadmin"


def test_cookie_es_httponly_y_secure():
    r = Response()
    _auth().create_session_cookie(r, "superadmin")
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie


def test_sin_cookie_no_hay_usuario():
    assert _auth().current_user(Request({"type": "http", "method": "GET",
                                         "path": "/", "headers": []})) is None


def test_cookie_manipulada_se_rechaza():
    a = _auth()
    r = Response()
    a.create_session_cookie(r, "superadmin")
    valor = r.headers["set-cookie"].split("=", 1)[1].split(";")[0]
    roto = valor[:-3] + ("aaa" if not valor.endswith("aaa") else "bbb")
    assert a.current_user(_request_con_cookie(a.cookie_name, roto)) is None


def test_cookie_vencida_se_rechaza():
    # 2.2s con max_age=1 y no 1.1s: itsdangerous calcula la edad en segundos
    # enteros, asi que a 1.1s da 1, que NO supera el maximo y la cookie sigue
    # siendo valida. Con 1.1 este test pasaba a veces y fallaba otras.
    a = _auth(max_age=1)
    r = Response()
    a.create_session_cookie(r, "superadmin")
    valor = r.headers["set-cookie"].split("=", 1)[1].split(";")[0]
    time.sleep(2.2)
    assert a.current_user(_request_con_cookie(a.cookie_name, valor)) is None


def test_cookie_de_otro_secreto_se_rechaza(monkeypatch):
    """La cookie del backoffice de un producto no debe servir en otro."""
    a1 = _auth()
    r = Response()
    a1.create_session_cookie(r, "superadmin")
    valor = r.headers["set-cookie"].split("=", 1)[1].split(";")[0]
    monkeypatch.setenv("SECRET_KEY", "otro-secreto-distinto")
    a2 = _auth()
    assert a2.current_user(_request_con_cookie(a2.cookie_name, valor)) is None


def test_cookie_propia_separada_de_la_del_usuario_final():
    """`cladmin_session` por defecto: entrar al backoffice no loguea en el
    producto ni al reves."""
    assert _auth().cookie_name == "cladmin_session"
    assert _auth(cookie_name="otra").cookie_name == "otra"


def test_require_login_redirige_si_no_hay_sesion():
    from starlette.exceptions import HTTPException
    a = _auth()
    req = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    with pytest.raises(HTTPException) as exc:
        a.require_login(req)
    assert exc.value.status_code == 307
    assert exc.value.headers["Location"] == "/login"


# ── rate limiting ────────────────────────────────────────────────────────

def test_rate_limit_despues_de_N_intentos():
    a = _auth(login_max_intentos=3)
    assert a.rate_limit_excedido("1.2.3.4") is False
    for _ in range(3):
        a.registrar_intento_fallido("1.2.3.4")
    assert a.rate_limit_excedido("1.2.3.4") is True
    # Es por IP: otra no queda bloqueada
    assert a.rate_limit_excedido("5.6.7.8") is False


def test_rate_limit_se_libera_al_pasar_la_ventana():
    a = _auth(login_max_intentos=2, login_ventana_segundos=1)
    a.registrar_intento_fallido("1.2.3.4")
    a.registrar_intento_fallido("1.2.3.4")
    assert a.rate_limit_excedido("1.2.3.4") is True
    time.sleep(1.1)
    assert a.rate_limit_excedido("1.2.3.4") is False


def test_ip_vacia_no_rompe_ni_bloquea():
    a = _auth(login_max_intentos=1)
    a.registrar_intento_fallido("")
    assert a.rate_limit_excedido("") is False
