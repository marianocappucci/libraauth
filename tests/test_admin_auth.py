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


# ── Sesion por inactividad y renovacion deslizante (ADR-017) ───────────────
#
# Mismo mecanismo y mismos siete casos que `test_session_auth.py` -- ver el
# comentario largo ahi sobre por que el reloj se controla parcheando
# `TimestampSigner.get_timestamp` y no con freezegun.

from http.cookies import SimpleCookie

import itsdangerous.timed
from fastapi import Depends, FastAPI
from fastapi import Response as FastApiResponse
from fastapi.testclient import TestClient as FastAPITestClient

from libraauth.session_auth import RENOVACION_MINIMA_SEGUNDOS


class _RelojFalso:
    def __init__(self):
        self.ahora = 1_800_000_000

    def avanzar(self, segundos: float) -> None:
        self.ahora += segundos


@pytest.fixture
def reloj(monkeypatch):
    r = _RelojFalso()
    monkeypatch.setattr(
        itsdangerous.timed.TimestampSigner,
        "get_timestamp",
        lambda self: int(r.ahora),
    )
    return r


def _cookie_valor(set_cookie_header: str, nombre: str) -> str:
    c = SimpleCookie()
    c.load(set_cookie_header)
    return c[nombre].value


def _make_admin_sliding_app(admin_auth):
    """Misma forma que la de `test_session_auth.py`: una ruta protegida por
    `require_login` via `Depends`, tal como la usa `libracore.admin.app`
    (y por lo tanto Contalibra y Restolibra) sin declarar `response` en la
    ruta."""
    app = FastAPI()

    @app.get("/ping")
    def ping(user: str = Depends(admin_auth.require_login)):
        return {"user": user}

    @app.post("/login")
    def login(username: str, response: FastApiResponse):
        admin_auth.create_session_cookie(response, username)
        return {"ok": True}

    @app.post("/logout")
    def logout(response: FastApiResponse):
        admin_auth.clear_session_cookie(response)
        return {"ok": True}

    return app


def test_admin_sesion_usada_cada_hora_durante_10h_sigue_viva(reloj):
    """(a) para AdminAuth."""
    a = _auth()
    client = FastAPITestClient(_make_admin_sliding_app(a), base_url="https://testserver")
    assert client.post("/login", params={"username": "superadmin"}).status_code == 200

    r = None
    for _ in range(10):
        reloj.avanzar(3600)
        r = client.get("/ping")
        assert r.status_code == 200, r.text
    assert r.json()["user"] == "superadmin"


def test_admin_sesion_sin_uso_8h_mas_1s_se_rechaza(reloj):
    """(b) para AdminAuth. Literal `8 * 3600 + 1`, no la constante -- ver el
    comentario de `test_sesion_sin_uso_8h_mas_1s_se_rechaza` en
    test_session_auth.py: con la constante este test seria tautologico."""
    a = _auth()
    client = FastAPITestClient(_make_admin_sliding_app(a), base_url="https://testserver")
    client.post("/login", params={"username": "superadmin"})

    reloj.avanzar(8 * 3600 + 1)
    r = client.get("/ping", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/login"


def test_admin_renovacion_reemite_cookie_con_los_mismos_atributos(reloj):
    """(c) para AdminAuth."""
    a = _auth()
    client = FastAPITestClient(_make_admin_sliding_app(a), base_url="https://testserver")
    client.post("/login", params={"username": "superadmin"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS + 1)
    r = client.get("/ping")
    assert r.status_code == 200
    set_cookie = r.headers["set-cookie"]
    minuscula = set_cookie.lower()
    assert "httponly" in minuscula
    assert "secure" in minuscula
    assert "samesite=lax" in minuscula
    assert set_cookie.split("=", 1)[0] == a.cookie_name


def test_admin_no_renueva_antes_de_n_minutos(reloj):
    """(d) para AdminAuth."""
    a = _auth()
    client = FastAPITestClient(_make_admin_sliding_app(a), base_url="https://testserver")
    client.post("/login", params={"username": "superadmin"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS - 1)
    r = client.get("/ping")
    assert r.status_code == 200
    assert "set-cookie" not in r.headers


def test_admin_logout_no_resucita_la_cookie_borrada(reloj):
    """(e) para AdminAuth."""
    a = _auth()
    client = FastAPITestClient(_make_admin_sliding_app(a), base_url="https://testserver")
    client.post("/login", params={"username": "superadmin"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS + 1)
    r = client.post("/logout")
    set_cookie = r.headers["set-cookie"]
    assert _cookie_valor(set_cookie, a.cookie_name) == ""

    r2 = client.get("/ping", follow_redirects=False)
    assert r2.status_code == 307


def test_admin_cookie_firmada_hace_9h_se_rechaza_aunque_falten_dias_para_los_3(reloj):
    """(g) para AdminAuth: el default viejo eran 3 dias ABSOLUTOS; 9 horas
    hubieran sido validas. Con la ventana de inactividad, no."""
    a = _auth()
    client = FastAPITestClient(_make_admin_sliding_app(a), base_url="https://testserver")
    client.post("/login", params={"username": "superadmin"})

    reloj.avanzar(9 * 3600)
    r = client.get("/ping", follow_redirects=False)
    assert r.status_code == 307
