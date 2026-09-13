"""Rate limiting del login (v0.27.0).

Existia en Contalibra y Restolibra, escrito a mano en cada uno, y **no en este
motor** — asi que los otros cuatro productos no tenian ninguno. Migrarlos al
router de aca sin esto les habria sacado una defensa que ya tenian: la copia
mas pobre ganando por ser la compartida.

Lo que se fija:

- corta **antes** de chequear la credencial, para que no funcione como oraculo
  (una IP bloqueada tiene que contestar igual con la clave buena y con la mala);
- cuenta por IP, no global;
- se puede apagar con `max_intentos_fallidos=0`;
- si no hay de donde contar, **deja pasar** en vez de dejar a todos afuera.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth.auth_events import LOGIN_BLOQUEADO, AuthEventRepository
from libraauth.models import Base
from libraauth.session_auth import build_json_api_auth_router


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-rate-limiting")


@pytest.fixture
def sessions_de_test(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/rate_limiting_test.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


CLAVE_BUENA = {"username": "admin", "password": "correcta"}
CLAVE_MALA = {"username": "admin", "password": "incorrecta"}


#: Lo que `_UserOut` exige: sin `id` y `name` el 200 explota con
#: ResponseValidationError, no con un fallo del rate limiting.
_ADMIN = {"id": "1", "username": "admin", "name": "Admin", "role": "admin", "active": True}


class _UsersFalso:
    """Lo minimo que el router le pide a `app.state.users`."""

    def check_credentials(self, username, password):
        if username == "admin" and password == "correcta":
            return dict(_ADMIN)
        return None

    def get_by_username(self, username):
        return dict(_ADMIN)


class _SessionAuthFalso:
    def create_session_cookie(self, response, username):
        response.set_cookie("sesion", username)

    def get_current_user(self, request, response=None):
        return request.cookies.get("sesion")

    def clear_session_cookie(self, response):
        response.delete_cookie("sesion")


def _app(sessions=None, **kwargs):
    app = FastAPI()
    app.state.users = _UsersFalso()
    app.state.session_auth = _SessionAuthFalso()
    if sessions is not None:
        app.state.auth_events = AuthEventRepository(sessions)
    # El builder ya trae su propio prefix (`/auth` por defecto).
    app.include_router(build_json_api_auth_router(**kwargs))
    return app


#: La IP con la que Nginx Proxy Manager le habla a cada contenedor en el VPS
#: (red `stack_stack-net`, medido el 2026-09-11).
IP_DEL_PROXY = "172.18.0.19"


def _cliente(app, par=IP_DEL_PROXY):
    # El par directo es el proxy, como en produccion. Con el `testclient` por
    # defecto de Starlette, `ip_del_request` no le cree a ningun
    # `X-Forwarded-For` (ver su docstring) y los tests medirian otra cosa.
    return TestClient(app, base_url="https://producto.test", client=(par, 50000))


def test_corta_a_los_cinco_intentos(sessions_de_test):
    c = _cliente(_app(sessions_de_test))
    for _ in range(5):
        assert c.post("/auth/login", json=CLAVE_MALA).status_code == 401
    r = c.post("/auth/login", json=CLAVE_MALA)
    assert r.status_code == 429, r.text


def test_la_ip_bloqueada_no_delata_la_clave_correcta(sessions_de_test):
    """El control que hace que esto no sea un oraculo.

    Si el corte fuera despues de chequear la credencial, esta llamada
    devolveria 200 (o un 401 distinto) y quien barre sabria que acerto.
    """
    c = _cliente(_app(sessions_de_test))
    for _ in range(5):
        c.post("/auth/login", json=CLAVE_MALA)
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 429


def test_cuenta_por_ip_y_no_global(sessions_de_test):
    """Otra IP entra igual: si contara global, un solo atacante deja afuera a
    todos los usuarios del sistema."""
    app = _app(sessions_de_test)
    c = _cliente(app)
    for _ in range(5):
        c.post("/auth/login", json=CLAVE_MALA)
    otra = _cliente(app)
    r = otra.post("/auth/login", json=CLAVE_BUENA, headers={"X-Forwarded-For": "203.0.113.9"})
    assert r.status_code == 200, r.text


def test_rotar_x_forwarded_for_no_esquiva_el_bloqueo(sessions_de_test):
    """🔴 El control negativo de v0.39.0.

    Cada intento manda un `X-Forwarded-For` distinto, y NPM le agrega a la
    derecha el par TCP real, que es siempre el mismo. Hasta v0.38.0 se contaba
    por el primer elemento —el que elige el cliente— y esto nunca llegaba al
    429: la fuerza bruta pasaba con sólo cambiar un header.
    """
    c = _cliente(_app(sessions_de_test))
    real = "198.51.100.23"
    for n in range(5):
        r = c.post("/auth/login", json=CLAVE_MALA,
                   headers={"X-Forwarded-For": f"203.0.113.{n}, {real}"})
        assert r.status_code == 401, r.text
    r = c.post("/auth/login", json=CLAVE_BUENA,
               headers={"X-Forwarded-For": f"203.0.113.99, {real}"})
    assert r.status_code == 429, r.text


def test_sin_pasar_por_el_proxy_el_header_no_cambia_la_ip(sessions_de_test):
    """Quien le habla al contenedor directo, sin NPM, escribió el header entero:
    se cuenta por su par TCP, diga lo que diga."""
    c = _cliente(_app(sessions_de_test), par="198.51.100.23")
    for n in range(5):
        c.post("/auth/login", json=CLAVE_MALA,
               headers={"X-Forwarded-For": f"203.0.113.{n}"})
    r = c.post("/auth/login", json=CLAVE_BUENA,
               headers={"X-Forwarded-For": "203.0.113.200"})
    assert r.status_code == 429, r.text


def test_se_puede_apagar(sessions_de_test):
    c = _cliente(_app(sessions_de_test, max_intentos_fallidos=0))
    for _ in range(8):
        assert c.post("/auth/login", json=CLAVE_MALA).status_code == 401
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 200


def test_sin_auth_events_no_bloquea_a_nadie(sessions_de_test):
    """Sin de donde contar, deja pasar.

    Fallar cerrado aca seria dejar a todos afuera porque falla el que cuenta.
    """
    c = _cliente(_app(None))
    for _ in range(8):
        assert c.post("/auth/login", json=CLAVE_MALA).status_code == 401
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 200


def test_el_bloqueo_queda_anotado(sessions_de_test):
    c = _cliente(_app(sessions_de_test))
    for _ in range(6):
        c.post("/auth/login", json=CLAVE_MALA)
    eventos = AuthEventRepository(sessions_de_test).listar()
    assert any(e["evento"] == LOGIN_BLOQUEADO for e in eventos), eventos
