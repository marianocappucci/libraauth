"""El visitante de la demo VE todo, y no toca nada.

Pedido del humano (2026-08-06): *"que muestre todos los menús y todas las
opciones como si fuera admin aunque no deje modificar esas cosas"*.

🔴 **Por qué esto y no un rol más alto.** El auto-login se niega a entregar
`admin`, y con `DEMO_PASSWORD` puesta el arranque corta si el usuario de demo
quedó admin. La única forma de que vea las pantallas de administración sin
volverse administrador es abrir **la lectura**: el rol sigue siendo el que es.

Lo que fijan estos tests, en orden de lo que se rompe sin que se note:

1. 🔴 **Que la escritura siga cerrada.** Es lo único que separa "una demo que
   se puede mirar entera" de "cualquiera edita la configuración desde
   internet". Y el GET que pasa sólo prueba algo si el mismo archivo verifica
   que el POST **no** pasa.
2. 🔴 **Que esto no exista fuera de una demo.** En la instancia de un cliente,
   un usuario que se llame `demo` no abre nada: la excepción cuelga de
   `demo_username()`, que devuelve `None` sin `DEMO_MODE`.
3. Que `demo_readonly` viaje en `/auth/me`, que es de donde el frontend saca
   si muestra los menús de administración.
"""
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from libraauth.session_auth import (
    SessionAuth,
    build_json_api_auth_router,
    json_api_require_admin,
    json_api_require_admin_o_servicio,
)


class _Usuarios:
    def __init__(self):
        self._users = {
            "admin": {"id": "1", "username": "admin", "name": "Admin",
                      "role": "admin", "active": True, "_password": "adminpw"},
            "demo": {"id": "2", "username": "demo", "name": "Visitante",
                     "role": "staff", "active": True, "_password": "demo"},
            "ana": {"id": "3", "username": "ana", "name": "Ana",
                    "role": "staff", "active": True, "_password": "anapw"},
        }

    def _publico(self, u):
        return {k: v for k, v in u.items() if k != "_password"}

    def get_by_username(self, username):
        u = self._users.get(username)
        return self._publico(u) if u else None

    def check_credentials(self, username, password):
        u = self._users.get(username)
        return self._publico(u) if u and u["_password"] == password else None


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")


@pytest.fixture
def demo_encendida(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "demo")


def _app():
    """Una app con un router admin-only, que es el caso real: en los productos
    hay routers enteros colgados de `require_admin`."""
    app = FastAPI()
    usuarios = _Usuarios()
    app.state.users = usuarios
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="test-secret",
        get_user_by_username=usuarios.get_by_username,
        check_credentials=usuarios.check_credentials,
        cookie_name="test_session",
    )
    app.include_router(build_json_api_auth_router(incluir_demo=True))

    @app.get("/config", dependencies=[Depends(json_api_require_admin)])
    def leer_config():
        return {"empresa": "Demo SA"}

    @app.put("/config", dependencies=[Depends(json_api_require_admin)])
    def guardar_config():
        return {"guardado": True}

    @app.delete("/config", dependencies=[Depends(json_api_require_admin)])
    def borrar_config():
        return {"borrado": True}

    # El router de usuarios de los seis productos NO cuelga de `require_admin`
    # sino de éste, que acepta además el token de servicio del backoffice. Es
    # un camino distinto y por eso se prueba aparte: con la excepción sólo en
    # el otro guard, el visitante veía 403 justo en la pantalla de Usuarios.
    @app.get("/usuarios", dependencies=[Depends(json_api_require_admin_o_servicio)])
    def listar_usuarios():
        return [{"username": "admin"}]

    @app.post("/usuarios", dependencies=[Depends(json_api_require_admin_o_servicio)])
    def crear_usuario():
        return {"creado": True}

    return TestClient(app, base_url="https://testserver")


def _entrar(cliente, usuario, clave):
    r = cliente.post("/auth/login", json={"username": usuario, "password": clave})
    assert r.status_code == 200, r.text
    return r


# ── 🔴 Ve, pero no toca ────────────────────────────────────────────────────

def test_el_visitante_ve_una_pantalla_de_admin(demo_encendida):
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    r = cliente.get("/config")

    assert r.status_code == 200, r.text
    assert r.json() == {"empresa": "Demo SA"}


def test_el_visitante_no_puede_guardar(demo_encendida):
    """La mitad que sostiene todo: sin esto, la demo es un panel de
    administración abierto a internet."""
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    assert cliente.put("/config").status_code == 403


def test_el_visitante_no_puede_borrar(demo_encendida):
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    assert cliente.delete("/config").status_code == 403


def test_el_visitante_ve_la_pantalla_de_usuarios(demo_encendida):
    """🔴 Camino distinto: el router de usuarios cuelga de
    `require_admin_o_servicio`, no de `require_admin`. Con la excepción sólo en
    el otro guard, el visitante veía 403 justo en esa pantalla — y lo encontró
    probarlo contra la demo desplegada, no la suite."""
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    assert cliente.get("/usuarios").status_code == 200


def test_el_visitante_no_puede_crear_usuarios(demo_encendida):
    """La otra mitad, y la que importa: ver la lista de usuarios de una demo es
    inocuo; poder darse de alta uno, no."""
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    assert cliente.post("/usuarios").status_code == 403


# ── 🔴 Sólo en una demo, y sólo ese usuario ────────────────────────────────

def test_fuera_de_una_demo_no_ve_nada(monkeypatch):
    """El mismo usuario, con el mismo nombre, en la instancia de un cliente:
    la excepción cuelga de `demo_username()`, que sin `DEMO_MODE` es `None`."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    assert cliente.get("/config").status_code == 403


def test_otro_staff_de_la_demo_tampoco_ve(demo_encendida):
    """Se abre para **el visitante**, no para el rol. Un empleado de la demo
    con rol staff sigue sin ver la configuración."""
    cliente = _app()
    _entrar(cliente, "ana", "anapw")

    assert cliente.get("/config").status_code == 403


def test_el_admin_sigue_pudiendo_todo(demo_encendida):
    cliente = _app()
    _entrar(cliente, "admin", "adminpw")

    assert cliente.get("/config").status_code == 200
    assert cliente.put("/config").status_code == 200


# ── La bandera que mira el frontend ────────────────────────────────────────

def test_me_marca_al_visitante(demo_encendida):
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    yo = cliente.get("/auth/me").json()

    assert yo["demo_readonly"] is True
    # 🔴 Y el rol NO se toca: los botones de guardar se siguen gateando por
    # rol, así que mentir acá llenaría la pantalla de acciones que fallan.
    assert yo["role"] == "staff"


def test_el_admin_no_queda_marcado(demo_encendida):
    cliente = _app()
    _entrar(cliente, "admin", "adminpw")

    assert cliente.get("/auth/me").json()["demo_readonly"] is False


def test_fuera_de_una_demo_nadie_queda_marcado(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    cliente = _app()
    _entrar(cliente, "demo", "demo")

    assert cliente.get("/auth/me").json()["demo_readonly"] is False


def test_el_auto_login_devuelve_la_bandera(demo_encendida):
    """El botón entra por acá, así que si la bandera no viniera en esta
    respuesta el menú quedaría corto hasta el primer refresco."""
    cliente = _app()

    assert cliente.post("/auth/demo").json()["demo_readonly"] is True
