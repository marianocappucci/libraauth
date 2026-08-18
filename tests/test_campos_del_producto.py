"""Campos del producto en el usuario que devuelve el router (`get_extras`).

Generaliza lo que `get_empresa_nombre` ya hacia para un campo solo. Existe
por Contalibra y Restolibra: su `/me` devuelve `modulos` —de lo que depende
que menus dibuja el frontend—, `nombre` en castellano y dos contadores de
badge. Sin punto de extension, adoptar este router les vaciaria la pantalla,
y **sin error en ningun lado**: FastAPI valida contra `_UserOut` y descarta lo
que no este declarado, en silencio.

Ese descarte silencioso es lo que fija el primer test.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from libraauth.session_auth import build_json_api_auth_router

_ADMIN = {"id": "1", "username": "admin", "name": "Admin", "role": "admin", "active": True}


class _UsersFalso:
    def check_credentials(self, username, password):
        return dict(_ADMIN) if password == "correcta" else None

    def get_by_username(self, username):
        return dict(_ADMIN)


class _SessionAuthFalso:
    def create_session_cookie(self, response, username):
        response.set_cookie("sesion", username)

    def get_current_user(self, request):
        return request.cookies.get("sesion")

    def clear_session_cookie(self, response):
        response.delete_cookie("sesion")


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-extras")


def _cliente(**kwargs):
    app = FastAPI()
    app.state.users = _UsersFalso()
    app.state.session_auth = _SessionAuthFalso()
    app.include_router(build_json_api_auth_router(**kwargs))
    return TestClient(app, base_url="https://producto.test")


def test_sin_get_extras_el_usuario_sale_pelado():
    """El comportamiento de siempre, que no se mueve."""
    r = _cliente().post("/auth/login", json={"username": "admin", "password": "correcta"})
    assert r.status_code == 200
    assert set(r.json()) == {"id", "username", "name", "role", "active", "demo_readonly", "empresa_nombre"}


def test_los_campos_del_producto_llegan_al_frontend():
    c = _cliente(get_extras=lambda request, user: {
        "modulos": ["ventas", "compras"], "nombre": "Administrador", "badge": 3,
    })
    datos = c.post("/auth/login", json={"username": "admin", "password": "correcta"}).json()
    assert datos["modulos"] == ["ventas", "compras"]
    assert datos["nombre"] == "Administrador"
    assert datos["badge"] == 3


def test_tambien_en_me_y_no_solo_en_login():
    """Si sólo estuvieran en el login, el frontend los tendría al entrar y los
    perdería al recargar — y el sidebar cambiaria de forma sin que nadie toque
    nada."""
    c = _cliente(get_extras=lambda request, user: {"modulos": ["ventas"]})
    c.post("/auth/login", json={"username": "admin", "password": "correcta"})
    assert c.get("/auth/me").json()["modulos"] == ["ventas"]


def test_no_puede_pisar_lo_que_sostiene_el_gateo_por_rol():
    """El control que impide que un extra se coma la seguridad.

    Un producto que devolviera `role: "admin"` por descuido —o por un bug en
    su propio calculo— le daria a cualquiera los menus de administracion.
    """
    c = _cliente(get_extras=lambda request, user: {
        "role": "admin", "active": True, "demo_readonly": False, "modulos": ["x"],
    })
    datos = c.post("/auth/login", json={"username": "admin", "password": "correcta"}).json()
    assert datos["role"] == "admin"     # el real, que en este falso ya es admin
    assert datos["modulos"] == ["x"]    # el extra si pasa


def test_un_get_extras_que_devuelve_nada_no_rompe():
    c = _cliente(get_extras=lambda request, user: None)
    assert c.post("/auth/login", json={"username": "admin", "password": "correcta"}).status_code == 200
