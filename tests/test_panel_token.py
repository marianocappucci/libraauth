"""
Credencial del panel del cliente — la segunda credencial de servicio, separada
de la del backoffice del proveedor a proposito.

Lo que estos tests fijan, en orden de importancia:

1. 🔴 **Las dos credenciales no se cruzan.** El token de servicio no vale como
   token de panel ni al reves. Es el motivo de que exista una segunda:
   `LIBRA_SERVICE_TOKEN` es **por producto**, y dos clientes distintos de
   LibraDesk comparten uno. Si se cruzaran, el panel de un cliente leeria las
   instancias de otro.
2. **Sin `LIBRA_PANEL_TOKEN` no mira el header.** Una instancia que no participa
   de ningun panel no expone nada de mas, y actualizar no le cambia nada.
3. Un token equivocado no entra, y un header vacio tampoco.
"""
import pytest
from fastapi import Request

from libraauth.session_auth import (
    PANEL_TOKEN_ENV,
    PANEL_TOKEN_HEADER,
    SERVICE_TOKEN_ENV,
    SERVICE_TOKEN_HEADER,
    token_de_panel_valido,
    token_de_servicio_valido,
)

TOKEN_PANEL = "un-token-de-panel-largo-y-aleatorio"
TOKEN_SERVICIO = "un-token-de-servicio-largo-y-aleatorio"


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.delenv(PANEL_TOKEN_ENV, raising=False)
    monkeypatch.delenv(SERVICE_TOKEN_ENV, raising=False)


def _request(headers: dict) -> Request:
    """Una `Request` minima: estos guards solo miran headers y entorno."""
    crudos = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": crudos})


def test_sin_la_variable_no_mira_el_header():
    assert token_de_panel_valido(_request({PANEL_TOKEN_HEADER: TOKEN_PANEL})) is False


def test_con_la_variable_y_el_token_correcto_entra(monkeypatch):
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    assert token_de_panel_valido(_request({PANEL_TOKEN_HEADER: TOKEN_PANEL})) is True


def test_un_token_equivocado_no_entra(monkeypatch):
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    assert token_de_panel_valido(_request({PANEL_TOKEN_HEADER: "otra-cosa"})) is False


def test_sin_header_no_entra(monkeypatch):
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    assert token_de_panel_valido(_request({})) is False
    assert token_de_panel_valido(_request({PANEL_TOKEN_HEADER: ""})) is False


def test_el_token_de_servicio_NO_vale_como_token_de_panel(monkeypatch):
    """🔴 El test que justifica que exista una segunda credencial."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN_SERVICIO)
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)

    # Con el token de servicio, por su header y por el del panel.
    assert token_de_panel_valido(_request({SERVICE_TOKEN_HEADER: TOKEN_SERVICIO})) is False
    assert token_de_panel_valido(_request({PANEL_TOKEN_HEADER: TOKEN_SERVICIO})) is False


def test_el_token_de_panel_NO_vale_como_token_de_servicio(monkeypatch):
    """La otra direccion: el panel de un cliente no administra nada."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN_SERVICIO)
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)

    assert token_de_servicio_valido(_request({PANEL_TOKEN_HEADER: TOKEN_PANEL})) is False
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: TOKEN_PANEL})) is False


def test_las_dos_credenciales_conviven(monkeypatch):
    """Con las dos definidas, cada una entra por la suya.

    El control de que los dos tests de arriba prueban algo: sin esto, un
    `token_de_panel_valido` que devolviera siempre False los pasaria todos.
    """
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN_SERVICIO)
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)

    assert token_de_panel_valido(_request({PANEL_TOKEN_HEADER: TOKEN_PANEL})) is True
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: TOKEN_SERVICIO})) is True


def test_los_headers_y_las_variables_son_distintos():
    """Si alguien los unificara sin querer, el resto de los tests se volveria
    vacuo y esto lo delata."""
    assert PANEL_TOKEN_HEADER != SERVICE_TOKEN_HEADER
    assert PANEL_TOKEN_ENV != SERVICE_TOKEN_ENV


# ── El guard, que es lo que monta el router del resumen ─────────────────────

def _app_con_guard(session_auth):
    from fastapi import Depends, FastAPI

    from libraauth.session_auth import json_api_require_panel_o_admin

    app = FastAPI()
    app.state.session_auth = session_auth

    @app.get("/protegido")
    def protegido(u: dict = Depends(json_api_require_panel_o_admin)):
        return {"quien": u["username"]}

    return app


class _SesionFalsa:
    """Un  minimo: devuelve el usuario que le pongan, o ninguno."""

    def __init__(self, usuario=None):
        self._usuario = usuario

    def get_current_user(self, request):
        return self._usuario


def test_el_guard_deja_entrar_al_panel(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    cliente = TestClient(_app_con_guard(_SesionFalsa()))

    resp = cliente.get("/protegido", headers={PANEL_TOKEN_HEADER: TOKEN_PANEL})

    assert resp.status_code == 200
    assert resp.json()["quien"] == "@panel"


def test_el_guard_NO_deja_entrar_con_el_token_de_servicio(monkeypatch):
    """Lo mismo que arriba, pero en la puerta que usa el producto."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN_SERVICIO)
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    cliente = TestClient(_app_con_guard(_SesionFalsa()))

    resp = cliente.get("/protegido", headers={SERVICE_TOKEN_HEADER: TOKEN_SERVICIO})

    assert resp.status_code in (401, 403)
