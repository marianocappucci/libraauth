"""
El gate que deja al panel del cliente aprovisionar empleados en SU instancia.

Hasta v0.34.0 la credencial del panel autorizaba **una sola ruta**,
`/api/resumen`, y de solo lectura. `json_api_require_admin_o_servicio_o_panel`
la deja tambien administrar usuarios en los routers que lo declaren.

Lo que estos tests fijan, en orden de importancia:

1. 🔴 **La ampliacion NO se filtro al gate viejo.** `json_api_require_admin_o_servicio`
   ---del que cuelgan siete u ocho routers por producto--- sigue rechazando la
   credencial del panel. Si se hubiera ampliado aquel en vez de agregar este, el
   panel habria ganado todo eso de una sin que nadie lo pidiera.
2. **Opt-in por ausencia**: sin `LIBRA_PANEL_TOKEN` en el entorno, el header no
   sirve para nada. Una instancia que no participa de ningun panel no expone
   nada de mas.
3. Las dos credenciales siguen sin cruzarse, y la sesion de admin sigue
   entrando por los dos.
"""
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from libraauth.session_auth import (
    PANEL_TOKEN_ENV,
    PANEL_TOKEN_HEADER,
    SERVICE_TOKEN_ENV,
    SERVICE_TOKEN_HEADER,
    json_api_require_admin_o_servicio,
    json_api_require_admin_o_servicio_o_panel,
)

TOKEN_PANEL = "un-token-de-panel-largo-y-aleatorio"
TOKEN_SERVICIO = "un-token-de-servicio-largo-y-aleatorio"


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 64)
    monkeypatch.delenv(PANEL_TOKEN_ENV, raising=False)
    monkeypatch.delenv(SERVICE_TOKEN_ENV, raising=False)


class _SessionAuthFalso:
    def __init__(self, username):
        self._username = username

    def get_current_user(self, request):
        return self._username


class _UsersFalso:
    def __init__(self, user):
        self._user = user

    def get_by_username(self, username):
        return self._user


def _cliente(*, logueado=False, rol="admin"):
    """Una app con las DOS rutas, la nueva y la vieja, gateadas cada una por su
    guard. Tenerlas juntas es lo que permite comparar en el mismo test que una
    acepta la credencial del panel y la otra no."""
    app = FastAPI()
    app.state.session_auth = _SessionAuthFalso("admin1" if logueado else None)
    app.state.users = _UsersFalso(
        {"id": "1", "username": "admin1", "name": "Admin", "role": rol, "active": True}
    )

    @app.post("/con-panel")
    def con_panel(usuario: dict = Depends(json_api_require_admin_o_servicio_o_panel)):
        return {"quien": usuario["username"]}

    @app.post("/sin-panel")
    def sin_panel(usuario: dict = Depends(json_api_require_admin_o_servicio)):
        return {"quien": usuario["username"]}

    return TestClient(app)


# -- Lo que mas importa: la ampliacion no se filtro ------------------------


def test_EL_GATE_VIEJO_SIGUE_RECHAZANDO_AL_PANEL(monkeypatch):
    """🔴 El test que justifica que exista un guard nuevo en vez de ampliar el otro.

    De `json_api_require_admin_o_servicio` cuelga el router de usuarios ---y seis
    o siete mas--- en los ocho productos. Ampliarlo le habria dado al panel todo
    eso de una. Se aplica router por router, y esto lo fija.
    """
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    cliente = _cliente()

    # El control positivo: por el gate nuevo SI entra, o sea que el token es
    # bueno y el 401 de abajo no es por una credencial mal escrita.
    assert cliente.post("/con-panel", headers={PANEL_TOKEN_HEADER: TOKEN_PANEL}).status_code == 200
    # Y por el viejo no.
    r = cliente.post("/sin-panel", headers={PANEL_TOKEN_HEADER: TOKEN_PANEL})
    assert r.status_code == 401, (
        "la credencial del panel entro por el gate viejo: la ampliacion se filtro"
    )


# -- Opt-in por ausencia ---------------------------------------------------


def test_sin_la_variable_el_header_no_sirve_para_nada():
    """La garantia de adopcion: una instancia que actualiza y no toca su compose
    se comporta exactamente como antes."""
    r = _cliente().post("/con-panel", headers={PANEL_TOKEN_HEADER: TOKEN_PANEL})
    assert r.status_code == 401


def test_sin_la_variable_la_sesion_admin_sigue_entrando():
    assert _cliente(logueado=True).post("/con-panel").status_code == 200


# -- Con la variable -------------------------------------------------------


def test_con_el_token_del_panel_entra_y_se_identifica(monkeypatch):
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    r = _cliente().post("/con-panel", headers={PANEL_TOKEN_HEADER: TOKEN_PANEL})
    assert r.status_code == 200, r.text
    # Se identifica como el panel y no como el servicio: los dos son "admin"
    # para el resto del codigo, pero la auditoria tiene que poder distinguirlos.
    assert r.json()["quien"] == "@panel"


def test_el_token_de_servicio_tambien_entra_por_el_gate_nuevo(monkeypatch):
    """No se le saca nada al backoffice: el gate nuevo es el viejo MAS el panel."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN_SERVICIO)
    r = _cliente().post("/con-panel", headers={SERVICE_TOKEN_HEADER: TOKEN_SERVICIO})
    assert r.status_code == 200, r.text
    assert r.json()["quien"] == "@servicio"


def test_un_token_de_panel_equivocado_no_entra(monkeypatch):
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    r = _cliente().post("/con-panel", headers={PANEL_TOKEN_HEADER: "otra-cosa"})
    assert r.status_code == 401


def test_LAS_DOS_CREDENCIALES_NO_SE_CRUZAN(monkeypatch):
    """🔴 Sigue siendo el motivo de que exista una segunda credencial.

    `LIBRA_SERVICE_TOKEN` es por PRODUCTO ---dos clientes distintos de LibraDesk
    comparten uno---. Si el token de servicio valiera por el header del panel, o
    al reves, la credencial de un cliente abriria las instancias de otro.
    """
    monkeypatch.setenv(PANEL_TOKEN_ENV, TOKEN_PANEL)
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN_SERVICIO)
    cliente = _cliente()

    # El de servicio por el header del panel: no.
    assert cliente.post(
        "/con-panel", headers={PANEL_TOKEN_HEADER: TOKEN_SERVICIO}
    ).status_code == 401
    # El del panel por el header de servicio: tampoco.
    assert cliente.post(
        "/con-panel", headers={SERVICE_TOKEN_HEADER: TOKEN_PANEL}
    ).status_code == 401
    # Los controles: cada uno por su header SI entra.
    assert cliente.post(
        "/con-panel", headers={PANEL_TOKEN_HEADER: TOKEN_PANEL}
    ).status_code == 200
    assert cliente.post(
        "/con-panel", headers={SERVICE_TOKEN_HEADER: TOKEN_SERVICIO}
    ).status_code == 200


def test_un_usuario_no_admin_no_entra(monkeypatch):
    """Que el gate acepte dos tokens no lo vuelve laxo con las sesiones."""
    r = _cliente(logueado=True, rol="staff").post("/con-panel")
    assert r.status_code == 403
