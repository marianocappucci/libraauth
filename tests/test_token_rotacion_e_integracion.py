"""
Rotacion sin corte del token de servicio y credencial de integracion (ADR-025).

Lo que estos tests fijan, en orden de importancia:

1. 🔴 **La integracion no abre ningun gate anterior.** Ni `json_api_require_admin`,
   ni el de servicio, ni el del panel, ni los routers de SMTP, usuarios y codigos
   de demo. Solo entra por los dos gates nuevos.
2. 🔴 **Las dos comparaciones se hacen siempre**, con `compare_digest`: el
   tiempo de respuesta no dice cual de los dos tokens coincidio.
3. Rotacion: con `_ANTERIOR` definida valen los dos; vacia o ausente, solo el
   nuevo. Sin ninguna variable, el header no sirve para nada.
4. Un token corto se avisa en el log una vez, sin el valor.
"""
import logging

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth import session_auth
from libraauth.models import Base
from libraauth.session_auth import (
    INTEGRACION_TOKEN_ANTERIOR_ENV,
    INTEGRACION_TOKEN_ENV,
    INTEGRACION_TOKEN_HEADER,
    PANEL_TOKEN_ENV,
    PANEL_TOKEN_HEADER,
    SERVICE_TOKEN_ANTERIOR_ENV,
    SERVICE_TOKEN_ENV,
    SERVICE_TOKEN_HEADER,
    build_demo_codigos_router,
    build_smtp_settings_router,
    json_api_require_admin,
    json_api_require_admin_o_servicio,
    json_api_require_admin_o_servicio_o_integracion,
    json_api_require_admin_o_servicio_o_panel,
    json_api_require_integracion_o_servicio,
    json_api_require_panel_o_admin,
    json_api_require_staff,
    token_de_integracion_valido,
    token_de_servicio_valido,
)
from libraauth.smtp_settings import SmtpSettingsRepository
from libraauth.usuarios import build_users_router

# Ficticios, todos de 32 caracteres o mas salvo el "corto".
SERVICIO = "servicio-nuevo-ficticio-0123456789abcdef"
SERVICIO_ANT = "servicio-anterior-ficticio-0123456789ab"
INTEGRACION = "integracion-nueva-ficticia-0123456789ab"
INTEGRACION_ANT = "integracion-anterior-ficticia-012345678"
PANEL = "panel-ficticio-0123456789abcdef0123456"

_VARIABLES = (
    SERVICE_TOKEN_ENV, SERVICE_TOKEN_ANTERIOR_ENV,
    INTEGRACION_TOKEN_ENV, INTEGRACION_TOKEN_ANTERIOR_ENV, PANEL_TOKEN_ENV,
)


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 64)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    for v in _VARIABLES:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(session_auth, "_ya_avisadas", set())


def _request(headers: dict) -> Request:
    crudos = [(k.lower().encode(), v.encode("latin-1")) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": crudos})


# ── Rotacion del token de servicio ──────────────────────────────────────────


def test_sin_ninguna_variable_no_vale_nada():
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO})) is False
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: ""})) is False


def test_con_anterior_valen_los_dos(monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    monkeypatch.setenv(SERVICE_TOKEN_ANTERIOR_ENV, SERVICIO_ANT)
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO})) is True
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO_ANT})) is True
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: "otra-cosa"})) is False
    assert token_de_servicio_valido(_request({})) is False


def test_sin_anterior_el_viejo_ya_no_vale(monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO_ANT})) is False


def test_anterior_vacia_no_vale_nada(monkeypatch):
    """Una variable puesta en blanco en el compose no habilita el header vacio."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    monkeypatch.setenv(SERVICE_TOKEN_ANTERIOR_ENV, "")
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: ""})) is False
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO})) is True


def test_solo_anterior_definida_vale_la_anterior(monkeypatch):
    """Cada variable vale por si misma: la nueva vacia no anula la anterior."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, "")
    monkeypatch.setenv(SERVICE_TOKEN_ANTERIOR_ENV, SERVICIO_ANT)
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO_ANT})) is True
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: ""})) is False


def test_header_no_ascii_da_false_y_no_explota(monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: "ñandú"})) is False


# ── Tiempo constante ────────────────────────────────────────────────────────


class _Espia:
    def __init__(self, real):
        self.real = real
        self.llamadas = []

    def __call__(self, a, b):
        self.llamadas.append((a, b))
        return self.real(a, b)


@pytest.mark.parametrize(
    "funcion, env, env_ant, header, nuevo, anterior",
    [
        (token_de_servicio_valido, SERVICE_TOKEN_ENV, SERVICE_TOKEN_ANTERIOR_ENV,
         SERVICE_TOKEN_HEADER, SERVICIO, SERVICIO_ANT),
        (token_de_integracion_valido, INTEGRACION_TOKEN_ENV, INTEGRACION_TOKEN_ANTERIOR_ENV,
         INTEGRACION_TOKEN_HEADER, INTEGRACION, INTEGRACION_ANT),
    ],
)
@pytest.mark.parametrize("enviado", ["nuevo", "anterior", "ninguno"])
def test_compara_siempre_contra_los_dos(
    monkeypatch, funcion, env, env_ant, header, nuevo, anterior, enviado
):
    """🔴 Aunque coincida con el nuevo, tambien compara contra el anterior: sin
    cortocircuito, el tiempo no dice cual coincidio."""
    monkeypatch.setenv(env, nuevo)
    monkeypatch.setenv(env_ant, anterior)
    espia = _Espia(session_auth.hmac.compare_digest)
    monkeypatch.setattr(session_auth.hmac, "compare_digest", espia)

    valor = {"nuevo": nuevo, "anterior": anterior, "ninguno": "x" * 40}[enviado]
    assert funcion(_request({header: valor})) is (enviado != "ninguno")

    comparados = {b for _, b in espia.llamadas}
    assert comparados == {nuevo.encode(), anterior.encode()}
    assert len(espia.llamadas) == 2


def test_sin_anterior_compara_una_vez(monkeypatch):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    espia = _Espia(session_auth.hmac.compare_digest)
    monkeypatch.setattr(session_auth.hmac, "compare_digest", espia)
    assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO})) is True
    assert len(espia.llamadas) == 1


# ── Aviso de token corto ────────────────────────────────────────────────────


def test_token_corto_se_avisa_una_vez_y_sin_el_valor(monkeypatch, caplog):
    corto = "corto-ficticio-123"
    monkeypatch.setenv(SERVICE_TOKEN_ENV, corto)
    with caplog.at_level(logging.WARNING, logger="libraauth.session_auth"):
        for _ in range(3):
            assert token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: corto})) is True
    avisos = [r for r in caplog.records if r.name == "libraauth.session_auth"]
    assert len(avisos) == 1
    assert SERVICE_TOKEN_ENV in avisos[0].getMessage()
    assert corto not in caplog.text


def test_token_largo_no_avisa(monkeypatch, caplog):
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    monkeypatch.setenv(SERVICE_TOKEN_ANTERIOR_ENV, SERVICIO_ANT)
    with caplog.at_level(logging.WARNING, logger="libraauth.session_auth"):
        token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: SERVICIO}))
    assert not [r for r in caplog.records if r.name == "libraauth.session_auth"]


def test_anterior_corta_tambien_se_avisa(monkeypatch, caplog):
    monkeypatch.setenv(INTEGRACION_TOKEN_ENV, INTEGRACION)
    monkeypatch.setenv(INTEGRACION_TOKEN_ANTERIOR_ENV, "corta-ficticia")
    with caplog.at_level(logging.WARNING, logger="libraauth.session_auth"):
        token_de_integracion_valido(_request({}))
    mensajes = [r.getMessage() for r in caplog.records if r.name == "libraauth.session_auth"]
    assert len(mensajes) == 1 and INTEGRACION_TOKEN_ANTERIOR_ENV in mensajes[0]
    assert "corta-ficticia" not in caplog.text


# ── Credencial de integracion: la funcion ───────────────────────────────────


def test_integracion_sin_variable_no_mira_el_header():
    r = _request({INTEGRACION_TOKEN_HEADER: INTEGRACION})
    assert token_de_integracion_valido(r) is False


def test_integracion_rota_igual_que_el_servicio(monkeypatch):
    monkeypatch.setenv(INTEGRACION_TOKEN_ENV, INTEGRACION)
    monkeypatch.setenv(INTEGRACION_TOKEN_ANTERIOR_ENV, INTEGRACION_ANT)
    assert token_de_integracion_valido(_request({INTEGRACION_TOKEN_HEADER: INTEGRACION}))
    assert token_de_integracion_valido(_request({INTEGRACION_TOKEN_HEADER: INTEGRACION_ANT}))
    assert not token_de_integracion_valido(_request({INTEGRACION_TOKEN_HEADER: "otra"}))


def test_integracion_y_servicio_no_se_cruzan(monkeypatch):
    monkeypatch.setenv(INTEGRACION_TOKEN_ENV, INTEGRACION)
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    assert not token_de_integracion_valido(_request({INTEGRACION_TOKEN_HEADER: SERVICIO}))
    assert not token_de_integracion_valido(_request({SERVICE_TOKEN_HEADER: INTEGRACION}))
    assert not token_de_servicio_valido(_request({SERVICE_TOKEN_HEADER: INTEGRACION}))
    assert not token_de_servicio_valido(_request({INTEGRACION_TOKEN_HEADER: SERVICIO}))


# ── Los gates, por HTTP ─────────────────────────────────────────────────────


class _SessionAuthFalso:
    def __init__(self, username):
        self._username = username

    def get_current_user(self, request, response=None):
        return self._username


class _UsersFalso:
    def __init__(self, user):
        self._user = user

    def get_by_username(self, username):
        return self._user

    def list(self):
        return [self._user]


_GATES_VIEJOS = {
    "admin": json_api_require_admin,
    "staff": json_api_require_staff,
    "admin_o_servicio": json_api_require_admin_o_servicio,
    "admin_o_servicio_o_panel": json_api_require_admin_o_servicio_o_panel,
    "panel_o_admin": json_api_require_panel_o_admin,
}


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/tokens.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _cliente(session_factory=None, *, logueado=False, rol="admin"):
    app = FastAPI()
    app.state.session_auth = _SessionAuthFalso("admin1" if logueado else None)
    app.state.users = _UsersFalso(
        {"id": "1", "username": "admin1", "name": "Admin", "role": rol, "active": True}
    )

    def _ruta(nombre, gate):
        @app.post(f"/{nombre}")
        def _(usuario: dict = Depends(gate)):
            return {"quien": usuario["username"], "rol": usuario["role"]}

    for nombre, gate in _GATES_VIEJOS.items():
        _ruta(nombre, gate)
    _ruta("integraciones", json_api_require_admin_o_servicio_o_integracion)
    _ruta("ingesta", json_api_require_integracion_o_servicio)

    if session_factory is not None:
        app.state.smtp_settings = SmtpSettingsRepository(session_factory)
        app.include_router(build_smtp_settings_router())
        app.include_router(build_demo_codigos_router())
        app.include_router(build_users_router(admin_guard=json_api_require_admin_o_servicio,
                                              prefix="/api/usuarios"))
    return TestClient(app)


@pytest.mark.parametrize("ruta", sorted(_GATES_VIEJOS))
def test_LA_INTEGRACION_NO_ABRE_LOS_GATES_VIEJOS(monkeypatch, ruta):
    """🔴 Con todas las variables puestas, el token de integracion por su header
    no entra a ningun gate anterior. El control positivo (entra por el nuevo)
    descarta que el 401 sea por un token mal escrito."""
    for env, valor in ((INTEGRACION_TOKEN_ENV, INTEGRACION),
                       (SERVICE_TOKEN_ENV, SERVICIO), (PANEL_TOKEN_ENV, PANEL)):
        monkeypatch.setenv(env, valor)
    cliente = _cliente()
    h = {INTEGRACION_TOKEN_HEADER: INTEGRACION}
    assert cliente.post("/integraciones", headers=h).status_code == 200
    assert cliente.post(f"/{ruta}", headers=h).status_code == 401
    # Ni puesto en el header de otro.
    for otro in (SERVICE_TOKEN_HEADER, PANEL_TOKEN_HEADER):
        assert cliente.post(f"/{ruta}", headers={otro: INTEGRACION}).status_code == 401


@pytest.mark.parametrize("valor", [INTEGRACION, INTEGRACION_ANT])
def test_LA_INTEGRACION_NO_ABRE_SMTP_USUARIOS_NI_DEMO_CODIGOS(
    session_factory, monkeypatch, valor
):
    """🔴 Lo mismo contra los routers reales que administra el backoffice."""
    monkeypatch.setenv(INTEGRACION_TOKEN_ENV, INTEGRACION)
    monkeypatch.setenv(INTEGRACION_TOKEN_ANTERIOR_ENV, INTEGRACION_ANT)
    cliente = _cliente(session_factory)
    h = {INTEGRACION_TOKEN_HEADER: valor}
    assert cliente.get("/admin/smtp", headers=h).status_code == 401
    assert cliente.put("/admin/smtp", headers=h, json={"host": "smtp.test"}).status_code == 401
    assert cliente.delete("/admin/smtp", headers=h).status_code == 401
    assert cliente.get("/api/usuarios", headers=h).status_code == 401
    assert cliente.post("/api/usuarios", headers=h, json={}).status_code == 401
    assert cliente.get("/admin/demo-codigos", headers=h).status_code == 401


def test_gate_de_integraciones_acepta_integracion_servicio_y_admin(monkeypatch):
    monkeypatch.setenv(INTEGRACION_TOKEN_ENV, INTEGRACION)
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    cliente = _cliente()
    r = cliente.post("/integraciones", headers={INTEGRACION_TOKEN_HEADER: INTEGRACION})
    assert r.json() == {"quien": "@integracion", "rol": "integracion"}
    r = cliente.post("/integraciones", headers={SERVICE_TOKEN_HEADER: SERVICIO})
    assert r.json()["quien"] == "@servicio"
    r = _cliente(logueado=True).post("/integraciones")
    assert r.status_code == 200 and r.json()["quien"] == "admin1"


def test_gate_de_integraciones_rechaza_panel_y_no_admin(monkeypatch):
    monkeypatch.setenv(PANEL_TOKEN_ENV, PANEL)
    assert _cliente().post("/integraciones", headers={PANEL_TOKEN_HEADER: PANEL}).status_code == 401
    assert _cliente(logueado=True, rol="staff").post("/integraciones").status_code == 403


def test_gate_de_ingesta_solo_maquinas(monkeypatch):
    """Sin sesion: ni un admin logueado entra. Si integracion y servicio."""
    monkeypatch.setenv(INTEGRACION_TOKEN_ENV, INTEGRACION)
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    monkeypatch.setenv(PANEL_TOKEN_ENV, PANEL)
    cliente = _cliente(logueado=True)
    assert cliente.post("/ingesta").status_code == 401
    assert cliente.post("/ingesta", headers={PANEL_TOKEN_HEADER: PANEL}).status_code == 401
    r = cliente.post("/ingesta", headers={INTEGRACION_TOKEN_HEADER: INTEGRACION})
    assert r.status_code == 200 and r.json()["quien"] == "@integracion"
    r = cliente.post("/ingesta", headers={SERVICE_TOKEN_HEADER: SERVICIO})
    assert r.status_code == 200 and r.json()["quien"] == "@servicio"


def test_gate_de_ingesta_sin_variables_no_entra_nadie():
    cliente = _cliente(logueado=True)
    assert cliente.post("/ingesta", headers={INTEGRACION_TOKEN_HEADER: INTEGRACION}).status_code == 401


def test_el_servicio_anterior_entra_por_los_gates_de_servicio(monkeypatch):
    """La rotacion vale en todos los gates que aceptan servicio, no solo en uno."""
    monkeypatch.setenv(SERVICE_TOKEN_ENV, SERVICIO)
    monkeypatch.setenv(SERVICE_TOKEN_ANTERIOR_ENV, SERVICIO_ANT)
    cliente = _cliente()
    h = {SERVICE_TOKEN_HEADER: SERVICIO_ANT}
    for ruta in ("admin_o_servicio", "admin_o_servicio_o_panel", "integraciones", "ingesta"):
        assert cliente.post(f"/{ruta}", headers=h).status_code == 200, ruta
