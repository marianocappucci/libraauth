"""Términos propios de una instancia: lo que un revendedor de marca blanca carga para sus clientes (ADR-030).

Lo que fijan estos tests, en orden de lo que se rompe sin que se note:

1. 🔴 **Que una instancia que debe tener Términos propios NUNCA caiga a los de Libra.** Si el revendedor todavía no cargó los suyos, la
   instancia queda frenada y nadie puede aceptar. Un fallback «amable» haría que su cliente aceptara un contrato con otro prestador.
2. 🔴 **Que el mismo número de versión con otro texto no valga como aceptado.** La prueba de la cláusula 30.3 es versión Y hash.
3. Que el contrato propio sea el que se muestra, se hashea y se registra, y no el de la familia.
4. Que la próxima versión de la familia (la 1.1) no se le anuncie ni se le acepte a quien no se rige por ella.
5. Que el gate siga siendo barato: la versión se resuelve sin leer ni hashear el texto de la familia.
6. Que sin los ganchos nada cambie (los 48 tests de `test_terminos.py` lo prueban sin tocarse).
"""
import hashlib
import logging
from datetime import date

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from libraauth import terminos as terminos_mod
from libraauth.models import AceptacionTerminos, Base
from libraauth.session_auth import SessionAuth, build_json_api_auth_router, json_api_require_staff
from libraauth.terminos import (
    CODIGO_PENDIENTE,
    MAX_TEXTO_PROPIO,
    VERSION_VIGENTE,
    Contrato,
    ContratoSinCargar,
    TerminosRepository,
    build_terminos_router,
    hash_vigente,
    normalizar_texto,
    texto_vigente,
)
from tests.test_terminos import _logueado, _Usuarios

TEXTO = "# Términos de Gestión Sur\n\n1. El servicio lo presta Gestión Sur.\n2. Los datos son del Cliente.\n"
PROPIO = {"version": "2026-1", "vigente_desde": "01-11-2026", "texto": TEXTO}


def _sha(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)
    # Antes del 09-11-2026 la 1.1 de la familia está «próxima» (anunciada, no vigente): el escenario del punto 4.
    monkeypatch.setattr(terminos_mod, "_hoy_argentina", lambda: date(2026, 10, 10))


@pytest.fixture
def sessions():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


class Instancia:
    """Lo que el producto cablea: el contrato propio que hoy tiene la instancia y si debe tenerlo."""

    def __init__(self, sessions, *, propio=None, exigir=False):
        self.propio = propio
        self.exigir = exigir
        self.repo = TerminosRepository(
            sessions, contrato_propio=lambda: self.propio, exigir_propio=lambda: self.exigir,
        )
        self.app = FastAPI()
        usuarios = _Usuarios()
        self.app.state.users = usuarios
        self.app.state.session_auth = SessionAuth(
            dev_secret_fallback="dev",
            get_user_by_username=usuarios.get_by_username,
            check_credentials=usuarios.check_credentials,
        )
        self.app.state.terminos = self.repo
        self.app.include_router(build_json_api_auth_router())
        self.app.include_router(build_terminos_router())

        @self.app.get("/clientes", dependencies=[Depends(json_api_require_staff)])
        def clientes():
            return {"ok": True}


# ── 3. El contrato propio es el que se muestra, se hashea y se registra ─────

def test_el_estado_trae_el_contrato_propio_y_no_el_de_la_familia(sessions):
    inst = Instancia(sessions, propio=dict(PROPIO))
    cliente = _logueado(inst.app)
    e = cliente.get("/terminos?texto=1").json()
    assert e["propio"] is True and e["sin_contrato"] is False
    assert e["version"] == "2026-1" and e["vigente_desde"] == "01-11-2026"
    assert e["hash_texto"] == _sha(TEXTO) != hash_vigente()
    assert e["texto"] == TEXTO
    assert "<h1>Términos de Gestión Sur</h1>" in e["texto_html"]
    assert texto_vigente()[:40] not in e["texto"]  # nada del contrato de la familia
    assert e["pendiente"] is True and e["puede_aceptar"] is True


def test_sin_texto_en_el_estado_liviano(sessions):
    """El gate consulta este endpoint en cada carga: el texto sólo viaja con `?texto=1`, también el propio."""
    e = _logueado(Instancia(sessions, propio=dict(PROPIO)).app).get("/terminos").json()
    assert e["texto"] is None and e["texto_html"] is None and e["hash_texto"] == _sha(TEXTO)


def test_el_gate_corta_con_la_version_propia_y_se_destraba_aceptandola(sessions):
    inst = Instancia(sessions, propio=dict(PROPIO))
    cliente = _logueado(inst.app)
    r = cliente.get("/clientes")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == CODIGO_PENDIENTE
    assert r.json()["detail"]["version"] == "2026-1"

    assert cliente.post("/terminos/aceptar", json={"version": "2026-1"}).status_code == 200
    assert cliente.get("/clientes").status_code == 200


def test_aceptar_la_version_de_la_familia_en_una_instancia_propia_es_409(sessions):
    cliente = _logueado(Instancia(sessions, propio=dict(PROPIO)).app)
    r = cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})
    assert r.status_code == 409
    assert "2026-1" in r.json()["detail"]


def test_la_fila_probatoria_guarda_la_version_y_el_hash_propios(sessions):
    cliente = _logueado(Instancia(sessions, propio=dict(PROPIO)).app)
    cliente.post("/terminos/aceptar", json={"version": "2026-1"}, headers={"x-forwarded-for": "190.1.2.3"})
    with sessions() as s:
        fila = s.execute(select(AceptacionTerminos)).scalars().one()
    assert (fila.version, fila.hash_texto) == ("2026-1", _sha(TEXTO))
    assert fila.hash_texto != hash_vigente()
    assert fila.username == "admin"


def test_el_hash_no_depende_de_los_finales_de_linea(sessions):
    """La misma garantía que `texto_vigente()`, para el texto que llega de un formulario de Windows."""
    crlf = {**PROPIO, "texto": TEXTO.replace("\n", "\r\n")}
    e = _logueado(Instancia(sessions, propio=crlf).app).get("/terminos?texto=1").json()
    assert e["hash_texto"] == _sha(TEXTO) and "\r" not in e["texto"]


# ── 2. Versión Y hash: el mismo número con otro texto no vale ────────────────

def test_el_mismo_numero_de_version_con_otro_texto_vuelve_a_quedar_pendiente(sessions):
    inst = Instancia(sessions, propio=dict(PROPIO))
    cliente = _logueado(inst.app)
    cliente.post("/terminos/aceptar", json={"version": "2026-1"})
    assert cliente.get("/clientes").status_code == 200  # aceptado, y la caché se prendió

    inst.propio = {**PROPIO, "texto": TEXTO + "3. Una cláusula nueva.\n"}  # misma versión, otro texto
    r = cliente.get("/clientes")
    assert r.status_code == 403 and r.json()["detail"]["code"] == CODIGO_PENDIENTE
    assert cliente.get("/terminos").json()["pendiente"] is True

    inst.propio = dict(PROPIO)  # y si vuelve el texto aceptado, vuelve a pasar
    assert cliente.get("/clientes").status_code == 200


def test_pasar_de_los_terminos_de_la_familia_a_los_propios_con_el_mismo_numero_no_hereda_la_aceptacion(sessions):
    inst = Instancia(sessions)  # arranca con los de la familia
    cliente = _logueado(inst.app)
    assert cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE}).status_code == 200
    assert cliente.get("/clientes").status_code == 200

    inst.propio = {**PROPIO, "version": VERSION_VIGENTE}  # el revendedor elige también "1.0"
    assert cliente.get("/clientes").status_code == 403


# ── 1. Una instancia que debe tener términos propios nunca cae a los de Libra ─

def test_sin_terminos_propios_cargados_la_instancia_queda_frenada_y_no_cae_a_los_de_la_familia(sessions):
    inst = Instancia(sessions, propio=None, exigir=True)
    cliente = _logueado(inst.app)

    r = cliente.get("/clientes")
    assert r.status_code == 403
    detalle = r.json()["detail"]
    assert detalle["code"] == CODIGO_PENDIENTE and detalle["sin_contrato"] is True and detalle["version"] == ""
    assert "Avisale a tu proveedor" in detalle["mensaje"]

    e = cliente.get("/terminos?texto=1").json()
    assert e["sin_contrato"] is True and e["pendiente"] is True
    assert e["puede_aceptar"] is False  # ni siquiera el admin
    assert e["version"] == "" and e["hash_texto"] == "" and e["texto"] is None and e["texto_html"] is None
    assert e["proxima"] is None


def test_en_una_instancia_sin_contrato_no_se_puede_aceptar_ni_siquiera_la_version_de_la_familia(sessions):
    cliente = _logueado(Instancia(sessions, propio=None, exigir=True).app)
    for version in (VERSION_VIGENTE, "1.1", ""):
        r = cliente.post("/terminos/aceptar", json={"version": version})
        assert r.status_code == 409, version
        assert "Avisale a tu proveedor" in r.json()["detail"]
    with sessions() as s:
        assert s.execute(select(AceptacionTerminos)).first() is None


def test_registrar_sin_contrato_levanta(sessions):
    repo = Instancia(sessions, propio=None, exigir=True).repo
    with pytest.raises(ContratoSinCargar):
        repo.registrar(usuario_id=1, username="admin", nombre="Admin")
    assert repo.esta_aceptada() is False and repo.version == ""


def test_al_cargar_los_terminos_la_instancia_se_destraba(sessions):
    inst = Instancia(sessions, propio=None, exigir=True)
    cliente = _logueado(inst.app)
    assert cliente.get("/clientes").status_code == 403

    inst.propio = dict(PROPIO)
    r = cliente.get("/clientes")
    assert r.status_code == 403 and "sin_contrato" not in r.json()["detail"]  # ahora pide aceptar los suyos
    assert cliente.post("/terminos/aceptar", json={"version": "2026-1"}).status_code == 200
    assert cliente.get("/clientes").status_code == 200


def test_unos_terminos_propios_rotos_no_tumban_la_instancia_ni_caen_a_la_familia(sessions, caplog):
    """Un valor que no cumple la forma se ignora con un error en el log. Con `exigir`, la instancia queda frenada;
    sin `exigir`, es una instancia común y rige la familia. Nunca un 500 en cada pedido."""
    roto = {"version": "versión con espacios", "vigente_desde": "01-11-2026", "texto": TEXTO}
    with caplog.at_level(logging.ERROR, logger="libraauth.terminos"):
        exigida = Instancia(sessions, propio=dict(roto), exigir=True)
        assert _logueado(exigida.app).get("/terminos").json()["sin_contrato"] is True
        comun = Instancia(sessions, propio=dict(roto), exigir=False)
        e = _logueado(comun.app).get("/terminos").json()
    assert e["propio"] is False and e["version"] == VERSION_VIGENTE
    assert "no son válidos" in caplog.text


# ── 4. La próxima versión de la familia no es de las instancias propias ──────

def test_la_proxima_de_la_familia_no_se_anuncia_ni_se_acepta_en_una_instancia_propia(sessions):
    comun = _logueado(Instancia(sessions).app).get("/terminos").json()
    assert comun["proxima"] is not None and comun["proxima"]["version"] == "1.1"  # el control: en la común sí se anuncia

    inst = Instancia(sessions, propio=dict(PROPIO))
    cliente = _logueado(inst.app)
    assert cliente.get("/terminos").json()["proxima"] is None
    assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 409
    with pytest.raises(ValueError):
        inst.repo.registrar_proxima(usuario_id=1, username="admin", nombre="Admin")


def test_el_dia_que_rige_la_1_1_no_cambia_nada_para_una_instancia_propia(sessions, monkeypatch):
    inst = Instancia(sessions, propio=dict(PROPIO))
    cliente = _logueado(inst.app)
    cliente.post("/terminos/aceptar", json={"version": "2026-1"})
    monkeypatch.setattr(terminos_mod, "_hoy_argentina", lambda: date(2026, 11, 9))
    assert cliente.get("/clientes").status_code == 200
    assert cliente.get("/terminos").json()["version"] == "2026-1"


# ── 5. El gate sigue siendo barato ───────────────────────────────────────────

def test_el_gate_de_la_familia_no_lee_ni_hashea_el_texto(sessions, monkeypatch):
    """Casi siempre el gate sólo necesita la versión. Si el contrato leyera su texto de antemano, cada pedido gateado pagaría ~30 KB."""
    inst = Instancia(sessions)
    cliente = _logueado(inst.app)
    cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})

    def _no_deberia_leerse():
        raise AssertionError("el gate leyó el texto del contrato")

    monkeypatch.setattr(terminos_mod, "texto_vigente", _no_deberia_leerse)
    assert cliente.get("/clientes").status_code == 200
    assert inst.repo.esta_aceptada() is True


def test_un_contrato_propio_se_arma_y_se_hashea_una_sola_vez_mientras_el_producto_devuelva_el_mismo_objeto(sessions):
    inst = Instancia(sessions, propio=dict(PROPIO))
    primero = inst.repo.contrato()
    assert inst.repo.contrato() is primero  # el mismo objeto de origen: no se vuelve a armar
    assert primero.hash == primero.hash
    inst.propio = dict(PROPIO)  # otro objeto con el mismo contenido: se rearma (el costo es el de un hash)
    assert inst.repo.contrato() is not primero and inst.repo.contrato().hash == primero.hash


# ── La demo y el resto de lo de siempre ──────────────────────────────────────

def test_una_demo_no_exige_aceptar_ni_con_marca_propia_sin_terminos(sessions, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "demo")
    cliente = _logueado(Instancia(sessions, propio=None, exigir=True).app, "demo", "demo")
    assert cliente.get("/terminos").json()["pendiente"] is False
    assert cliente.get("/clientes").status_code == 200


def test_el_historial_lista_las_aceptaciones_propias(sessions):
    cliente = _logueado(Instancia(sessions, propio=dict(PROPIO)).app)
    cliente.post("/terminos/aceptar", json={"version": "2026-1"})
    h = cliente.get("/terminos/historial").json()
    assert [(f["version"], f["hash_texto"]) for f in h] == [("2026-1", _sha(TEXTO))]


# ── La forma de un contrato propio ───────────────────────────────────────────

class TestContratoPropio:
    def test_normaliza_y_hashea(self):
        c = Contrato.propio_desde({"version": "v1", "vigente_desde": "31-12-2026", "texto": "a\r\nb\rc\n"})
        assert c.texto == "a\nb\nc\n" and c.hash == _sha("a\nb\nc\n") and c.propio is True

    def test_un_contrato_ya_armado_pasa_tal_cual(self):
        c = Contrato(version="v1", vigente_desde="01-01-2027", texto="x", propio=True)
        assert Contrato.propio_desde(c) is c

    @pytest.mark.parametrize("version", ["", " ", "a b", "x" * 21, "-v1", "v/1", "v1\n", None, 3])
    def test_versiones_invalidas(self, version):
        with pytest.raises(ValueError, match="version"):
            Contrato.propio_desde({**PROPIO, "version": version})

    @pytest.mark.parametrize("desde", ["", "2026-11-01", "31-02-2026", "1/11/2026", "mañana", None, 20261101])
    def test_fechas_invalidas(self, desde):
        with pytest.raises(ValueError, match="vigente_desde"):
            Contrato.propio_desde({**PROPIO, "vigente_desde": desde})

    @pytest.mark.parametrize("texto", ["", "   \n ", None, 5])
    def test_texto_vacio_o_que_no_es_texto(self, texto):
        with pytest.raises(ValueError, match="texto"):
            Contrato.propio_desde({**PROPIO, "texto": texto})

    def test_texto_demasiado_largo(self):
        with pytest.raises(ValueError, match="máximo"):
            Contrato.propio_desde({**PROPIO, "texto": "x" * (MAX_TEXTO_PROPIO + 1)})
        Contrato.propio_desde({**PROPIO, "texto": "x" * MAX_TEXTO_PROPIO})  # el tope exacto entra

    def test_normalizar_texto(self):
        assert normalizar_texto("a\r\nb\rc") == "a\nb\nc"
