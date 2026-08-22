"""El gate de Términos y Condiciones: qué corta, qué deja pasar y qué prueba.

Lo que fijan estos tests, en orden de lo que se rompe sin que se note:

1. 🔴 **Que el gate no se cierre sobre sí mismo.** Es el defecto que deja una
   instancia inutilizable: si las rutas de `/terminos` y `/auth` pasaran por el
   mismo guard que el resto, no habría forma de aceptar y nadie podría entrar
   nunca más. El test que dice "la ruta gateada corta" no prueba nada si el
   mismo archivo no verifica que las de aceptar **siguen abiertas**.
2. 🔴 **Que el hash no dependa del checkout.** El archivo puede llegar con CRLF
   a cualquier clon de Windows. Sin normalizar, la misma versión del contrato
   daría un sha256 distinto según dónde corra, y la cláusula 30.3 no probaría
   nada. Se verifica **mutando el archivo a CRLF**, no leyendo el código.
3. Que sólo el responsable (rol `admin`) pueda aceptar — cláusula 30.5.
4. Que la fila probatoria guarde versión, hash, quién e IP real detrás del proxy.
5. Que la demo pública no quede bloqueada para siempre.
6. Que las tres cláusulas que el contrato existe para sentar sigan en el texto.
"""
import hashlib

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from libraauth import terminos as terminos_mod
from libraauth.models import AceptacionTerminos, Base
from libraauth.session_auth import (
    SessionAuth, build_json_api_auth_router, json_api_require_staff,
)
from libraauth.terminos import (
    CODIGO_PENDIENTE, VERSION_VIGENTE, TerminosRepository, build_terminos_router,
    hash_vigente, texto_html, texto_vigente,
)


class _Usuarios:
    def __init__(self):
        self._users = {
            "admin": {"id": "1", "username": "admin", "name": "Admin",
                      "role": "admin", "active": True, "_password": "adminpw"},
            "ana": {"id": "2", "username": "ana", "name": "Ana",
                    "role": "staff", "active": True, "_password": "anapw"},
            "demo": {"id": "3", "username": "demo", "name": "Visitante",
                     "role": "staff", "active": True, "_password": "demo"},
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
    # El resto de la suite deja `DEMO_MODE` prendido en sus propios fixtures;
    # acá se apaga salvo donde el test lo pida, para que `es_visitante_de_demo`
    # no abra excepciones que este archivo no está midiendo.
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)


@pytest.fixture
def sessions():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _app(sessions, *, con_terminos=True):
    app = FastAPI()
    usuarios = _Usuarios()
    app.state.users = usuarios
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=usuarios.get_by_username,
        check_credentials=usuarios.check_credentials,
    )
    if con_terminos:
        app.state.terminos = TerminosRepository(sessions)
    app.include_router(build_json_api_auth_router())
    app.include_router(build_terminos_router())

    @app.get("/clientes", dependencies=[Depends(json_api_require_staff)])
    def clientes():
        return {"ok": True}

    return app


def _logueado(app, username="admin", password="adminpw"):
    cliente = TestClient(app, base_url="https://testserver")
    r = cliente.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return cliente


# ── 1. El gate corta, y no se cierra sobre sí mismo ──────────────────────────

def test_ruta_gateada_corta_con_el_codigo_de_terminos(sessions):
    cliente = _logueado(_app(sessions))
    r = cliente.get("/clientes")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == CODIGO_PENDIENTE
    assert r.json()["detail"]["version"] == VERSION_VIGENTE


def test_las_rutas_para_salir_del_gate_siguen_abiertas(sessions):
    """El control que hace útil al de arriba: con la instancia frenada, lo que
    permite destrabarla tiene que seguir contestando 200."""
    cliente = _logueado(_app(sessions))
    assert cliente.get("/auth/me").status_code == 200
    assert cliente.get("/terminos").status_code == 200
    assert cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE}).status_code == 200
    # Y salir tampoco puede quedar del otro lado del gate: sin esto, un usuario
    # sin facultades para aceptar quedaría encerrado en la pantalla.
    assert cliente.post("/auth/logout").status_code == 200


def test_aceptar_destraba_la_ruta_gateada(sessions):
    app = _app(sessions)
    cliente = _logueado(app)
    assert cliente.get("/clientes").status_code == 403
    r = cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})
    assert r.status_code == 200, r.text
    assert r.json()["pendiente"] is False
    assert cliente.get("/clientes").status_code == 200


def test_sin_repositorio_cableado_no_gatea(sessions):
    """Compatibilidad hacia atrás: un consumidor que suba el pin sin tocar su
    factory sigue funcionando igual que antes. Es un opt-in por ausencia, y por
    eso cada producto tiene que **probar** su corte, no asumirlo."""
    cliente = _logueado(_app(sessions, con_terminos=False))
    assert cliente.get("/clientes").status_code == 200


# ── 2. El hash no depende del checkout ───────────────────────────────────────

def test_el_hash_es_el_sha256_del_texto():
    assert hash_vigente() == hashlib.sha256(
        texto_vigente().encode("utf-8")
    ).hexdigest()
    assert len(hash_vigente()) == 64


def test_el_hash_no_cambia_si_el_archivo_llega_con_crlf(tmp_path, monkeypatch):
    """Control con mutación: se escribe el MISMO contrato con finales CRLF y el
    hash tiene que dar idéntico. Sin la normalización de `texto_vigente()` este
    test se pone rojo, que es la única forma de saber que la normalización está
    haciendo algo."""
    esperado = hash_vigente()
    crudo = terminos_mod.ARCHIVO_TERMINOS.read_text(encoding="utf-8")
    copia = tmp_path / "terminos_crlf.md"
    copia.write_bytes(crudo.replace("\n", "\r\n").encode("utf-8"))
    monkeypatch.setattr(terminos_mod, "ARCHIVO_TERMINOS", copia)

    assert "\r\n" in copia.read_bytes().decode("utf-8")  # el insumo es el que se cree
    assert hash_vigente() == esperado


# ── 3. Sólo el responsable acepta ────────────────────────────────────────────

def test_un_operador_ve_el_texto_pero_no_puede_aceptar(sessions):
    app = _app(sessions)
    cliente = _logueado(app, "ana", "anapw")
    estado = cliente.get("/terminos")
    assert estado.status_code == 200
    assert estado.json()["puede_aceptar"] is False
    assert cliente.post(
        "/terminos/aceptar", json={"version": VERSION_VIGENTE}
    ).status_code == 403
    # Y la instancia sigue frenada: el 403 de arriba no dejó una fila a medias.
    assert cliente.get("/clientes").status_code == 403


def test_el_admin_puede_aceptar_y_el_estado_lo_dice(sessions):
    cliente = _logueado(_app(sessions))
    assert cliente.get("/terminos").json()["puede_aceptar"] is True


# ── El texto viaja sólo cuando se pide ───────────────────────────────────────

def test_el_estado_no_arrastra_el_contrato_salvo_que_se_pida(sessions):
    """El frontend consulta este endpoint en cada carga para decidir si muestra
    la pantalla bloqueante. Mandar los ~30 KB del contrato siempre sería pagarlo
    para casi siempre contestar `pendiente: false`."""
    cliente = _logueado(_app(sessions))
    liviano = cliente.get("/terminos").json()
    assert liviano["texto"] is None
    assert liviano["hash_texto"] == hash_vigente()  # la huella sí va siempre

    assert liviano["texto_html"] is None

    completo = cliente.get("/terminos?texto=1").json()
    assert completo["texto"] == texto_vigente()
    assert len(completo["texto"]) > 10_000  # el insumo es el que se cree
    assert completo["texto_html"] == texto_html()


def test_el_html_sale_del_mismo_markdown_que_se_hashea():
    """Un solo convertidor para la pantalla de aceptación y para las páginas
    públicas: si cada lado convirtiera por su cuenta, el cliente podría estar
    leyendo un contrato con otro formato sin que nada falle."""
    html = texto_html()
    assert "<h1>" in html and "<table>" in html
    assert html.count("<table>") == 2  # severidades de soporte + Anexo II
    # Y el HTML no interviene en el hash: lo que se firma es el Markdown.
    assert hash_vigente() == hashlib.sha256(texto_vigente().encode("utf-8")).hexdigest()


def test_aceptar_una_version_que_no_es_la_vigente_da_409(sessions):
    """La pestaña abierta desde antes de un deploy no puede aceptar un texto
    que ya no es el que se le mostró."""
    cliente = _logueado(_app(sessions))
    r = cliente.post("/terminos/aceptar", json={"version": "0.9"})
    assert r.status_code == 409


# ── 4. La fila probatoria ────────────────────────────────────────────────────

def test_la_fila_guarda_version_hash_quien_e_ip_real(sessions):
    app = _app(sessions)
    cliente = _logueado(app)
    cliente.post(
        "/terminos/aceptar", json={"version": VERSION_VIGENTE},
        headers={"x-forwarded-for": "190.1.2.3, 172.18.0.1", "user-agent": "Firefox/1"},
    )
    with sessions() as s:
        fila = s.query(AceptacionTerminos).one()
    assert fila.version == VERSION_VIGENTE
    assert fila.hash_texto == hash_vigente()
    assert fila.username == "admin"
    assert fila.nombre == "Admin"
    assert fila.usuario_id == 1  # entero, no la cadena "1" que devuelve el repo
    # 🔴 La del cliente, no la del proxy: detrás de NPM las ocho instancias ven
    # siempre la misma IP interna, y una prueba que diga eso no prueba nada.
    assert fila.ip == "190.1.2.3"
    assert fila.user_agent == "Firefox/1"


def test_aceptar_dos_veces_no_duplica_la_fila(sessions):
    app = _app(sessions)
    cliente = _logueado(app)
    for _ in range(3):
        cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})
    with sessions() as s:
        assert s.query(AceptacionTerminos).count() == 1


def test_el_historial_lo_lee_el_admin_y_no_el_operador(sessions):
    app = _app(sessions)
    admin = _logueado(app)
    admin.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})
    assert len(admin.get("/terminos/historial").json()) == 1
    ana = _logueado(app, "ana", "anapw")
    assert ana.get("/terminos/historial").status_code == 403


# ── 5. La demo no queda bloqueada ────────────────────────────────────────────

def test_el_visitante_de_la_demo_no_queda_frenado(sessions, monkeypatch):
    """Sin esta excepción la demo pública queda inutilizable para siempre: su
    usuario es `staff`, así que no puede aceptar, y no entra nadie más."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "demo")
    app = _app(sessions)
    cliente = _logueado(app, "demo", "demo")
    assert cliente.get("/clientes").status_code == 200
    # Control negativo: en la misma instancia, un usuario que NO es el de la
    # demo sigue frenado. Sin esto, el verde de arriba también se explicaría
    # por un gate que no gatea nada.
    otra = _logueado(app, "ana", "anapw")
    assert otra.get("/clientes").status_code == 403


# ── 6. Lo que el contrato existe para sentar ─────────────────────────────────

@pytest.mark.parametrize("frase", [
    "se actualiza cada seis (6) meses",          # cláusula 6 — IPC semestral
    "Índice de Precios al Consumidor (IPC) Nivel General que",
    "Los Datos del Cliente son de su exclusiva propiedad",  # cláusula 12
    "El Software es de propiedad exclusiva del Prestador",  # cláusula 11
    "titularidad del código permanece en el Prestador",     # 11.4, a medida
    "sin plazo mínimo de\npermanencia",          # cláusula 9, decisión del humano
])
def test_el_texto_conserva_las_clausulas_que_lo_justifican(frase):
    """Guard de contenido. El texto se va a editar —una corrección de estilo, un
    ajuste del abogado— y estas cuatro son las que no pueden desaparecer en el
    camino sin que alguien lo decida."""
    assert frase in texto_vigente()


def test_el_texto_no_tiene_placeholders_sin_resolver():
    """Un `{{...}}` que sobreviva se publica tal cual en las ocho webs."""
    assert "{{" not in texto_vigente()
