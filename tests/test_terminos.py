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
from datetime import date

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from libraauth import terminos as terminos_mod
from libraauth.models import AceptacionTerminos, Base
from libraauth.session_auth import (
    SessionAuth,
    build_json_api_auth_router,
    json_api_require_admin_o_servicio,
    json_api_require_staff,
)
from libraauth.terminos import (
    CODIGO_PENDIENTE,
    VERSION_VIGENTE,
    TerminosRepository,
    build_terminos_router,
    hash_vigente,
    texto_html,
    texto_vigente,
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
    # 🔴 La versión vigente se decide por fecha (ADR-021): sin fijar el día, desde el 09-11-2026 todos los tests que aceptan
    # `VERSION_VIGENTE` (1.0) darían 409 solos. Se fija ANTES del cambio; los tests del cambio mueven el día ellos.
    import libraauth.terminos as _t

    monkeypatch.setattr(_t, "_hoy_argentina", lambda: date(2026, 10, 10))


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

    # 🔴 El router de usuarios de los ocho productos cuelga de ESTE guard, que no
    # pasa por `json_api_require_role`. Con el gate sólo en aquél, `/usuarios`
    # seguía contestando 200 con el contrato sin aceptar — lo encontró el test
    # del gate de LibraClub, no una revisión del código.
    @app.get("/usuarios", dependencies=[Depends(json_api_require_admin_o_servicio)])
    def usuarios():
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


def test_el_guard_de_admin_o_servicio_tambien_corta(sessions):
    """No pasa por `json_api_require_role`, así que necesita su propia llamada.
    De este guard cuelga el router de usuarios de los ocho productos."""
    cliente = _logueado(_app(sessions))
    r = cliente.get("/usuarios")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == CODIGO_PENDIENTE

    cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})
    assert cliente.get("/usuarios").status_code == 200


def test_el_token_de_servicio_no_queda_frenado(sessions, monkeypatch):
    """El backoffice del proveedor administra instancias ajenas y no tiene
    contrato propio que aceptar. Si el gate lo frenara, el alta de usuarios de
    un cliente nuevo quedaría bloqueada por un contrato que ese cliente todavía
    no puede aceptar — porque todavía no tiene con qué entrar."""
    monkeypatch.setenv("LIBRA_SERVICE_TOKEN", "token-de-servicio")
    app = _app(sessions)
    sin_sesion = TestClient(app, base_url="https://testserver")
    r = sin_sesion.get("/usuarios", headers={"x-internal-auth": "token-de-servicio"})
    assert r.status_code == 200


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
    # El par directo es el proxy, como en el VPS: sin eso `ip_del_request` no
    # le cree al header y la fila guardaria el par.
    cliente = TestClient(app, base_url="https://testserver", client=("172.18.0.19", 50000))
    r = cliente.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    assert r.status_code == 200, r.text
    cliente.post(
        "/terminos/aceptar", json={"version": VERSION_VIGENTE},
        # Lo que llega detras de NPM cuando el cliente manda su propio header:
        # el suyo a la izquierda, el par TCP agregado a la derecha. La prueba de
        # la clausula 30.3 no puede guardar lo que el cliente quiso escribir.
        headers={"x-forwarded-for": "6.6.6.6, 190.1.2.3", "user-agent": "Firefox/1"},
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

def _demo(monkeypatch):
    """Prende los DOS cerrojos que `demo_username()` exige."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "demo")


def test_en_una_demo_no_queda_frenado_nadie(sessions, monkeypatch):
    """Una demo no es una instancia de cliente: no hay contrato que aceptar.

    🔴 **Este test reemplaza a uno que eximía sólo al visitante**, y el cambio
    ES el arreglo. Hasta la v0.34.0 la excepción era por usuario, así que el
    visitante entraba y todo el resto de la instancia seguía con 403. Como
    `ROLES_QUE_ACEPTAN` es `("admin",)` y el auto-login **se niega a entregar
    `admin`** (`ROLES_PROHIBIDOS_EN_DEMO`), en una demo no había por dónde
    aceptar: el gate era una puerta sin llave. El síntoma medido: la siembra
    nocturna entra como `admin`, se comía el 403, y las ocho demos amanecían
    vacías.

    El control negativo de aquel test —que `ana` siguiera frenada en la MISMA
    instancia— **tenía que caerse**: es exactamente el comportamiento que se
    corrige. El control equivalente vive ahora en
    `test_fuera_de_una_demo_el_gate_sigue_cortando`, que es donde corresponde.
    """
    _demo(monkeypatch)
    app = _app(sessions)
    for usuario, clave in (("demo", "demo"), ("ana", "anapw"), ("admin", "adminpw")):
        cliente = _logueado(app, usuario, clave)
        assert cliente.get("/clientes").status_code == 200, (
            f"{usuario} quedó frenado en una demo"
        )

        # El otro guard, el del router de usuarios de los ocho productos.
        #
        # 🔑 Lo que se aserta es **que ningún 403 sea de términos**, no un código
        # concreto por usuario. Este guard tiene sus propias reglas de rol y de
        # lectura para el visitante, que no son asunto de este arreglo: fijarlas
        # acá pondría el test en rojo el día que cambien, por un motivo que no
        # tiene nada que ver con el contrato.
        r = cliente.get("/usuarios")
        detalle = r.json().get("detail") if r.status_code == 403 else None
        codigo = detalle.get("code") if isinstance(detalle, dict) else None
        assert codigo != CODIGO_PENDIENTE, (
            f"{usuario} recibió un 403 de TÉRMINOS en una demo"
        )

    # Control positivo de la ruta: que el admin la pueda leer de verdad. Sin
    # esto, un `/usuarios` que devolviera 404 para todos también pasaría el
    # chequeo de arriba — "no es un 403 de términos" se cumple sin gate y
    # también sin ruta.
    admin = _logueado(app, "admin", "adminpw")
    assert admin.get("/usuarios").status_code == 200


def test_en_una_demo_el_estado_no_dice_pendiente(sessions, monkeypatch):
    """🔴 El otro muro, el que no deja rastro en los logs.

    `GateTerminos` (libra-ui) bloquea la aplicación entera con el `pendiente`
    de este endpoint, sin esperar ningún 403. Eximir sólo el gate del backend
    dejaría la demo trabada igual, del lado del navegador — y ahí no hay un 403
    que lo explique. Por eso la exención vive en `hay_terminos_pendientes`, que
    es de donde sale este booleano.
    """
    _demo(monkeypatch)
    cliente = _logueado(_app(sessions), "admin", "adminpw")
    r = cliente.get("/terminos")
    assert r.status_code == 200, r.text
    assert r.json()["pendiente"] is False


def test_fuera_de_una_demo_el_gate_sigue_cortando(sessions, monkeypatch):
    """El control negativo del arreglo: que no haya quedado una puerta abierta.

    Se prueban las **tres** formas en que la marca puede no estar, porque
    `demo_username()` tiene dos cerrojos y alcanza con que falte uno: sin
    ninguna variable, con `DEMO_MODE` pero sin usuario, y con usuario pero sin
    `DEMO_MODE`. Si cualquiera de esas eximiera, un `.env` copiado a medias
    dejaría sin gate a una instancia de cliente — que es justo lo que los dos
    cerrojos existen para evitar.
    """
    casos = (
        ("sin ninguna", {}),
        ("solo DEMO_MODE", {"DEMO_MODE": "1"}),
        ("solo DEMO_USERNAME", {"DEMO_USERNAME": "demo"}),
    )
    for etiqueta, variables in casos:
        monkeypatch.delenv("DEMO_MODE", raising=False)
        monkeypatch.delenv("DEMO_USERNAME", raising=False)
        for k, v in variables.items():
            monkeypatch.setenv(k, v)

        cliente = _logueado(_app(sessions), "admin", "adminpw")
        r = cliente.get("/clientes")
        assert r.status_code == 403, f"el gate no cortó con {etiqueta}"
        assert r.json()["detail"]["code"] == CODIGO_PENDIENTE
        assert cliente.get("/terminos").json()["pendiente"] is True, (
            f"el estado no dijo pendiente con {etiqueta}"
        )


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


# ── La próxima versión (1.1): publicada, todavía no vigente (cláusula 29.2) ──────

def test_la_proxima_version_no_cambia_lo_vigente():
    """Publicar la 1.1 no pide nada adentro del sistema: el gate y la prueba siguen siendo los de la 1.0."""
    import libraauth.terminos as t

    assert t.VERSION_VIGENTE == "1.0"
    assert t.ARCHIVO_TERMINOS.name == "terminos_v1.md"
    assert t.VERSION_PROXIMA == "1.1" and t.PROXIMA_DESDE == "09-11-2026"
    assert t.hash_proximo() != t.hash_vigente()


def test_el_hash_de_la_proxima_es_el_sha256_de_su_texto_normalizado():
    import libraauth.terminos as t

    crudo = t.ARCHIVO_PROXIMA.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    assert t.texto_proximo() == crudo
    assert t.hash_proximo() == hashlib.sha256(crudo.encode("utf-8")).hexdigest()
    assert "<h2>5. Precio, impuestos y forma de pago</h2>" in t.texto_html_proximo()


def test_la_1_1_cambia_solo_el_encabezado_y_la_clausula_5_1():
    """Decisión del dueño (2026-10-10): «más IVA» pasa a «precio final con el IVA incluido». Ninguna otra cláusula cambia."""
    import difflib

    import libraauth.terminos as t

    cambios = [l for l in difflib.unified_diff(t.texto_vigente().splitlines(), t.texto_proximo().splitlines(), lineterm="", n=0)
               if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    quitadas = [l[1:] for l in cambios if l.startswith("-")]
    agregadas = [l[1:] for l in cambios if l.startswith("+")]
    assert quitadas == ["**Versión 1.0 — vigente desde el 22-08-2026**", "pesos argentinos, **más IVA** y todo otro tributo que corresponda."]
    assert "pesos argentinos, como **precio final con el IVA incluido** cuando corresponda," in agregadas
    assert "más IVA" not in t.texto_proximo()


def test_sin_proxima_version_las_funciones_devuelven_none(monkeypatch):
    import libraauth.terminos as t

    monkeypatch.setattr(t, "VERSION_PROXIMA", None)
    assert t.texto_proximo() is None and t.hash_proximo() is None and t.texto_html_proximo() is None


# ── La 1.1 entra en vigencia sola el 09-11-2026 (ADR-021) ───────────────────────

def test_la_version_vigente_cambia_el_dia_de_la_proxima(monkeypatch):
    import libraauth.terminos as t

    assert t.version_vigente(date(2026, 11, 8)) == "1.0" and t.vigente_desde(date(2026, 11, 8)) == "22-08-2026"
    assert t.version_vigente(date(2026, 11, 9)) == "1.1" and t.vigente_desde(date(2026, 11, 9)) == "09-11-2026"
    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2026, 11, 9))
    assert "precio final con el IVA incluido" in t.texto_vigente()
    assert t.hash_vigente() == hashlib.sha256(t.texto_vigente().encode("utf-8")).hexdigest()
    # Una vez que rige, deja de ser «próxima».
    assert t.texto_proximo() is None and t.hash_proximo() is None


def test_una_instancia_que_ya_acepto_la_1_0_vuelve_a_pedir_aceptacion_el_09_11(sessions, monkeypatch):
    """El mismo proceso (misma app, misma cache del repositorio) que aceptó la 1.0 corta otra vez desde el día de la 1.1, y
    la nueva fila guarda la 1.1 con su hash. Sin redeploy."""
    import libraauth.terminos as t

    app = _app(sessions)
    cliente = _logueado(app)
    assert cliente.post("/terminos/aceptar", json={"version": "1.0"}).status_code == 200
    assert cliente.get("/clientes").status_code == 200

    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2026, 11, 9))
    r = cliente.get("/clientes")
    assert r.status_code == 403 and r.json()["detail"]["version"] == "1.1"
    estado = cliente.get("/terminos").json()
    assert estado["pendiente"] is True and estado["version"] == "1.1" and estado["vigente_desde"] == "09-11-2026"
    assert cliente.post("/terminos/aceptar", json={"version": "1.0"}).status_code == 409

    r = cliente.post("/terminos/aceptar", json={"version": "1.1"})
    assert r.status_code == 200 and r.json()["pendiente"] is False
    assert cliente.get("/clientes").status_code == 200
    filas = app.state.terminos.historial()
    assert [f["version"] for f in filas] == ["1.1", "1.0"]
    assert filas[0]["hash_texto"] == t.hash_vigente() != filas[1]["hash_texto"]


def test_el_dia_anterior_sigue_rigiendo_la_1_0(sessions, monkeypatch):
    import libraauth.terminos as t

    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2026, 11, 8))
    cliente = _logueado(_app(sessions))
    assert cliente.get("/terminos").json()["version"] == "1.0"
    # Aceptar la 1.1 el día anterior es la aceptación por adelantado (ADR-024): se registra, pero no rige todavía, y la
    # vigente (1.0) sigue pendiente. Antes de ADR-024 esto era un 409.
    assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 200
    estado = cliente.get("/terminos").json()
    assert estado["version"] == "1.0" and estado["pendiente"] is True
    assert cliente.get("/clientes").status_code == 403


def test_un_repositorio_con_version_fija_no_cambia_por_fecha(sessions, monkeypatch):
    import libraauth.terminos as t

    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2027, 1, 1))
    assert t.TerminosRepository(sessions, version="1.0").version == "1.0"
    assert t.TerminosRepository(sessions).version == "1.1"


# ── Aceptar la próxima versión por adelantado (ADR-024) ───────────────────────────
#
# El responsable acepta la 1.1 antes del 09-11 desde adentro del sistema (cláusulas 29.2 y 29.4). Lo que se fija, en orden de
# lo que más duele si falla: que el 09-11 esa instancia NO vuelva a quedar pendiente, que la fila sea una prueba completa,
# que sólo la acepte quien puede (30.5), que una demo no vea el aviso y que nada de lo que ya existía cambie.

def test_el_estado_anuncia_la_proxima_con_su_hash_y_el_resumen(sessions):
    import libraauth.terminos as t

    cliente = _logueado(_app(sessions))
    estado = cliente.get("/terminos").json()
    assert estado["proxima"] == {
        "version": "1.1",
        "vigente_desde": "09-11-2026",
        "hash_texto": t.hash_proximo(),
        "aceptada": False,
        "aceptada_por": None,
        "aceptada_at": None,
        "resumen_del_cambio": "El abono mensual pasa a ser precio final con IVA incluido.",
        "texto": None,
        "texto_html": None,
    }
    # Los campos de siempre no cambian: la vigente sigue siendo la 1.0 y sigue pendiente.
    assert estado["version"] == "1.0" and estado["pendiente"] is True
    assert estado["hash_texto"] == t.hash_vigente() != estado["proxima"]["hash_texto"]


def test_el_texto_de_la_proxima_viaja_solo_con_texto_1(sessions):
    import libraauth.terminos as t

    cliente = _logueado(_app(sessions))
    liviano = cliente.get("/terminos").json()["proxima"]
    assert liviano["texto"] is None and liviano["texto_html"] is None
    completo = cliente.get("/terminos", params={"texto": 1}).json()["proxima"]
    assert completo["texto"] == t.texto_proximo()
    assert "precio final con el IVA incluido" in completo["texto_html"]
    # No se mezcla con el de la vigente.
    assert cliente.get("/terminos", params={"texto": 1}).json()["texto"] == t.texto_vigente()


def test_sin_proxima_anunciada_el_estado_trae_proxima_null(sessions, monkeypatch):
    import libraauth.terminos as t

    monkeypatch.setattr(t, "VERSION_PROXIMA", None)
    cliente = _logueado(_app(sessions))
    estado = cliente.get("/terminos").json()
    assert "proxima" in estado and estado["proxima"] is None
    assert estado["version"] == "1.0"
    assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 409


def test_aceptar_la_proxima_registra_version_hash_quien_e_ip_y_aparece_en_el_historial(sessions):
    import libraauth.terminos as t

    app = _app(sessions)
    cliente = TestClient(app, base_url="https://testserver", client=("172.18.0.19", 50000))
    assert cliente.post("/auth/login", json={"username": "admin", "password": "adminpw"}).status_code == 200

    r = cliente.post(
        "/terminos/aceptar", json={"version": "1.1"},
        headers={"X-Forwarded-For": "203.0.113.7", "User-Agent": "pytest-adelanto"},
    )
    assert r.status_code == 200, r.text
    estado = r.json()
    # La respuesta es el estado de siempre más el bloque: la vigente sigue pendiente, la próxima ya figura aceptada.
    assert estado["version"] == "1.0" and estado["pendiente"] is True
    assert estado["proxima"]["aceptada"] is True
    assert estado["proxima"]["aceptada_por"] == "Admin" and estado["proxima"]["aceptada_at"]

    (fila,) = cliente.get("/terminos/historial").json()
    assert fila["version"] == "1.1" and fila["hash_texto"] == t.hash_proximo()
    assert fila["username"] == "admin" and fila["nombre"] == "Admin"
    assert fila["ip"] == "203.0.113.7" and fila["user_agent"] == "pytest-adelanto"
    # Aceptar la próxima no destraba nada de lo vigente.
    assert cliente.get("/clientes").status_code == 403


def test_aceptar_la_proxima_dos_veces_no_duplica_la_fila(sessions):
    app = _app(sessions)
    cliente = _logueado(app)
    for _ in range(2):
        assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 200
    assert [f["version"] for f in app.state.terminos.historial()] == ["1.1"]


def test_aceptar_la_proxima_no_pisa_la_cache_de_la_vigente(sessions):
    """`esta_aceptada` es sobre la vigente: aceptar la 1.1 no puede dejar pasar el gate de la 1.0."""
    app = _app(sessions)
    cliente = _logueado(app)
    cliente.post("/terminos/aceptar", json={"version": "1.1"})
    assert app.state.terminos.esta_aceptada() is False
    assert cliente.get("/clientes").status_code == 403
    assert cliente.post("/terminos/aceptar", json={"version": "1.0"}).status_code == 200
    assert cliente.get("/clientes").status_code == 200
    # Y las dos quedan: la 1.0 aceptada hoy, la 1.1 por adelantado.
    assert sorted(f["version"] for f in app.state.terminos.historial()) == ["1.0", "1.1"]


def test_un_operador_no_puede_aceptar_la_proxima(sessions):
    """Cláusula 30.5: la misma regla de roles que la vigente. Ve el anuncio (el estado es de lectura) pero no acepta."""
    app = _app(sessions)
    ana = _logueado(app, "ana", "anapw")
    estado = ana.get("/terminos").json()
    assert estado["puede_aceptar"] is False and estado["proxima"]["aceptada"] is False
    assert ana.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 403
    assert app.state.terminos.historial() == []


def test_una_version_que_no_es_ni_la_vigente_ni_la_proxima_da_409(sessions):
    cliente = _logueado(_app(sessions))
    for version in ("0.9", "1.2", "2.0", ""):
        r = cliente.post("/terminos/aceptar", json={"version": version})
        assert r.status_code == 409, version
    assert "1.0" in r.json()["detail"] and "1.1" in r.json()["detail"]


def test_el_09_11_una_instancia_que_ya_acepto_la_proxima_no_queda_pendiente(sessions, monkeypatch):
    """🔴 El punto de todo el cambio. Sin esto, aceptar por adelantado no sirve de nada: el gate volvería a cortar igual."""
    import libraauth.terminos as t

    app = _app(sessions)
    cliente = _logueado(app)
    # Hoy (10-10) la instancia acepta la 1.0 que rige y la 1.1 por adelantado.
    assert cliente.post("/terminos/aceptar", json={"version": "1.0"}).status_code == 200
    assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 200
    assert cliente.get("/clientes").status_code == 200

    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2026, 11, 9))
    # El mismo proceso, el mismo repositorio, sin redeploy: la 1.1 rige y ya está aceptada.
    r = cliente.get("/clientes")
    assert r.status_code == 200, r.text
    estado = cliente.get("/terminos").json()
    assert estado["version"] == "1.1" and estado["vigente_desde"] == "09-11-2026"
    assert estado["pendiente"] is False
    assert estado["aceptada_por"] == "Admin" and estado["aceptada_at"]
    # La prueba es la fila hecha por adelantado, con el hash del texto que rige ese día.
    assert estado["hash_texto"] == t.hash_vigente()
    filas = app.state.terminos.historial()
    assert [f["version"] for f in filas] == ["1.1", "1.0"]
    assert filas[0]["hash_texto"] == t.hash_vigente()
    # Y ya no hay «próxima»: pasó a ser la vigente.
    assert estado["proxima"] is None
    assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 200  # idempotente
    assert len(app.state.terminos.historial()) == 2


def test_el_09_11_sin_la_aceptacion_adelantada_la_instancia_sigue_pendiente(sessions, monkeypatch):
    """Control negativo del anterior: el verde de arriba se explicaría igual por un gate que ya no corta."""
    import libraauth.terminos as t

    cliente = _logueado(_app(sessions))
    cliente.post("/terminos/aceptar", json={"version": "1.0"})
    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2026, 11, 9))
    assert cliente.get("/clientes").status_code == 403
    assert cliente.get("/terminos").json()["pendiente"] is True


def test_si_la_proxima_ya_rige_aceptarla_es_aceptar_la_vigente(sessions, monkeypatch):
    """El 09-11 deja de existir el camino «por adelantado»: es el de siempre, y el bloque `proxima` desaparece."""
    import libraauth.terminos as t

    monkeypatch.setattr(t, "_hoy_argentina", lambda: date(2026, 11, 9))
    app = _app(sessions)
    cliente = _logueado(app)
    assert cliente.get("/terminos").json()["proxima"] is None
    assert cliente.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 200
    assert cliente.get("/clientes").status_code == 200
    assert t.proxima_anunciada() is None


def test_en_una_demo_no_hay_aviso_ni_se_acepta_la_proxima(sessions, monkeypatch):
    """Una demo no es una instancia de cliente (`exige_aceptacion`): nadie firma por nadie, ni hoy ni por adelantado."""
    _demo(monkeypatch)
    app = _app(sessions)
    admin = _logueado(app, "admin", "adminpw")
    assert admin.get("/terminos").json()["proxima"] is None
    assert admin.get("/terminos", params={"texto": 1}).json()["proxima"] is None
    assert admin.post("/terminos/aceptar", json={"version": "1.1"}).status_code == 409
    assert app.state.terminos.historial() == []
    # Control: fuera de la demo, el mismo admin sí ve el anuncio.
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)
    assert _logueado(_app(sessions), "admin", "adminpw").get("/terminos").json()["proxima"] is not None


def test_el_texto_de_la_1_1_esta_congelado_desde_que_se_anuncia():
    """La prueba de una aceptación adelantada es (versión, hash) y el 09-11 `aceptacion_vigente` la encuentra POR VERSIÓN.

    Si alguien tocara el texto de la 1.1 después de que un cliente la aceptó, esa fila diría haber aceptado un texto que
    ya no es el que rige, sin ningún síntoma. Este test es el aviso: cambiar el contenido exige una versión nueva (1.2),
    como ya dice el comentario de `VERSION_VIGENTE`, y recién ahí se actualiza este hash."""
    import libraauth.terminos as t

    assert t.hash_proximo() == "72b7eb3b9a0797596c3671d08a9dc4f1aa5677e4b1b68ee83e520528130fe113"


def test_con_el_prefijo_api_terminos_de_contalibra_y_restolibra_tambien_anda(sessions):
    """Contalibra y Restolibra montan el router en `/api/terminos` (`build_terminos_router(prefix=...)`); el frontend
    lo sabe por `terminosPath`. El bloque `proxima` y la aceptación viajan por el mismo prefijo, sin ruta aparte."""
    app = FastAPI()
    usuarios = _Usuarios()
    app.state.users = usuarios
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=usuarios.get_by_username,
        check_credentials=usuarios.check_credentials,
    )
    app.state.terminos = TerminosRepository(sessions)
    app.include_router(build_json_api_auth_router())
    app.include_router(build_terminos_router(prefix="/api/terminos"))
    cliente = _logueado(app)

    assert cliente.get("/api/terminos").json()["proxima"]["aceptada"] is False
    assert cliente.post("/api/terminos/aceptar", json={"version": "1.1"}).json()["proxima"]["aceptada"] is True
    assert [f["version"] for f in cliente.get("/api/terminos/historial").json()] == ["1.1"]
