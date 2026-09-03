"""El codigo de acceso a la demo publica (v0.26.0).

> *"Las demos no tienen que ser libres, se debe pedir un codigo que es el que
> van a cargar en la demo y asi poder ingresar, sacamos el ingreso a las demos
> de forma indiscriminada."*

Hasta v0.25.x `POST /auth/demo` no recibia nada y entraba: cualquiera que
supiera la URL de `demo.<producto>.com.ar` estaba adentro de un sistema
completo. Estos tests fijan que eso se cerro, y **que se cerro por el motivo
correcto**.

El orden es el de lo que se rompe sin que se note:

1. 🔴 **Que sin codigo no se entre**, y que el que no entra sea el mismo
   endpoint que con codigo si deja entrar. Un 401 contra una demo apagada no
   prueba nada; cada negativo de acá tiene su positivo al lado.
2. 🔴 **Que falle cerrado sin repositorio.** Es el modo de falla que importa al
   subir el pin en los seis productos: una demo que actualiza el motor y no
   cablea `app.state.demo_codigos` tiene que dejar de dejar entrar, no seguir
   abierta.
3. 🔴 **Que el codigo no se pueda leer de vuelta.** Ni de `listar()`, ni de la
   base: lo que se guarda es el sha256.
4. Que el tope de usos y el vencimiento corten de verdad, medidos moviendo el
   reloj inyectado y no durmiendo.
5. Que los cuatro rechazos contesten **lo mismo**, para no decirle a quien
   prueba codigos al azar cual de sus intentos estuvo cerca.

El reloj se inyecta en todo lo que depende del tiempo, mismo criterio que
`test_password_reset.py`.
"""
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from libraauth.demo_codigos import (
    ALFABETO,
    LARGO,
    CodigoInvalido,
    DemoCodigoRepository,
    normalizar,
)
from libraauth.models import Base, DemoCodigo
from libraauth.session_auth import (
    SessionAuth,
    build_demo_codigos_router,
    build_json_api_auth_router,
)

AHORA = datetime(2026, 8, 17, 10, 0, 0)


class _Usuarios:
    def __init__(self):
        self._users = {
            "visitante": {"id": "2", "username": "visitante", "name": "Visitante",
                          "role": "staff", "active": True, "_password": "x"},
            "admin": {"id": "1", "username": "admin", "name": "Admin",
                      "role": "admin", "active": True, "_password": "adminpw"},
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
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "visitante")


@pytest.fixture
def reloj():
    return {"ahora": AHORA}


@pytest.fixture
def repo(reloj):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    r = DemoCodigoRepository(sessions, now=lambda: reloj["ahora"])
    # El engine viaja pegado para poder mirar la tabla cruda: hay un test que
    # necesita ver que ahi no esta el codigo.
    r._engine_de_test = engine
    r._sessions_de_test = sessions
    return r


def _cliente(repo=None, *, con_admin_router=False):
    app = FastAPI()
    usuarios = _Usuarios()
    app.state.users = usuarios
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="test-secret",
        get_user_by_username=usuarios.get_by_username,
        check_credentials=usuarios.check_credentials,
        cookie_name="test_demo_codigos",
    )
    if repo is not None:
        app.state.demo_codigos = repo
    app.include_router(build_json_api_auth_router(incluir_demo=True))
    if con_admin_router:
        app.include_router(build_demo_codigos_router())
    return TestClient(app, base_url="https://testserver")


# ── 🔴 Sin codigo no se entra ─────────────────────────────────────────────

def test_con_codigo_valido_se_entra(repo):
    """El positivo. Sin este, los 401 de abajo podrian ser de una demo rota."""
    codigo = repo.crear()["codigo"]
    cliente = _cliente(repo)

    r = cliente.post("/auth/demo", json={"codigo": codigo})

    assert r.status_code == 200, r.text
    assert r.json()["username"] == "visitante"
    assert cliente.get("/auth/me").json()["username"] == "visitante"


def test_sin_cuerpo_no_se_entra(repo):
    """🔴 Es exactamente la llamada que hacia el frontend hasta v0.25.x, y la
    que hara cualquier bundle viejo que quede servido despues del deploy.

    Da 401 y no 422 a proposito: el cuerpo es opcional en la firma justamente
    para que este caso reciba el mensaje que explica que falta el codigo, y no
    un error de validacion que no dice nada."""
    r = _cliente(repo).post("/auth/demo")

    assert r.status_code == 401, r.text
    assert "código" in r.text


def test_con_codigo_vacio_no_se_entra(repo):
    assert _cliente(repo).post("/auth/demo", json={"codigo": ""}).status_code == 401


def test_con_un_codigo_inventado_no_se_entra(repo):
    repo.crear()  # hay codigos vigentes; el inventado sigue sin servir
    r = _cliente(repo).post("/auth/demo", json={"codigo": "AAAA-BBBB-CCCC"})

    assert r.status_code == 401


def test_no_gasta_un_uso_el_intento_fallido(repo):
    """Un barrido de codigos al azar no puede agotar los codigos buenos."""
    repo.crear()
    _cliente(repo).post("/auth/demo", json={"codigo": "AAAA-BBBB-CCCC"})

    assert repo.listar()[0]["usos"] == 0


# ── 🔴 Falla cerrado ──────────────────────────────────────────────────────

def test_sin_repositorio_no_se_entra(repo):
    """🔴 El modo de falla que importa al subir el pin en los seis productos.

    Una instancia demo que actualiza el motor y no cablea
    `app.state.demo_codigos` tiene que **dejar de dejar entrar**. Si en vez de
    esto la ausencia de repositorio significara "no hay codigos, entra", un
    olvido de configuracion dejaria la demo tan abierta como antes — que es lo
    que este cambio existe para cerrar."""
    sin_repo = _cliente(None)

    r = sin_repo.post("/auth/demo", json={"codigo": repo.crear()["codigo"]})

    assert r.status_code == 503
    assert "not configured" in r.text


# ── 🔴 El codigo no se lee de vuelta ──────────────────────────────────────

def test_el_alta_devuelve_el_codigo_una_vez(repo):
    creado = repo.crear(etiqueta="Estudio Perez")

    assert creado["codigo"]
    assert creado["etiqueta"] == "Estudio Perez"
    assert creado["estado"] == "vigente"


def test_listar_no_trae_el_codigo(repo):
    """🔴 Se busca el VALOR concreto en todo el JSON, no la ausencia de una
    clave llamada `codigo`: si manana viajara dentro de otro campo, un
    `"codigo" not in fila` pasaria igual."""
    codigo = repo.crear()["codigo"]

    import json
    volcado = json.dumps(repo.listar())

    assert codigo not in volcado
    assert normalizar(codigo) not in volcado


def test_en_la_base_no_esta_el_codigo(repo):
    """La otra mitad: aunque la API no lo devuelva, podria estar guardado en
    claro y salir en cualquier backup."""
    codigo = repo.crear()["codigo"]

    with repo._sessions_de_test() as s:
        fila = s.scalars(select(DemoCodigo)).one()
        guardado = f"{fila.codigo_hash}{fila.prefijo}{fila.etiqueta}"

    assert normalizar(codigo) not in guardado
    assert len(fila.codigo_hash) == 64


def test_el_prefijo_permite_reconocerlo(repo):
    """Los 4 primeros caracteres si van en claro: sin ellos la lista del
    backoffice es una grilla de filas indistinguibles."""
    codigo = repo.crear()["codigo"]

    assert repo.listar()[0]["prefijo"] == normalizar(codigo)[:4]


# ── El tope de usos ───────────────────────────────────────────────────────

def test_el_tope_de_usos_corta(repo):
    codigo = repo.crear(usos_max=2)["codigo"]
    cliente = _cliente(repo)

    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 200
    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 200
    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 401
    assert repo.listar()[0]["estado"] == "agotado"


def test_un_codigo_de_un_solo_uso_se_quema(repo):
    codigo = repo.crear(usos_max=1)["codigo"]
    cliente = _cliente(repo)

    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 200
    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 401


def test_cuenta_los_usos_y_anota_el_ultimo(repo, reloj):
    codigo = repo.crear(usos_max=5)["codigo"]
    cliente = _cliente(repo)
    reloj["ahora"] = AHORA + timedelta(hours=3)

    cliente.post("/auth/demo", json={"codigo": codigo})

    fila = repo.listar()[0]
    assert fila["usos"] == 1
    assert fila["ultimo_uso"] == (AHORA + timedelta(hours=3)).isoformat()


def test_usos_max_cero_no_se_puede_emitir(repo):
    """Un codigo con tope cero nace agotado: es un error de quien lo emite, y
    conviene que falle en el alta y no cuando el cliente no puede entrar."""
    with pytest.raises(ValueError):
        repo.crear(usos_max=0)


# ── El vencimiento ────────────────────────────────────────────────────────

def test_vence(repo, reloj):
    codigo = repo.crear(dias=7)["codigo"]
    cliente = _cliente(repo)
    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 200

    reloj["ahora"] = AHORA + timedelta(days=7, seconds=1)

    assert cliente.post("/auth/demo", json={"codigo": codigo}).status_code == 401
    assert repo.listar()[0]["estado"] == "vencido"


def test_el_dia_del_vencimiento_todavia_sirve(repo, reloj):
    """El limite exacto: vence *a los* 7 dias, no *antes de* los 7."""
    codigo = repo.crear(dias=7)["codigo"]
    reloj["ahora"] = AHORA + timedelta(days=7) - timedelta(seconds=1)

    assert _cliente(repo).post("/auth/demo", json={"codigo": codigo}).status_code == 200


def test_dias_cero_no_se_puede_emitir(repo):
    with pytest.raises(ValueError):
        repo.crear(dias=0)


# ── Revocar ───────────────────────────────────────────────────────────────

def test_revocar_corta_el_acceso(repo):
    creado = repo.crear()
    cliente = _cliente(repo)
    assert cliente.post("/auth/demo", json={"codigo": creado["codigo"]}).status_code == 200

    repo.revocar(creado["id"])

    assert cliente.post("/auth/demo", json={"codigo": creado["codigo"]}).status_code == 401
    assert repo.listar()[0]["estado"] == "revocado"


def test_revocar_no_borra_la_fila(repo):
    """Interesa saber que ese codigo existio y cuantas veces se uso antes de
    cortarlo."""
    creado = repo.crear()
    _cliente(repo).post("/auth/demo", json={"codigo": creado["codigo"]})

    repo.revocar(creado["id"])

    fila = repo.listar()[0]
    assert fila["id"] == creado["id"]
    assert fila["usos"] == 1


def test_revocar_uno_que_no_existe(repo):
    with pytest.raises(LookupError):
        repo.revocar(9999)


# ── 🔴 Los cuatro rechazos contestan lo mismo ─────────────────────────────

def test_los_cuatro_motivos_dan_la_misma_respuesta(repo, reloj):
    """🔴 Distinguir "no existe" de "vencido", "agotado" o "revocado" le dice a
    quien esta probando codigos al azar cual de sus intentos estuvo cerca.

    Se comparan status **y** cuerpo: un mensaje distinto con el mismo 401
    filtra igual."""
    vencido = repo.crear(dias=1)["codigo"]
    agotado = repo.crear(usos_max=1)["codigo"]
    revocado = repo.crear()
    cliente = _cliente(repo)
    cliente.post("/auth/demo", json={"codigo": agotado})
    repo.revocar(revocado["id"])
    reloj["ahora"] = AHORA + timedelta(days=2)

    respuestas = {
        motivo: cliente.post("/auth/demo", json={"codigo": c})
        for motivo, c in [
            ("desconocido", "ZZZZ-ZZZZ-ZZZZ"), ("vencido", vencido),
            ("agotado", agotado), ("revocado", revocado["codigo"]),
        ]
    }

    assert {m: r.status_code for m, r in respuestas.items()} == {
        "desconocido": 401, "vencido": 401, "agotado": 401, "revocado": 401}
    assert len({r.text for r in respuestas.values()}) == 1


def test_el_motivo_real_le_llega_al_servidor(repo, reloj):
    """El de arriba fija que afuera no se distingue; este, que adentro si.
    Sin esto, "todos contestan igual" se podria cumplir no sabiendo nada."""
    codigo = repo.crear(dias=1)["codigo"]
    reloj["ahora"] = AHORA + timedelta(days=2)

    with pytest.raises(CodigoInvalido) as e:
        repo.consumir(codigo)

    assert e.value.motivo == "vencido"


# ── Como se tipea ─────────────────────────────────────────────────────────

def test_se_puede_tipear_en_minuscula_y_sin_guiones(repo):
    """Lo van a copiar de un WhatsApp y a tipear a mano."""
    codigo = repo.crear()["codigo"]
    cliente = _cliente(repo)

    variante = codigo.replace("-", "").lower()

    assert cliente.post("/auth/demo", json={"codigo": variante}).status_code == 200


def test_se_puede_tipear_con_espacios(repo):
    codigo = repo.crear()["codigo"]

    variante = codigo.replace("-", " ")

    assert _cliente(repo).post("/auth/demo", json={"codigo": variante}).status_code == 200


def test_un_caracter_de_mas_no_se_ignora(repo):
    """🔴 `normalizar` saca separadores, **no** caracteres desconocidos. Si los
    descartara, un codigo tipeado con una `O` donde va otra cosa se
    "arreglaria" corriendose un lugar, y dos codigos distintos podrian
    normalizar al mismo."""
    codigo = repo.crear()["codigo"]

    assert _cliente(repo).post(
        "/auth/demo", json={"codigo": codigo + "X"}).status_code == 401


def test_el_alfabeto_no_tiene_caracteres_ambiguos(repo):
    """Se dictan por telefono: una `I` que se lee `1` es un cliente potencial
    que no entra y se va."""
    for c in "IL O01":
        assert c not in ALFABETO


def test_los_codigos_no_se_repiten(repo):
    codigos = {repo.crear()["codigo"] for _ in range(50)}

    assert len(codigos) == 50
    assert all(len(normalizar(c)) == LARGO for c in codigos)


# ── El router de administracion ───────────────────────────────────────────

def test_el_backoffice_emite_con_el_token_de_servicio(repo, monkeypatch):
    monkeypatch.setenv("LIBRA_SERVICE_TOKEN", "token-del-backoffice")
    cliente = _cliente(repo, con_admin_router=True)

    r = cliente.post("/admin/demo-codigos",
                     json={"etiqueta": "Estudio Perez", "dias": 3, "usos_max": 5},
                     headers={"X-Internal-Auth": "token-del-backoffice"})

    assert r.status_code == 201, r.text
    assert r.json()["codigo"]
    assert r.json()["etiqueta"] == "Estudio Perez"
    # Y el codigo que emitio sirve de verdad — el alta no es un formulario que
    # escribe una fila que nadie usa.
    assert cliente.post(
        "/auth/demo", json={"codigo": r.json()["codigo"]}).status_code == 200


def test_sin_token_no_se_emite(repo, monkeypatch):
    """La mitad que hace util al test de arriba."""
    monkeypatch.setenv("LIBRA_SERVICE_TOKEN", "token-del-backoffice")
    cliente = _cliente(repo, con_admin_router=True)

    r = cliente.post("/admin/demo-codigos", json={})

    assert r.status_code in (401, 403), r.text
    assert repo.listar() == []


def test_el_listado_del_backoffice_no_trae_codigos(repo, monkeypatch):
    monkeypatch.setenv("LIBRA_SERVICE_TOKEN", "token-del-backoffice")
    codigo = repo.crear(etiqueta="Feria")["codigo"]
    cliente = _cliente(repo, con_admin_router=True)

    r = cliente.get("/admin/demo-codigos",
                    headers={"X-Internal-Auth": "token-del-backoffice"})

    assert r.status_code == 200, r.text
    assert r.json()["codigos"][0]["etiqueta"] == "Feria"
    assert codigo not in r.text
    assert normalizar(codigo) not in r.text


def test_el_backoffice_revoca(repo, monkeypatch):
    monkeypatch.setenv("LIBRA_SERVICE_TOKEN", "token-del-backoffice")
    creado = repo.crear()
    cliente = _cliente(repo, con_admin_router=True)

    r = cliente.delete(f"/admin/demo-codigos/{creado['id']}",
                       headers={"X-Internal-Auth": "token-del-backoffice"})

    assert r.status_code == 200, r.text
    assert r.json()["estado"] == "revocado"
    assert cliente.post(
        "/auth/demo", json={"codigo": creado["codigo"]}).status_code == 401


def test_revocar_uno_inexistente_es_404(repo, monkeypatch):
    monkeypatch.setenv("LIBRA_SERVICE_TOKEN", "token-del-backoffice")
    cliente = _cliente(repo, con_admin_router=True)

    r = cliente.delete("/admin/demo-codigos/9999",
                       headers={"X-Internal-Auth": "token-del-backoffice"})

    assert r.status_code == 404


def test_el_admin_de_la_instancia_tambien_puede(repo, monkeypatch):
    """Sin depender del backoffice: es lo que permite emitir un codigo desde
    la propia instancia si hace falta."""
    monkeypatch.delenv("LIBRA_SERVICE_TOKEN", raising=False)
    cliente = _cliente(repo, con_admin_router=True)
    cliente.post("/auth/login", json={"username": "admin", "password": "adminpw"})

    r = cliente.post("/admin/demo-codigos", json={})

    assert r.status_code == 201, r.text


def test_el_visitante_de_la_demo_no_puede_emitirse_codigos(repo, monkeypatch):
    """🔴 El visitante entra como `staff` y `json_api_require_admin_o_servicio`
    lo deja **leer** cualquier pantalla de administracion. Emitir es un POST,
    asi que esa excepcion no lo alcanza — pero conviene fijarlo: si alcanzara,
    quien entra una vez con un codigo se emite codigos ilimitados y el cerrojo
    deja de existir."""
    monkeypatch.delenv("LIBRA_SERVICE_TOKEN", raising=False)
    codigo = repo.crear()["codigo"]
    cliente = _cliente(repo, con_admin_router=True)
    cliente.post("/auth/demo", json={"codigo": codigo})

    r = cliente.post("/admin/demo-codigos", json={})

    assert r.status_code == 403, r.text
    assert len(repo.listar()) == 1


# ── La sonda ──────────────────────────────────────────────────────────────

def test_la_sonda_avisa_que_hace_falta_codigo(repo):
    """La pantalla de login tiene que decidir si dibuja un boton suelto o un
    boton con campo, y eso no se puede resolver en tiempo de build: la imagen
    de la demo y la del cliente salen del mismo codigo."""
    r = _cliente(repo).get("/auth/demo")

    assert r.status_code == 200, r.text
    assert r.json()["requiere_codigo"] is True


# ── Limpieza ──────────────────────────────────────────────────────────────

def test_purgar_borra_los_vencidos_viejos(repo, reloj):
    repo.crear(dias=1)
    vigente = repo.crear(dias=90)["codigo"]
    reloj["ahora"] = AHORA + timedelta(days=40)

    assert repo.purgar() == 1

    filas = repo.listar()
    assert len(filas) == 1
    assert _cliente(repo).post(
        "/auth/demo", json={"codigo": vigente}).status_code == 200


def test_purgar_no_toca_uno_vencido_hace_poco(repo, reloj):
    """30 dias de gracia: el listado tiene que poder mostrar que un codigo
    vencio, no hacerlo desaparecer apenas pasa la fecha."""
    repo.crear(dias=1)
    reloj["ahora"] = AHORA + timedelta(days=10)

    assert repo.purgar() == 0
    assert repo.listar()[0]["estado"] == "vencido"
