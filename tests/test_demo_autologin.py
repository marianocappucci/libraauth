"""El auto-login de las demos publicas — item 8 de los pendientes de Libra.

> *"...para que la gente pueda entrar por la pagina web y ver una muestra del
> sistema semi funcional."*

Un boton en cada landing tiene que dejar entrar **sin credenciales**. Eso es,
por definicion, un agujero de autenticacion: todo el trabajo esta en que exista
unicamente donde debe.

Lo que fijan estos tests, en orden de lo que se rompe sin que se note:

1. 🔴 **Que en una instancia normal la ruta NO exista.** Es lo unico que separa
   "demo publica" de "cualquiera entra al sistema del cliente". Y el 404 solo
   prueba algo si el mismo test sabe que con la configuracion puesta la ruta
   **si** responde — un 404 contra una ruta que nunca existio no distingue
   nada.
2. 🔴 **Que hagan falta las DOS variables.** Un flag booleano solo se prende al
   copiar un `.env`; que ademas haya que nombrar al usuario obliga a que
   alguien haya pensado en ese usuario para esa instancia.
3. 🔴 **Que nunca entregue admin**, aunque el usuario nombrado lo sea. El rol
   puede cambiar despues de desplegar, desde el ABM de la propia demo.
4. Que el consumidor tenga que pedirlo (`incluir_demo=True`).

> 🔑 **Desde v0.26.0 ya no entra sin credenciales: entra con un codigo.** El
> titulo de este archivo quedo viejo a proposito —sigue siendo el auto-login,
> en el sentido de que no hay usuario ni contrasena que elegir—, pero el
> ingreso indiscriminado se cerro. Lo que un codigo agrega esta en
> `test_demo_codigos.py`; lo de aca sigue siendo *donde existe la ruta* y
> *con que rol deja entrar*, que son preguntas independientes del codigo.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from libraauth.demo_codigos import DemoCodigoRepository
from libraauth.models import Base
from libraauth.session_auth import SessionAuth, build_json_api_auth_router


class _Usuarios:
    def __init__(self, extra=None):
        self._users = {
            "admin": {"id": "1", "username": "admin", "name": "Admin",
                      "role": "admin", "active": True, "_password": "adminpw"},
            "visitante": {"id": "2", "username": "visitante", "name": "Visitante",
                          "role": "staff", "active": True, "_password": "x"},
            "de-baja": {"id": "3", "username": "de-baja", "name": "De baja",
                        "role": "staff", "active": False, "_password": "x"},
        }
        self._users.update(extra or {})

    def _publico(self, u):
        return {k: v for k, v in u.items() if k != "_password"}

    def get_by_username(self, username):
        u = self._users.get(username)
        return self._publico(u) if u else None

    def check_credentials(self, username, password):
        u = self._users.get(username)
        return self._publico(u) if u and u["_password"] == password else None


@pytest.fixture(autouse=True)
def _entorno_de_test(monkeypatch):
    """`SessionAuth` se niega a arrancar sin `SECRET_KEY` fuera de desarrollo,
    y con razón. Acá alcanza con declarar el entorno."""
    monkeypatch.setenv("ENV", "development")


def _app(*, incluir_demo=True, usuarios=None, con_codigos=True):
    app = FastAPI()
    usuarios = usuarios or _Usuarios()
    app.state.users = usuarios
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="test-secret",
        get_user_by_username=usuarios.get_by_username,
        check_credentials=usuarios.check_credentials,
        cookie_name="test_demo_session",
    )
    app.include_router(build_json_api_auth_router(incluir_demo=incluir_demo))
    cliente = TestClient(app, base_url="https://testserver")
    # El repositorio va cableado como en una instancia demo real
    # (`app.state.demo_codigos`), y es **el de verdad** sobre SQLite en
    # memoria, no un doble. Un doble que conteste "codigo valido" no probaria
    # lo unico que importa acá, que es que sin codigo no se entra.
    if con_codigos:
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        cliente.codigos = DemoCodigoRepository(sessionmaker(bind=engine))
        app.state.demo_codigos = cliente.codigos
    return cliente


def _entrar(cliente, **kw):
    """Emite un codigo y entra con el. `kw` va a `crear()`."""
    codigo = cliente.codigos.crear(**kw)["codigo"]
    return cliente.post("/auth/demo", json={"codigo": codigo})


@pytest.fixture
def demo_encendida(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "visitante")


# ── 🔴 Que exista SOLO donde debe ─────────────────────────────────────────

def test_con_la_demo_encendida_y_un_codigo_valido_se_entra(demo_encendida):
    """La mitad util del par: sin esto, el 404 del test de abajo no prueba
    nada — podria ser el 404 de una ruta que nunca existio."""
    cliente = _app()
    r = _entrar(cliente)

    assert r.status_code == 200, r.text
    assert r.json()["username"] == "visitante"
    assert cliente.get("/auth/me").json()["username"] == "visitante"


def test_sin_las_variables_la_ruta_no_existe(monkeypatch):
    """🔴 Es lo unico que separa "demo publica" de "cualquiera entra al sistema
    del cliente"."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)

    assert _app().post("/auth/demo").status_code == 404


def test_con_DEMO_MODE_pero_sin_usuario_la_ruta_no_existe(monkeypatch):
    """Dos cerrojos, no uno: un flag booleano se prende solo al copiar un
    `.env` de una instancia a otra."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.delenv("DEMO_USERNAME", raising=False)

    assert _app().post("/auth/demo").status_code == 404


def test_con_usuario_pero_sin_DEMO_MODE_la_ruta_no_existe(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.setenv("DEMO_USERNAME", "visitante")

    assert _app().post("/auth/demo").status_code == 404


def test_DEMO_MODE_apagado_explicitamente_tampoco_alcanza(monkeypatch):
    """`DEMO_MODE=0` es lo que va a quedar escrito en los `.env` de las
    instancias reales cuando alguien copie el de la demo."""
    monkeypatch.setenv("DEMO_MODE", "0")
    monkeypatch.setenv("DEMO_USERNAME", "visitante")

    assert _app().post("/auth/demo").status_code == 404


def test_el_consumidor_tiene_que_pedirlo(demo_encendida):
    """Con las variables puestas pero sin `incluir_demo`, tampoco. Asi un
    producto que nunca va a tener demo no depende de que nadie se equivoque
    con el entorno."""
    assert _app(incluir_demo=False).post("/auth/demo").status_code == 404


def test_es_404_y_no_403(monkeypatch):
    """Un 403 le confirma a quien barre que el endpoint esta ahi y que la
    instancia lo soporta. El 404 no dice nada."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    r = _app().post("/auth/demo")

    assert r.status_code == 404
    assert "demo" not in r.text.lower()


# ── 🔴 Que nunca reparta admin ────────────────────────────────────────────

def test_no_entrega_admin_aunque_el_usuario_nombrado_lo_sea(monkeypatch):
    """🔴 El rol puede cambiar **despues** de desplegar: alguien promueve al
    usuario desde el ABM de la propia demo y el auto-login empezaria a repartir
    admin sin que nadie haya tocado el `.env`. Por eso el chequeo esta en el
    endpoint y no en el despliegue."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "admin")

    r = _app().post("/auth/demo")

    assert r.status_code == 503
    assert "forbidden role" in r.text


def test_un_usuario_promovido_a_admin_deja_de_entrar(monkeypatch):
    """El mismo caso pero visto desde el otro lado: el usuario de la demo
    empieza siendo staff y alguien lo promueve."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "visitante")
    usuarios = _Usuarios()
    cliente = _app(usuarios=usuarios)
    assert _entrar(cliente).status_code == 200

    usuarios._users["visitante"]["role"] = "admin"

    assert _app(usuarios=usuarios).post("/auth/demo").status_code == 503


# ── El usuario tiene que estar ────────────────────────────────────────────

def test_si_el_usuario_no_existe_avisa_que_falta_sembrar(monkeypatch):
    """503 y no 404: la ruta existe y esta bien configurada, lo que falta es
    el usuario. Un 404 diria "no hay demo aca", que manda a mirar el lugar
    equivocado."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "no-existe")

    r = _app().post("/auth/demo")

    assert r.status_code == 503
    assert "not provisioned" in r.text


def test_un_usuario_desactivado_no_entra(monkeypatch):
    """Desactivar al usuario de la demo es la forma de apagarla sin redesplegar."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "de-baja")

    assert _app().post("/auth/demo").status_code == 503


# ── Lo que no cambia ──────────────────────────────────────────────────────

def test_el_login_normal_sigue_funcionando_con_la_demo_encendida(demo_encendida):
    cliente = _app()
    r = cliente.post("/auth/login", json={"username": "admin", "password": "adminpw"})

    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"


def test_el_cuerpo_solo_lleva_el_codigo(demo_encendida):
    """Sigue sin haber usuario que elegir desde afuera: el usuario sale del
    entorno. Mandar `username` y `password` no cambia con quien se entra —
    los campos de mas se ignoran, y el que decide es el codigo."""
    cliente = _app()
    codigo = cliente.codigos.crear()["codigo"]
    r = cliente.post("/auth/demo", json={
        "codigo": codigo, "username": "admin", "password": "adminpw"})

    assert r.status_code == 200, r.text
    assert r.json()["username"] == "visitante"


# ── La sonda `GET /auth/demo` (2026-08-06) ────────────────────────────────
#
# El boton "Entrar a la demo" no se puede decidir en tiempo de build: la
# imagen de la demo y la del cliente salen del mismo codigo. La pantalla de
# login le pregunta a la instancia, y esta es la respuesta.

def test_la_sonda_dice_que_es_una_demo(demo_encendida):
    r = _app().get("/auth/demo")

    assert r.status_code == 200, r.text
    assert r.json() == {"enabled": True, "username": "visitante",
                        "requiere_codigo": True}


def test_la_sonda_no_existe_fuera_de_una_demo(monkeypatch):
    """La mitad que hace util al test de arriba: la misma ruta, sin las
    variables, no esta."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)

    assert _app().get("/auth/demo").status_code == 404


def test_la_sonda_tampoco_existe_si_el_consumidor_no_la_pidio(demo_encendida):
    assert _app(incluir_demo=False).get("/auth/demo").status_code == 404


def test_la_sonda_no_devuelve_la_contrasena(demo_encendida, monkeypatch):
    """🔴 `DEMO_PASSWORD` es publica por diseno, pero un endpoint **sin
    autenticar** que reparte contrasenas es un patron que despues alguien
    copia a un lugar donde no da lo mismo.

    El test busca el valor concreto en el cuerpo entero, no la ausencia de una
    clave llamada `password`: si manana la contrasena viajara dentro de otro
    campo —o del `username`— un `"password" not in json` pasaria igual."""
    monkeypatch.setenv("DEMO_PASSWORD", "una-clave-muy-reconocible")

    r = _app().get("/auth/demo")

    assert r.status_code == 200
    assert "una-clave-muy-reconocible" not in r.text
