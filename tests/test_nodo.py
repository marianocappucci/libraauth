"""El nodo de LibraEdge: sus usuarios son los del central (ADR-027).

Un nodo se reconoce por `LIBRAEDGE_NODE_ID`. Lo que fijan estos tests, en orden de lo que se rompe sin que se note:

1. 🔴 **Que un nodo no cree usuarios al arrancar.** El `admin` local con otro id choca con `UNIQUE(username)` cuando baja
   el `admin` del central y traba el espejo entero. El test del choque lo muestra con la base real.
2. 🔴 **Que ninguna escritura de usuarios pase en un nodo** (alta, edición, clave de otro, clave propia, baja, recupero
   por correo, re-hash al entrar), y que en el central todo siga igual: cada caso lleva su contraprueba.
3. Que las lecturas anden: el nodo tiene que poder listar y loguear usuarios sin internet.
4. Que el nodo no exija aceptar los Términos ni acepte por su cuenta.
5. Que un usuario que baja del central con `activo=false` pierda la sesión en el nodo.
"""
import hashlib
import secrets
from datetime import date

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import libraauth.terminos as terminos_mod
from libraauth.bootstrap import ensure_admin_user, ensure_default_admin, ensure_demo_user
from libraauth.email_sender import SmtpConfig
from libraauth.models import AceptacionTerminos, Base, Usuario
from libraauth.nodo import (
    CODIGO_SOLO_CENTRAL,
    MENSAJE_USUARIOS_SOLO_CENTRAL,
    NODE_ID_ENV,
    es_nodo,
)
from libraauth.password_reset import PasswordResetService
from libraauth.repository import UserRepository
from libraauth.session_auth import (
    SessionAuth,
    build_json_api_auth_router,
    json_api_require_admin,
    json_api_require_staff,
)
from libraauth.terminos import (
    CODIGO_PENDIENTE,
    VERSION_VIGENTE,
    TerminosRepository,
    build_terminos_router,
)
from libraauth.usuarios import build_users_router

ROLES = ("admin", "staff")


def hash_pbkdf2_como_antes(password: str) -> str:
    """El formato de las instancias viejas (ver `test_rehash_al_login`)."""
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("SECRET_KEY", "secreto-de-test-nodo")
    for var in (NODE_ID_ENV, "DEMO_MODE", "DEMO_USERNAME", "ADMIN_PASSWORD", "ADMIN_USER",
                "LIBRA_SERVICE_TOKEN", "LIBRAAUTH_COOKIE_SECURE"):
        monkeypatch.delenv(var, raising=False)
    # La versión vigente de los Términos se decide por fecha (ADR-021): se fija el día.
    monkeypatch.setattr(terminos_mod, "_hoy_argentina", lambda: date(2026, 10, 10))


@pytest.fixture
def nodo(monkeypatch):
    monkeypatch.setenv(NODE_ID_ENV, "nodo-sucursal-centro")


@pytest.fixture
def sessions():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def repo(sessions):
    return UserRepository(sessions, roles=ROLES)


def _codigo(respuesta) -> str:
    return respuesta.json()["detail"]["code"]


# ── Cómo se reconoce un nodo ─────────────────────────────────────────────────

def test_sin_la_variable_no_es_nodo():
    assert es_nodo() is False


@pytest.mark.parametrize("valor", ["", "   ", "\n"])
def test_variable_vacia_no_es_nodo(monkeypatch, valor):
    monkeypatch.setenv(NODE_ID_ENV, valor)
    assert es_nodo() is False


def test_con_la_variable_es_nodo(nodo):
    assert es_nodo() is True


# ── 1. Al arrancar no crea usuarios ──────────────────────────────────────────

def test_default_admin_en_el_nodo_no_crea_nada_ni_exige_la_clave(nodo, repo, capsys, monkeypatch):
    """Sin `ADMIN_PASSWORD` y sin `ENV=development` el central corta el arranque (fail-closed); el nodo ni lo pregunta."""
    monkeypatch.setenv("ENV", "production")
    ensure_default_admin(repo, env_prefix="CONTALIBRA")
    assert repo.list() == []
    assert "LIBRAEDGE_NODE_ID" in capsys.readouterr().out


def test_admin_user_en_el_nodo_no_crea_nada(nodo, repo, capsys):
    ensure_admin_user(repo)
    assert repo.list() == []
    salida = capsys.readouterr().out
    assert "nodo de LibraEdge" in salida
    assert "Contrasena generada" not in salida  # y no deja una clave aleatoria en el log


def test_en_el_central_los_dos_siguen_creando_el_admin(repo, monkeypatch):
    """La contraprueba: sin la variable, nada cambió."""
    monkeypatch.setenv("CONTALIBRA_ADMIN_PASSWORD", "clave-del-central")
    ensure_default_admin(repo, env_prefix="CONTALIBRA")
    assert [u["username"] for u in repo.list()] == ["admin"]


def test_admin_user_en_el_central_sigue_creandolo(repo):
    ensure_admin_user(repo)
    assert [u["username"] for u in repo.list()] == ["admin"]


def test_demo_en_el_nodo_no_crea_el_usuario(nodo, repo, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "visitante")
    assert ensure_demo_user(repo, rol="staff") is None
    assert repo.list() == []


def test_el_choque_que_motivo_el_cambio(sessions, repo, monkeypatch):
    """Medido: el admin local (id 1) y el `admin` que baja del central (id 7) chocan en `UNIQUE(username)`.
    En el nodo no hay admin local, y la fila del central entra."""
    # Sin el arreglo (central): el admin local existe y la bajada revienta.
    ensure_admin_user(repo)
    with sessions() as s:
        s.add(Usuario(id=7, username="admin", nombre="Admin del central", password_hash="x", role="admin"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_en_el_nodo_la_fila_del_central_entra_sin_chocar(nodo, sessions, repo):
    ensure_admin_user(repo)
    ensure_default_admin(repo, env_prefix="CONTALIBRA")
    with sessions() as s:
        s.add(Usuario(id=7, username="admin", nombre="Admin del central", password_hash="x", role="admin"))
        s.commit()
    assert [u["id"] for u in repo.list()] == ["7"]


# ── 2. Las escrituras de usuarios por API ────────────────────────────────────

def _app_usuarios(repo):
    """El router de usuarios con el guard real de admin."""
    app = FastAPI()
    app.state.users = repo
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=repo.get_by_username,
        check_credentials=repo.check_credentials,
    )
    app.include_router(build_json_api_auth_router())
    app.include_router(build_users_router(prefix="/api/usuarios", roles=ROLES, admin_guard=json_api_require_admin))
    return app


def _entrar(app, username, password):
    cliente = TestClient(app, base_url="https://testserver")
    r = cliente.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return cliente


@pytest.fixture
def admin_y_ana(repo):
    repo.create("admin", "Admin", "clave-admin", "admin")
    repo.create("ana", "Ana", "clave-ana", "staff")
    return repo


def test_en_el_nodo_las_escrituras_dan_409_con_el_codigo(nodo, admin_y_ana):
    repo = admin_y_ana
    cliente = _entrar(_app_usuarios(repo), "admin", "clave-admin")
    ana = repo.get_by_username("ana")["id"]
    admin = repo.get_by_username("admin")["id"]
    escrituras = [
        cliente.post("/api/usuarios", json={"username": "luis", "name": "Luis", "password": "clave-luis", "role": "staff"}),
        cliente.put(f"/api/usuarios/{ana}", json={"name": "Ana Maria", "role": "staff", "active": True}),
        cliente.put(f"/api/usuarios/{ana}/password", json={"password": "clave-nueva"}),
        cliente.put(f"/api/usuarios/{admin}/password", json={"password": "clave-nueva"}),  # la propia, por el ABM
        cliente.delete(f"/api/usuarios/{ana}"),
    ]
    for r in escrituras:
        assert r.status_code == 409, r.text
        assert _codigo(r) == CODIGO_SOLO_CENTRAL
        assert r.json()["detail"]["mensaje"] == MENSAJE_USUARIOS_SOLO_CENTRAL
    # Y no se escribió nada.
    assert {u["username"] for u in repo.list()} == {"admin", "ana"}
    assert repo.get_by_id(ana)["name"] == "Ana"
    assert repo.check_credentials("ana", "clave-ana") is not None
    assert repo.check_credentials("admin", "clave-admin") is not None


def test_en_el_nodo_la_guarda_corta_antes_que_la_validacion_del_cuerpo(nodo, admin_y_ana):
    """Un cuerpo inválido da 409, no 422: el nodo no discute el formulario de algo que no puede hacer."""
    cliente = _entrar(_app_usuarios(admin_y_ana), "admin", "clave-admin")
    r = cliente.post("/api/usuarios", json={"username": "luis"})
    assert r.status_code == 409
    assert _codigo(r) == CODIGO_SOLO_CENTRAL


def test_en_el_nodo_las_lecturas_andan(nodo, admin_y_ana):
    cliente = _entrar(_app_usuarios(admin_y_ana), "admin", "clave-admin")
    r = cliente.get("/api/usuarios")
    assert r.status_code == 200
    assert {u["username"] for u in r.json()} == {"admin", "ana"}
    ana = admin_y_ana.get_by_username("ana")["id"]
    assert cliente.get(f"/api/usuarios/{ana}").status_code == 200


def test_en_el_nodo_sin_ser_admin_se_recibe_el_403_y_no_el_409(nodo, admin_y_ana):
    """La guarda va después de la identidad: quien no es admin no se entera de si esto es un nodo."""
    cliente = _entrar(_app_usuarios(admin_y_ana), "ana", "clave-ana")
    r = cliente.post("/api/usuarios", json={"username": "luis", "name": "Luis", "password": "clave-luis", "role": "staff"})
    assert r.status_code == 403
    sin_sesion = TestClient(_app_usuarios(admin_y_ana), base_url="https://testserver")
    assert sin_sesion.post("/api/usuarios", json={}).status_code == 401


def test_en_el_central_las_escrituras_siguen_andando(admin_y_ana):
    """La contraprueba: sin la variable, el mismo router escribe."""
    repo = admin_y_ana
    cliente = _entrar(_app_usuarios(repo), "admin", "clave-admin")
    ana = repo.get_by_username("ana")["id"]
    assert cliente.post("/api/usuarios", json={
        "username": "luis", "name": "Luis", "password": "clave-luis", "role": "staff"}).status_code == 201
    assert cliente.put(f"/api/usuarios/{ana}", json={"name": "Ana Maria", "role": "staff", "active": True}).status_code == 200
    assert cliente.put(f"/api/usuarios/{ana}/password", json={"password": "clave-nueva"}).status_code == 204
    assert cliente.delete(f"/api/usuarios/{ana}").status_code == 204


def test_el_nodo_se_lee_en_cada_pedido_no_al_armar_el_router(admin_y_ana, monkeypatch):
    cliente = _entrar(_app_usuarios(admin_y_ana), "admin", "clave-admin")
    cuerpo = {"username": "luis", "name": "Luis", "password": "clave-luis", "role": "staff"}
    monkeypatch.setenv(NODE_ID_ENV, "nodo-1")
    assert cliente.post("/api/usuarios", json=cuerpo).status_code == 409
    monkeypatch.delenv(NODE_ID_ENV)
    assert cliente.post("/api/usuarios", json=cuerpo).status_code == 201


# ── La clave propia y el recupero por correo ────────────────────────────────

class _Buzon:
    def __init__(self):
        self.enviados = []

    def __call__(self, *, to_email, asunto, cuerpo):
        self.enviados.append(to_email)


def _app_auth(repo, sessions, buzon):
    app = FastAPI()
    app.state.users = repo
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=repo.get_by_username,
        check_credentials=repo.check_credentials,
    )
    app.state.password_reset = PasswordResetService(
        sessions, product_name="Contalibra", reset_url_base="https://x.test/reset",
        smtp_config=SmtpConfig(host="smtp.test", from_email="no-reply@test"), send_email=buzon,
    )
    app.include_router(build_json_api_auth_router(incluir_password_reset=True))
    return app


def test_en_el_nodo_no_se_cambia_la_clave_propia(nodo, repo, sessions):
    repo.create("ana", "Ana", "clave-ana", "staff")
    cliente = _entrar(_app_auth(repo, sessions, _Buzon()), "ana", "clave-ana")
    r = cliente.post("/auth/change-password", json={"current_password": "clave-ana", "new_password": "clave-nueva"})
    assert r.status_code == 409
    assert _codigo(r) == CODIGO_SOLO_CENTRAL
    assert repo.check_credentials("ana", "clave-ana") is not None
    assert repo.check_credentials("ana", "clave-nueva") is None


def test_en_el_central_se_cambia_la_clave_propia(repo, sessions):
    repo.create("ana", "Ana", "clave-ana", "staff")
    cliente = _entrar(_app_auth(repo, sessions, _Buzon()), "ana", "clave-ana")
    r = cliente.post("/auth/change-password", json={"current_password": "clave-ana", "new_password": "clave-nueva"})
    assert r.status_code == 200, r.text
    assert repo.check_credentials("ana", "clave-nueva") is not None


def test_en_el_nodo_no_hay_recupero_por_correo(nodo, repo, sessions):
    repo.create("ana", "Ana", "clave-ana", "staff", email="ana@x.test")
    buzon = _Buzon()
    cliente = TestClient(_app_auth(repo, sessions, buzon), base_url="https://testserver")
    r = cliente.post("/auth/forgot-password", json={"identificador": "ana"})
    assert r.status_code == 409 and _codigo(r) == CODIGO_SOLO_CENTRAL
    assert buzon.enviados == []
    r = cliente.post("/auth/reset-password", json={"token": "cualquiera", "new_password": "clave-nueva"})
    assert r.status_code == 409 and _codigo(r) == CODIGO_SOLO_CENTRAL


def test_en_el_central_el_recupero_por_correo_sigue_andando(repo, sessions):
    repo.create("ana", "Ana", "clave-ana", "staff", email="ana@x.test")
    buzon = _Buzon()
    cliente = TestClient(_app_auth(repo, sessions, buzon), base_url="https://testserver")
    assert cliente.post("/auth/forgot-password", json={"identificador": "ana"}).status_code == 200
    assert buzon.enviados == ["ana@x.test"]


# ── 3. El re-hash al entrar no escribe en un nodo ────────────────────────────

def _forzar_hash_viejo(sessions, username, clave):
    with sessions() as s:
        u = s.execute(select(Usuario).where(Usuario.username == username)).scalar_one()
        u.password_hash = hash_pbkdf2_como_antes(clave)
        s.commit()


def _hash_de(sessions, username):
    with sessions() as s:
        return s.execute(select(Usuario.password_hash).where(Usuario.username == username)).scalar_one()


def test_en_el_nodo_el_login_no_reescribe_el_hash(nodo, repo, sessions):
    repo.create("vieja", "Vieja", "da-igual", "staff")
    _forzar_hash_viejo(sessions, "vieja", "clave-vieja")
    viejo = _hash_de(sessions, "vieja")

    # Entra igual: la lectura y la verificación andan sin internet.
    assert repo.check_credentials("vieja", "clave-vieja") is not None
    assert _hash_de(sessions, "vieja") == viejo


def test_en_el_central_el_login_si_migra_el_hash(repo, sessions):
    """La contraprueba: el mismo caso sin la variable migra a argon2."""
    repo.create("vieja", "Vieja", "da-igual", "staff")
    _forzar_hash_viejo(sessions, "vieja", "clave-vieja")
    assert repo.check_credentials("vieja", "clave-vieja") is not None
    assert _hash_de(sessions, "vieja").startswith("$argon2id$")


# ── 4. Términos y Condiciones ────────────────────────────────────────────────

def _app_terminos(repo, sessions):
    app = FastAPI()
    app.state.users = repo
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=repo.get_by_username,
        check_credentials=repo.check_credentials,
    )
    app.state.terminos = TerminosRepository(sessions)
    app.include_router(build_json_api_auth_router())
    app.include_router(build_terminos_router())

    @app.get("/clientes", dependencies=[Depends(json_api_require_staff)])
    def clientes():
        return {"ok": True}

    return app


def _filas_de_aceptacion(sessions) -> int:
    with sessions() as s:
        return len(s.execute(select(AceptacionTerminos)).scalars().all())


def test_en_el_nodo_no_se_exige_aceptar_y_no_se_acepta(nodo, repo, sessions):
    repo.create("admin", "Admin", "clave-admin", "admin")
    cliente = _entrar(_app_terminos(repo, sessions), "admin", "clave-admin")

    # El gate no corta la operación del local.
    assert cliente.get("/clientes").status_code == 200
    estado = cliente.get("/terminos").json()
    assert estado["pendiente"] is False
    assert estado["puede_aceptar"] is False
    assert estado["proxima"] is None

    # Y aceptar en el nodo no escribe la prueba: 409, y la tabla queda como estaba.
    r = cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE})
    assert r.status_code == 409
    assert _codigo(r) == CODIGO_SOLO_CENTRAL
    assert "versión web" in r.json()["detail"]["mensaje"]
    assert _filas_de_aceptacion(sessions) == 0


def test_en_el_nodo_la_aceptacion_espejada_se_sigue_mostrando(nodo, repo, sessions):
    repo.create("admin", "Admin", "clave-admin", "admin")
    TerminosRepository(sessions).registrar(usuario_id=1, username="admin", nombre="Admin")  # lo que baja del central
    estado = _entrar(_app_terminos(repo, sessions), "admin", "clave-admin").get("/terminos").json()
    assert estado["pendiente"] is False
    assert estado["aceptada_por"] == "Admin"


def test_en_el_central_el_gate_sigue_cortando_y_se_acepta(repo, sessions):
    """La contraprueba: sin la variable, el gate corta y aceptar escribe la fila."""
    repo.create("admin", "Admin", "clave-admin", "admin")
    cliente = _entrar(_app_terminos(repo, sessions), "admin", "clave-admin")
    r = cliente.get("/clientes")
    assert r.status_code == 403 and r.json()["detail"]["code"] == CODIGO_PENDIENTE
    assert cliente.get("/terminos").json()["puede_aceptar"] is True
    assert cliente.post("/terminos/aceptar", json={"version": VERSION_VIGENTE}).status_code == 200
    assert _filas_de_aceptacion(sessions) == 1
    assert cliente.get("/clientes").status_code == 200


# ── 5. Un usuario dado de baja en el central pierde la sesión en el nodo ─────

def test_el_usuario_que_baja_inactivo_pierde_la_sesion_del_nodo(nodo, repo, sessions):
    """Lo que hace el espejo al bajar `activo=false` es escribir la fila: se simula con `Usuario.activo = False`, sin
    pasar por la API (que en el nodo está cerrada). La cookie de la sesión en curso deja de servir."""
    repo.create("ana", "Ana", "clave-ana", "staff")
    app = _app_auth(repo, sessions, _Buzon())
    cliente = _entrar(app, "ana", "clave-ana")
    assert cliente.get("/auth/me").status_code == 200

    with sessions() as s:
        s.execute(select(Usuario).where(Usuario.username == "ana")).scalar_one().activo = False
        s.commit()

    assert cliente.get("/auth/me").status_code == 401
    # Y tampoco puede volver a entrar.
    otro = TestClient(app, base_url="https://testserver")
    assert otro.post("/auth/login", json={"username": "ana", "password": "clave-ana"}).status_code == 401
