"""Tests del log de accesos (v0.8.0): el repositorio, la resolucion de la IP
detras del proxy, y que el router de login/logout deje las filas que tiene que
dejar."""
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

from libraauth.auth_events import (
    LOGIN,
    LOGIN_FALLIDO,
    LOGOUT,
    AuthEventRepository,
    ip_del_request,
    registrar_seguro,
)
from libraauth.models import AuthEvent, Base
from libraauth.repository import UserRepository
from libraauth.session_auth import SessionAuth, build_json_api_auth_router


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-auth-events")


@pytest.fixture
def sessions(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/auth_events_test.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def repo(sessions):
    return AuthEventRepository(sessions)


# ── Repositorio ───────────────────────────────────────────────────────────

def test_registrar_y_listar(repo):
    repo.registrar(LOGIN, "admin", ip="10.0.0.5")
    fila = repo.listar()[0]
    assert fila["evento"] == LOGIN
    assert fila["username"] == "admin"
    assert fila["ip"] == "10.0.0.5"
    assert fila["detalle"] == ""
    # El formato de `ts` es el mismo que escribe LibraCore, sin la "T" de ISO
    # ni microsegundos: la pantalla de logs de Contalibra ya lo parte asi.
    datetime.strptime(fila["ts"], "%Y-%m-%d %H:%M:%S")


def test_listar_devuelve_lo_mas_reciente_primero(repo):
    for n in range(3):
        repo.registrar(LOGIN, f"user{n}")
    assert [f["username"] for f in repo.listar()] == ["user2", "user1", "user0"]


def test_listar_pagina(repo):
    for n in range(5):
        repo.registrar(LOGIN, f"user{n}")
    assert [f["username"] for f in repo.listar(limit=2, offset=2)] == ["user2", "user1"]
    assert repo.contar() == 5


def test_campos_largos_se_recortan_en_vez_de_romper(repo):
    """Un username de 400 caracteres es exactamente el tipo de intento que hay
    que poder ver en el log — no puede tumbar el registro."""
    repo.registrar(LOGIN_FALLIDO, "x" * 400, ip="y" * 200, detalle="z" * 900)
    fila = repo.listar()[0]
    assert len(fila["username"]) == 100
    assert len(fila["ip"]) == 64
    assert len(fila["detalle"]) == 500


def test_contar_fallidos_recientes_solo_cuenta_su_ip_su_evento_y_su_ventana(repo, sessions):
    repo.registrar(LOGIN_FALLIDO, "admin", ip="1.1.1.1")
    repo.registrar(LOGIN_FALLIDO, "admin", ip="1.1.1.1")
    repo.registrar(LOGIN_FALLIDO, "admin", ip="2.2.2.2")   # otra IP
    repo.registrar(LOGIN, "admin", ip="1.1.1.1")           # otro evento
    # Un fallido viejo, fuera de la ventana: se escribe con `ts` hacia atras.
    with sessions() as session:
        session.add(AuthEvent(
            evento=LOGIN_FALLIDO, username="admin", ip="1.1.1.1", detalle="",
            ts=datetime.now() - timedelta(minutes=60),
        ))
        session.commit()

    assert repo.contar_fallidos_recientes("1.1.1.1") == 2
    assert repo.contar_fallidos_recientes("1.1.1.1", minutos=90) == 3
    assert repo.contar_fallidos_recientes("2.2.2.2") == 1
    assert repo.contar_fallidos_recientes("9.9.9.9") == 0


def test_contar_fallidos_con_ip_vacia_es_cero(repo):
    """Sin IP, la ventana juntaria a todos los clientes en un mismo balde y el
    primer fallido de cualquiera bloquearia a todos."""
    repo.registrar(LOGIN_FALLIDO, "admin", ip="")
    assert repo.contar_fallidos_recientes("") == 0


def test_la_tabla_es_auth_log_y_no_otra(sessions):
    """El nombre importa: es la misma tabla que ya crea LibraCore en
    Contalibra y Restolibra. Si alguien la renombra, esos dos productos
    terminarian con dos logs de accesos en la misma base."""
    assert AuthEvent.__tablename__ == "auth_log"
    with sessions() as session:
        nombres = {r[0] for r in session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        )}
    assert "auth_log" in nombres


def test_ts_usa_hora_local_y_no_utc(repo):
    """`func.now()` en SQLite devuelve UTC; LibraCore escribe localtime. Si
    esta columna se fuera a UTC, los eventos de un mismo dia quedarian
    corridos tres horas contra los que ya estan escritos."""
    repo.registrar(LOGIN, "admin")
    escrito = datetime.strptime(repo.listar()[0]["ts"], "%Y-%m-%d %H:%M:%S")
    assert abs((escrito - datetime.now()).total_seconds()) < 60


# ── IP detras del proxy ───────────────────────────────────────────────────

class _FakeRequest:
    def __init__(self, headers=None, client_host="172.18.0.1"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": client_host})()


def test_ip_prefiere_x_forwarded_for():
    """Detras de Nginx Proxy Manager `request.client.host` es siempre el
    proxy — un log lleno de 172.18.0.1 no sirve para nada."""
    req = _FakeRequest({"x-forwarded-for": "203.0.113.7"})
    assert ip_del_request(req) == "203.0.113.7"


def test_ip_toma_el_primer_salto_de_la_cadena():
    req = _FakeRequest({"x-forwarded-for": "203.0.113.7, 10.0.0.1, 172.18.0.1"})
    assert ip_del_request(req) == "203.0.113.7"


def test_ip_cae_al_cliente_directo_sin_header():
    assert ip_del_request(_FakeRequest(client_host="192.168.1.50")) == "192.168.1.50"


def test_ip_sin_cliente_ni_header_es_vacia():
    req = _FakeRequest()
    req.client = None
    assert ip_del_request(req) == ""


# ── Integracion con el router ─────────────────────────────────────────────

def _app(sessions, con_log=True):
    users = UserRepository(sessions)
    users.create(username="admin", name="Admin", password="secreto", role="admin")
    app = FastAPI()
    app.state.users = users
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=users.get_by_username,
        check_credentials=users.check_credentials,
    )
    if con_log:
        app.state.auth_events = AuthEventRepository(sessions)
    app.include_router(build_json_api_auth_router())
    return app


def _client(app) -> TestClient:
    """`https://` y no `http://`: la cookie de sesion se emite con
    `secure=True`, asi que sobre http el cliente no la manda de vuelta y
    cualquier test que dependa de estar logueado (el logout, sin ir mas lejos)
    fallaria por el motivo equivocado. Mismo criterio que test_session_auth.py."""
    return TestClient(app, base_url="https://testserver")


def test_login_ok_deja_una_fila(sessions, repo):
    client = _client(_app(sessions))
    assert client.post("/auth/login", json={"username": "admin", "password": "secreto"}).status_code == 200
    fila = repo.listar()[0]
    assert (fila["evento"], fila["username"]) == (LOGIN, "admin")


def test_login_fallido_deja_el_username_tipeado(sessions, repo):
    """El username puede no existir: un intento contra un usuario inexistente
    es la firma de un barrido, y es justo el que se pierde si solo se
    registran los logins que salen bien."""
    client = _client(_app(sessions))
    r = client.post("/auth/login", json={"username": "fantasma", "password": "x"})
    assert r.status_code == 401
    fila = repo.listar()[0]
    assert (fila["evento"], fila["username"]) == (LOGIN_FALLIDO, "fantasma")


def test_no_se_registra_nada_de_la_contrasena(sessions, repo):
    client = _client(_app(sessions))
    client.post("/auth/login", json={"username": "admin", "password": "una-clave-muy-secreta"})
    client.post("/auth/login", json={"username": "admin", "password": "otra-mal"})
    for fila in repo.listar():
        assert "secreta" not in str(fila).lower()
        assert "otra-mal" not in str(fila)


def test_logout_registra_al_usuario_de_la_cookie(sessions, repo):
    client = _client(_app(sessions))
    client.post("/auth/login", json={"username": "admin", "password": "secreto"})
    assert client.post("/auth/logout").status_code == 200
    fila = repo.listar()[0]
    assert (fila["evento"], fila["username"]) == (LOGOUT, "admin")


def test_logout_sin_sesion_no_registra_nada(sessions, repo):
    """Sin cookie no hay nombre que anotar, y una fila con username vacio
    ensucia el log sin decir nada."""
    client = _client(_app(sessions))
    assert client.post("/auth/logout").status_code == 200
    assert repo.listar() == []


def test_sin_auth_events_configurado_el_login_funciona_igual(sessions, repo):
    """Opt-in por ausencia: un consumidor que actualice el motor y no
    configure nada no cambia de comportamiento en nada."""
    client = TestClient(_app(sessions, con_log=False))
    assert client.post("/auth/login", json={"username": "admin", "password": "secreto"}).status_code == 200
    assert client.post("/auth/logout").status_code == 200
    assert repo.listar() == []


def test_si_el_log_falla_el_login_sigue_entrando(sessions):
    """La alternativa a tragarse el error es un 500 en el login: nadie podria
    entrar al sistema porque falla el que anota que entraron."""
    class RepoRoto:
        def registrar(self, *a, **kw):
            raise RuntimeError("base bloqueada")

    app = _app(sessions, con_log=False)
    app.state.auth_events = RepoRoto()
    client = _client(app)
    assert client.post("/auth/login", json={"username": "admin", "password": "secreto"}).status_code == 200


def test_registrar_seguro_sin_state_no_explota(sessions):
    """`app.state.auth_events` ausente es el caso normal de un consumidor que
    todavia no lo adopto."""
    app = _app(sessions, con_log=False)
    with _client(app) as client:
        client.post("/auth/login", json={"username": "admin", "password": "secreto"})
    # Y llamado a mano, con un request cuyo app.state no tiene el atributo:
    req = _FakeRequest()
    req.app = type("A", (), {"state": type("S", (), {})()})()
    registrar_seguro(req, LOGIN, "admin")  # no levanta
