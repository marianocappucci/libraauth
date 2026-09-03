"""Tests de la recuperacion de contrasena por correo (v0.5.0).

El reloj se inyecta en todos los casos que dependen del tiempo: la familia
ya tuvo dos rondas de tests que fallaban por la hora real (los de agenda que
se rompian media hora por dia, y los 401 del reloj de WSL), asi que el
vencimiento se prueba moviendo `now`, sin dormir ni depender de la maquina.
"""
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from libraauth.email_sender import SmtpConfig
from libraauth.models import Base, PasswordResetToken
from libraauth.password_reset import (
    EmailNotConfigured,
    InvalidResetToken,
    PasswordResetService,
)
from libraauth.repository import UserRepository
from libraauth.session_auth import SessionAuth, build_json_api_auth_router

AHORA = datetime(2026, 7, 30, 12, 0, 0)

SMTP_OK = SmtpConfig(host="smtp.test", from_email="no-reply@test")


class MailboxFalso:
    """Transporte inyectado: acumula en memoria en vez de hablar SMTP."""

    def __init__(self):
        self.enviados = []

    def __call__(self, *, to_email, asunto, cuerpo):
        self.enviados.append({"to": to_email, "asunto": asunto, "cuerpo": cuerpo})

    def ultimo_token(self) -> str:
        return self.enviados[-1]["cuerpo"].split("?token=")[1].split("\n")[0].strip()


@pytest.fixture
def entorno(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/auth.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    repo = UserRepository(sessions)
    buzon = MailboxFalso()
    reloj = {"ahora": AHORA}
    servicio = PasswordResetService(
        sessions,
        product_name="Gestiolibra",
        reset_url_base="https://dev.gestiolibra.com.ar/reset-password",
        smtp_config=SMTP_OK,
        send_email=buzon,
        now=lambda: reloj["ahora"],
    )
    return repo, servicio, buzon, reloj, sessions


# ── Pedido del reset ────────────────────────────────────────────────────────

def test_manda_el_mail_al_usuario_que_existe(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")

    assert servicio.request_reset("ana") == 1
    assert buzon.enviados[0]["to"] == "ana@empresa.com"
    assert "Gestiolibra" in buzon.enviados[0]["asunto"]
    assert "https://dev.gestiolibra.com.ar/reset-password?token=" in buzon.enviados[0]["cuerpo"]


def test_tambien_acepta_el_email_como_identificador(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="Ana@Empresa.com")

    # Escrito con otras mayusculas de las que quedaron guardadas.
    assert servicio.request_reset("ana@empresa.COM") == 1
    assert len(buzon.enviados) == 1


def test_usuario_inexistente_no_manda_nada_y_no_falla(entorno):
    _, servicio, buzon, _, _ = entorno
    # Que no lance es el punto: el router responde igual que en el caso feliz.
    assert servicio.request_reset("no-existe") == 0
    assert buzon.enviados == []


def test_usuario_inactivo_no_recibe_mail(entorno):
    repo, servicio, buzon, _, _ = entorno
    u = repo.create(username="baja", name="Baja", password="vieja123", role="staff",
                    email="baja@empresa.com")
    repo.update(u["id"], name="Baja", role="staff", active=False)

    assert servicio.request_reset("baja") == 0
    assert buzon.enviados == []


def test_usuario_sin_email_cargado_no_genera_token(entorno):
    repo, servicio, buzon, _, sessions = entorno
    repo.create(username="sinmail", name="Sin Mail", password="vieja123", role="staff")

    assert servicio.request_reset("sinmail") == 0
    with sessions() as s:
        assert s.execute(select(PasswordResetToken)).scalars().all() == []


def test_email_compartido_manda_uno_por_cada_cuenta(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="familia@empresa.com")
    repo.create(username="luis", name="Luis", password="vieja123", role="staff",
                email="familia@empresa.com")

    assert servicio.request_reset("familia@empresa.com") == 2
    # Cada cuerpo nombra SU cuenta: con la casilla compartida, si no, no se
    # sabe cual se esta recuperando.
    cuerpos = "\n".join(m["cuerpo"] for m in buzon.enviados)
    assert "'ana'" in cuerpos and "'luis'" in cuerpos


def test_sin_smtp_configurado_avisa_en_vez_de_fallar_en_silencio(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/auth.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    UserRepository(sessions).create(username="ana", name="Ana", password="vieja123",
                                    role="admin", email="ana@empresa.com")
    servicio = PasswordResetService(
        sessions, product_name="X", reset_url_base="https://x/reset",
        smtp_config=SmtpConfig(),  # vacia
    )
    with pytest.raises(EmailNotConfigured):
        servicio.request_reset("ana")


def test_el_token_no_se_guarda_en_claro(entorno):
    repo, servicio, buzon, _, sessions = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")
    token = buzon.ultimo_token()

    with sessions() as s:
        guardado = s.execute(select(PasswordResetToken)).scalar_one()
    assert guardado.token_hash != token
    assert len(guardado.token_hash) == 64


# ── Uso del token ───────────────────────────────────────────────────────────

def test_reset_cambia_la_contrasena(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")

    resultado = servicio.reset(buzon.ultimo_token(), "nueva-clave-1")

    assert resultado["username"] == "ana"
    assert repo.check_credentials("ana", "nueva-clave-1") is not None
    assert repo.check_credentials("ana", "vieja123") is None


def test_el_token_sirve_una_sola_vez(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")
    token = buzon.ultimo_token()
    servicio.reset(token, "nueva-clave-1")

    with pytest.raises(InvalidResetToken):
        servicio.reset(token, "otra-clave-2")
    # Y la contrasena del primer reset sigue siendo la buena.
    assert repo.check_credentials("ana", "nueva-clave-1") is not None


def test_el_token_vence(entorno):
    repo, servicio, buzon, reloj, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")
    token = buzon.ultimo_token()

    reloj["ahora"] = AHORA + timedelta(minutes=61)
    with pytest.raises(InvalidResetToken):
        servicio.reset(token, "nueva-clave-1")
    assert repo.check_credentials("ana", "vieja123") is not None


def test_justo_antes_de_vencer_todavia_sirve(entorno):
    repo, servicio, buzon, reloj, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")
    token = buzon.ultimo_token()

    reloj["ahora"] = AHORA + timedelta(minutes=59)
    assert servicio.reset(token, "nueva-clave-1")["username"] == "ana"


def test_token_inventado_es_invalido(entorno):
    _, servicio, _, _, _ = entorno
    with pytest.raises(InvalidResetToken):
        servicio.reset("cualquier-cosa", "nueva-clave-1")


def test_un_reset_exitoso_quema_los_otros_tokens_pendientes(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")
    primero = buzon.ultimo_token()
    servicio.request_reset("ana")
    segundo = buzon.ultimo_token()
    assert primero != segundo

    servicio.reset(segundo, "nueva-clave-1")
    with pytest.raises(InvalidResetToken):
        servicio.reset(primero, "otra-clave-2")


def test_usuario_dado_de_baja_despues_de_pedir_el_reset(entorno):
    repo, servicio, buzon, _, _ = entorno
    u = repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                    email="ana@empresa.com")
    servicio.request_reset("ana")
    token = buzon.ultimo_token()
    repo.update(u["id"], name="Ana", role="admin", active=False)

    with pytest.raises(InvalidResetToken):
        servicio.reset(token, "nueva-clave-1")


def test_contrasena_corta_se_rechaza(entorno):
    repo, servicio, buzon, _, _ = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")

    with pytest.raises(ValueError):
        servicio.reset(buzon.ultimo_token(), "123")
    # Y el token NO se quemo: el usuario puede reintentar con una valida.
    assert servicio.reset(buzon.ultimo_token(), "valida-123")["username"] == "ana"


def test_purgar_vencidos(entorno):
    repo, servicio, buzon, reloj, sessions = entorno
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    servicio.request_reset("ana")
    reloj["ahora"] = AHORA + timedelta(hours=2)
    servicio.request_reset("ana")  # este queda vigente

    assert servicio.purgar_vencidos() == 1
    with sessions() as s:
        assert len(s.execute(select(PasswordResetToken)).scalars().all()) == 1


# ── Endpoints HTTP ──────────────────────────────────────────────────────────

@pytest.fixture
def cliente(entorno, monkeypatch):
    repo, servicio, buzon, reloj, _ = entorno
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    app = FastAPI()
    app.state.users = repo
    app.state.password_reset = servicio
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=repo.get_by_username,
        check_credentials=repo.check_credentials,
    )
    app.include_router(build_json_api_auth_router(incluir_password_reset=True))
    return TestClient(app), repo, buzon


def test_forgot_password_responde_igual_exista_o_no(cliente):
    client, repo, buzon = cliente
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")

    real = client.post("/auth/forgot-password", json={"identificador": "ana"})
    inventado = client.post("/auth/forgot-password", json={"identificador": "fantasma"})

    # Este assert es el corazon del endpoint: mismo status y mismo cuerpo.
    assert real.status_code == inventado.status_code == 200
    assert real.json() == inventado.json() == {"ok": True}
    # Y sin embargo solo uno genero un mail.
    assert len(buzon.enviados) == 1


def test_reset_password_por_http(cliente):
    client, repo, buzon = cliente
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    client.post("/auth/forgot-password", json={"identificador": "ana"})

    r = client.post("/auth/reset-password",
                    json={"token": buzon.ultimo_token(), "new_password": "nueva-clave-1"})

    assert r.status_code == 200
    assert r.json()["username"] == "ana"
    # No crea sesion: la persona tiene que entrar con la contrasena nueva.
    assert "set-cookie" not in {k.lower() for k in r.headers}
    assert client.post("/auth/login",
                       json={"username": "ana", "password": "nueva-clave-1"}).status_code == 200


def test_reset_password_con_token_malo_da_400(cliente):
    client, _, _ = cliente
    r = client.post("/auth/reset-password",
                    json={"token": "no-existe", "new_password": "nueva-clave-1"})
    assert r.status_code == 400


def test_reset_password_con_clave_corta_da_422(cliente):
    client, repo, buzon = cliente
    repo.create(username="ana", name="Ana", password="vieja123", role="admin",
                email="ana@empresa.com")
    client.post("/auth/forgot-password", json={"identificador": "ana"})

    r = client.post("/auth/reset-password",
                    json={"token": buzon.ultimo_token(), "new_password": "12"})
    assert r.status_code == 422


def test_los_endpoints_no_existen_si_no_se_piden(entorno, monkeypatch):
    repo, servicio, _, _, _ = entorno
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    app = FastAPI()
    app.state.users = repo
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=repo.get_by_username,
        check_credentials=repo.check_credentials,
    )
    app.include_router(build_json_api_auth_router())  # sin incluir_password_reset

    client = TestClient(app)
    assert client.post("/auth/forgot-password", json={"identificador": "ana"}).status_code == 404
    assert client.post("/auth/reset-password",
                       json={"token": "x", "new_password": "y"}).status_code == 404
