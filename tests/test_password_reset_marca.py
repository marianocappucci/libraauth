"""El mail de recuperación con la marca de la instancia (ADR-030, marca blanca).

`product_name` y `reset_url_base` pueden ser una función que se resuelve en cada pedido, así el mail de una instancia de un revendedor
sale con SU nombre y SU dominio. Lo que se fija:

1. 🔴 **Que ninguna de las dos fuentes pueda revelar qué cuentas existen.** Si la función falla *después* de buscar al usuario, el error
   sólo ocurre con cuentas reales y el endpoint vuelve a ser un buscador de usuarios. Se resuelven antes, como el SMTP.
2. Que el mail lleve el nombre y el dominio de AHORA, no los de cuando se construyó el servicio.
3. Que el texto fijo de siempre siga andando, y que las dos propiedades sigan siendo asignables (ya rompió una vez con `smtp_config`).
"""
from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from libraauth.email_sender import SmtpConfig
from libraauth.models import Base, PasswordResetToken
from libraauth.password_reset import EmailNotConfigured, PasswordResetService
from libraauth.repository import UserRepository
from libraauth.session_auth import SessionAuth, build_json_api_auth_router

SMTP_OK = SmtpConfig(host="smtp.test", from_email="no-reply@test")


class Buzon:
    def __init__(self):
        self.enviados = []

    def __call__(self, *, to_email, asunto, cuerpo):
        self.enviados.append({"to": to_email, "asunto": asunto, "cuerpo": cuerpo})


@pytest.fixture
def entorno(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/auth.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    repo = UserRepository(sessions)
    repo.create(username="ana", name="Ana", password="vieja123", role="admin", email="ana@sur.com")
    return repo, sessions, Buzon()


def _servicio(sessions, buzon, **kwargs):
    return PasswordResetService(
        sessions,
        smtp_config=SMTP_OK,
        send_email=buzon,
        now=lambda: datetime(2026, 10, 30, 12, 0, 0),
        **kwargs,
    )


def test_el_mail_sale_con_el_nombre_y_el_dominio_de_la_marca(entorno):
    repo, sessions, buzon = entorno
    marca = {"nombre": "Gestión Sur", "url": "https://sistema.gestionsur.com.ar/reset-password"}
    servicio = _servicio(sessions, buzon, product_name=lambda: marca["nombre"], reset_url_base=lambda: marca["url"])

    assert servicio.request_reset("ana") == 1
    mail = buzon.enviados[0]
    assert mail["asunto"] == "Recuperar la contraseña de Gestión Sur"
    assert "en Gestión Sur." in mail["cuerpo"]
    assert "https://sistema.gestionsur.com.ar/reset-password?token=" in mail["cuerpo"]
    assert "libra" not in (mail["asunto"] + mail["cuerpo"]).lower()


def test_se_resuelve_en_cada_pedido_no_al_construir(entorno):
    """Si la marca cambia (el revendedor cambia su nombre o su dominio) el próximo mail ya sale con lo nuevo, sin reiniciar nada."""
    repo, sessions, buzon = entorno
    marca = {"nombre": "VentaLibra", "url": "https://dev.ventalibra.com.ar/reset-password"}
    servicio = _servicio(sessions, buzon, product_name=lambda: marca["nombre"], reset_url_base=lambda: marca["url"])

    servicio.request_reset("ana")
    marca.update(nombre="Gestión Sur", url="https://sistema.gestionsur.com.ar/reset-password")
    servicio.request_reset("ana")

    assert "VentaLibra" in buzon.enviados[0]["asunto"] and "dev.ventalibra.com.ar" in buzon.enviados[0]["cuerpo"]
    assert "Gestión Sur" in buzon.enviados[1]["asunto"]
    assert "https://sistema.gestionsur.com.ar/reset-password?token=" in buzon.enviados[1]["cuerpo"]


def test_una_url_base_con_signos_al_final_se_limpia_tambien_viniendo_de_una_funcion(entorno):
    _, sessions, buzon = entorno
    servicio = _servicio(sessions, buzon, product_name="X", reset_url_base=lambda: "https://x.test/reset?&")
    assert servicio.reset_url_base == "https://x.test/reset"


def test_el_texto_fijo_de_siempre_sigue_andando(entorno):
    _, sessions, buzon = entorno
    servicio = _servicio(sessions, buzon, product_name="Gestiolibra", reset_url_base="https://dev.gestiolibra.com.ar/reset-password?")
    assert servicio.product_name == "Gestiolibra"
    assert servicio.reset_url_base == "https://dev.gestiolibra.com.ar/reset-password"
    servicio.request_reset("ana")
    assert "Gestiolibra" in buzon.enviados[0]["asunto"]


def test_las_dos_propiedades_siguen_siendo_asignables_con_un_texto_o_con_una_funcion(entorno, monkeypatch):
    """Convertir `smtp_config` en propiedad de solo lectura rompió a Contalibra y Restolibra con `monkeypatch.setattr`."""
    _, sessions, buzon = entorno
    servicio = _servicio(sessions, buzon, product_name="A", reset_url_base="https://a.test/r")
    monkeypatch.setattr(servicio, "product_name", "B")
    monkeypatch.setattr(servicio, "reset_url_base", lambda: "https://b.test/r")
    assert servicio.product_name == "B" and servicio.reset_url_base == "https://b.test/r"
    servicio.request_reset("ana")
    assert "B" in buzon.enviados[0]["asunto"] and "https://b.test/r?token=" in buzon.enviados[0]["cuerpo"]


# ── 1. Una función que falla no revela qué cuentas existen ──────────────────

def _falla():
    raise RuntimeError("no se pudo leer la marca")


@pytest.mark.parametrize(
    "fuente", [_falla, lambda: "", lambda: "   ", lambda: None, lambda: 5],
    ids=["lanza", "vacío", "espacios", "None", "no es texto"],
)
@pytest.mark.parametrize("cual", ["product_name", "reset_url_base"])
def test_una_fuente_rota_falla_igual_exista_o_no_la_cuenta(entorno, fuente, cual):
    repo, sessions, buzon = entorno
    kwargs = {"product_name": "X", "reset_url_base": "https://x.test/r", cual: fuente}
    servicio = _servicio(sessions, buzon, **kwargs)

    for identificador in ("ana", "fantasma"):
        with pytest.raises(EmailNotConfigured):
            servicio.request_reset(identificador)
    assert buzon.enviados == []
    with sessions() as s:
        assert s.execute(select(PasswordResetToken)).scalars().all() == []  # y no quedó ningún token pendiente


def test_por_http_una_fuente_rota_es_503_para_las_dos_cuentas(entorno, monkeypatch):
    repo, sessions, buzon = entorno
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    servicio = _servicio(sessions, buzon, product_name=_falla, reset_url_base="https://x.test/r")
    app = FastAPI()
    app.state.users = repo
    app.state.password_reset = servicio
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev", get_user_by_username=repo.get_by_username, check_credentials=repo.check_credentials,
    )
    app.include_router(build_json_api_auth_router(incluir_password_reset=True))
    client = TestClient(app)

    real = client.post("/auth/forgot-password", json={"identificador": "ana"})
    inventado = client.post("/auth/forgot-password", json={"identificador": "fantasma"})
    assert real.status_code == inventado.status_code == 503
    assert real.json() == inventado.json()


def test_enviar_directo_sin_producto_ni_url_los_resuelve_solo(entorno):
    """`_enviar` lo llaman algunos tests directo y sin los dos argumentos nuevos."""
    _, sessions, buzon = entorno
    servicio = _servicio(sessions, buzon, product_name=lambda: "Gestión Sur", reset_url_base=lambda: "https://s.test/r")
    servicio._enviar(SMTP_OK, email="ana@sur.com", username="ana", nombre="Ana", token="T0K3N")
    assert "Gestión Sur" in buzon.enviados[0]["asunto"] and "https://s.test/r?token=T0K3N" in buzon.enviados[0]["cuerpo"]
