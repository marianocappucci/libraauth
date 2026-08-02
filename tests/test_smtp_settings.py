"""Tests de la config SMTP persistida y su router de backoffice (v0.6.0).

Los dos hechos que mas importa fijar:

1. **La contrasena nunca sale por HTTP.** Ni en el `GET`, ni como eco del
   `PUT`, ni enmascarada con su largo real.
2. **Adoptar esta version no cambia nada** en una instancia que hoy usa las
   variables de entorno: sin fila en la base, `resolver_smtp_config` cae al
   entorno tal cual.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from libraauth.crypto import ClaveDeCifradoAusente
from libraauth.models import Base, SmtpSettings
from libraauth.session_auth import build_smtp_settings_router
from libraauth.smtp_settings import (
    FILA_UNICA,
    SIN_CAMBIOS,
    SmtpSettingsRepository,
    resolver_smtp_config,
)


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 64)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    for v in ("LIBRAAUTH_SMTP_HOST", "LIBRAAUTH_SMTP_USER",
              "LIBRAAUTH_SMTP_PASSWORD", "LIBRAAUTH_SMTP_FROM_EMAIL",
              "LIBRAAUTH_SMTP_FROM_NAME", "LIBRAAUTH_SMTP_PORT"):
        monkeypatch.delenv(v, raising=False)


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/smtp_test.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def repo(session_factory):
    return SmtpSettingsRepository(session_factory)


# ── Persistencia y cifrado ──────────────────────────────────────────────────

def test_sin_nada_guardado_devuelve_none(repo):
    assert repo.get() is None


def test_guardar_y_leer(repo):
    repo.save(host="smtp.empresa.com", port=2525, user="cuenta",
              password="clave-real", from_email="no-reply@empresa.com",
              from_name="Soporte")
    cfg = repo.get()
    assert (cfg.host, cfg.port, cfg.user, cfg.password) == (
        "smtp.empresa.com", 2525, "cuenta", "clave-real")
    assert cfg.from_email == "no-reply@empresa.com"
    assert cfg.configurado is True


def test_en_la_base_la_contrasena_esta_cifrada(repo, session_factory):
    """El test que justifica todo el modulo: leer el archivo `.db` no
    alcanza para mandar correo en nombre del cliente."""
    repo.save(host="smtp.test", password="hunter2", from_email="a@b.com")
    with session_factory() as session:
        crudo = session.execute(
            text("SELECT password_cifrada FROM smtp_settings")
        ).scalar_one()
    assert crudo != "hunter2"
    assert "hunter2" not in crudo
    assert crudo.startswith("v1:")


def test_la_columna_se_llama_password_cifrada(session_factory):
    """El nombre es parte de la mitigacion: quien abra un backup con un visor
    de SQLite tiene que ver de entrada que ese valor no es usable tal cual."""
    assert "password_cifrada" in SmtpSettings.__table__.columns
    assert "password" not in SmtpSettings.__table__.columns


def test_estado_no_incluye_la_contrasena(repo):
    """`estado()` es la superficie publica de verdad, no el router.

    Contalibra y Restolibra **no montan el router de este motor** — escriben
    sus propios endpoints bajo `/api` y serializan lo que este metodo
    devuelva, sin `response_model` que filtre nada. Este test existe porque
    una mutacion lo demostro: filtrar la contrasena en `estado()` no ponia
    roja la suite, porque el unico test que lo cubria pasaba por el router y
    ahi el `response_model` la descartaba. O sea que se estaba probando
    Pydantic, no el codigo propio.
    """
    repo.save(host="smtp.test", user="cuenta", password="hunter2",
              from_email="a@b.com")
    estado = repo.estado()

    assert "password" not in estado
    assert "hunter2" not in str(estado)
    assert estado["password_definida"] is True


def test_no_hay_dos_filas_por_mas_que_se_guarde_muchas_veces(repo, session_factory):
    repo.save(host="uno.test", from_email="a@b.com")
    repo.save(host="dos.test", from_email="a@b.com")
    with session_factory() as session:
        assert session.execute(text("SELECT COUNT(*) FROM smtp_settings")).scalar_one() == 1
        assert session.get(SmtpSettings, FILA_UNICA).host == "dos.test"


# ── El centinela SIN_CAMBIOS ────────────────────────────────────────────────

def test_guardar_sin_tocar_la_password_la_conserva(repo):
    """Editar el remitente no tiene por que obligar a tipear la contrasena de
    nuevo — que es lo que lleva a que alguien la anote en un papel."""
    repo.save(host="smtp.test", password="secreta", from_email="a@b.com")
    repo.save(host="smtp-nuevo.test", from_email="a@b.com")  # sin password
    cfg = repo.get()
    assert cfg.host == "smtp-nuevo.test"
    assert cfg.password == "secreta"


def test_password_vacia_explicita_la_borra(repo):
    repo.save(host="smtp.test", password="secreta", from_email="a@b.com")
    repo.save(host="smtp.test", password="", from_email="a@b.com")
    assert repo.get().password == ""
    assert repo.estado()["password_definida"] is False


def test_sin_cambios_es_distinto_de_cadena_vacia():
    """Si fueran lo mismo, un formulario que no toca el campo borraria la
    contrasena en silencio."""
    assert SIN_CAMBIOS is not None
    assert SIN_CAMBIOS != ""


# ── Validacion ──────────────────────────────────────────────────────────────

def test_host_vacio_se_rechaza(repo):
    with pytest.raises(ValueError):
        repo.save(host="   ", from_email="a@b.com")


@pytest.mark.parametrize("puerto", [0, -1, 70000])
def test_puerto_invalido_se_rechaza(repo, puerto):
    with pytest.raises(ValueError):
        repo.save(host="smtp.test", port=puerto, from_email="a@b.com")


def test_sin_from_email_cae_al_usuario(repo):
    """Mismo criterio que `from_env()`: la mayoria de los proveedores exige
    que el remitente coincida con la cuenta autenticada."""
    repo.save(host="smtp.test", user="cuenta@empresa.com")
    assert repo.get().from_email == "cuenta@empresa.com"


def test_sin_clave_de_cifrado_no_guarda_nada(repo, session_factory, monkeypatch):
    """Fail-closed: antes que persistir la contrasena en claro, falla."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ClaveDeCifradoAusente):
        repo.save(host="smtp.test", password="secreta", from_email="a@b.com")
    with session_factory() as session:
        assert session.execute(text("SELECT COUNT(*) FROM smtp_settings")).scalar_one() == 0


# ── SECRET_KEY rotado ───────────────────────────────────────────────────────

def test_rotar_el_secret_key_deja_la_config_como_no_configurada(repo, monkeypatch):
    """No revienta: devuelve la config marcada, y `configurado` da False para
    que el endpoint publico responda 503 ("no configurado", que es la verdad)
    en vez de un 500 al intentar el login SMTP."""
    repo.save(host="smtp.test", password="secreta", from_email="a@b.com")
    monkeypatch.setenv("SECRET_KEY", "z" * 64)

    cfg = repo.get()
    assert cfg.password_indescifrable is True
    assert cfg.password == ""
    assert cfg.configurado is False
    assert repo.estado()["password_indescifrable"] is True


def test_config_sin_password_indescifrable_sigue_configurada(repo):
    """Control del test de arriba: sin la marca, host + remitente alcanzan."""
    repo.save(host="smtp.test", from_email="a@b.com")
    assert repo.get().configurado is True


# ── Precedencia base / entorno ──────────────────────────────────────────────

def test_sin_fila_cae_al_entorno(session_factory, monkeypatch):
    """Adoptar la v0.6.0 no cambia el comportamiento de una instancia que hoy
    usa variables de entorno."""
    monkeypatch.setenv("LIBRAAUTH_SMTP_HOST", "smtp.del-entorno")
    monkeypatch.setenv("LIBRAAUTH_SMTP_FROM_EMAIL", "env@empresa.com")
    cfg = resolver_smtp_config(session_factory)
    assert cfg.host == "smtp.del-entorno"


def test_la_base_le_gana_al_entorno(session_factory, monkeypatch):
    monkeypatch.setenv("LIBRAAUTH_SMTP_HOST", "smtp.del-entorno")
    monkeypatch.setenv("LIBRAAUTH_SMTP_FROM_EMAIL", "env@empresa.com")
    SmtpSettingsRepository(session_factory).save(
        host="smtp.de-la-base", from_email="base@empresa.com")
    assert resolver_smtp_config(session_factory).host == "smtp.de-la-base"


def test_borrar_vuelve_al_entorno(session_factory, monkeypatch):
    monkeypatch.setenv("LIBRAAUTH_SMTP_HOST", "smtp.del-entorno")
    monkeypatch.setenv("LIBRAAUTH_SMTP_FROM_EMAIL", "env@empresa.com")
    repo = SmtpSettingsRepository(session_factory)
    repo.save(host="smtp.de-la-base", from_email="base@empresa.com")
    assert repo.delete() is True
    assert resolver_smtp_config(session_factory).host == "smtp.del-entorno"
    assert repo.delete() is False


# ── El servicio la relee en cada envio ──────────────────────────────────────

def test_password_reset_relee_la_config_en_cada_pedido(session_factory):
    """Sin esto, guardar el SMTP por pantalla no tendria efecto hasta
    recrear el contenedor — o sea, el problema que la v0.6.0 viene a
    resolver."""
    from libraauth.password_reset import PasswordResetService

    servicio = PasswordResetService(
        session_factory, product_name="Test",
        reset_url_base="https://test/reset",
        smtp_config=lambda: resolver_smtp_config(session_factory),
    )
    assert servicio.smtp_config.configurado is False

    SmtpSettingsRepository(session_factory).save(
        host="smtp.test", from_email="a@b.com")

    assert servicio.smtp_config.configurado is True
    assert servicio.smtp_config.host == "smtp.test"


def test_smtp_config_sigue_siendo_asignable(session_factory):
    """Hasta la v0.5.0 `smtp_config` era un atributo comun. Convertirlo en
    property de solo lectura rompio a quien lo sobreescribia en runtime —
    `monkeypatch.setattr(servicio, "smtp_config", ...)` con
    `AttributeError: property has no setter`. Paso de verdad en las suites de
    Contalibra y Restolibra al adoptar la v0.6.0, los dos productos con
    clientes facturando. Este test fija el setter para que no vuelva.
    """
    from libraauth.email_sender import SmtpConfig
    from libraauth.password_reset import PasswordResetService

    servicio = PasswordResetService(
        session_factory, product_name="Test",
        reset_url_base="https://test/reset",
        smtp_config=lambda: resolver_smtp_config(session_factory),
    )
    fija = SmtpConfig(host="inyectada.test", from_email="a@b.com")
    servicio.smtp_config = fija          # <- esto es lo que rompia

    assert servicio.smtp_config is fija
    # Y se puede volver a un callable.
    servicio.smtp_config = lambda: SmtpConfig(host="otra.test", from_email="a@b.com")
    assert servicio.smtp_config.host == "otra.test"


def test_smtp_config_se_puede_monkeypatchear(session_factory, monkeypatch):
    """El caso exacto que rompio, con la herramienta que lo rompio."""
    from libraauth.email_sender import SmtpConfig
    from libraauth.password_reset import PasswordResetService

    servicio = PasswordResetService(
        session_factory, product_name="Test", reset_url_base="https://test/reset")
    monkeypatch.setattr(servicio, "smtp_config",
                        SmtpConfig(host="smtp.suite.test", from_email="noreply@suite.test"))
    assert servicio.smtp_config.configurado is True


def test_password_reset_sigue_aceptando_una_config_fija(session_factory):
    """Compatibilidad con lo que hacian los consumidores hasta la v0.5.0."""
    from libraauth.email_sender import SmtpConfig
    from libraauth.password_reset import PasswordResetService

    fija = SmtpConfig(host="fijo.test", from_email="a@b.com")
    servicio = PasswordResetService(
        session_factory, product_name="Test",
        reset_url_base="https://test/reset", smtp_config=fija)
    assert servicio.smtp_config is fija


# ── Router de backoffice ────────────────────────────────────────────────────

class _UsersFalso:
    def __init__(self, user):
        self._user = user

    def get_by_username(self, username):
        return self._user


class _SessionAuthFalso:
    def __init__(self, username):
        self._username = username

    def get_current_user(self, request):
        return self._username


def _app(session_factory, *, rol="admin", logueado=True):
    app = FastAPI()
    app.state.smtp_settings = SmtpSettingsRepository(session_factory)
    app.state.session_auth = _SessionAuthFalso("admin1" if logueado else None)
    app.state.users = _UsersFalso(
        {"id": "1", "username": "admin1", "name": "Admin",
         "role": rol, "active": True}
    )
    app.include_router(build_smtp_settings_router())
    return TestClient(app)


def test_get_no_devuelve_la_contrasena(session_factory):
    """El test central del router."""
    SmtpSettingsRepository(session_factory).save(
        host="smtp.test", user="cuenta", password="hunter2",
        from_email="a@b.com")

    r = _app(session_factory).get("/admin/smtp")

    assert r.status_code == 200
    assert "hunter2" not in r.text
    body = r.json()
    assert body["password_definida"] is True
    assert "password" not in body
    assert (body["origen"], body["host"], body["user"]) == ("base", "smtp.test", "cuenta")


def test_put_guarda_y_tampoco_devuelve_la_contrasena(session_factory):
    r = _app(session_factory).put("/admin/smtp", json={
        "host": "smtp.test", "port": 2525, "user": "cuenta",
        "password": "hunter2", "from_email": "a@b.com", "from_name": "Soporte",
    })

    assert r.status_code == 200
    assert "hunter2" not in r.text
    assert r.json()["password_definida"] is True
    assert SmtpSettingsRepository(session_factory).get().password == "hunter2"


def test_put_sin_el_campo_password_conserva_la_guardada(session_factory):
    """La distincion que hace `model_fields_set`: omitir != mandar vacio."""
    SmtpSettingsRepository(session_factory).save(
        host="smtp.test", password="secreta", from_email="a@b.com")

    r = _app(session_factory).put("/admin/smtp", json={
        "host": "smtp-nuevo.test", "from_email": "a@b.com"})

    assert r.status_code == 200
    cfg = SmtpSettingsRepository(session_factory).get()
    assert (cfg.host, cfg.password) == ("smtp-nuevo.test", "secreta")


def test_put_con_password_null_la_borra(session_factory):
    SmtpSettingsRepository(session_factory).save(
        host="smtp.test", password="secreta", from_email="a@b.com")

    r = _app(session_factory).put("/admin/smtp", json={
        "host": "smtp.test", "from_email": "a@b.com", "password": None})

    assert r.status_code == 200
    assert r.json()["password_definida"] is False


def test_put_con_host_vacio_da_422(session_factory):
    r = _app(session_factory).put("/admin/smtp", json={"host": "  "})
    assert r.status_code == 422


def test_put_sin_clave_de_cifrado_da_500_y_no_guarda(session_factory, monkeypatch, tmp_path):
    """500 y no 422: no es un error de quien manda el formulario, es que a la
    instancia le falta el secreto del entorno. Lo que importa del test es la
    segunda mitad — que no quede nada guardado."""
    monkeypatch.delenv("SECRET_KEY", raising=False)

    r = _app(session_factory).put("/admin/smtp", json={
        "host": "smtp.test", "password": "secreta", "from_email": "a@b.com"})

    assert r.status_code == 500
    assert SmtpSettingsRepository(session_factory).get() is None


def test_delete_vuelve_al_entorno(session_factory):
    SmtpSettingsRepository(session_factory).save(
        host="smtp.de-la-base", from_email="a@b.com")

    r = _app(session_factory).delete("/admin/smtp")

    assert r.status_code == 200
    assert r.json()["origen"] == "entorno"
    assert SmtpSettingsRepository(session_factory).get() is None


@pytest.mark.parametrize("metodo", ["get", "put", "delete"])
def test_todo_exige_admin(session_factory, metodo):
    """Quien pueda escribir aca puede redirigir a donde salen los enlaces de
    recuperacion de contrasena de todos los usuarios."""
    client = _app(session_factory, rol="staff")
    kwargs = {"json": {"host": "smtp.test"}} if metodo == "put" else {}
    assert getattr(client, metodo)("/admin/smtp", **kwargs).status_code == 403


@pytest.mark.parametrize("metodo", ["get", "put", "delete"])
def test_sin_sesion_da_401(session_factory, metodo):
    client = _app(session_factory, logueado=False)
    kwargs = {"json": {"host": "smtp.test"}} if metodo == "put" else {}
    assert getattr(client, metodo)("/admin/smtp", **kwargs).status_code == 401


def test_prefijo_configurable(session_factory):
    """Los consumidores no montan sus APIs igual: los 4 FastAPI cuelgan de
    `/api`."""
    app = FastAPI()
    app.state.smtp_settings = SmtpSettingsRepository(session_factory)
    app.state.session_auth = _SessionAuthFalso("admin1")
    app.state.users = _UsersFalso(
        {"id": "1", "username": "admin1", "name": "A", "role": "admin", "active": True})
    app.include_router(build_smtp_settings_router(prefix="/api/config/smtp"))

    client = TestClient(app)
    assert client.get("/api/config/smtp").status_code == 200
    assert client.get("/admin/smtp").status_code == 404
