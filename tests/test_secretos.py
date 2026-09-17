"""Tests del almacen de secretos de instancia (v0.39.0).

Lo que estos tests existen para fijar, en orden de importancia:

1. **En la base no queda el valor en claro.** Es la razon entera por la que
   estos tres secretos se mudaron de `config.json` a esta tabla, asi que el
   test mira el archivo `.db` **crudo**, no el valor que devuelve el
   repositorio. Un assert contra `repo.get()` pasaria igual con una
   implementacion que no cifrara nada.
2. **Rotar `SECRET_KEY` degrada, no revienta** — y `estado()` lo dice, que es
   la mitad que en `config.json` no existia.
3. **`recifrar()` no se detiene en una fila ilegible**, y no la pisa.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth.crypto import CLAVES_ANTERIORES, ClaveDeCifradoAusente
from libraauth.models import Base, SecretoInstancia
from libraauth.secretos import SecretosRepository

#: Un token con la forma real de uno de MercadoPago. Importa que sea largo y
#: distintivo: es lo que se busca dentro del archivo de la base.
TOKEN = "APP_USR-1234567890123456-091712-abcdef0123456789abcdef0123456789-3392230021"
CLAVE_VIEJA = "v" * 64
CLAVE_NUEVA = "n" * 64


@pytest.fixture(autouse=True)
def _entorno(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", CLAVE_VIEJA)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv(CLAVES_ANTERIORES, raising=False)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "secretos_test.db"


@pytest.fixture
def session_factory(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def repo(session_factory):
    return SecretosRepository(session_factory)


# ── Lo minimo ───────────────────────────────────────────────────────────────

def test_sin_nada_guardado_devuelve_vacio(repo):
    assert repo.get("mp_access_token") == ""
    assert repo.leer("mp_access_token") == ("", True)
    assert repo.claves_cargadas() == []
    assert repo.estado() == {}


def test_ida_y_vuelta(repo):
    repo.set("mp_access_token", TOKEN)
    assert repo.get("mp_access_token") == TOKEN
    assert repo.claves_cargadas() == ["mp_access_token"]


def test_sobreescribir(repo):
    repo.set("mp_access_token", TOKEN)
    repo.set("mp_access_token", "otro-token")
    assert repo.get("mp_access_token") == "otro-token"
    # Una sola fila, no dos: la clave es la PK.
    with repo.session_factory() as s:
        assert s.query(SecretoInstancia).count() == 1


def test_las_claves_no_se_pisan(repo):
    repo.set("mp_access_token", TOKEN)
    repo.set("mp_webhook_secret", "firma-del-webhook")
    repo.set("email_smtp_password", "la-contrasena-del-correo")
    assert repo.get("mp_access_token") == TOKEN
    assert repo.get("mp_webhook_secret") == "firma-del-webhook"
    assert repo.get("email_smtp_password") == "la-contrasena-del-correo"
    assert repo.claves_cargadas() == [
        "email_smtp_password", "mp_access_token", "mp_webhook_secret",
    ]


def test_vacio_borra_la_fila(repo):
    repo.set("mp_access_token", TOKEN)
    repo.set("mp_access_token", "")
    assert repo.get("mp_access_token") == ""
    # 🔑 No queda una fila con el blob vacio: "sin credencial" tiene que verse
    # igual que "nunca hubo una" para cualquier barrido que cuente filas.
    assert repo.estado() == {}
    with repo.session_factory() as s:
        assert s.query(SecretoInstancia).count() == 0


def test_delete_dice_si_habia_algo(repo):
    assert repo.delete("mp_access_token") is False
    repo.set("mp_access_token", TOKEN)
    assert repo.delete("mp_access_token") is True
    assert repo.delete("mp_access_token") is False


@pytest.mark.parametrize("clave", ["", "   ", None])
def test_clave_vacia_se_rechaza(repo, clave):
    with pytest.raises(ValueError):
        repo.set(clave, TOKEN)


def test_clave_demasiado_larga_se_rechaza(repo):
    with pytest.raises(ValueError):
        repo.set("x" * 101, TOKEN)


# ── Lo que de verdad importa: en la base no hay texto plano ─────────────────

def test_el_token_no_queda_en_claro_en_el_archivo(repo, db_path):
    """🔑 El test que justifica todo el cambio.

    Mira los **bytes del archivo**, no lo que devuelve el repositorio. Un
    assert sobre `repo.get()` da verde con una implementacion que guarde el
    token tal cual, que es exactamente lo que hacia `config.json`.

    El control positivo esta abajo: el mismo barrido **si** encuentra el nombre
    de la clave, asi que no esta leyendo un archivo vacio ni buscando mal.
    """
    repo.set("mp_access_token", TOKEN)
    crudo = db_path.read_bytes()
    assert TOKEN.encode() not in crudo
    # Control positivo del mismo barrido, sobre el mismo archivo.
    assert b"mp_access_token" in crudo
    # Y lo que si esta es el blob versionado.
    assert b"v1:" in crudo


def test_el_mismo_secreto_dos_veces_da_blobs_distintos(repo):
    """El nonce es aleatorio: dos instancias con la misma contrasena SMTP no
    tienen por que poder reconocerse mirando la base."""
    repo.set("a", TOKEN)
    repo.set("b", TOKEN)
    with repo.session_factory() as s:
        blob_a = s.get(SecretoInstancia, "a").valor_cifrado
        blob_b = s.get(SecretoInstancia, "b").valor_cifrado
    assert blob_a != blob_b
    assert repo.get("a") == repo.get("b") == TOKEN


def test_estado_no_filtra_el_valor_ni_su_largo(repo):
    repo.set("mp_access_token", TOKEN)
    est = repo.estado()["mp_access_token"]
    plano = repr(est)
    assert TOKEN not in plano
    assert str(len(TOKEN)) not in plano
    assert est["cargado"] is True
    assert est["legible"] is True
    assert est["al_dia"] is True


def test_sin_clave_de_cifrado_no_se_guarda_en_claro(repo, monkeypatch, db_path):
    """Sin `SECRET_KEY` en produccion, `set` lanza — y **no** deja el secreto
    guardado de ninguna forma. Guardarlo en claro "porque no habia con que
    cifrar" seria justo lo que este modulo existe para impedir."""
    repo.set("mp_access_token", TOKEN)
    monkeypatch.delenv("SECRET_KEY")
    monkeypatch.setenv("ENV", "production")
    with pytest.raises(ClaveDeCifradoAusente):
        repo.set("mp_access_token", "token-nuevo-en-claro")
    assert b"token-nuevo-en-claro" not in db_path.read_bytes()
    # Y la fila vieja quedo como estaba: un `set` que falla no destruye lo
    # anterior.
    monkeypatch.setenv("SECRET_KEY", CLAVE_VIEJA)
    assert repo.get("mp_access_token") == TOKEN


# ── Rotacion de SECRET_KEY ─────────────────────────────────────────────────

def test_rotar_sin_declarar_la_anterior_degrada_pero_no_revienta(repo, monkeypatch):
    repo.set("mp_access_token", TOKEN)
    monkeypatch.setenv("SECRET_KEY", CLAVE_NUEVA)

    # La app sigue levantando: "sin credencial configurada", que es la verdad.
    assert repo.get("mp_access_token") == ""
    # Pero se distingue de "no hay nada guardado" —
    assert repo.leer("mp_access_token") == ("", False)
    # — y la sonda lo puede ver, que es la mitad que en config.json no existia.
    est = repo.estado()["mp_access_token"]
    assert est["cargado"] is True
    assert est["legible"] is False


def test_declarar_la_anterior_permite_leer_y_recifrar(repo, monkeypatch):
    repo.set("mp_access_token", TOKEN)
    monkeypatch.setenv("SECRET_KEY", CLAVE_NUEVA)
    monkeypatch.setenv(CLAVES_ANTERIORES, CLAVE_VIEJA)

    # Se lee, pero la rotacion NO esta cerrada.
    assert repo.get("mp_access_token") == TOKEN
    assert repo.estado()["mp_access_token"] == {
        **repo.estado()["mp_access_token"], "legible": True, "al_dia": False,
    }

    informe = repo.recifrar()
    assert informe["recifradas"] == ["mp_access_token"]
    assert repo.estado()["mp_access_token"]["al_dia"] is True

    # Recien ahora se puede sacar la variable de transicion sin perder nada.
    monkeypatch.delenv(CLAVES_ANTERIORES)
    assert repo.get("mp_access_token") == TOKEN


def test_recifrar_es_idempotente(repo):
    repo.set("mp_access_token", TOKEN)
    with repo.session_factory() as s:
        antes = s.get(SecretoInstancia, "mp_access_token").valor_cifrado
    informe = repo.recifrar()
    assert informe["recifradas"] == []
    assert informe["al_dia"] == ["mp_access_token"]
    with repo.session_factory() as s:
        assert s.get(SecretoInstancia, "mp_access_token").valor_cifrado == antes


def test_recifrar_no_se_detiene_en_una_fila_ilegible(repo, monkeypatch):
    """🔑 La diferencia con `SmtpSettingsRepository.recifrar()`, que si lanza.

    Aca hay N filas: cortar en la primera ilegible dejaria sin cerrar la
    rotacion de todas las sanas. Y la ilegible **no se toca** — pisarla seria
    destruir el unico rastro de lo que habia.
    """
    repo.set("sana", TOKEN)
    # Una fila cifrada con una clave que despues no se va a declarar.
    monkeypatch.setenv("SECRET_KEY", "z" * 64)
    repo.set("perdida", "secreto-de-otra-clave")
    with repo.session_factory() as s:
        blob_perdido = s.get(SecretoInstancia, "perdida").valor_cifrado

    monkeypatch.setenv("SECRET_KEY", CLAVE_NUEVA)
    monkeypatch.setenv(CLAVES_ANTERIORES, CLAVE_VIEJA)

    informe = repo.recifrar()
    assert informe["recifradas"] == ["sana"]
    assert informe["indescifrables"] == ["perdida"]

    # La sana quedo al dia…
    monkeypatch.delenv(CLAVES_ANTERIORES)
    assert repo.get("sana") == TOKEN
    # …y la perdida quedo intacta, byte por byte.
    with repo.session_factory() as s:
        assert s.get(SecretoInstancia, "perdida").valor_cifrado == blob_perdido


def test_recifrar_sin_nada_guardado_no_hace_nada(repo):
    assert repo.recifrar() == {"recifradas": [], "al_dia": [], "indescifrables": []}
