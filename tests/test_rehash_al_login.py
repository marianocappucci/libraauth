"""El re-hash al entrar: la mitad que hace que la migracion realmente ocurra.

Sin esto, pasar a argon2 alcanzaria solo a las contrasenas creadas despues del
cambio. Las de la gente que ya existe se quedarian en PBKDF2 para siempre, y el
cambio de algoritmo seria una linea en el CHANGELOG y nada mas.
"""
import hashlib
import secrets

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from libraauth.models import Base, Usuario
from libraauth.repository import UserRepository

CLAVE = "clave-del-usuario-viejo"


def _hash_pbkdf2_como_antes(password: str) -> str:
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


@pytest.fixture
def repo_y_sesion(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/rehash.db")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    return UserRepository(session_factory), session_factory


def _hash_guardado(session_factory, username):
    with session_factory() as s:
        return s.execute(
            select(Usuario.password_hash).where(Usuario.username == username)
        ).scalar_one()


def test_un_login_valido_migra_el_hash_viejo_a_argon2(repo_y_sesion):
    repo, session_factory = repo_y_sesion
    repo.create(username="vieja", name="Usuaria vieja", password="da-igual", role="staff")

    # Se pisa la fila con el formato que tienen hoy las instancias vivas.
    with session_factory() as s:
        u = s.execute(select(Usuario).where(Usuario.username == "vieja")).scalar_one()
        u.password_hash = _hash_pbkdf2_como_antes(CLAVE)
        s.commit()
    assert _hash_guardado(session_factory, "vieja").startswith("pbkdf2:")

    assert repo.check_credentials("vieja", CLAVE) is not None

    migrado = _hash_guardado(session_factory, "vieja")
    assert migrado.startswith("$argon2id$"), migrado[:40]
    # Y la clave sigue siendo la misma: se re-hasheo, no se cambio.
    assert repo.check_credentials("vieja", CLAVE) is not None


def test_un_login_FALLIDO_no_toca_el_hash(repo_y_sesion):
    """La contraprueba. Si el re-hash corriera antes de validar, una clave
    equivocada reescribiria la fila — y eso es cambiarle la contrasena a
    alguien desde la pantalla de login."""
    repo, session_factory = repo_y_sesion
    repo.create(username="vieja", name="Usuaria vieja", password="da-igual", role="staff")
    viejo = _hash_pbkdf2_como_antes(CLAVE)
    with session_factory() as s:
        u = s.execute(select(Usuario).where(Usuario.username == "vieja")).scalar_one()
        u.password_hash = viejo
        s.commit()

    assert repo.check_credentials("vieja", "la-equivocada") is None
    assert _hash_guardado(session_factory, "vieja") == viejo


def test_un_hash_ya_nuevo_no_se_reescribe(repo_y_sesion):
    """No hay churn: entrar mil veces no reescribe la fila mil veces."""
    repo, session_factory = repo_y_sesion
    repo.create(username="nueva", name="Usuaria nueva", password=CLAVE, role="staff")
    antes = _hash_guardado(session_factory, "nueva")
    assert antes.startswith("$argon2id$")

    assert repo.check_credentials("nueva", CLAVE) is not None
    assert _hash_guardado(session_factory, "nueva") == antes


def test_un_usuario_inexistente_no_explota_ni_escribe(repo_y_sesion):
    repo, _ = repo_y_sesion
    assert repo.check_credentials("no-existe", CLAVE) is None
