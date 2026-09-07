"""argon2id, y la migracion de los hashes PBKDF2 viejos al entrar.

Lo que este archivo cuida no es "argon2 funciona" —eso lo cuida argon2-cffi—
sino las dos mitades que son nuestras:

1. Que un hash **viejo** siga entrando. Si esto se rompe, el dia del deploy
   nadie puede loguearse y no hay vuelta atras que no sea resetear contrasenas.
2. Que ese login **migre** la fila. Sin la migracion, el cambio de algoritmo
   solo alcanza a las contrasenas creadas despues, y las de la gente que ya
   existe se quedan en PBKDF2 para siempre — que es como se vuelve permanente
   una decision que se creia transitoria.
"""
import hashlib
import secrets

import pytest

from libraauth.hashing import (
    DUMMY_PASSWORD_HASH,
    hash_password,
    needs_rehash,
    verify_password,
)

CLAVE = "una-clave-de-prueba-123"


def _hash_pbkdf2_como_antes(password: str) -> str:
    """El formato exacto que escribia `hash_password` hasta la v0.36.0.

    Se reimplementa aca en vez de importarlo: el codigo viejo ya no existe, y
    esto es lo que hay en la columna `password_hash` de las instancias vivas.
    """
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


def test_el_formato_nuevo_es_argon2id():
    h = hash_password(CLAVE)
    assert h.startswith("$argon2id$"), h[:40]
    assert "m=19456" in h and "t=2" in h and "p=1" in h, h[:60]


def test_argon2_verifica_y_rechaza():
    h = hash_password(CLAVE)
    assert verify_password(h, CLAVE) is True
    assert verify_password(h, CLAVE + "x") is False


def test_el_hash_viejo_de_pbkdf2_SIGUE_entrando():
    """La mitad que, si falla, deja a todo el parque afuera."""
    viejo = _hash_pbkdf2_como_antes(CLAVE)
    assert verify_password(viejo, CLAVE) is True
    assert verify_password(viejo, CLAVE + "x") is False


def test_needs_rehash_distingue_los_dos_formatos():
    assert needs_rehash(_hash_pbkdf2_como_antes(CLAVE)) is True
    assert needs_rehash(hash_password(CLAVE)) is False


@pytest.mark.parametrize("basura", ["", "no-es-un-hash", "pbkdf2:roto", "$argon2id$roto"])
def test_un_hash_ilegible_es_false_y_no_excepcion(basura):
    """En el camino del login, una fila corrupta no puede ser un 500."""
    assert verify_password(basura, CLAVE) is False


def test_el_señuelo_es_del_formato_nuevo():
    """Si el señuelo quedara en PBKDF2, el costo de un usuario inexistente
    delataria el cambio de algoritmo en vez de taparlo."""
    assert DUMMY_PASSWORD_HASH.startswith("$argon2id$")


def test_dos_hashes_de_la_misma_clave_son_distintos():
    """Control de que hay salt: sin el, dos filas iguales se ven iguales."""
    assert hash_password(CLAVE) != hash_password(CLAVE)
