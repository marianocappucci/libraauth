"""
Hashing de contrasenas (PBKDF2), portado de `libracore.db.usuarios` sin
cambios de algoritmo — mismos parametros (260k iteraciones, salt de 32
bytes) para que una migracion futura de contrasenas existentes no
requiera resetearlas.
"""
import hashlib
import hmac
import secrets


def hash_password(password: str) -> str:
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


def verify_password(stored: str, provided: str) -> bool:
    try:
        _, algo, salt, stored_hash = stored.split(":")
        dk = hashlib.pbkdf2_hmac(algo, provided.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False


# Hash señuelo, mismo costo (260k iteraciones PBKDF2) que uno real — se
# verifica contra este cuando el username no existe, para que
# `UserRepository.check_credentials` tarde lo mismo con usuario inexistente
# que con password incorrecta (mitiga timing attack de enumeracion de
# usuarios). Generado una sola vez al importar el modulo, no en cada
# request.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(16))
