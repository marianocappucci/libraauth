"""
Hashing de contrasenas: **argon2id**, con verificacion de los hashes PBKDF2
viejos y **re-hash al login**.

Hasta la v0.37.0 esto era PBKDF2-HMAC-SHA256 con 260.000 iteraciones. PBKDF2 se
defiende del atacante gastandole *tiempo de CPU*, y contra una GPU o un ASIC eso
es justo lo barato: el mismo presupuesto compra ordenes de magnitud mas intentos
por segundo que contra un algoritmo que ademas gasta *memoria*. Argon2id gasta
las dos cosas, y es lo que recomienda OWASP para contrasenas nuevas.

**Los parametros son los del piso recomendado por OWASP para argon2id**
(19 MiB, 2 pasadas, 1 hilo) y no los defaults de la libreria (64 MiB, 4 hilos), a
proposito: en este parque conviven doce instancias en un VPS chico, y 64 MiB por
login concurrente es memoria que se le saca a PostgreSQL. El piso de OWASP sigue
estando muy por encima de PBKDF2.

## La migracion no pide resetear ninguna contrasena

`verify_password` acepta los dos formatos, y `needs_rehash` dice cuando el hash
guardado quedo viejo. Quien valide un login exitoso re-hashea y guarda — ver
`UserRepository.check_credentials`. Una contrasena vieja se migra sola la
proxima vez que su dueno entra; una que nadie usa se queda en PBKDF2, que es
peor que argon2 pero no es una puerta abierta.

> ⚠️ **El hash señuelo tiene una ventana, y conviene decirla.** `DUMMY_PASSWORD_HASH`
> es argon2, o sea que un usuario **inexistente** cuesta lo que cuesta argon2.
> Mientras queden usuarios con hash PBKDF2 sin migrar, verificar contra ellos
> cuesta otra cosa, y esa diferencia es medible: dice "este usuario existe y
> todavia no entro desde el cambio". Es una fuga mas debil que la que el señuelo
> venia a tapar —que era "este usuario no existe"— y se cierra sola a medida que
> la gente entra. Igualar los dos costos exigiria hacer el señuelo PBKDF2, que
> es dejar el hueco abierto para siempre del otro lado.
"""
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError

#: Piso recomendado por OWASP para argon2id. Ver el docstring del modulo para
#: por que no son los defaults de argon2-cffi.
_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)

#: Iteraciones del formato viejo. Se conserva **exacto**: cambiarlo invalidaria
#: todos los hashes PBKDF2 que todavia no se migraron, que es lo mismo que
#: resetearle la contrasena a esa gente sin avisarle.
_PBKDF2_ITERACIONES = 260_000

_PREFIJO_PBKDF2 = "pbkdf2:"
_PREFIJO_ARGON2 = "$argon2"


def hash_password(password: str) -> str:
    """El formato nuevo. Nada escribe PBKDF2 desde la v0.37.0."""
    return _HASHER.hash(password)


def _verify_pbkdf2(stored: str, provided: str) -> bool:
    try:
        _, algo, salt, stored_hash = stored.split(":")
        dk = hashlib.pbkdf2_hmac(algo, provided.encode(), salt.encode(), _PBKDF2_ITERACIONES)
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False


def verify_password(stored: str, provided: str) -> bool:
    """Acepta los dos formatos. Un hash ilegible es `False`, no una excepcion:
    quien llama esta en el camino del login y no puede distinguir entre "la
    clave esta mal" y "la fila esta corrupta" sin filtrar cual de las dos es."""
    if not stored:
        return False
    if stored.startswith(_PREFIJO_ARGON2):
        try:
            return _HASHER.verify(stored, provided)
        except Exception:
            # Amplio a proposito: `verify` levanta VerifyMismatchError con la
            # clave equivocada, InvalidHashError con una fila corrupta y
            # VerificationError con parametros que no puede reconstruir. Las
            # tres son "no entra", y distinguirlas aca seria filtrar cual paso.
            return False
    if stored.startswith(_PREFIJO_PBKDF2):
        return _verify_pbkdf2(stored, provided)
    return False


def needs_rehash(stored: str) -> bool:
    """Si el hash guardado quedo viejo — otro algoritmo, u otros parametros.

    Solo tiene sentido llamarla **despues** de que `verify_password` haya dado
    `True`: re-hashear necesita la contrasena en claro, y la unica vez que se
    la tiene es en un login exitoso.
    """
    if not stored:
        return False
    if stored.startswith(_PREFIJO_ARGON2):
        try:
            return _HASHER.check_needs_rehash(stored)
        except InvalidHashError:
            return True
    return True


# Hash señuelo, del mismo costo que uno real — se verifica contra este cuando el
# username no existe, para que `UserRepository.check_credentials` tarde lo mismo
# con usuario inexistente que con password incorrecta (mitiga la enumeracion de
# usuarios por tiempo). Se genera una sola vez al importar, no en cada request.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(16))
