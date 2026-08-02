"""
Cifrado en reposo de los secretos que este motor guarda en la base del
producto (hoy: la contrasena SMTP de `smtp_settings`).

**Por que existe.** La decision del 2026-08-01 fue que la configuracion SMTP
viva entera en la base del cliente, contrasena incluida, para que se pueda
editar por backoffice sin tocar el compose ni recrear el contenedor. Eso
convierte a esa contrasena en un secreto en reposo: entra en **todos** los
backups de la instancia y en cualquier copia de la base a dev. Cifrarla con
una clave que vive en el ENTORNO es lo que hace que el archivo `.db` por si
solo no alcance para mandar correo en nombre del cliente.

**De donde sale la clave.** Por defecto se DERIVA del `SECRET_KEY` que la
instancia ya tiene (el mismo que firma la cookie de sesion), con HKDF y un
`info` fijo. Derivar y no reusar importa: la clave que sale de aca es
distinta de la que usa `itsdangerous`, asi que un problema en un uso no se
traslada al otro. Y derivarla en vez de pedir una variable nueva es
deliberado — las 4 instancias de cliente ya tienen `SECRET_KEY`, mientras que
una variable nueva habria que agregarla a cada compose del VPS antes de que
nada funcione, que es exactamente la forma en que esta familia ya se comio un
bug (el `RESET_URL_BASE` de LibraDesk que quedo apuntando a dev porque el
compose del cliente no se toco).

Para separarlas del todo mas adelante, `LIBRAAUTH_ENCRYPTION_KEY` tiene
prioridad sobre `SECRET_KEY` si esta definida.

**Consecuencia que hay que conocer**: si se rota el `SECRET_KEY` de una
instancia, lo guardado deja de poder descifrarse. No se pierde nada mas que
esa contrasena y se vuelve a cargar por pantalla; el codigo que lee lo trata
como "sin configurar" en vez de reventar (ver `smtp_settings.py`).
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Marca de version del formato. Va adelante del blob para que un cambio
# futuro de algoritmo se pueda detectar leyendo el valor, en vez de fallar
# como si la clave estuviera mal.
_PREFIJO = "v1:"

# `info` de HKDF: fija el proposito de la clave derivada. Cambiarlo invalida
# todo lo cifrado hasta ahora, asi que no se toca sin una migracion.
_INFO = b"libraauth/cifrado-en-reposo/v1"

# AES-GCM con nonce de 96 bits, que es el tamano recomendado para este modo.
_NONCE_BYTES = 12


class ClaveDeCifradoAusente(RuntimeError):
    """No hay ni `LIBRAAUTH_ENCRYPTION_KEY` ni `SECRET_KEY` en el entorno.

    Se lanza al intentar **guardar** un secreto, no al arrancar: una
    instancia sin SMTP configurado tiene que poder levantar igual, y el
    unico momento en que la falta de clave es un problema real es cuando
    hay algo que cifrar.
    """


class SecretoIndescifrable(Exception):
    """El valor guardado no se puede descifrar con la clave actual.

    El caso realista no es un ataque: es que se roto el `SECRET_KEY` de la
    instancia. Quien llama decide que hacer — `smtp_settings` lo trata como
    "sin configurar" para que la app siga levantando.
    """


# Fallback SOLO para ENV=development, misma convencion que
# `session_auth._resolve_secret_key`. Ver `_material_de_clave`.
_DEV_FALLBACK = "libraauth-dev-encryption-key-no-usar-en-produccion"


def _material_de_clave() -> bytes:
    """El secreto crudo del entorno, sin derivar todavia.

    **Por que hay un fallback de desarrollo y por que no debilita nada.** Sin
    el, cualquier entorno local o suite de tests que no exporte `SECRET_KEY`
    —que es el caso de los 6 productos de la familia, que corren con
    `ENV=development`— recibia un 500 al guardar la config SMTP. Y no se puede
    colar en produccion: `session_auth._resolve_secret_key` **no deja levantar
    la app** sin `SECRET_KEY` salvo con `ENV=development`, asi que una
    instancia productiva que llegue aca ya tiene un secreto propio. Si alguien
    pusiera `ENV=development` en produccion, el problema grave seria que las
    cookies de sesion se pueden falsificar, no esta clave.
    """
    explicita = os.environ.get("LIBRAAUTH_ENCRYPTION_KEY", "")
    if explicita:
        return explicita.encode()
    secret = os.environ.get("SECRET_KEY", "")
    if secret:
        return secret.encode()
    if os.environ.get("ENV", "production") == "development":
        return _DEV_FALLBACK.encode()
    raise ClaveDeCifradoAusente(
        "No hay con que cifrar: falta LIBRAAUTH_ENCRYPTION_KEY o SECRET_KEY "
        "en el entorno de la instancia."
    )


def clave_de_cifrado() -> bytes:
    """32 bytes derivados por HKDF-SHA256 del secreto del entorno.

    Sin `salt` a proposito: el salt tendria que persistirse en algun lado
    para poder derivar la misma clave en el proximo arranque, y ese lugar
    seria la misma base que se esta protegiendo. HKDF sin salt sigue siendo
    correcto — el material de entrada ya es un secreto de alta entropia
    (los `SECRET_KEY` de esta familia son 64 caracteres hex).
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO
    ).derive(_material_de_clave())


def cifrar(texto: str) -> str:
    """Devuelve `v1:<base64(nonce || ciphertext || tag)>`.

    El nonce es aleatorio y va adelante: cifrar dos veces el mismo texto da
    dos valores distintos, asi que nadie puede deducir mirando la base que
    dos instancias comparten la misma contrasena SMTP.
    """
    if texto == "":
        # Un secreto vacio se guarda vacio: cifrar "" daria un blob que
        # parece un valor cargado, y despues habria que descifrarlo para
        # descubrir que no habia nada.
        return ""
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(clave_de_cifrado()).encrypt(nonce, texto.encode(), None)
    return _PREFIJO + base64.b64encode(nonce + ct).decode()


def descifrar(blob: str) -> str:
    """Inversa de `cifrar`. Lanza `SecretoIndescifrable` si el valor esta
    corrupto, fue cifrado con otra clave, o tiene un formato que esta version
    no conoce."""
    if not blob:
        return ""
    if not blob.startswith(_PREFIJO):
        raise SecretoIndescifrable(
            "El valor guardado no tiene el formato esperado "
            f"(no empieza con {_PREFIJO!r})."
        )
    try:
        crudo = base64.b64decode(blob[len(_PREFIJO):], validate=True)
    except Exception as exc:
        raise SecretoIndescifrable("El valor guardado no es base64 valido.") from exc
    if len(crudo) <= _NONCE_BYTES:
        raise SecretoIndescifrable("El valor guardado esta truncado.")
    nonce, ct = crudo[:_NONCE_BYTES], crudo[_NONCE_BYTES:]
    try:
        return AESGCM(clave_de_cifrado()).decrypt(nonce, ct, None).decode()
    except InvalidTag as exc:
        # El caso realista: se roto el SECRET_KEY de la instancia.
        raise SecretoIndescifrable(
            "No se puede descifrar con la clave actual. Lo mas probable es "
            "que se haya rotado el SECRET_KEY de esta instancia; hay que "
            "volver a cargar la contrasena por pantalla."
        ) from exc
