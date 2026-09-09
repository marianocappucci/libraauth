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
instancia, lo guardado deja de poder descifrarse. El codigo que lee lo trata
como "sin configurar" en vez de reventar (ver `smtp_settings.py`).

🔑 **Y por eso existe `LIBRAAUTH_CLAVES_ANTERIORES`.** Declarando ahi el valor
viejo, una rotacion deja de ser una perdida: se sigue leyendo lo guardado, se
`recifrar()` con la clave nueva, y recien despues se saca la variable. Sin ese
camino, rotar significaba destruir credenciales de terceros —paso el 2026-09-07
con tres de ellas— y una medida de seguridad que rompe cosas termina siendo un
argumento para no tomarla.

**Cifrar usa siempre la vigente.** Las anteriores sirven para leer y nada mas.
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
    """El valor guardado no se puede descifrar con ninguna clave conocida.

    El caso realista no es un ataque: es que se roto el `SECRET_KEY` de la
    instancia **sin declarar el anterior** en `LIBRAAUTH_CLAVES_ANTERIORES`.
    Quien llama decide que hacer — `smtp_settings` lo trata como "sin
    configurar" para que la app siga levantando.
    """


#: Valores ANTERIORES del material de clave, separados por coma. Existe para
#: que rotar `SECRET_KEY` deje de destruir lo que ya estaba cifrado.
#:
#: 🔴 **Por que hizo falta.** El 2026-09-07 se roto el `SECRET_KEY` de cinco
#: instancias como respuesta a un incidente y quedaron ilegibles tres
#: credenciales de terceros. El comportamiento era el buscado —que un respaldo
#: por si solo no alcance para recuperarlas— pero convertia cada rotacion en una
#: perdida silenciosa, que en la practica es un argumento para no rotar.
#:
#: **Es transitoria, no permanente.** El ciclo es: rotar, declarar el valor
#: viejo aca, `recifrar()` lo guardado, y **sacar la variable**. Mientras siga
#: puesta, la clave vieja sigue alcanzando para leer la base: la rotacion
#: todavia no termino. Por eso `descifrar_al_dia()` informa si el valor vino de
#: una clave anterior — es lo que permite auditar que el ciclo se haya cerrado,
#: en vez de confiar en que alguien se acuerde.
CLAVES_ANTERIORES = "LIBRAAUTH_CLAVES_ANTERIORES"


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


def _materiales_anteriores() -> list[bytes]:
    """Los valores viejos declarados en `LIBRAAUTH_CLAVES_ANTERIORES`.

    Se ignoran los vacios: `"a,,b"` y `" , "` son formas normales de quedar
    despues de editar la variable a mano, y una cadena vacia derivaria una
    clave perfectamente valida que no es la de nadie.
    """
    crudo = os.environ.get(CLAVES_ANTERIORES, "")
    vistos: list[bytes] = []
    for parte in crudo.split(","):
        limpio = parte.strip()
        if limpio and limpio.encode() not in vistos:
            vistos.append(limpio.encode())
    return vistos


def _derivar(material: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO
    ).derive(material)


def clave_de_cifrado() -> bytes:
    """32 bytes derivados por HKDF-SHA256 del secreto VIGENTE del entorno.

    Sin `salt` a proposito: el salt tendria que persistirse en algun lado
    para poder derivar la misma clave en el proximo arranque, y ese lugar
    seria la misma base que se esta protegiendo. HKDF sin salt sigue siendo
    correcto — el material de entrada ya es un secreto de alta entropia
    (los `SECRET_KEY` de esta familia son 64 caracteres hex).

    **Cifrar usa SIEMPRE esta y ninguna otra.** Las claves anteriores sirven
    para leer, nunca para escribir: si `cifrar()` pudiera usar una vieja, sacar
    la variable de transicion volveria ilegible algo recien guardado.
    """
    return _derivar(_material_de_clave())


def claves_de_descifrado() -> list[bytes]:
    """La vigente primero y despues las anteriores, en el orden declarado.

    El orden importa poco para la correccion —AES-GCM autentica, asi que una
    clave equivocada da `InvalidTag` y no un texto plausible— pero mucho para
    el costo: lo normal es que acierte la primera.
    """
    return [clave_de_cifrado()] + [_derivar(m) for m in _materiales_anteriores()]


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


def descifrar_al_dia(blob: str) -> tuple[str, bool]:
    """Como `descifrar`, pero ademas dice si la clave usada es la VIGENTE.

    El `False` no es un error: el valor se leyo bien, con una clave anterior
    declarada en `LIBRAAUTH_CLAVES_ANTERIORES`. Lo que significa es que **falta
    recifrarlo**, y por lo tanto que la variable de transicion todavia no se
    puede sacar. Es la señal que hace auditable el cierre de una rotacion.
    """
    if not blob:
        return "", True
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
    for indice, clave in enumerate(claves_de_descifrado()):
        try:
            return AESGCM(clave).decrypt(nonce, ct, None).decode(), indice == 0
        except InvalidTag:
            continue
    # El caso realista: se roto el SECRET_KEY y no se declaro el anterior.
    anteriores = len(_materiales_anteriores())
    raise SecretoIndescifrable(
        "No se puede descifrar con la clave vigente"
        + (
            f" ni con las {anteriores} anteriores declaradas."
            if anteriores
            else f", y no hay ninguna declarada en {CLAVES_ANTERIORES}."
        )
        + " Lo mas probable es que se haya rotado el SECRET_KEY de esta"
        " instancia; hay que volver a cargar el secreto, o declarar el valor"
        " anterior para poder recifrarlo."
    )


def descifrar(blob: str) -> str:
    """Inversa de `cifrar`. Lanza `SecretoIndescifrable` si el valor esta
    corrupto, fue cifrado con una clave que no se conoce, o tiene un formato
    que esta version no entiende."""
    return descifrar_al_dia(blob)[0]


def recifrar(blob: str) -> str | None:
    """Devuelve el valor cifrado con la clave VIGENTE, o `None` si ya lo estaba.

    El `None` es lo que hace que recifrar sea idempotente y barato de correr en
    todas las filas: quien llama no escribe nada cuando no hay nada que cambiar,
    asi que una segunda pasada no toca la base ni genera nonces nuevos.

    Un valor que no se puede leer con ninguna clave conocida **no se toca**:
    lanza `SecretoIndescifrable`. Reemplazarlo por algo cifrado con la clave
    nueva seria destruir el unico rastro de lo que habia.
    """
    if not blob:
        return None
    texto, al_dia = descifrar_al_dia(blob)
    if al_dia:
        return None
    return cifrar(texto)
