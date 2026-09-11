"""
Captcha de prueba de trabajo (ALTCHA), emitido y verificado en el propio
servidor (v0.40.0, ADR-014).

**Por que existe.** El bloqueo por intentos fallidos cuenta por IP, y una IP
no frena a quien reparte los intentos entre muchas. El captcha le pone un
costo a **cada** intento, venga de donde venga: para enviar una contrasena
hay que haber resuelto antes un desafio que tarda del orden de un segundo.
No detecta bots —ningun captcha de prueba de trabajo lo hace—: los encarece.
Por eso va **junto** con el bloqueo, no en su lugar.

**Por que ALTCHA y no Turnstile, hCaptcha o reCAPTCHA.** Es el unico de los
cuatro que se emite y se verifica sin salir del servidor: no hay proveedor que
vea la IP del usuario, no hay cookies, no hay que abrir la CSP a un tercero y
el login no se cae cuando se cae otro. Lo decidio el humano el 2026-09-11,
junto con que el captcha va **siempre**, no recien despues de N fallos.

**De donde salen las claves.** Se derivan del `SECRET_KEY` de la instancia por
HKDF, con un `info` propio — la misma receta que `crypto.py`, sin variable
nueva que agregar a cada compose. Rotar `SECRET_KEY` solo invalida los
desafios en curso (duran minutos): no hay nada guardado que quede ilegible,
asi que esto **no** es un consumidor mas de la rotacion.

**Anti-replay.** Un desafio resuelto sirve una sola vez. Sin eso, se resuelve
uno y se lo reusa para cada contrasena durante toda su vigencia, y el costo
por intento desaparece. Los usados viven en memoria del proceso hasta que
vencen: los productos corren un solo proceso de uvicorn por contenedor (medido
el 2026-09-11, `CMD uvicorn ...` sin `--workers`). Un reinicio vacia la lista,
y lo peor que eso habilita es reusar un desafio de antes del reinicio mientras
siga vigente.
"""
import base64
import json
import secrets
import threading
import time
from collections.abc import Callable

from altcha import create_challenge, verify_solution
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITMO = "PBKDF2/SHA-256"

#: Iteraciones de PBKDF2 por cada contador que prueba el navegador.
COSTO = 1000
#: El contador que el navegador tiene que encontrar sale al azar de
#: `[CONTADOR_MIN, CONTADOR_MIN + CONTADOR_RANGO)`. El trabajo esperado es
#: contador x costo iteraciones.
#:
#: 🟠 **Provisorio.** Medido en un hilo de Python en una PC de escritorio
#: (2026-09-11): 0,70 s en promedio. El widget reparte el trabajo en varios
#: workers y un telefono es mas lento, asi que el numero que vale es el del
#: navegador, y se ajusta aca cuando se mida en dev. Verificar cuesta 0,1 ms
#: sea cual sea el costo: el servidor no paga lo que paga el cliente.
CONTADOR_MIN = 2000
CONTADOR_RANGO = 2000

#: Cuanto vive un desafio. Diez minutos alcanzan para que alguien tilde la
#: casilla y despues busque la contrasena; el widget pide uno nuevo solo si
#: vence.
VIGENCIA_SEGUNDOS = 10 * 60

#: Un payload legitimo mide unos 600 bytes. Lo que pase de esto no se decodifica.
PAYLOAD_MAXIMO = 4096

_INFO_FIRMA = b"libraauth/captcha/firma/v1"
_INFO_CLAVE = b"libraauth/captcha/clave/v1"


def _derivar(material: bytes, info: bytes) -> str:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(material).hex()


class Captcha:
    """Emite desafios y verifica sus soluciones, una sola vez cada una.

    `costo`, `contador_min` y `contador_rango` existen para los tests, que no
    pueden gastar un segundo de CPU por cada login. `reloj` tambien: con el se
    emite un desafio ya vencido sin esperar diez minutos.
    """

    def __init__(
        self,
        secret_key: str,
        *,
        costo: int = COSTO,
        contador_min: int = CONTADOR_MIN,
        contador_rango: int = CONTADOR_RANGO,
        vigencia_segundos: int = VIGENCIA_SEGUNDOS,
        reloj: Callable[[], float] = time.time,
    ):
        if not secret_key:
            raise ValueError("Captcha necesita el SECRET_KEY de la instancia.")
        material = secret_key.encode()
        self._firma = _derivar(material, _INFO_FIRMA)
        self._clave = _derivar(material, _INFO_CLAVE)
        self._costo = costo
        self._contador_min = contador_min
        self._contador_rango = contador_rango
        self._vigencia = vigencia_segundos
        self._reloj = reloj
        self._usados: dict[str, float] = {}
        self._lock = threading.Lock()

    def emitir(self) -> dict:
        """El desafio, en la forma que el widget espera (`parameters` + `signature`)."""
        desafio = create_challenge(
            algorithm=ALGORITMO,
            cost=self._costo,
            counter=self._contador_min + secrets.randbelow(self._contador_rango),
            expires_at=int(self._reloj()) + self._vigencia,
            hmac_secret=self._firma,
            hmac_key_secret=self._clave,
        )
        return desafio.to_dict()

    def verificar(self, payload: str) -> bool:
        """`True` si el payload resuelve un desafio de ESTA instancia, vigente y
        no usado. Lo marca como usado en el mismo paso.

        Nunca lanza: un payload roto es un intento invalido, no un 500. Hace
        falta atraparlo aca porque `verify_solution` no atrapa todo — con un
        desafio bien firmado y un `derived_key` que no es hex, revienta.
        """
        if not payload or len(payload) > PAYLOAD_MAXIMO:
            return False
        try:
            resultado = verify_solution(payload, self._firma, hmac_key_secret=self._clave)
            if not resultado.verified:
                return False
            desafio = json.loads(base64.b64decode(payload))["challenge"]
            firma = str(desafio["signature"])
            vence = float(desafio["parameters"]["expiresAt"])
        except Exception:
            return False
        with self._lock:
            ahora = self._reloj()
            for usada in [f for f, v in self._usados.items() if v < ahora]:
                del self._usados[usada]
            if firma in self._usados:
                return False
            self._usados[firma] = vence
        return True
