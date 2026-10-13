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
por intento desaparece. Donde viven los usados es una costura (`usados=`,
ADR-023):

- `UsadosEnMemoria` (el default, lo de siempre): en el proceso. **Alcanza con un
  solo proceso por contenedor** (`CMD uvicorn ...` sin `--workers`, medido el
  2026-09-11). Con `--workers N` cada proceso tiene su lista y un desafio
  resuelto sirve **una vez por worker**: N veces mas barato el ataque.
- `UsadosEnBase(session_factory)`: en la tabla `libraauth_captcha_usados`
  (migracion `0003`), con un `INSERT ... ON CONFLICT DO NOTHING` por desafio:
  si inserto, es la primera vez; si no, es un replay. Lo ve cualquier proceso, y
  sobrevive a un reinicio. Es lo que hay que usar apenas un producto corre con
  `WEB_CONCURRENCY` > 1.

Con la lista en memoria, un reinicio la vacia, y lo peor que eso habilita es
reusar un desafio de antes del reinicio mientras siga vigente.
"""
import base64
import json
import random
import secrets
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Protocol

from altcha import create_challenge, verify_solution
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import delete, insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import CaptchaUsado

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


class UsadosDeCaptcha(Protocol):
    """Donde se anotan los desafios ya resueltos. La costura de `Captcha(usados=...)`."""

    def usar(self, firma: str, vence: float, ahora: float) -> bool:
        """Anota `firma` (valida hasta `vence`, en segundos desde la epoca). `True` si **era la primera vez**,
        `False` si ya estaba anotada (un replay). Atomico: dos llamadas simultaneas con la misma firma, desde
        donde sea, devuelven `True` una sola vez."""
        ...


class UsadosEnMemoria:
    """Los desafios usados, en el proceso: el default de siempre. Ver el docstring del modulo."""

    def __init__(self) -> None:
        self._usados: dict[str, float] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._usados)

    def usar(self, firma: str, vence: float, ahora: float) -> bool:
        with self._lock:
            for usada in [f for f, v in self._usados.items() if v < ahora]:
                del self._usados[usada]
            if firma in self._usados:
                return False
            self._usados[firma] = vence
        return True


class UsadosEnBase:
    """Los desafios usados, en la tabla `libraauth_captcha_usados`: compartidos por todos los procesos de la instancia.

    `session_factory` es el mismo que recibe el `UserRepository` del producto (cualquier callable que devuelva un
    `Session` como context manager). La tabla la crea la migracion `0003_captcha_usados`.

    **Una sola sentencia decide, y es atomica:** `INSERT ... ON CONFLICT DO NOTHING` sobre la PK (la firma). Si inserto
    una fila, la firma era nueva; si no, ya estaba. No hay un `SELECT` antes (dos procesos lo contestarian los dos).

    **Poda probabilistica.** Cada `usar` borra los vencidos con probabilidad `poda` (2 % por defecto): la tabla no
    crece sin tope y ningun login paga un `DELETE` extra casi nunca. Un desafio vive 10 minutos y el login se hace
    de a uno por vez: la tabla tiene decenas de filas, no importa cuando se poda. `azar` existe para los tests.

    **Si la base falla**, `usar` levanta: el captcha no se puede validar y el login responde 500 en lugar de dejar pasar
    un desafio sin anotar (que permitiria el replay). Es lo contrario del rate limiting, que falla abierto: aca el
    costo del error es justamente lo que el captcha existe para cobrar.
    """

    def __init__(
        self,
        session_factory: Callable[[], AbstractContextManager[Session]],
        *,
        poda: float = 0.02,
        azar: Callable[[], float] = random.random,
    ) -> None:
        self._sessions = session_factory
        self._poda = poda
        self._azar = azar

    def usar(self, firma: str, vence: float, ahora: float) -> bool:
        with self._sessions() as session:
            nuevo = self._insertar(session, firma, vence)
            if self._azar() < self._poda:
                session.execute(delete(CaptchaUsado.__table__).where(CaptchaUsado.__table__.c.vence < ahora))
            session.commit()
        return nuevo

    @staticmethod
    def _insertar(session: Session, firma: str, vence: float) -> bool:
        dialecto = session.get_bind().dialect.name
        if dialecto in ("postgresql", "sqlite"):
            if dialecto == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as insert_propio
            else:
                from sqlalchemy.dialects.sqlite import insert as insert_propio
            tabla = CaptchaUsado.__table__
            # `RETURNING` y no `rowcount`: con psycopg 3 el `rowcount` de este INSERT vuelve -1. Si inserto, devuelve
            # la fila; si el conflicto lo descarto, no devuelve nada.
            sentencia = (insert_propio(tabla).values(firma=firma, vence=vence)
                         .on_conflict_do_nothing().returning(tabla.c.firma))
            return session.execute(sentencia).first() is not None
        # Otro dialecto: el INSERT pelado y la PK deciden, dentro de un savepoint para no abortar la transaccion.
        try:
            with session.begin_nested():
                session.execute(insert(CaptchaUsado.__table__).values(firma=firma, vence=vence))
        except IntegrityError:
            return False
        return True


class Captcha:
    """Emite desafios y verifica sus soluciones, una sola vez cada una.

    `costo`, `contador_min` y `contador_rango` existen para los tests, que no
    pueden gastar un segundo de CPU por cada login. `reloj` tambien: con el se
    emite un desafio ya vencido sin esperar diez minutos.

    `usados` es donde se anotan los desafios ya resueltos (ver el docstring del
    modulo): `UsadosEnMemoria()` por defecto, `UsadosEnBase(session_factory)` para
    un producto que corre con varios procesos.
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
        usados: UsadosDeCaptcha | None = None,
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
        self._usados = usados if usados is not None else UsadosEnMemoria()

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
        return self._usados.usar(firma, vence, self._reloj())
