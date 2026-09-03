"""
Log de accesos: quien entro, cuando, desde donde, y quien lo intento sin
lograrlo (v0.8.0).

**Por que vive en este motor y no en cada producto.** El evento que hay que
registrar ocurre dentro de `build_json_api_auth_router()`, que es codigo de
este paquete: el producto consumidor no ve pasar el login, solo monta el
router. Escrito en cada producto, cada uno tendria que envolver o reimplementar
el endpoint de login del motor para poder anotarlo — cuatro copias de lo mismo,
y cuatro oportunidades de que una se olvide del intento fallido, que es el
evento que mas importa.

`libracore.db.logs` ya tenia estas tres funciones (`registrar_auth_event`,
`get_auth_log`, `contar_login_fallidos_recientes`) sobre sqlite3 crudo, y las
usan Contalibra y Restolibra. Esto es la misma tabla y el mismo contrato, sobre
SQLAlchemy, para los productos cuyo dominio no vive en sqlite3 crudo. Ver
`models.AuthEvent` para por que la tabla conserva el nombre `auth_log`.
"""
import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime, timedelta

from sqlalchemy import String, func, inspect, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from .auditoria import ts_legible
from .models import AuthEvent

# Los tres eventos que registra el router de este paquete. Son strings y no un
# Enum para que un producto pueda anotar uno propio (ej. "password_reset") sin
# tener que esperar una version nueva del motor.
LOGIN = "login"
LOGOUT = "logout"
LOGIN_FALLIDO = "login_fallido"
#: Un intento rechazado por el rate limiting, sin llegar a chequear la clave.
#: El string es **el mismo que ya venian anotando Contalibra y Restolibra** con
#: su rate limiting propio: cambiarlo partiria en dos el historial de esas dos
#: instancias, donde los bloqueos viejos y los nuevos dejarian de agruparse.
LOGIN_BLOQUEADO = "login_bloqueado"

# Mismo valor que usa `libracore.db.logs.contar_login_fallidos_recientes`.
VENTANA_FALLIDOS_MINUTOS = 15

#: 🔴 **Este logger existe para que la defensa no pueda apagarse en silencio.**
#: `registrar_seguro` y `contar_fallidos_seguro` se tragan cualquier error a
#: propósito —ver sus docstrings—, y hasta el 2026-08-22 lo hacían sin dejar
#: rastro. Eso convirtió un desacuerdo de esquema en un rate limiting inerte
#: durante meses, en tres productos, sin una sola línea en ningún log.
_log = logging.getLogger("libraauth.auth_events")

#: El formato en que los DOS escritores guardan `ts`: el `datetime.now` del
#: modelo de acá y el `datetime('now','localtime')` de `libracore.db.logs`.
#: Es ISO con espacio, y **cero-padded**, que es lo que hace que comparar
#: lexicográficamente sea comparar cronológicamente.
FORMATO_TS = "%Y-%m-%d %H:%M:%S"


def ip_del_request(request: Request) -> str:
    """La IP del cliente, mirando primero `X-Forwarded-For`.

    Los seis productos corren detras de Nginx Proxy Manager, asi que
    `request.client.host` es **siempre la IP del proxy** — un log de accesos
    lleno de `172.18.0.1` no sirve para nada. NPM manda la real en
    `X-Forwarded-For`.

    Se toma el **primer** elemento de la lista, que es el cliente original: el
    header es una cadena `cliente, proxy1, proxy2` y cada salto appendea el
    suyo.

    > ⚠️ Un cliente puede mandar `X-Forwarded-For` inventado y el proxy le
    > appendea el suyo detras en vez de descartarlo. O sea: **esta IP sirve
    > para leer un log, no para decidir un bloqueo**, y por eso el rate
    > limiting que se apoye en `contar_fallidos_recientes` no puede ser la
    > unica defensa contra fuerza bruta. Registrarla igual es lo correcto —
    > una IP falsificada tambien es informacion.
    """
    reenviada = request.headers.get("x-forwarded-for", "")
    if reenviada:
        return reenviada.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""


def _to_dict(e: AuthEvent) -> dict:
    return {
        "id": e.id,
        # ISO con espacio en vez de "T": es como se ve la columna en las filas
        # que escribe LibraCore, y la pantalla de logs de Contalibra ya parte
        # ese formato.
        #
        # Por `ts_legible` y no `.strftime()` directo: `auth_log` la crea el DDL
        # crudo de LibraCore como TEXT, asi que contra PostgreSQL este valor
        # llega como `str` -- ver el docstring de esa funcion.
        "ts": ts_legible(e.ts),
        "evento": e.evento,
        "username": e.username,
        "ip": e.ip or "",
        "detalle": e.detalle or "",
    }


class AuthEventRepository:
    """`session_factory` es el mismo que recibe `UserRepository`: cualquier
    callable que devuelva un `Session` usable como context manager."""

    def __init__(self, session_factory: Callable[[], AbstractContextManager[Session]]):
        self.session_factory = session_factory
        #: Cache de `_ts_es_texto`. `None` = todavía no se miró.
        self._ts_texto: bool | None = None

    def registrar(self, evento: str, username: str, ip: str = "", detalle: str = "") -> None:
        """Anota un evento. **Nunca levanta**: ver `registrar_seguro` para el
        motivo de que exista la variante que traga errores — esta si propaga,
        para que los tests y los llamadores que quieran enterarse puedan."""
        with self.session_factory() as session:
            session.add(AuthEvent(
                evento=evento,
                # El username entra como lo tipeo quien intento entrar. Se
                # recorta al largo de la columna en vez de rechazarlo: un
                # username absurdamente largo es *justamente* algo que se
                # quiere ver en el log, no algo que deba tumbar el login.
                username=(username or "")[:100],
                ip=(ip or "")[:64],
                detalle=(detalle or "")[:500],
            ))
            session.commit()

    def listar(self, limit: int = 200, offset: int = 0) -> list[dict]:
        """Los eventos mas recientes primero."""
        with self.session_factory() as session:
            filas = session.execute(
                select(AuthEvent).order_by(AuthEvent.id.desc()).limit(limit).offset(offset)
            ).scalars()
            return [_to_dict(e) for e in filas]

    def contar(self) -> int:
        with self.session_factory() as session:
            return int(session.execute(select(func.count(AuthEvent.id))).scalar_one())

    def _ts_es_texto(self, session: Session) -> bool:
        """Si la columna `ts` de ESTA base es texto en vez de timestamp.

        🔴 **Las dos formas son legítimas y conviven en la familia.** El modelo
        de acá declara `ts` como `DateTime`, pero en los productos donde la
        tabla la crea el **DDL crudo** de LibraCore la columna es `TEXT` — a
        propósito, porque esa capa filtra fechas comparando lexicográficamente.
        `ts_legible` ya tolera las dos al LEER; esto es lo mismo al CONTAR.

        Se resuelve mirando el esquema y no probando y viendo qué pasa: un
        `except` acá es indistinguible de una base momentáneamente trabada, y
        justamente lo que hay que evitar es volver a confundir un desacuerdo de
        tipos con un problema pasajero.

        El resultado se cachea por repositorio: el tipo de una columna no
        cambia mientras el proceso vive, y esto corre en el camino del login.
        """
        if self._ts_texto is None:
            try:
                columnas = inspect(session.get_bind()).get_columns(AuthEvent.__tablename__)
                tipo = next(c["type"] for c in columnas if c["name"] == "ts")
                self._ts_texto = isinstance(tipo, String)
            except Exception:  # noqa: BLE001 — sin esquema legible, el default
                # es el del modelo. Si además la consulta falla, quien llama se
                # entera por `contar_fallidos_seguro`, que ahora sí lo registra.
                self._ts_texto = False
        return self._ts_texto

    def contar_fallidos_recientes(self, ip: str, minutos: int = VENTANA_FALLIDOS_MINUTOS) -> int:
        """Intentos fallidos desde esa IP en los ultimos `minutos`. Ventana
        deslizante sobre la misma tabla, sin estado nuevo — igual que
        `libracore.db.logs.contar_login_fallidos_recientes`.

        Devuelve 0 con `ip` vacia: sin IP, la ventana agruparia a todos los
        clientes en un mismo balde y el primer fallido de cualquiera
        bloquearia a todos.

        🔴 **El corte se compara contra el tipo REAL de la columna** (ver
        `_ts_es_texto`). Hasta el 2026-08-22 esto mandaba siempre un `datetime`,
        y contra una columna `TEXT` en PostgreSQL la consulta moría con
        *operator does not exist: text >= timestamp*. Como `contar_fallidos_seguro`
        se traga los errores y devuelve 0 —que significa "nadie agotó
        intentos"—, **el bloqueo por fuerza bruta nunca disparaba**. Medido en
        vivo: nueve intentos fallidos seguidos contra una demo, los nueve
        anotados con la IP real, ni un solo 429.

        Contra SQLite no se veía: es dinámicamente tipado y la comparación
        pasa igual. Sólo aparece contra PostgreSQL real.
        """
        if not ip:
            return 0
        desde = datetime.now() - timedelta(minutes=int(minutos))
        with self.session_factory() as session:
            # Texto contra texto, o timestamp contra timestamp: nunca cruzados,
            # y sin `CAST` — un cast de timestamp a texto depende del
            # `DateStyle` del servidor, que es una variable de sesión.
            corte = desde.strftime(FORMATO_TS) if self._ts_es_texto(session) else desde
            return int(session.execute(
                select(func.count(AuthEvent.id)).where(
                    AuthEvent.evento == LOGIN_FALLIDO,
                    AuthEvent.ip == ip,
                    AuthEvent.ts >= corte,
                )
            ).scalar_one())


def registrar_seguro(request: Request, evento: str, username: str, detalle: str = "") -> None:
    """Registra el evento si el producto configuro `app.state.auth_events`, y
    **se traga cualquier error**.

    Las dos mitades son deliberadas:

    - **Opt-in por ausencia.** Un consumidor que actualice el motor y no
      configure nada sigue funcionando exactamente igual, sin tabla nueva ni
      escrituras. Mismo criterio que el token de servicio de `session_auth`.
    - **No propaga errores.** Esto corre dentro del endpoint de login. Si la
      base esta bloqueada o la tabla no existe todavia, la alternativa a tragar
      el error es un 500 en el login: **nadie podria entrar al sistema porque
      falla el que anota que entraron**. El log es informacion valiosa, pero
      vale menos que poder loguearse.
    """
    repo = getattr(request.app.state, "auth_events", None)
    if repo is None:
        return
    try:
        repo.registrar(evento, username, ip_del_request(request), detalle)
    except Exception:  # noqa: BLE001 — a proposito, ver docstring
        # Se traga el error, pero NO en silencio: un `pass` pelado convierte
        # un problema permanente (una tabla que no existe, un tipo que no
        # cuadra) en algo indistinguible de "no pasó nada".
        _log.warning("no se pudo registrar el evento de acceso %r", evento, exc_info=True)


def contar_fallidos_seguro(request: Request, minutos: int = VENTANA_FALLIDOS_MINUTOS) -> int:
    """Intentos fallidos recientes desde la IP del request, o **0** si no se
    puede saber.

    🔴 **Devuelve 0 ante cualquier problema, y eso es a proposito.** Este
    numero alimenta el rate limiting del login: si la tabla no existe, el
    producto no configuro `auth_events` o la base esta trabada, la alternativa
    a devolver 0 es tratar a todo el mundo como si hubiera agotado sus
    intentos — o sea, **dejar a todos afuera porque falla el que cuenta**. Es
    el mismo criterio que `registrar_seguro`: el rate limiting es defensa en
    profundidad, no la puerta.

    🔴 **Pero devolver 0 SIN DECIR NADA fue el defecto.** Ese `except` mudo
    tapó durante meses un desacuerdo de tipos en `auth_log.ts` que dejaba el
    bloqueo por fuerza bruta inerte en tres productos. Sigue devolviendo 0
    —eso está bien—, pero ahora lo registra: un fallo permanente y una base
    trabada un segundo dejan de ser la misma cosa para quien mire los logs.
    """
    repo = getattr(request.app.state, "auth_events", None)
    if repo is None:
        # No es un error: es el opt-in por ausencia. Pero se dice UNA vez, en
        # el arranque, no en cada login — ver `advertir_si_no_hay_registro`.
        return 0
    try:
        return repo.contar_fallidos_recientes(ip_del_request(request), minutos)
    except Exception:  # noqa: BLE001 — ver docstring
        _log.warning(
            "no se pudieron contar los intentos fallidos: el rate limiting del "
            "login queda INERTE hasta que esto se arregle", exc_info=True,
        )
        return 0


def verificar_registro_de_accesos(repo: "AuthEventRepository | None") -> str:
    """Un diagnóstico de una línea sobre el registro de accesos, para gritar en
    el arranque. Devuelve `""` si está todo bien.

    🔴 **Existe porque las dos mitades de este módulo fallan calladas.** El
    `registrar_seguro` que no puede escribir y el `contar_fallidos_seguro` que
    no puede contar devuelven lo mismo que si no hubiera pasado nada. Un
    producto podía correr meses con el log de accesos vacío y el rate limiting
    apagado sin una sola señal — pasó, en cuatro de ocho productos.

    No levanta: se llama al arrancar y lo que corresponde es un log ruidoso, no
    tumbar la app porque no puede anotar quién entra.

    **Ejecuta las dos operaciones de verdad**, no mira el esquema: un chequeo
    que no ejercita la consulta es exactamente el que dejó pasar esto.
    """
    if repo is None:
        return ("el producto no configuró `app.state.auth_events`: no se "
                "registran accesos NI funciona el rate limiting del login")
    try:
        repo.contar()
    except Exception as e:  # noqa: BLE001
        return f"no se puede leer `auth_log`: {e}"
    try:
        # Una IP que no va a existir: cuenta cero, pero EJECUTA la comparación
        # de `ts`, que es la que se rompía. Un `contar()` a secas no la toca.
        repo.contar_fallidos_recientes("0.0.0.0")
    except Exception as e:  # noqa: BLE001
        return (f"el rate limiting del login está INERTE — la cuenta de "
                f"intentos fallidos falla: {e}")
    return ""


def advertir_si_no_hay_registro(app) -> str:
    """`verificar_registro_de_accesos` sobre `app.state`, y lo registra como
    warning. Devuelve el mismo diagnóstico para que un test pueda afirmarlo."""
    problema = verificar_registro_de_accesos(getattr(app.state, "auth_events", None))
    if problema:
        _log.warning("registro de accesos: %s", problema)
    return problema
