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
from contextlib import AbstractContextManager
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from .models import AuthEvent

# Los tres eventos que registra el router de este paquete. Son strings y no un
# Enum para que un producto pueda anotar uno propio (ej. "password_reset") sin
# tener que esperar una version nueva del motor.
LOGIN = "login"
LOGOUT = "logout"
LOGIN_FALLIDO = "login_fallido"

# Mismo valor que usa `libracore.db.logs.contar_login_fallidos_recientes`.
VENTANA_FALLIDOS_MINUTOS = 15


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
        "ts": e.ts.strftime("%Y-%m-%d %H:%M:%S"),
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

    def contar_fallidos_recientes(self, ip: str, minutos: int = VENTANA_FALLIDOS_MINUTOS) -> int:
        """Intentos fallidos desde esa IP en los ultimos `minutos`. Ventana
        deslizante sobre la misma tabla, sin estado nuevo — igual que
        `libracore.db.logs.contar_login_fallidos_recientes`.

        Devuelve 0 con `ip` vacia: sin IP, la ventana agruparia a todos los
        clientes en un mismo balde y el primer fallido de cualquiera
        bloquearia a todos.
        """
        if not ip:
            return 0
        desde = datetime.now() - timedelta(minutes=int(minutos))
        with self.session_factory() as session:
            return int(session.execute(
                select(func.count(AuthEvent.id)).where(
                    AuthEvent.evento == LOGIN_FALLIDO,
                    AuthEvent.ip == ip,
                    AuthEvent.ts >= desde,
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
        pass
