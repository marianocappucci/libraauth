"""
`AdminAuth`: autenticacion del backoffice de superadmin.

Un unico usuario definido por variables de entorno (`ADMIN_PANEL_USER` /
`ADMIN_PANEL_PASSWORD`), **sin dependencia de base de datos** — no hay tabla ni
roles, es un solo superadmin por proceso.

Portado de `libracore.auth.AdminAuth` **sin cambios de comportamiento** el
2026-07-30. Habia quedado deliberadamente afuera al crear este paquete, con el
argumento de que un backoffice multi-cliente "no es auth puro"; el argumento no
se sostuvo: es literalmente autenticacion, y sobre todo **era lo unico que
mantenia a Contalibra y Restolibra importando `libracore.auth`**, o sea lo que
bloqueaba poder borrar ese modulo del motor.

Se diferencia de `SessionAuth` (mismo paquete) en tres cosas, todas a proposito:

- **No consulta usuarios**: las credenciales salen del entorno, no de la tabla
  `usuarios`. Por eso no recibe callbacks ni repositorio.
- **Cookie propia** (`cladmin_session` por defecto), separada de la sesion del
  usuario final: entrar al backoffice no te loguea en el producto ni al reves.
- **Rate limiting de login por IP** (5 intentos fallidos en 15 minutos). Hasta
  la F2 del 2026-09-05 vivia solo en memoria del proceso, asi que reiniciar el
  contenedor lo borraba. Ahora, con `ADMIN_PANEL_ESTADO_PATH` seteado, el estado
  va a un archivo JSON y **sobrevive al reinicio**; sin la variable se comporta
  como antes. Un archivo ilegible o no escribible avisa por log y sigue en
  memoria: fallar abierto, como el resto del rate limiting de este paquete —
  dejar a todos afuera porque falla el que cuenta es peor que no contar.

Y desde esa misma F2 tiene un **segundo factor TOTP opcional** (ver `totp.py`):
con `ADMIN_PANEL_TOTP_SECRET` en el entorno, `check_credentials` exige ademas
el codigo de 6 digitos del autenticador, y cada codigo sirve una sola vez. Es
el activo mas sensible de la familia —una contrasena filtrada de un `-admin` da
acceso a todas las instancias del producto— y el que menos cuesta proteger:
un usuario, una pantalla, un motor.
"""
import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from starlette.exceptions import HTTPException
from starlette.requests import Request

from .session_auth import _resolve_secret_key
from .totp import Totp

_log = logging.getLogger("libraauth.admin_auth")

#: Variable de entorno con el secreto base32 del segundo factor. Vacia = sin 2FA.
TOTP_SECRET_ENV = "ADMIN_PANEL_TOTP_SECRET"
#: Variable de entorno con la ruta del archivo de estado del login. Vacia = memoria.
ESTADO_PATH_ENV = "ADMIN_PANEL_ESTADO_PATH"


def _estado_vacio() -> dict:
    return {"intentos": {}, "ultimo_paso_totp": 0}


class _EstadoLogin:
    """Intentos fallidos por IP y ultimo contador TOTP aceptado.

    En memoria si `path` es `None`; si no, cada lectura abre el archivo y cada
    escritura lo reemplaza entero (tmp + `os.replace`, atomico en el mismo
    filesystem). Son decenas de bytes y un login cada tanto: no vale la pena
    cachear, y leer siempre del archivo es lo que hace que dos procesos —o el
    mismo despues de reiniciar— vean lo mismo."""

    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._mem = _estado_vacio()

    def _leer(self) -> dict:
        if self.path is None:
            return self._mem
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return _estado_vacio()
        except (OSError, ValueError) as e:
            _log.warning("estado de login ilegible en %s (%s): se arranca vacio", self.path, e)
            return _estado_vacio()
        if not isinstance(data, dict) or not isinstance(data.get("intentos"), dict):
            _log.warning("estado de login con forma inesperada en %s: se arranca vacio", self.path)
            return _estado_vacio()
        data["ultimo_paso_totp"] = int(data.get("ultimo_paso_totp") or 0)
        return data

    def _guardar(self, data: dict) -> None:
        if self.path is None:
            self._mem = data
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            # Se avisa UNA vez y se sigue en memoria: el rate limiting no se
            # apaga, pero deja de sobrevivir al reinicio, que es lo que el log
            # tiene que decir.
            _log.warning(
                "no se pudo guardar el estado de login en %s (%s): sigue en memoria "
                "y NO sobrevive a un reinicio", self.path, e,
            )
            self.path = None
            self._mem = data

    @staticmethod
    def _vigentes(data: dict, ventana: float, ahora: float) -> dict[str, list[float]]:
        podados = {
            ip: [t for t in marcas if isinstance(t, (int, float)) and ahora - t < ventana]
            for ip, marcas in data["intentos"].items()
            if isinstance(marcas, list)
        }
        return {ip: marcas for ip, marcas in podados.items() if marcas}

    def intentos_vigentes(self, ip: str, ventana: float, ahora: float) -> int:
        with self._lock:
            data = self._leer()
            return len(self._vigentes(data, ventana, ahora).get(ip, []))

    def registrar_fallido(self, ip: str, ventana: float, ahora: float) -> None:
        with self._lock:
            data = self._leer()
            intentos = self._vigentes(data, ventana, ahora)
            intentos.setdefault(ip, []).append(ahora)
            data["intentos"] = intentos
            self._guardar(data)

    def ultimo_paso_totp(self) -> int:
        with self._lock:
            return int(self._leer()["ultimo_paso_totp"])

    def marcar_paso_totp(self, paso: int) -> None:
        with self._lock:
            data = self._leer()
            data["ultimo_paso_totp"] = max(int(data["ultimo_paso_totp"]), int(paso))
            self._guardar(data)


class AdminAuth:
    """Autenticacion del backoffice de superadmin (ver docstring del modulo).

    `totp_secret` y `estado_path` se leen del entorno cuando son `None`; pasar
    `""` los apaga explicitamente (util en tests). Un secreto TOTP invalido
    frena el arranque con `RuntimeError`: un segundo factor mal cargado que
    nunca valida es peor que ninguno, porque parece que esta."""

    def __init__(
        self,
        *,
        dev_secret_fallback: str,
        cookie_name: str = "cladmin_session",
        max_age: int = 86400 * 3,
        login_max_intentos: int = 5,
        login_ventana_segundos: int = 15 * 60,
        totp_secret: str | None = None,
        estado_path: str | os.PathLike | None = None,
    ):
        self.secret_key = _resolve_secret_key(
            dev_secret_fallback,
            "SECRET_KEY no esta seteado para el backoffice de superadmin. "
            "Para desarrollo local sin uno, setear ENV=development.",
        )
        self.panel_user = os.environ.get("ADMIN_PANEL_USER", "superadmin")
        self.panel_pass = os.environ.get("ADMIN_PANEL_PASSWORD", "")
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.login_max_intentos = login_max_intentos
        self.login_ventana_segundos = login_ventana_segundos
        self._signer = URLSafeTimedSerializer(self.secret_key)

        secreto = os.environ.get(TOTP_SECRET_ENV, "") if totp_secret is None else totp_secret
        if secreto.strip():
            try:
                self._totp: Totp | None = Totp(secreto)
            except ValueError as e:
                raise RuntimeError(f"{TOTP_SECRET_ENV} invalido: {e}") from None
        else:
            self._totp = None

        ruta = os.environ.get(ESTADO_PATH_ENV, "") if estado_path is None else estado_path
        self._estado = _EstadoLogin(ruta or None)

    # ── credenciales ───────────────────────────────────────────────────────

    @property
    def totp_habilitado(self) -> bool:
        """`True` cuando el login exige el codigo del autenticador."""
        return self._totp is not None

    def check_credentials(self, username: str, password: str, codigo: str | None = None) -> bool:
        """Usuario y contrasena, y ademas el codigo TOTP si esta habilitado.

        Con 2FA, las dos comprobaciones corren siempre y la respuesta es un
        solo `False`: que la clave este mal no ahorra la del codigo, y quien
        llama no puede distinguir cual de las dos fallo. El contador del
        codigo se marca como usado solo cuando TODO valido — asi un error de
        tipeo en la contrasena no quema el codigo de ese medio minuto."""
        if not self.panel_pass:
            # Sin contrasena configurada se rechaza todo (fail-closed): si no,
            # una instancia mal configurada dejaria entrar con password vacia.
            return False
        clave_ok = hmac.compare_digest(
            username or "", self.panel_user
        ) and hmac.compare_digest(password or "", self.panel_pass)
        if self._totp is None:
            return clave_ok
        paso = self._totp.paso_valido(codigo or "", ultimo_paso=self._estado.ultimo_paso_totp())
        if not clave_ok or paso is None:
            return False
        self._estado.marcar_paso_totp(paso)
        return True

    # ── rate limiting ──────────────────────────────────────────────────────

    def rate_limit_excedido(self, ip: str) -> bool:
        if not ip:
            return False
        vigentes = self._estado.intentos_vigentes(ip, self.login_ventana_segundos, time.time())
        return vigentes >= self.login_max_intentos

    def registrar_intento_fallido(self, ip: str):
        if not ip:
            return
        self._estado.registrar_fallido(ip, self.login_ventana_segundos, time.time())

    # ── cookie de sesion ───────────────────────────────────────────────────

    def create_session_cookie(self, response, username: str):
        response.set_cookie(
            self.cookie_name,
            self._signer.dumps(username),
            httponly=True,
            samesite="lax",
            secure=True,
        )

    def clear_session_cookie(self, response):
        response.delete_cookie(self.cookie_name)

    def current_user(self, request: Request) -> str | None:
        token = request.cookies.get(self.cookie_name)
        if not token:
            return None
        try:
            return self._signer.loads(token, max_age=self.max_age)
        except (BadSignature, SignatureExpired):
            return None

    def require_login(self, request: Request) -> str:
        user = self.current_user(request)
        if not user:
            raise HTTPException(status_code=307, headers={"Location": "/login"})
        return user
