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

Desde la F3 (2026-09-13) el secreto TOTP tambien se puede **enrolar en
runtime**, sin tocar el `.env` ni recrear el contenedor: `iniciar_totp` /
`confirmar_totp` / `desactivar_totp` lo guardan en un archivo JSON aparte del
estado de login (`ADMIN_PANEL_TOTP_PATH`, o el hermano `totp.json` de
`ADMIN_PANEL_ESTADO_PATH` cuando esa variable no esta seteada). El entorno
sigue mandando cuando esta presente: con `ADMIN_PANEL_TOTP_SECRET` seteado,
`totp_origen` es `"entorno"` y enrolar o desactivar desde la app se rechaza
con `TotpNoEnrolable`. Y a diferencia del estado de login —que falla
ABIERTO—, un archivo de TOTP roto falla CERRADO: `totp_habilitado` da `True`
y el login queda cerrado hasta borrar el archivo a mano desde el host, porque
un segundo factor que se apaga solo porque el archivo se rompio es peor que
un login cerrado que se arregla borrando un archivo (ver ADR-015).
"""
import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Literal

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from starlette.exceptions import HTTPException
from starlette.requests import Request

from .session_auth import _resolve_secret_key
from .totp import Totp, generar_secreto, uri_otpauth

_log = logging.getLogger("libraauth.admin_auth")

#: Variable de entorno con el secreto base32 del segundo factor. Vacia = sin 2FA.
TOTP_SECRET_ENV = "ADMIN_PANEL_TOTP_SECRET"
#: Variable de entorno con la ruta del archivo del secreto TOTP enrolable en
#: runtime. Vacia = se deriva de ESTADO_PATH_ENV (ver `AdminAuth.__init__`).
TOTP_PATH_ENV = "ADMIN_PANEL_TOTP_PATH"
#: Variable de entorno con la ruta del archivo de estado del login. Vacia = memoria.
ESTADO_PATH_ENV = "ADMIN_PANEL_ESTADO_PATH"
#: Segundos que un secreto PENDIENTE de `iniciar_totp` sigue confirmable con
#: `confirmar_totp` antes de vencer (10 minutos).
TOTP_PENDIENTE_SEGUNDOS = 600


class TotpNoEnrolable(RuntimeError):
    """`iniciar_totp` / `confirmar_totp` / `desactivar_totp` no se pueden usar
    ahora. El mensaje dice cual de los tres motivos es:

    - El origen es el entorno: `ADMIN_PANEL_TOTP_SECRET` manda y el segundo
      factor no se enrola ni se desactiva desde la app.
    - No hay ruta de archivo configurada (ni `ADMIN_PANEL_TOTP_PATH` ni
      `ADMIN_PANEL_ESTADO_PATH`): no enrolable por falta de donde guardar.
    - El archivo de TOTP esta roto (ver `_EstadoTotp.leer`): hay que borrarlo
      a mano desde el host antes de enrolar o desactivar de nuevo.
    """


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


def _totp_archivo_vacio() -> dict:
    return {"secreto": None, "pendiente": None, "roto": False}


class _EstadoTotp:
    """El secreto TOTP enrolado en runtime, en un archivo JSON aparte del
    estado de login (`_EstadoLogin`). En memoria (siempre vacio, nunca
    enrolable) si `path` es `None`; si no, cada lectura abre el archivo y
    cada escritura lo reemplaza entero (tmp + `os.chmod(0o600)` +
    `os.replace`, atomico en el mismo filesystem) — igual convencion que
    `_EstadoLogin` y por la misma razon: un reinicio o dos procesos tienen
    que ver lo mismo.

    **Fail CLOSED, a diferencia de `_EstadoLogin`**: un archivo que existe
    pero es ilegible, no es JSON o tiene forma inesperada NO se trata como
    vacio. `leer()` devuelve `roto=True`, y es responsabilidad de quien llama
    (`AdminAuth`) convertir eso en `totp_habilitado=True` con el login
    cerrado. La justificacion vive en el docstring del modulo: un segundo
    factor que se apaga solo porque el archivo se rompio es peor que un login
    cerrado que se arregla borrando un archivo desde el host.
    """

    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()

    def leer(self) -> dict:
        """`{"secreto": str | None, "pendiente": {"secreto", "creado"} | None,
        "roto": bool}`. Se lee siempre del archivo, sin cache."""
        if self.path is None:
            return _totp_archivo_vacio()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return _totp_archivo_vacio()
        except (OSError, ValueError) as e:
            _log.error(
                "archivo de TOTP ilegible en %s (%s): el 2FA queda CERRADO "
                "(fail closed) hasta borrarlo a mano desde el host", self.path, e,
            )
            return {**_totp_archivo_vacio(), "roto": True}
        # Un `secreto` que no es texto (un archivo editado a mano con un
        # numero, una lista) cuenta como forma inesperada: si pasara, `Totp()`
        # reventaria con `AttributeError` en el login -- un 500 en vez del
        # cierre controlado.
        if (
            not isinstance(data, dict)
            or "secreto" not in data
            or not isinstance(data["secreto"], (str, type(None)))
        ):
            _log.error(
                "archivo de TOTP con forma inesperada en %s: el 2FA queda "
                "CERRADO (fail closed) hasta borrarlo a mano desde el host", self.path,
            )
            return {**_totp_archivo_vacio(), "roto": True}
        pendiente = data.get("pendiente") or None
        # Un pendiente malformado se descarta sin cerrar nada: todavia no es
        # un segundo factor, y sin el volver a iniciar lo reemplaza.
        if pendiente is not None and not (
            isinstance(pendiente, dict)
            and isinstance(pendiente.get("secreto"), str)
            and isinstance(pendiente.get("creado"), (int, float))
            and not isinstance(pendiente.get("creado"), bool)
        ):
            pendiente = None
        return {"secreto": data.get("secreto") or None, "pendiente": pendiente, "roto": False}

    def guardar(self, *, secreto: str | None, pendiente: dict | None) -> bool:
        """Reemplaza el archivo entero. `False` si fallo (nunca lanza): quien
        llama decide si eso implica `RuntimeError` (ver `AdminAuth`:
        `confirmar_totp` y `desactivar_totp` RELEEN despues de guardar, asi
        que un fallo silencioso igual se detecta)."""
        if self.path is None:
            return False
        data = {"secreto": secreto, "pendiente": pendiente}
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_name(self.path.name + ".tmp")
                tmp.write_text(json.dumps(data), encoding="utf-8")
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
            except OSError as e:
                _log.error("no se pudo guardar el archivo de TOTP en %s (%s)", self.path, e)
                return False
        return True


class AdminAuth:
    """Autenticacion del backoffice de superadmin (ver docstring del modulo).

    `totp_secret`, `estado_path` y `totp_path` se leen del entorno cuando son
    `None`; pasar `""` los apaga explicitamente (util en tests). Un secreto
    TOTP del entorno invalido frena el arranque con `RuntimeError`: un segundo
    factor mal cargado que nunca valida es peor que ninguno, porque parece que
    esta."""

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
        totp_path: str | os.PathLike | None = None,
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

        ruta_estado = os.environ.get(ESTADO_PATH_ENV, "") if estado_path is None else estado_path
        self._estado = _EstadoLogin(ruta_estado or None)

        # Ruta del archivo TOTP enrolable en runtime: ADMIN_PANEL_TOTP_PATH si
        # esta; si no (y solo si totp_path no vino explicitamente en "" -
        # misma convencion que estado_path: None = leer entorno, "" = apagado
        # explicito), el hermano `totp.json` de ADMIN_PANEL_ESTADO_PATH.
        if totp_path is None:
            ruta_totp = os.environ.get(TOTP_PATH_ENV, "")
            if not ruta_totp and ruta_estado:
                ruta_totp = Path(ruta_estado).parent / "totp.json"
        else:
            ruta_totp = totp_path
        self._totp_archivo = _EstadoTotp(ruta_totp or None)

    # ── credenciales ───────────────────────────────────────────────────────

    @property
    def totp_origen(self) -> Literal["entorno", "archivo"] | None:
        """De donde sale el segundo factor activo, o `None` sin 2FA.

        Se lee en cada acceso, sin cache — igual que `totp_habilitado` y
        `check_credentials`, y por la misma razon: dos procesos (o un archivo
        que un humano acaba de editar) tienen que verse igual."""
        if self._totp is not None:
            return "entorno"
        if self._totp_archivo.path is None:
            return None
        estado = self._totp_archivo.leer()
        if estado["roto"] or estado["secreto"]:
            return "archivo"
        return None

    @property
    def totp_habilitado(self) -> bool:
        """`True` cuando el login exige el codigo del autenticador: con
        secreto en el entorno, con un secreto activo guardado en archivo, o
        -- fail CLOSED -- con el archivo de TOTP roto (ver `_EstadoTotp`)."""
        return self.totp_origen is not None

    @property
    def totp_enrolable(self) -> bool:
        """Hay ruta de archivo para el TOTP y el origen no es el entorno
        (equivalente a que `_exigir_enrolable` no levante)."""
        try:
            self._exigir_enrolable()
        except TotpNoEnrolable:
            return False
        return True

    def _exigir_enrolable(self) -> None:
        """La regla de `iniciar_totp` / `confirmar_totp` / `desactivar_totp`,
        compartida: levanta `TotpNoEnrolable` con el motivo, o no hace nada."""
        if self._totp is not None:
            raise TotpNoEnrolable(
                f"{TOTP_SECRET_ENV} esta seteado: el segundo factor lo maneja "
                "el entorno, no se puede enrolar ni desactivar desde la app."
            )
        if self._totp_archivo.path is None:
            raise TotpNoEnrolable(
                f"no hay ruta de archivo para el TOTP: setear {TOTP_PATH_ENV} "
                f"o {ESTADO_PATH_ENV}."
            )
        if self._totp_archivo.leer()["roto"]:
            raise TotpNoEnrolable(
                "el archivo de TOTP esta roto: borrarlo a mano desde el host "
                "antes de enrolar o desactivar de nuevo."
            )

    def _totp_activo(self) -> tuple[Totp | None, bool]:
        """El validador del secreto activo ahora mismo (entorno o archivo) y
        si el archivo esta roto. `(None, False)` = sin 2FA."""
        if self._totp is not None:
            return self._totp, False
        if self._totp_archivo.path is None:
            return None, False
        estado = self._totp_archivo.leer()
        if estado["roto"]:
            return None, True
        if not estado["secreto"]:
            return None, False
        try:
            return Totp(estado["secreto"]), False
        except ValueError as e:
            _log.error(
                "secreto TOTP guardado en %s no es valido (%s): el 2FA queda "
                "CERRADO (fail closed)", self._totp_archivo.path, e,
            )
            return None, True

    def check_credentials(self, username: str, password: str, codigo: str | None = None) -> bool:
        """Usuario y contrasena, y ademas el codigo TOTP si esta habilitado.

        Con 2FA, las dos comprobaciones corren siempre y la respuesta es un
        solo `False`: que la clave este mal no ahorra la del codigo, y quien
        llama no puede distinguir cual de las dos fallo. El contador del
        codigo se marca como usado solo cuando TODO valido — asi un error de
        tipeo en la contrasena no quema el codigo de ese medio minuto.

        Con el archivo de TOTP roto, `False` siempre (fail CLOSED): ni la
        clave correcta ni ningun codigo abren el login hasta que se borre el
        archivo a mano desde el host."""
        if not self.panel_pass:
            # Sin contrasena configurada se rechaza todo (fail-closed): si no,
            # una instancia mal configurada dejaria entrar con password vacia.
            return False
        clave_ok = hmac.compare_digest(
            username or "", self.panel_user
        ) and hmac.compare_digest(password or "", self.panel_pass)
        validador, roto = self._totp_activo()
        if roto:
            return False
        if validador is None:
            return clave_ok
        paso = validador.paso_valido(codigo or "", ultimo_paso=self._estado.ultimo_paso_totp())
        if not clave_ok or paso is None:
            return False
        self._estado.marcar_paso_totp(paso)
        return True

    # ── enrolamiento TOTP en runtime ─────────────────────────────────────────

    def iniciar_totp(self, cuenta: str) -> dict:
        """Arranca (o reinicia) el enrolamiento del segundo factor por
        archivo: genera un secreto nuevo, lo guarda como PENDIENTE (pisando
        cualquier pendiente anterior, sin tocar el activo) y devuelve
        `{"secreto", "uri"}` para mostrar el QR (`uri` sale de
        `totp.uri_otpauth`). Confirmar con `confirmar_totp` dentro de
        `TOTP_PENDIENTE_SEGUNDOS`.

        Levanta `TotpNoEnrolable` si no es enrolable (ver `_exigir_enrolable`)
        o si ya hay un secreto activo por archivo (hay que desactivarlo antes
        con `desactivar_totp`)."""
        self._exigir_enrolable()
        estado = self._totp_archivo.leer()
        if estado["secreto"]:
            raise TotpNoEnrolable(
                "ya hay un segundo factor activo por archivo: desactivarlo "
                "(desactivar_totp) antes de enrolar uno nuevo."
            )
        secreto = generar_secreto()
        if not self._totp_archivo.guardar(
            secreto=None, pendiente={"secreto": secreto, "creado": time.time()}
        ):
            raise RuntimeError("no se pudo guardar el secreto TOTP pendiente")
        return {"secreto": secreto, "uri": uri_otpauth(secreto, cuenta)}

    def confirmar_totp(self, codigo: str) -> bool:
        """Confirma el PENDIENTE de `iniciar_totp` y lo vuelve el secreto
        activo. `False` con codigo invalido, pendiente inexistente o pendiente
        vencido (mas de `TOTP_PENDIENTE_SEGUNDOS`). El codigo se valida igual
        que en el login (misma ventana, mismo `ultimo_paso_totp`: ese mismo
        codigo no sirve despues para entrar).

        Si el codigo vale: guarda el secreto como activo, RELEE el archivo
        para confirmar que quedo asi, y recien entonces marca el paso como
        usado. Si la escritura o la relectura no reflejan el cambio,
        `RuntimeError` — nunca se dice "activado" si no persistio."""
        self._exigir_enrolable()
        pendiente = self._totp_archivo.leer()["pendiente"]
        if not pendiente:
            return False
        if time.time() - float(pendiente["creado"]) > TOTP_PENDIENTE_SEGUNDOS:
            return False
        try:
            validador = Totp(pendiente["secreto"])
        except ValueError:
            return False
        paso = validador.paso_valido(codigo or "", ultimo_paso=self._estado.ultimo_paso_totp())
        if paso is None:
            return False
        nuevo_secreto = pendiente["secreto"]
        if not self._totp_archivo.guardar(secreto=nuevo_secreto, pendiente=None):
            raise RuntimeError("no se pudo confirmar el TOTP: la escritura fallo")
        if self._totp_archivo.leer()["secreto"] != nuevo_secreto:
            raise RuntimeError(
                "no se pudo confirmar el TOTP: la relectura no coincide con lo guardado"
            )
        self._estado.marcar_paso_totp(paso)
        return True

    def desactivar_totp(self, codigo: str) -> bool:
        """Apaga el segundo factor por archivo (y descarta cualquier
        pendiente). Exige un codigo valido del secreto ACTIVO, no reusado;
        `False` con codigo invalido o sin secreto activo. Solo aplica a
        origen "archivo" — con origen "entorno" levanta `TotpNoEnrolable`.

        Igual que `confirmar_totp`: guarda, RELEE para confirmar y recien
        entonces marca el paso como usado; si no persistio, `RuntimeError`."""
        self._exigir_enrolable()
        estado = self._totp_archivo.leer()
        if not estado["secreto"]:
            return False
        try:
            validador = Totp(estado["secreto"])
        except ValueError:
            return False
        paso = validador.paso_valido(codigo or "", ultimo_paso=self._estado.ultimo_paso_totp())
        if paso is None:
            return False
        if not self._totp_archivo.guardar(secreto=None, pendiente=None):
            raise RuntimeError("no se pudo desactivar el TOTP: la escritura fallo")
        if self._totp_archivo.leer()["secreto"] is not None:
            raise RuntimeError(
                "no se pudo desactivar el TOTP: la relectura no coincide con lo guardado"
            )
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
