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
- **Rate limiting de login en memoria del proceso**. Alcanza porque el
  backoffice corre como un unico proceso; se resetea si reinicia, lo que es
  aceptable para un panel de bajo trafico. No sirve tal cual si algun dia corre
  con varios workers.
"""
import hmac
import os
import threading
import time

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.exceptions import HTTPException
from starlette.requests import Request

from .session_auth import _resolve_secret_key


class AdminAuth:
    """Autenticacion del backoffice de superadmin (ver docstring del modulo)."""

    def __init__(
        self,
        *,
        dev_secret_fallback: str,
        cookie_name: str = "cladmin_session",
        max_age: int = 86400 * 3,
        login_max_intentos: int = 5,
        login_ventana_segundos: int = 15 * 60,
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
        self._intentos_fallidos: dict[str, list[float]] = {}
        self._intentos_lock = threading.Lock()

    def check_credentials(self, username: str, password: str) -> bool:
        if not self.panel_pass:
            # Sin contrasena configurada se rechaza todo (fail-closed): si no,
            # una instancia mal configurada dejaria entrar con password vacia.
            return False
        return hmac.compare_digest(
            username or "", self.panel_user
        ) and hmac.compare_digest(password or "", self.panel_pass)

    def rate_limit_excedido(self, ip: str) -> bool:
        if not ip:
            return False
        ahora = time.time()
        with self._intentos_lock:
            vigentes = [
                t
                for t in self._intentos_fallidos.get(ip, [])
                if ahora - t < self.login_ventana_segundos
            ]
            self._intentos_fallidos[ip] = vigentes
            return len(vigentes) >= self.login_max_intentos

    def registrar_intento_fallido(self, ip: str):
        if not ip:
            return
        with self._intentos_lock:
            self._intentos_fallidos.setdefault(ip, []).append(time.time())

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
