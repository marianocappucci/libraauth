"""
Autenticacion por cookie firmada. Portado de `libracore.auth.SessionAuth`
sin cambios de diseno (misma firma de constructor, mismos metodos) para
que una eventual migracion del resto de la familia sea casi un drop-in.

Se deja afuera `AdminAuth` (backoffice de superadmin multi-cliente, no
aplica a un producto de instancia unica) y el endpoint `/auth/verify` de
`build_json_api_auth_router()` (login de `/docs/` de una landing publica
— este paquete no asume que el consumidor tenga una).
"""
import hmac
import os
from typing import Callable

from fastapi import APIRouter, Depends, Header, Response
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pydantic import BaseModel
from starlette.requests import Request
from starlette.exceptions import HTTPException


def _resolve_secret_key(dev_fallback: str, missing_error: str) -> str:
    secret = os.environ.get("SECRET_KEY", "")
    if secret:
        return secret
    if os.environ.get("ENV", "production") == "development":
        return dev_fallback
    # Fail-fast: sin esto, cualquiera puede forjar una cookie de sesion con
    # itsdangerous + un secreto publico conocido de antemano.
    raise RuntimeError(missing_error)


class SessionAuth:
    """Sesion del usuario final por cookie firmada. El producto instancia
    una vez, inyectando sus consultas a `UserRepository`."""

    def __init__(
        self,
        *,
        dev_secret_fallback: str,
        get_user_by_username: Callable[[str], dict | None],
        check_credentials: Callable[[str, str], object],
        cookie_name: str = "libra_session",
        max_age: int = 86400 * 7,
    ):
        self.secret_key = _resolve_secret_key(
            dev_secret_fallback,
            "SECRET_KEY no está seteado. No se levanta la app sin un secreto "
            "propio — para desarrollo local sin uno, setear ENV=development.",
        )
        self.cookie_name = cookie_name
        self.max_age = max_age
        self._get_user_by_username = get_user_by_username
        self._check_credentials_fn = check_credentials
        self._signer = URLSafeTimedSerializer(self.secret_key)

    def create_session_cookie(self, response, username: str):
        token = self._signer.dumps(username)
        response.set_cookie(
            self.cookie_name, token, httponly=True, samesite="lax", secure=True
        )

    def clear_session_cookie(self, response):
        response.delete_cookie(self.cookie_name)

    def get_current_user(self, request: Request) -> str | None:
        token = request.cookies.get(self.cookie_name)
        if not token:
            return None
        try:
            return self._signer.loads(token, max_age=self.max_age)
        except (BadSignature, SignatureExpired):
            return None

    def require_auth(self, request: Request) -> str:
        user = self.get_current_user(request)
        if not user:
            raise HTTPException(status_code=307, headers={"Location": "/login"})
        return user

    def require_admin(self, request: Request) -> dict:
        username = self.get_current_user(request)
        if not username:
            raise HTTPException(status_code=307, headers={"Location": "/login"})
        user = self._get_user_by_username(username)
        if not user or user.get("role") != "admin":
            raise HTTPException(status_code=307, headers={"Location": "/dashboard"})
        return user

    def require_role(self, *roles: str):
        """Factory de dependencia: exige que el usuario logueado tenga uno
        de los roles indicados."""

        def _dep(request: Request) -> dict:
            username = self.get_current_user(request)
            if not username:
                raise HTTPException(status_code=307, headers={"Location": "/login"})
            user = self._get_user_by_username(username)
            if not user or user.get("role") not in roles:
                raise HTTPException(status_code=307, headers={"Location": "/dashboard"})
            return user

        return _dep

    def check_credentials(self, username: str, password: str) -> bool:
        return self._check_credentials_fn(username, password) is not None


# ── Dependencias para APIs JSON puras ───────────────────────────────────────
#
# A diferencia de require_auth/require_role (redirect 307 a /login, pensado
# para apps server-rendered), estas dependencias devuelven 401/403 con
# cuerpo JSON — para SPAs sin pagina de login propia (como LibraDesk).
# Esperan `request.app.state.session_auth` (una `SessionAuth`) y
# `request.app.state.users` (contrato `UserRepository`: `check_credentials`,
# `get_by_username`).

class _LoginRequest(BaseModel):
    username: str
    password: str


class _UserOut(BaseModel):
    id: str
    username: str
    name: str
    role: str
    active: bool


# Solo para `POST /auth/verify` (opt-in, ver build_json_api_auth_router).
class _VerifyRequest(BaseModel):
    username: str
    password: str


class _VerifyResponse(BaseModel):
    valid: bool


def json_api_get_session_auth(request: Request) -> "SessionAuth":
    return request.app.state.session_auth


def json_api_get_current_user(
    request: Request, auth: "SessionAuth" = Depends(json_api_get_session_auth),
) -> dict:
    """401 JSON (no redirect) si no hay sesion valida o el usuario esta
    inactivo."""
    username = auth.get_current_user(request)
    if username is None:
        raise HTTPException(401, "not authenticated")
    users = request.app.state.users
    user = users.get_by_username(username)
    if user is None or not user["active"]:
        raise HTTPException(401, "not authenticated")
    return user


def json_api_require_role(*roles: str):
    """Dependency factory: 403 JSON a menos que el usuario logueado tenga
    uno de esos roles."""

    def _dependency(user: dict = Depends(json_api_get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(403, "forbidden")
        return user

    return _dependency


json_api_require_admin = json_api_require_role("admin")
json_api_require_staff = json_api_require_role("admin", "staff")


def build_json_api_auth_router(*, incluir_verify: bool = False) -> APIRouter:
    """Router `/auth` (login/logout/me) para SPAs sin backoffice
    server-rendered propio. Espera `request.app.state.users`/
    `request.app.state.session_auth` ya configurados al arrancar la app.

    `incluir_verify=True` agrega `POST /auth/verify`: el chequeo stateless de
    credenciales que usa el login de `/docs/` de la landing del producto
    (server-to-server con el secreto compartido `DOCS_AUTH_SECRET`, nunca crea
    cookie de sesion). Es opt-in porque no todo consumidor tiene landing —
    LibraDesk no la tenia cuando se creo este paquete, y por eso el endpoint
    habia quedado afuera.

    Que exista aca es lo que permite **borrar `libracore/auth.py`**: los tres
    productos con landing (Gestiolibra/MedLibra/VentaLibra) seguian importando
    el router de LibraCore justamente por este endpoint, asi que sin esto la
    migracion no se podia terminar sin romperles el `/docs/`.
    """
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/login", response_model=_UserOut)
    def login(data: _LoginRequest, request: Request, response: Response):
        users = request.app.state.users
        user = users.check_credentials(data.username, data.password)
        if user is None:
            raise HTTPException(401, "invalid credentials")
        json_api_get_session_auth(request).create_session_cookie(response, user["username"])
        return user

    @router.post("/logout")
    def logout(request: Request, response: Response):
        json_api_get_session_auth(request).clear_session_cookie(response)
        return {"ok": True}

    @router.get("/me", response_model=_UserOut)
    def me(user: dict = Depends(json_api_get_current_user)):
        return user

    if incluir_verify:
        @router.post("/verify", response_model=_VerifyResponse)
        def verify(
            data: _VerifyRequest,
            request: Request,
            x_internal_auth: str = Header(default=""),
        ):
            """Chequeo de credenciales stateless para el login de `/docs/` de
            la landing del producto. Server-to-server (secreto compartido
            `DOCS_AUTH_SECRET`), nunca crea cookie de sesion. **Falla cerrado
            si el secreto no esta configurado**: sin eso, un `DOCS_AUTH_SECRET`
            vacio en la app haria que cualquiera pudiera validar credenciales
            sin header."""
            secret = os.environ.get("DOCS_AUTH_SECRET", "")
            if not secret or not hmac.compare_digest(x_internal_auth, secret):
                raise HTTPException(401, "invalid internal auth")
            users = request.app.state.users
            user = users.check_credentials(data.username, data.password)
            return _VerifyResponse(valid=user is not None)

    return router
