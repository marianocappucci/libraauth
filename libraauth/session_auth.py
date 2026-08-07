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

from .auth_events import LOGIN, LOGIN_FALLIDO, LOGOUT, registrar_seguro
from .crypto import ClaveDeCifradoAusente
from .password_reset import EmailNotConfigured, InvalidResetToken
from .smtp_settings import SIN_CAMBIOS


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
    #: `True` sólo para el visitante de una demo publica. Es lo que le permite
    #: al frontend mostrarle **todos** los menus —incluidos los de
    #: administracion— sin mentir sobre su rol: el rol sigue siendo el que es,
    #: y los botones de escritura se siguen gateando por rol. Ver
    #: `json_api_require_role`.
    demo_readonly: bool = False


# Solo para `POST /auth/verify` (opt-in, ver build_json_api_auth_router).
class _VerifyRequest(BaseModel):
    username: str
    password: str


class _VerifyResponse(BaseModel):
    valid: bool


class _DemoInfo(BaseModel):
    """Respuesta de `GET /auth/demo`. `enabled` es siempre `True`: la ruta no
    se registra fuera de una demo, asi que un `False` no puede existir. Esta
    igual porque el frontend valida **la forma**, y una clave booleana
    explicita es lo que distingue este JSON de cualquier otro `200`."""
    enabled: bool
    username: str


# Solo para el par de endpoints de recuperacion (opt-in, ver
# build_json_api_auth_router).
class _ForgotPasswordRequest(BaseModel):
    # Username o email: el usuario no tiene por que saber con cual se dio de
    # alta, y aceptar los dos evita una pantalla que pregunte "¿esto es tu
    # usuario o tu correo?".
    identificador: str


class _ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


# Solo para el router de configuracion SMTP (opt-in, ver
# build_smtp_settings_router).
class _SmtpSettingsOut(BaseModel):
    """Lo que se le muestra a un admin. **No incluye la contrasena**, ni
    siquiera enmascarada con su largo real — eso ya diria cuantos caracteres
    tiene. Solo si hay una cargada."""

    origen: str          # "base" | "entorno"
    host: str
    port: int
    user: str
    from_email: str
    from_name: str
    password_definida: bool
    password_indescifrable: bool
    configurado: bool


class _SmtpSettingsIn(BaseModel):
    host: str
    port: int = 587
    user: str = ""
    # `None` explicito borra la contrasena; **omitir el campo** la deja como
    # esta. Son dos intenciones distintas y las dos son legitimas: editar el
    # remitente no tiene por que obligar a tipear la contrasena de nuevo, que
    # es justo lo que lleva a que alguien la anote en un papel para poder
    # repetirla. Se distinguen con `model_fields_set`, no por el valor.
    password: str | None = None
    from_email: str = ""
    from_name: str = ""


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


#: Metodos HTTP que sólo leen. El visitante de la demo pasa los cerrojos de rol
#: unicamente con estos: puede **ver** todo el sistema, no tocarlo.
_METODOS_DE_LECTURA = frozenset({"GET", "HEAD", "OPTIONS"})


def _con_bandera_demo(user: dict) -> dict:
    """El usuario, más `demo_readonly` si es el visitante de una demo.

    Va en la respuesta y no en la base: la bandera **depende del entorno de la
    instancia**, no de la fila. La misma fila copiada a la base de un cliente
    —por un restore, por ejemplo— no la lleva puesta.
    """
    return {**user, "demo_readonly": es_visitante_de_demo(user)}


def es_visitante_de_demo(user: dict | None) -> bool:
    """Si este usuario es el visitante de una demo publica.

    Devuelve `False` en cualquier instancia que no sea una demo, porque
    `demo_username()` ya devuelve `None` ahi — no alcanza con que el usuario se
    llame igual.
    """
    nombre = demo_username()
    return bool(nombre and user and user.get("username") == nombre)


def json_api_require_role(*roles: str):
    """Dependency factory: 403 JSON a menos que el usuario logueado tenga
    uno de esos roles.

    **Excepcion: el visitante de la demo pasa, pero sólo para leer**
    (2026-08-06, pedido del humano: *"que muestre todos los menus y todas las
    opciones como si fuera admin aunque no deje modificar esas cosas"*).

    🔴 **Por que no alcanzaba con darle un rol mas alto.** El auto-login se
    niega a entregar `admin` —y con `DEMO_PASSWORD` puesta, el arranque corta si
    el usuario de demo quedo admin—, asi que la unica forma de que vea las
    pantallas de administracion sin volverse administrador es esta: el rol
    sigue siendo el que es, y lo que se abre es la **lectura**.

    Lo que esto NO abre: cualquier POST/PUT/PATCH/DELETE sigue exigiendo el
    rol. El visitante ve Configuracion, usuarios y logs; no puede guardar,
    borrar ni crear en ninguno.
    """

    def _dependency(
        request: Request, user: dict = Depends(json_api_get_current_user),
    ) -> dict:
        if user["role"] in roles:
            return user
        if request.method in _METODOS_DE_LECTURA and es_visitante_de_demo(user):
            return user
        raise HTTPException(403, "forbidden")

    return _dependency


json_api_require_admin = json_api_require_role("admin")
json_api_require_staff = json_api_require_role("admin", "staff")


# ── Token de servicio (v0.7.0) ───────────────────────────────────────────────
#
# **Por que existe.** El backoffice de la suite (`admin.<producto>.com.ar`)
# administra VARIAS instancias del mismo producto y necesita leer y escribir la
# config de cada una. No es un usuario de ninguna: no tiene fila en la tabla
# `usuarios` de ningun cliente, asi que `json_api_require_admin` lo rechaza
# siempre. La alternativa —que el backoffice abriera la base de cada instancia—
# no funciona: la contrasena SMTP se cifra con una clave derivada del
# `SECRET_KEY` de la instancia, y un solo proceso no puede tener N secretos en
# su entorno. Hablando por HTTP, cada instancia sigue cifrando con su propia
# clave en su propio proceso.
#
# **Por que es seguro adoptarlo.** Es opt-in por ausencia: si la instancia no
# define `LIBRA_SERVICE_TOKEN`, esta funcion devuelve False sin mirar el header
# y el flujo cae exactamente en el de siempre. Una instancia que actualiza a
# v0.7.0 y no toca su compose no cambia de comportamiento en nada.
#
# El patron ya existe en la familia: `libracore.admin.app` usa este mismo header
# con `DOCS_AUTH_SECRET` para el login de `/docs/` de las landings.
SERVICE_TOKEN_HEADER = "x-internal-auth"
SERVICE_TOKEN_ENV = "LIBRA_SERVICE_TOKEN"

# Identidad que se le atribuye a una request autenticada por token. No es un
# usuario real y no tiene `id`: si algun dia un endpoint audita quien hizo un
# cambio, tiene que poder distinguir "lo hizo el proveedor desde el backoffice"
# de "lo hizo un admin del cliente".
SERVICE_USER = {
    "id": None,
    "username": "@servicio",
    "name": "Backoffice de la suite",
    "role": "admin",
    "active": True,
    "es_servicio": True,
}


def token_de_servicio_valido(request: Request) -> bool:
    esperado = os.environ.get(SERVICE_TOKEN_ENV, "")
    if not esperado:
        return False
    recibido = request.headers.get(SERVICE_TOKEN_HEADER, "")
    # `compare_digest` y no `==`: comparar tokens con el operador normal filtra
    # su largo y su prefijo por el tiempo que tarda en devolver False.
    return bool(recibido) and hmac.compare_digest(recibido, esperado)


def json_api_require_admin_o_servicio(request: Request) -> dict:
    """Rol admin del producto **o** token de servicio valido.

    El token se chequea primero y a proposito: una request del backoffice no
    trae cookie de sesion, asi que evaluar la sesion antes daria 401 y no
    llegaria nunca a mirar el header.
    """
    if token_de_servicio_valido(request):
        return dict(SERVICE_USER)
    usuario = json_api_get_current_user(request, request.app.state.session_auth)
    if usuario["role"] != "admin":
        raise HTTPException(403, "forbidden")
    return usuario


#: Variable de entorno que enciende `POST /auth/demo`.
DEMO_MODE = "DEMO_MODE"

#: Con que usuario entra el visitante de la demo.
DEMO_USERNAME = "DEMO_USERNAME"

#: Contrasena **conocida** del usuario de la demo, para poder decirle a un
#: cliente potencial "entra con demo/demo". Opcional: sin esto el usuario se
#: crea con una contrasena aleatoria y solo se entra por `POST /auth/demo`.
#: Ver `demo_password()` y `bootstrap.ensure_demo_user`.
DEMO_PASSWORD = "DEMO_PASSWORD"

#: Roles que el auto-login **nunca** entrega, por mas que el usuario nombrado
#: en `DEMO_USERNAME` los tenga. Ver `demo_username`.
ROLES_PROHIBIDOS_EN_DEMO = ("admin",)


def demo_username() -> str | None:
    """El usuario del auto-login, o `None` si la demo no esta encendida.

    🔴 **Son DOS cerrojos y es a proposito**: hace falta `DEMO_MODE` encendido
    *y* `DEMO_USERNAME` con un nombre. Un solo flag booleano se prende por
    accidente al copiar un `.env` de una instancia a otra; que ademas haya que
    nombrar al usuario obliga a que alguien haya pensado en ese usuario para
    esa instancia.

    Cuando devuelve `None` la ruta **ni se registra**: en produccion
    `POST /auth/demo` no existe, y lo que contesta es lo que conteste esa app
    para una ruta que no tiene — nunca un 403, que le confirmaria a quien barre
    que el endpoint esta ahi.

    > ⚠️ **Medido el 2026-08-06, y no es lo que decia esta docstring.** En los
    > productos que sirven la SPA con un catch-all (LibraDesk y compania), una
    > instancia normal contesta **405**, no 404: el catch-all matchea la ruta
    > por GET, asi que el POST cae en "metodo no permitido". Da igual para la
    > seguridad, pero **no** para escribir un chequeo: un 405 es tambien lo que
    > da una ruta de demo apagada, asi que ese codigo por si solo no distingue
    > "no hay demo" de "hay demo mal configurada".
    """
    if os.environ.get(DEMO_MODE, "").strip().lower() not in ("1", "true", "yes", "si"):
        return None
    return os.environ.get(DEMO_USERNAME, "").strip() or None


def demo_password() -> str | None:
    """La contrasena conocida del usuario de la demo, si se declaro una.

    Devuelve `None` si esta instancia no es una demo, **aunque
    `DEMO_PASSWORD` este puesta**. Es el mismo cerrojo que `demo_username()`
    y por la misma razon: la contrasena debil no puede filtrarse a la
    instancia de un cliente por copiar un `.env`, porque sin `DEMO_MODE` +
    `DEMO_USERNAME` esta funcion no la mira.

    Que exista una contrasena tipeable es un pedido explicito del negocio
    (2026-08-06): pasarle a un cliente potencial `demo.<producto>.com.ar` y
    decirle "entra con usuario demo y contrasena demo". El boton de auto-login
    cubre a quien llega solo; esto cubre a quien recibe el dato por telefono.
    """
    if not demo_username():
        return None
    return os.environ.get(DEMO_PASSWORD, "") or None


def build_json_api_auth_router(
    *, incluir_verify: bool = False, incluir_password_reset: bool = False,
    incluir_demo: bool = False,
) -> APIRouter:
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

    `incluir_password_reset=True` agrega `POST /auth/forgot-password` y
    `POST /auth/reset-password` (v0.5.0). Es opt-in porque **requiere que el
    producto haya configurado `app.state.password_reset`** con un
    `PasswordResetService` (que a su vez necesita SMTP y una pantalla propia
    donde aterrice el link): prenderlo sin eso seria publicar dos endpoints
    que fallan.
    """
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/login", response_model=_UserOut)
    def login(data: _LoginRequest, request: Request, response: Response):
        users = request.app.state.users
        user = users.check_credentials(data.username, data.password)
        if user is None:
            # Se anota el username TIPEADO, que puede no existir: un intento
            # contra un usuario inexistente es la firma de un barrido, y es
            # el dato que se pierde si solo se registran los logins que salen
            # bien. No se anota nada de la contrasena, ni su largo.
            registrar_seguro(request, LOGIN_FALLIDO, data.username)
            raise HTTPException(401, "invalid credentials")
        json_api_get_session_auth(request).create_session_cookie(response, user["username"])
        registrar_seguro(request, LOGIN, user["username"])
        return _con_bandera_demo(user)

    @router.post("/logout")
    def logout(request: Request, response: Response):
        # El username sale de la cookie, no del cuerpo: `/logout` no recibe
        # nada, y una sesion ya vencida cierra igual pero sin nombre que
        # anotar. Se registra antes de borrar la cookie, obviamente.
        username = json_api_get_session_auth(request).get_current_user(request) or ""
        json_api_get_session_auth(request).clear_session_cookie(response)
        if username:
            registrar_seguro(request, LOGOUT, username)
        return {"ok": True}

    @router.get("/me", response_model=_UserOut)
    def me(user: dict = Depends(json_api_get_current_user)):
        return _con_bandera_demo(user)

    # `POST /auth/demo` — el boton "Entrar a la demo" de la pantalla de login.
    #
    # Se registra **solo si el consumidor lo pidio Y las dos variables de
    # entorno estan puestas**. En cualquier otra instancia la ruta no existe
    # (ver `demo_username` para que contesta realmente una app con catch-all).
    if incluir_demo and demo_username():
        @router.get("/demo", response_model=_DemoInfo)
        def demo_info():
            """Le dice al frontend si esta instancia es una demo publica.

            Existe porque el boton **no se puede decidir en tiempo de build**:
            la imagen de la demo y la del cliente salen del mismo codigo, asi
            que la pantalla de login tiene que preguntarselo a la instancia.

            🔴 **Devuelve JSON y el frontend tiene que exigir JSON**, no un
            `200`. En los productos que sirven la SPA con un catch-all, un GET
            a una ruta inexistente contesta `200` con el `index.html` — o sea
            que "me contesto 200" es cierto tambien en la instancia de un
            cliente, y un boton condicionado a eso aparece en todas. Medido el
            2026-08-06 contra `demo.libradesk.com.ar/auth/inexistente`.

            **No devuelve la contrasena**, aunque `DEMO_PASSWORD` exista y sea
            publica por diseno: un endpoint sin autenticar que reparte
            contrasenas es un patron que despues alguien copia a un lugar
            donde no da lo mismo. El `username` si, porque es lo que el boton
            necesita mostrar.
            """
            return {"enabled": True, "username": demo_username()}

        @router.post("/demo", response_model=_UserOut)
        def demo(request: Request, response: Response):
            """Entra a la demo publica sin credenciales.

            No recibe cuerpo y no hay contrasena que adivinar: el usuario sale
            de `DEMO_USERNAME`, que lo fija quien despliega la instancia.

            🔴 **Nunca entrega un rol de la lista prohibida.** El chequeo esta
            aca y no en el despliegue porque el rol del usuario puede cambiar
            despues —alguien lo promueve desde el ABM de la propia demo— y
            entonces el auto-login empezaria a repartir admin sin que nadie
            haya tocado el `.env`. Es la clase de cambio que no deja rastro
            hasta que ya paso.
            """
            username = demo_username()
            users = request.app.state.users
            user = users.get_by_username(username)
            if user is None or not user.get("active"):
                # 503 y no 404: la ruta existe y esta bien configurada, lo que
                # falta es el usuario en la base — o sea, la instancia todavia
                # no termino de sembrarse. Un 404 diria "no hay demo aca", que
                # es falso y manda a mirar el lugar equivocado.
                raise HTTPException(503, "demo user not provisioned")
            if user["role"] in ROLES_PROHIBIDOS_EN_DEMO:
                raise HTTPException(503, "demo user has a forbidden role")
            json_api_get_session_auth(request).create_session_cookie(response, user["username"])
            registrar_seguro(request, LOGIN, user["username"])
            return _con_bandera_demo(user)

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

    if incluir_password_reset:
        @router.post("/forgot-password")
        def forgot_password(data: _ForgotPasswordRequest, request: Request):
            """Pide el mail de recuperacion.

            **Responde siempre lo mismo**, exista o no el usuario: es un
            endpoint publico y sin sesion, y una respuesta distinta lo
            convertiria en un buscador de usuarios y correos dados de alta.
            """
            servicio = request.app.state.password_reset
            try:
                servicio.request_reset(data.identificador)
            except EmailNotConfigured:
                # 503 y no 200: esto no depende de si el usuario existe, asi
                # que decirlo no filtra nada — y callarlo dejaria a la persona
                # esperando para siempre un mail que nadie puede mandar.
                raise HTTPException(503, "el envío de correo no está configurado")
            return {"ok": True}

        @router.post("/reset-password", response_model=_UserOut)
        def reset_password(data: _ResetPasswordRequest, request: Request):
            servicio = request.app.state.password_reset
            try:
                resultado = servicio.reset(data.token, data.new_password)
            except InvalidResetToken:
                raise HTTPException(400, "el enlace no es válido o ya venció")
            except ValueError as exc:
                raise HTTPException(422, str(exc))
            # Se devuelve el usuario completo (mismo contrato que /auth/me) para
            # que la pantalla pueda saludar por nombre sin una llamada mas.
            # **No se crea sesion**: cambiar la contrasena no loguea: quien la
            # cambio tiene que entrar con ella, que ademas confirma que quedo
            # bien.
            users = request.app.state.users
            return users.get_by_id(resultado["id"])

    return router


def build_smtp_settings_router(*, prefix: str = "/admin/smtp") -> APIRouter:
    """Router de configuracion SMTP por backoffice (v0.6.0).

    Espera `request.app.state.smtp_settings` con un
    `SmtpSettingsRepository`. **Es opt-in y va aparte del router de `/auth`**
    por dos razones: es de administracion y no de autenticacion, y montarlo
    sin el repositorio configurado publicaria endpoints que fallan — el mismo
    criterio que `incluir_password_reset`.

    **Todo exige rol admin.** Un endpoint que devuelve el servidor y la
    cuenta de correo de la instancia no es informacion publica, y el `PUT`
    permite redirigir a donde salen los mails de recuperacion de contrasena
    de todos los usuarios: quien pueda escribir aca puede hacerse mandar los
    enlaces de reset ajenos.

    `prefix` es configurable porque los consumidores no montan sus APIs
    igual: los 4 FastAPI cuelgan de `/api`, y Contalibra/Restolibra tienen su
    propio arbol.
    """
    router = APIRouter(prefix=prefix, tags=["smtp"])

    @router.get("", response_model=_SmtpSettingsOut)
    def leer(request: Request, _: dict = Depends(json_api_require_admin_o_servicio)):
        return request.app.state.smtp_settings.estado()

    @router.put("", response_model=_SmtpSettingsOut)
    def guardar(
        data: _SmtpSettingsIn,
        request: Request,
        _: dict = Depends(json_api_require_admin_o_servicio),
    ):
        repo = request.app.state.smtp_settings
        # Omitir `password` = dejarla como esta. Mandarla en `null` o vacia =
        # borrarla. Ver el comentario en `_SmtpSettingsIn`.
        if "password" in data.model_fields_set:
            password = data.password if data.password is not None else ""
        else:
            password = SIN_CAMBIOS
        try:
            repo.save(
                host=data.host, port=data.port, user=data.user,
                password=password,
                from_email=data.from_email, from_name=data.from_name,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except ClaveDeCifradoAusente as exc:
            # 500 y no 422: no es un error del que manda el formulario, es
            # que a la instancia le falta el secreto del entorno. Y **no se
            # guarda nada** — antes que persistir la contrasena en claro,
            # falla.
            raise HTTPException(500, str(exc))
        return repo.estado()

    @router.delete("", response_model=_SmtpSettingsOut)
    def borrar(request: Request, _: dict = Depends(json_api_require_admin_o_servicio)):
        """Vuelve la instancia a leer el SMTP del entorno, que es como
        funcionaban todas antes de la v0.6.0."""
        repo = request.app.state.smtp_settings
        repo.delete()
        return repo.estado()

    return router
