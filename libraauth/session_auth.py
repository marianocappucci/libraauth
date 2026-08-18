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
from .demo_codigos import CodigoInvalido, DIAS_DEFECTO, USOS_DEFECTO
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
        """Rol admin en las rutas HTML (redirige, no devuelve 403).

        Misma excepción de lectura que los guards JSON: el visitante de una
        demo pública pasa **sólo** con métodos de lectura. Sin esto la demo
        quedaba incoherente — veía la pantalla de Libros de IVA, que su API ya
        le permite, y el botón de exportar lo mandaba al dashboard.
        """
        username = self.get_current_user(request)
        if not username:
            raise HTTPException(status_code=307, headers={"Location": "/login"})
        user = self._get_user_by_username(username)
        if user and user.get("role") == "admin":
            return user
        if user and permite_lectura_de_demo(request, user):
            return user
        raise HTTPException(status_code=307, headers={"Location": "/dashboard"})

    def require_role(self, *roles: str):
        """Factory de dependencia: exige que el usuario logueado tenga uno
        de los roles indicados."""

        def _dep(request: Request) -> dict:
            username = self.get_current_user(request)
            if not username:
                raise HTTPException(status_code=307, headers={"Location": "/login"})
            user = self._get_user_by_username(username)
            if user and user.get("role") in roles:
                return user
            # Misma excepción de lectura que los guards JSON: sin ella el
            # visitante ve la pantalla y el botón de exportar lo expulsa.
            if user and permite_lectura_de_demo(request, user):
                return user
            raise HTTPException(status_code=307, headers={"Location": "/dashboard"})

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
    #: El nombre de la empresa que usa la instancia, para mostrarlo debajo del
    #: nombre del producto en el sidebar (`getUserSubtitle` de libra-ui).
    #:
    #: Va en el usuario y no en un endpoint aparte porque es lo que el Layout ya
    #: sabe leer: Contalibra y Restolibra lo vienen mostrando asi desde siempre,
    #: pero arman su propio `/auth/me`. Los cuatro que usan ESTE router no tenian
    #: de donde sacarlo, y por eso eran los cuatro que no lo mostraban.
    #:
    #: `None` cuando el producto no configura `get_empresa_nombre`: el sidebar
    #: simplemente no dibuja el subtitulo, que es lo que pasaba hasta ahora.
    empresa_nombre: str | None = None


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
    #: Desde v0.26.0 es **siempre `True`**, y esta igual por lo mismo que
    #: `enabled`: la pantalla de login tiene que decidir si dibuja un boton
    #: suelto o un boton con campo de codigo, y eso no se puede resolver en
    #: tiempo de build. Un frontend viejo que ignore la clave sigue viendo el
    #: boton — y recibe un `401` con el mensaje que explica que falta.
    requiere_codigo: bool = True


class _DemoLoginRequest(BaseModel):
    """Cuerpo de `POST /auth/demo`. Antes no recibia nada."""
    codigo: str = ""


class _DemoCodigoIn(BaseModel):
    """Alta de un codigo, desde el backoffice."""
    etiqueta: str = ""
    dias: int = DIAS_DEFECTO
    usos_max: int = USOS_DEFECTO


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


class _CambioPasswordRequest(BaseModel):
    # La actual **es obligatoria y no es un tramite**: sin ella, una sesion
    # robada —una cookie que quedo abierta en una maquina compartida— alcanza
    # para apropiarse de la cuenta para siempre. Pidiendola, el robo de sesion
    # sigue siendo grave pero es temporal.
    current_password: str
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


def permite_lectura_de_demo(request: Request, user: dict | None) -> bool:
    """Si este pedido es "el visitante de la demo mirando", y por lo tanto
    puede pasar un cerrojo de rol.

    Existe como funcion publica porque **hay productos con su propio guard**:
    Contalibra y Restolibra tienen `require_role_json` en su `api_auth.py` y no
    pasan por `json_api_require_role`. Que la regla viva acá evita que la
    copien —y que dentro de un mes uno de los dos tenga una version distinta de
    "que puede ver un visitante".
    """
    return request.method in _METODOS_DE_LECTURA and es_visitante_de_demo(user)


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
    if usuario["role"] == "admin":
        return usuario
    # Misma excepción de lectura que `json_api_require_role`. Hace falta acá
    # aparte porque este guard **no pasa por aquél**: el router de usuarios de
    # los seis productos cuelga de éste, y con la excepción sólo en el otro el
    # visitante veía `403` justo en la pantalla de Usuarios. Lo encontró
    # probarlo contra la demo desplegada, no la suite.
    if request.method in _METODOS_DE_LECTURA and es_visitante_de_demo(usuario):
        return usuario
    raise HTTPException(403, "forbidden")


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


def _prefijo_tipeado(data) -> str:
    """Los primeros 4 caracteres del codigo que llego, para el log de accesos.

    **Nunca el codigo entero.** Alcanza para reconocer un barrido en el log y
    no deja un codigo valido escrito en una tabla que se exporta con el backup.
    """
    return ((data.codigo if data else "") or "")[:4]


def build_json_api_auth_router(
    *, incluir_verify: bool = False, incluir_password_reset: bool = False,
    incluir_demo: bool = False, min_password_length: int = 6,
    get_empresa_nombre: Callable[[Request], str | None] | None = None,
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

    `POST /auth/change-password` va **siempre**, sin flag, a diferencia de los
    dos de arriba: no depende de SMTP ni de ninguna pantalla — solo del
    repositorio de usuarios, que este router ya exige para poder loguear. Un
    opt-in aca solo lograria que algunos productos se quedaran sin la unica
    forma de cambiar la clave estando adentro.

    `min_password_length` es el minimo que se le exige a la clave nueva. Por
    defecto **6, el mismo que `PasswordResetService`**: dos caminos que cambian
    la contrasena del mismo usuario no pueden pedir cosas distintas — el que
    fuera mas laxo volveria decorativo al otro.

    `get_empresa_nombre` es la funcion que devuelve el nombre de la empresa de
    la instancia, para que salga en el usuario y el sidebar lo muestre debajo
    del nombre del producto. Recibe el `Request` porque el dato vive en la
    configuracion del producto (una tabla, un env, `app.state`), no en el
    usuario: la empresa es de la INSTANCIA, no de la fila. Es opcional; sin
    ella el campo va en `None` y el sidebar no dibuja subtitulo, que es el
    comportamiento de siempre.

    > Contalibra y Restolibra ya mostraban el nombre de la empresa porque arman
    > su propio `/auth/me`. Los cuatro que usan este router —Gestiolibra,
    > MedLibra, VentaLibra, LibraDesk— no tenian de donde sacarlo, y por eso
    > eran exactamente los cuatro que no lo mostraban.
    """
    router = APIRouter(prefix="/auth", tags=["auth"])

    def _salida(user: dict, request: Request) -> dict:
        """El usuario tal como sale por la API: bandera de demo + empresa.

        Todas las respuestas que devuelven un usuario pasan por aca. Si el
        nombre de la empresa se agregara solo en `/me`, el frontend lo tendria
        despues de recargar y no despues de loguear — y el sidebar cambiaria de
        forma sin que nadie tocara nada.
        """
        datos = _con_bandera_demo(user)
        if get_empresa_nombre is not None:
            datos["empresa_nombre"] = get_empresa_nombre(request)
        return datos

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
        return _salida(user, request)

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
    def me(request: Request, user: dict = Depends(json_api_get_current_user)):
        return _salida(user, request)

    @router.post("/change-password", response_model=_UserOut)
    def change_password(
        data: _CambioPasswordRequest,
        request: Request,
        user: dict = Depends(json_api_get_current_user),
    ):
        """Cambia la contrasena del usuario **de la sesion**, pidiendo la actual.

        Es la unica forma de cambiarla estando adentro: `/auth/reset-password`
        necesita un token que llega por mail, o sea que alguien logueado tenia
        que salir de la aplicacion —y depender del SMTP— para hacer algo que no
        lo necesita.

        **El usuario sale de la cookie, nunca del cuerpo.** Es lo que impide que
        esto sea un cambiador de contrasenas ajenas: no hay ningun `user_id` que
        mandar. Cambiarle la clave a otro es tarea del ABM de usuarios, que pide
        rol admin.

        > 🔑 Media defensa la pone **Pydantic**, que descarta los campos extra
        > del cuerpo: mandar `user_id` no hace nada porque el modelo no lo tiene.
        > Se verifico rompiendolo — un `getattr(data, "user_id", ...)` sobre el
        > modelo actual es un no-op y el test sigue verde; hace falta **agregar
        > el campo al modelo** para que se ponga rojo. O sea: el dia que alguien
        > le sume un campo a `_CambioPasswordRequest` "porque el ABM lo
        > necesita", ese es el momento en que esto se vuelve peligroso.

        No se toca la sesion en curso: quien acaba de cambiar su clave sigue
        trabajando. Cerrarla lo dejaria afuera justo despues de un cambio
        exitoso, que se lee como un error.
        """
        users = request.app.state.users
        # `check_credentials` y no una comparacion propia: es el unico lugar del
        # paquete que sabe verificar un hash, y ademas corre en tiempo constante.
        if users.check_credentials(user["username"], data.current_password) is None:
            # Se registra como intento fallido igual que un login: alguien
            # probando contrasenas contra una sesion abierta es exactamente la
            # senal que este log tiene que dejar.
            registrar_seguro(request, LOGIN_FALLIDO, user["username"])
            raise HTTPException(400, "la contraseña actual no es correcta")

        if len(data.new_password or "") < min_password_length:
            raise HTTPException(
                422,
                f"la contraseña debe tener al menos {min_password_length} caracteres",
            )
        # Que la nueva sea distinta: un formulario que acepta la misma clave
        # devuelve "listo" sin haber cambiado nada, y quien la cambio por
        # sospecha de filtracion se queda creyendo que la roto.
        if data.new_password == data.current_password:
            raise HTTPException(422, "la contraseña nueva tiene que ser distinta")

        users.update_password(user["id"], data.new_password)
        return _salida(users.get_by_id(user["id"]), request)

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
            return {"enabled": True, "username": demo_username(),
                    "requiere_codigo": True}

        @router.post("/demo", response_model=_UserOut)
        def demo(request: Request, response: Response,
                 data: _DemoLoginRequest | None = None):
            """Entra a la demo publica con un codigo de acceso.

            El usuario sale de `DEMO_USERNAME`, que lo fija quien despliega la
            instancia; lo que hay que traer es el **codigo**, emitido desde el
            backoffice (ver `build_demo_codigos_router`).

            🔴 **Hasta v0.25.x este endpoint no recibia nada y entraba de una.**
            Cualquiera que supiera la URL de `demo.<producto>.com.ar` estaba
            adentro. Desde v0.26.0 hace falta un codigo vigente, con
            vencimiento y tope de usos.

            🔴 **Falla cerrado si el repositorio no esta configurado**, y esa
            es la parte que importa al subir el pin: una instancia demo que
            actualice el motor sin cablear `app.state.demo_codigos` deja de
            dejar entrar, en vez de seguir abierta. Es incomodo a proposito —
            la alternativa (si no hay repo, entrar sin codigo) convierte un
            olvido de configuracion en una demo publica abierta, que es
            exactamente lo que este cambio existe para cerrar.

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

            # 🔑 **El codigo se consume aca, y no arriba.** Consumiendolo antes
            # de resolver al usuario, una instancia mal sembrada devolveria 503
            # habiendo gastado un uso de un codigo valido: el visitante pierde
            # intentos por un problema que no es suyo. Consumido aca, el gasto
            # ocurre inmediatamente antes de crear la sesion.
            codigos = getattr(request.app.state, "demo_codigos", None)
            if codigos is None:
                # Fail-closed. Una instancia demo que suba el pin del motor sin
                # cablear el repositorio deja de dejar entrar, en vez de seguir
                # abierta como antes de v0.26.0.
                raise HTTPException(503, "demo access codes not configured")
            try:
                codigos.consumir(data.codigo if data else "")
            except CodigoInvalido as exc:
                # El intento se anota con el PREFIJO del codigo tipeado, no
                # con el codigo: alcanza para ver un barrido en el log de
                # accesos y no deja un codigo valido escrito en una tabla que
                # se exporta.
                registrar_seguro(
                    request, LOGIN_FALLIDO,
                    f"{username} (codigo {_prefijo_tipeado(data)}…)")
                # 🔴 **Un solo mensaje para los cuatro motivos.** Distinguir
                # "no existe" de "vencido" o "agotado" le dice a quien prueba
                # codigos al azar cual de sus intentos estuvo cerca. El motivo
                # real viaja en `exc.motivo` para el log del servidor.
                raise HTTPException(
                    401, "el código no es válido o ya venció") from exc

            json_api_get_session_auth(request).create_session_cookie(response, user["username"])
            registrar_seguro(request, LOGIN, user["username"])
            return _salida(user, request)

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


def build_demo_codigos_router(*, prefix: str = "/admin/demo-codigos") -> APIRouter:
    """ABM de codigos de acceso a la demo, para el backoffice (v0.26.0).

    Espera `request.app.state.demo_codigos` con un `DemoCodigoRepository`.
    Opt-in y aparte del router de `/auth` por lo mismo que
    `build_smtp_settings_router`: es administracion, no autenticacion, y
    montarlo sin el repositorio publicaria endpoints que fallan.

    **Todo exige rol admin o token de servicio.** El backoffice llega con
    `X-Internal-Auth` por la red interna de Docker; un admin de la propia
    instancia tambien puede, que es lo que permite emitir un codigo sin
    depender del backoffice.

    🔴 **Se monta solo en la instancia DEMO.** El guard de arriba lo permitiria
    en cualquiera, pero una instancia de cliente no tiene demo que abrir: ahi
    la tabla existiria vacia y los endpoints no significarian nada. Quien
    monta decide, igual que con `incluir_demo`.
    """
    router = APIRouter(prefix=prefix, tags=["demo"])

    @router.get("")
    def listar(request: Request, _: dict = Depends(json_api_require_admin_o_servicio)):
        """Los codigos emitidos. **Ninguno trae el codigo en si** — ver el
        docstring de `demo_codigos`: de la base no sale nada usable."""
        return {"codigos": request.app.state.demo_codigos.listar()}

    @router.post("", status_code=201)
    def emitir(
        data: _DemoCodigoIn,
        request: Request,
        usuario: dict = Depends(json_api_require_admin_o_servicio),
    ):
        """Emite un codigo y lo devuelve **en claro por unica vez**.

        Quien llama tiene que mostrarlo en ese momento: no hay forma de
        recuperarlo despues, y volver a pedirlo es emitir otro.
        """
        try:
            return request.app.state.demo_codigos.crear(
                etiqueta=data.etiqueta, dias=data.dias, usos_max=data.usos_max,
                emitido_por=usuario.get("username", ""),
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.delete("/{codigo_id}")
    def revocar(
        codigo_id: int,
        request: Request,
        _: dict = Depends(json_api_require_admin_o_servicio),
    ):
        """Corta un codigo sin borrar la fila: interesa saber que existio y
        cuantas veces se uso antes de cortarlo."""
        try:
            return request.app.state.demo_codigos.revocar(codigo_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    return router
