"""
Contrato único de la API de usuarios de la familia Libra: los MODELOS
PÚBLICOS y la factory `build_users_router()` que reemplaza las ocho copias
que hoy tiene cada producto (`app/routers/users.py` en cuatro,
`app/routers/usuarios.py` en dos, `app/web/api/usuarios.py` +
`app/db_usuarios.py` en los dos restantes).

Decisión del humano, 2026-09-13 (ver `DECISIONS.md`, ADR-018): **un solo
contrato, definido en un solo lugar, que no pueda volver a divergir.** Hasta
hoy los ocho routers eran ocho copias con pequeñas diferencias -- alguna
protección que unas tenían y otras no, un `PUT` que en Contalibra dejaba
escapar un `ValueError` como 500, un `DELETE` que en unos responde `204` y en
otros `200`. La tabla función × producto está en `README.md`, sección "Router
de usuarios unificado".

**Modelos públicos y no privados** (a diferencia de los de `session_auth.py`,
con prefijo `_`): los importan tanto el backoffice (`UsuarioIn`/`UsuarioUpdate`
de `libra-backoffice`, que hoy los redefine) como `libraauth.testing`, para
armar los mismos payloads que arma la pantalla. Que sean el mismo objeto de
Python -- no una copia con la misma forma -- es lo que impide que backoffice,
test de contrato y factory diverjan de nuevo.

**`role` es `str` y no un `Literal`** a propósito: el vocabulario de roles NO
es el mismo en toda la familia (`("admin", "staff")` en seis productos,
`("admin", "operador", "cajero")` en Contalibra, con `"mozo"` sumado en
Restolibra). Un `Literal` fijo en el modelo público rechazaría un rol válido
de esos dos productos antes de que la request llegue al router. La validación
contra la tupla de roles de la instancia la hace `build_users_router()`, con
la tupla que le pasa cada producto -- ver su docstring.
"""
from collections.abc import Callable
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from .repository import UsernameTaken, UsuarioConHistorial

if TYPE_CHECKING:
    from .repository import UserRepository

#: Mínimo de largo de contraseña, en alta y en reset de la de otro usuario.
#: **Una sola constante para las dos operaciones** -- antes cada router tenía
#: la suya (Contalibra/Restolibra exigían 6 en el alta; los otros seis no
#: exigían nada en el alta y sólo rechazaban la cadena vacía en el reset).
#: Con esto, resetearle la contraseña a alguien a algo más corto que lo que
#: se le exigiría a un usuario nuevo deja de ser posible en ningún producto.
MIN_PASSWORD_LENGTH = 6

#: El rol que cuenta como "administrador" para las protecciones de abajo.
#: Es literal `"admin"` en los ocho productos hoy -- ver la tabla de
#: `README.md` -- así que el default alcanza para los ocho; queda como
#: parámetro (`admin_role=` en `build_users_router`) por si algún día deja de
#: serlo, no porque hoy varíe.
ADMIN_ROLE = "admin"


# ── Modelos públicos del contrato ────────────────────────────────────────────


class UsuarioAlta(BaseModel):
    """Cuerpo de `POST {prefix}`. El repositorio (`UserRepository.create`)
    crea siempre `active=True`: ningún producto de referencia acepta darlo de
    alta ya desactivado."""

    username: str
    name: str
    password: str
    #: Validado contra la tupla `roles` de la instancia por
    #: `build_users_router()`, no acá -- ver el docstring del módulo.
    role: str
    #: Opcional: el alta se puede seguir haciendo sin correo. Es la dirección
    #: a la que llega el mail de `POST /auth/forgot-password` quien lo tenga
    #: prendido, y el ABM es el único lugar donde se carga.
    email: str = ""


class UsuarioEdicion(BaseModel):
    """Cuerpo de `PUT {prefix}/{id}`."""

    name: str
    role: str
    active: bool = True
    #: `None` = "dejalo como está" (`UserRepository.update`); `""` = borralo.
    #: El default **tiene** que ser `None`: el botón de activar/desactivar de
    #: la grilla de `libra-ui` manda este mismo cuerpo sin tocar el correo, y
    #: con `""` por default desactivar a alguien le borraría el mail en
    #: silencio.
    email: str | None = None


class UsuarioClaveNueva(BaseModel):
    """Cuerpo de `PUT {prefix}/{id}/password` -- resetea la contraseña de
    OTRO usuario. Para la propia, ver `session_auth.build_json_api_auth_router`
    (`POST /auth/change-password`, que sí pide la actual)."""

    password: str


class UsuarioSalida(BaseModel):
    """`response_model` de listar/alta/edición/obtener. Mismo contrato que ya
    devuelve `UserRepository` (`id`/`username`/`name`/`role`/`active`/
    `email`) -- éste es el modelo Pydantic que lo documenta y lo valida en el
    borde HTTP."""

    id: str
    username: str
    name: str
    role: str
    active: bool
    email: str = ""


# ── Excepción de dominio ─────────────────────────────────────────────────────


class RolInvalido(ValueError):
    """El rol pedido no está en la tupla de roles válidos de esta instancia.

    Hereda de `ValueError` para que un consumidor que ya atrapaba el
    `ValueError` que tiraba `UserRepository.create`/`.update` (la validación
    de rol vivía sólo ahí, y sólo en algunos routers -- ver la tabla de
    `README.md`) lo siga atrapando sin tocar su código."""


def _validar_rol(role: str, roles: tuple[str, ...]) -> None:
    if role not in roles:
        raise RolInvalido(
            f"rol inválido: {role!r} (válidos: {', '.join(roles)})"
        )


# ── La factory ────────────────────────────────────────────────────────────


def build_users_router(
    *,
    prefix: str = "/users",
    roles: tuple[str, ...] = ("admin", "staff"),
    admin_role: str = ADMIN_ROLE,
    admin_guard: Callable[..., dict],
    get_repository: Callable[[Request], "UserRepository"] | None = None,
    tags: list[str] | None = None,
) -> APIRouter:
    """El router de usuarios único, para que los ocho productos dejen de
    tener su propia copia.

    `prefix` -- los productos usan `/api/usuarios` (LibraDesk, LibraCargo,
    LibraClub, Contalibra, Restolibra) o `/users` (Gestiolibra, MedLibra,
    VentaLibra); default `/users` por continuidad con esos tres, pero **cada
    producto tiene que pasar el que ya usa** -- cambiarlo mueve una ruta
    pública que `libra-ui`, el backoffice y los bookmarks del cliente ya
    conocen.

    `roles` -- la tupla de roles válidos de la instancia (ver
    `UserRepository(roles=...)`, que el producto ya construye con la suya:
    `("admin", "staff")` en seis, `("admin", "operador", "cajero")` en
    Contalibra, con `"mozo"` sumado en Restolibra). Se valida ACÁ, con un
    mensaje propio y en castellano, y no dejando que escape el `ValueError`
    de `UserRepository` -- que es justo el bug que tenía Contalibra: su `PUT`
    no atrapaba ese `ValueError` y un rol inválido en la edición volvía un
    500. Con la validación acá, alta y edición quedan con el mismo 422 en los
    ocho productos.

    `admin_role` -- qué rol de `roles` cuenta como "administrador" para las
    protecciones de abajo (único admin activo, no degradarse/desactivarse/
    borrarse a uno mismo). Ver `ADMIN_ROLE`.

    `admin_guard` -- la dependencia de FastAPI que gatea TODO el router, tal
    cual la construye cada producto hoy: `json_api_require_admin_o_servicio`
    de `session_auth` en cinco, `require_admin_o_servicio_o_panel` en
    LibraClub (para que el panel del cliente pueda dar de alta/baja
    empleados), y el envoltorio propio que además audita al usuario en
    LibraCargo/LibraClub (`_que_recuerde_al_usuario`). La factory no elige
    ningún guard por default a propósito: un router de usuarios sin admin
    exigido -- montado por un descuido -- sería el peor lugar posible para
    tener un default.

    El guard tiene que devolver un `dict` con al menos `id` (`None` para una
    identidad de token, como `SERVICE_USER`/`PANEL_USER` de `session_auth` --
    ver su docstring) y `role`: es lo que usan las protecciones de "no te
    podés borrar/desactivar/degradar a vos mismo", que comparan `id` contra
    el de la URL.

    `get_repository` -- de dónde sacar el `UserRepository` en cada request.
    Por default `request.app.state.users`, que es lo que usan los ocho
    productos hoy (confirmado leyendo sus `dependencies.py`/routers de
    referencia); un producto que guarde el repositorio en otro lado puede
    pasar el suyo.

    ── Las protecciones, unión de las que tenía cada producto ──────────────

    | Protección                                   | Quién la tenía HOY          |
    |-----------------------------------------------|------------------------------|
    | Username duplicado → 409                       | los ocho                    |
    | Rol inválido → 422 en el ALTA                  | los ocho                    |
    | Rol inválido → 422 en la EDICIÓN               | LibraDesk, VentaLibra,       |
    |                                                 | LibraCargo, LibraClub,      |
    |                                                 | Gestiolibra, MedLibra (por  |
    |                                                 | `Literal` en el modelo).    |
    |                                                 | Contalibra dejaba escapar   |
    |                                                 | el `ValueError` (500).      |
    | Contraseña ≥ 6 en el ALTA                      | sólo Contalibra/Restolibra  |
    | Contraseña ≥ 6 en el RESET de otro usuario     | ninguno (sólo no-vacía)     |
    | No desactivarse/degradarse a uno mismo         | LibraCargo, LibraClub       |
    | No borrarse a uno mismo                        | LibraCargo, LibraClub,      |
    |                                                 | Contalibra, Restolibra      |
    | No degradar/desactivar al único admin ACTIVO   | Contalibra, Restolibra      |
    |                                                 | (sólo el caso "degradar";   |
    |                                                 | "desactivar" es nuevo acá)  |
    | No eliminar al único admin                     | Contalibra, Restolibra      |
    | `GET /{id}`                                    | Gestiolibra, MedLibra,      |
    |                                                 | LibraCargo, LibraClub       |

    Las dos últimas filas de la tabla de "contraseña" y la de "desactivar al
    único admin activo" son estrictamente MÁS estrictas que lo que tenía
    cualquier producto -- nadie pierde una protección al adoptar esto, y
    Contalibra gana la del rol inválido en la edición que tenía rota.
    """
    router = APIRouter(prefix=prefix, tags=tags or ["usuarios"],
                        dependencies=[Depends(admin_guard)])

    def _repositorio(request: Request) -> "UserRepository":
        if get_repository is not None:
            return get_repository(request)
        return request.app.state.users

    def _validar_password(password: str) -> None:
        if len(password or "") < MIN_PASSWORD_LENGTH:
            raise HTTPException(
                422,
                f"la contraseña debe tener al menos {MIN_PASSWORD_LENGTH} "
                "caracteres",
            )

    def _es_uno_mismo(actual: dict | None, user_id: str) -> bool:
        # Una identidad de token (`SERVICE_USER`/`PANEL_USER` de
        # `session_auth`) trae `id: None`: nunca es "uno mismo", y es a
        # propósito -- es lo que permite destrabar una instancia desde
        # afuera. Ver el docstring de `json_api_require_admin_o_servicio_o_panel`.
        return bool(
            actual and actual.get("id") is not None
            and str(actual["id"]) == str(user_id)
        )

    def _admins_activos(usuarios: "UserRepository", excluir_id: str | None = None) -> int:
        return sum(
            1 for u in usuarios.list()
            if u["role"] == admin_role and u["active"]
            and str(u["id"]) != str(excluir_id)
        )

    @router.get("", response_model=list[UsuarioSalida])
    def listar(usuarios: "UserRepository" = Depends(_repositorio)):
        return usuarios.list()

    @router.post("", response_model=UsuarioSalida, status_code=201)
    def crear(datos: UsuarioAlta, usuarios: "UserRepository" = Depends(_repositorio)):
        _validar_password(datos.password)
        try:
            _validar_rol(datos.role, roles)
        except RolInvalido as exc:
            raise HTTPException(422, str(exc)) from exc
        try:
            return usuarios.create(
                datos.username, datos.name, datos.password, datos.role,
                email=datos.email,
            )
        except UsernameTaken:
            raise HTTPException(409, "ya existe un usuario con ese nombre") from None
        # Red de seguridad: si algún día `roles` (lo que valida esta factory)
        # y el `roles=` con el que el producto construyó el `UserRepository`
        # quedaran desalineados -- un bug de configuración, no el caso normal
        # -- que siga siendo 422 y no un 500.
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/{user_id}", response_model=UsuarioSalida)
    def obtener(user_id: str, usuarios: "UserRepository" = Depends(_repositorio)):
        usuario = usuarios.get_by_id(user_id)
        if usuario is None:
            raise HTTPException(404, f"no existe el usuario {user_id}")
        return usuario

    @router.put("/{user_id}", response_model=UsuarioSalida)
    def editar(
        user_id: str, datos: UsuarioEdicion,
        usuarios: "UserRepository" = Depends(_repositorio),
        actual: dict = Depends(admin_guard),
    ):
        """🔴 Un admin no puede desactivarse ni bajarse el rol a sí mismo
        (LibraCargo/LibraClub, incondicional -- corre exista o no otro admin
        activo), y nadie puede dejar a la instancia sin ningún admin activo
        degradando o desactivando al último que queda (Contalibra/Restolibra,
        y acá también para el caso "desactivar", que ninguno de los dos
        cubría)."""
        try:
            _validar_rol(datos.role, roles)
        except RolInvalido as exc:
            raise HTTPException(422, str(exc)) from exc

        if _es_uno_mismo(actual, user_id):
            if not datos.active:
                raise HTTPException(409, "no te podés desactivar a vos mismo")
            if actual.get("role") == admin_role and datos.role != admin_role:
                raise HTTPException(
                    409, "no te podés sacar el rol de admin a vos mismo"
                )

        objetivo = usuarios.get_by_id(user_id)
        if objetivo is None:
            raise HTTPException(404, f"no existe el usuario {user_id}")

        if objetivo["role"] == admin_role and objetivo["active"]:
            degradando = datos.role != admin_role
            desactivando = not datos.active
            if degradando or desactivando:
                if _admins_activos(usuarios, excluir_id=user_id) == 0:
                    if degradando:
                        raise HTTPException(
                            422,
                            "no se puede cambiar el rol del único "
                            "administrador activo",
                        )
                    raise HTTPException(
                        422, "no se puede desactivar al único administrador activo"
                    )

        try:
            return usuarios.update(
                user_id, datos.name, datos.role, datos.active, email=datos.email,
            )
        except KeyError:
            raise HTTPException(404, f"no existe el usuario {user_id}") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.put("/{user_id}/password", status_code=204)
    def cambiar_password(
        user_id: str, datos: UsuarioClaveNueva,
        usuarios: "UserRepository" = Depends(_repositorio),
    ):
        """Le pone una contraseña nueva a OTRO usuario -- no pide la actual:
        la sesión ya prueba quién es quien la cambia, y exigírsela dejaría sin
        poder ayudar en el único caso para el que esto existe (alguien que
        quedó afuera). La contraparte para la PROPIA, sabiendo la actual, es
        `POST /auth/change-password` de `session_auth`."""
        _validar_password(datos.password)
        try:
            usuarios.update_password(user_id, datos.password)
        except KeyError:
            raise HTTPException(404, f"no existe el usuario {user_id}") from None
        return Response(status_code=204)

    @router.delete("/{user_id}", status_code=204)
    def eliminar(
        user_id: str,
        usuarios: "UserRepository" = Depends(_repositorio),
        actual: dict = Depends(admin_guard),
    ):
        if _es_uno_mismo(actual, user_id):
            raise HTTPException(409, "no te podés borrar a vos mismo")
        objetivo = usuarios.get_by_id(user_id)
        if objetivo is None:
            raise HTTPException(404, f"no existe el usuario {user_id}")
        if objetivo["role"] == admin_role:
            # Acá SIN filtrar por activo, a propósito -- mismo criterio que
            # ya tenían Contalibra/Restolibra: borrar la última fila admin
            # (aunque esté inactiva) deja a la instancia sin ningún admin que
            # se pueda reactivar, que es peor que dejarla desactivada.
            total_admins = sum(1 for u in usuarios.list() if u["role"] == admin_role)
            if total_admins <= 1:
                raise HTTPException(422, "no se puede eliminar al único administrador")
        try:
            usuarios.delete(user_id)
        except KeyError:
            raise HTTPException(404, f"no existe el usuario {user_id}") from None
        except UsuarioConHistorial:
            raise HTTPException(
                409,
                "el usuario tiene historial (turnos, ventas u otros "
                "registros); desactivalo en lugar de borrarlo",
            ) from None
        return Response(status_code=204)

    return router
