"""
Creacion del usuario admin inicial. **Hay dos variantes y NO son
intercambiables** — las dos vienen de LibraCore y difieren en que hacen cuando
falta la contrasena:

- `ensure_default_admin(repo, env_prefix=...)`: **fail-closed**. Sin
  `<PREFIX>_ADMIN_PASSWORD` la app no levanta (salvo `ENV=development`). La usan
  los productos FastAPI de la familia.
- `ensure_admin_user(repo)`: **genera una contrasena aleatoria y la imprime**.
  La usan los server-rendered (Contalibra/Restolibra). Portada el 2026-07-30 a
  pedido explicito del usuario, tal cual estaba.

Elegir una por la otra cambia el comportamiento en una instancia nueva, asi que
al migrar un producto hay que mirar cual llamaba, no asumir.
"""
import os
import secrets

from .repository import UserRepository
from .session_auth import ROLES_PROHIBIDOS_EN_DEMO, demo_username

#: Rol por defecto del usuario de la demo publica. Es el vocabulario de cuatro
#: de los seis productos (`("admin", "staff")`), pero **no de todos**:
#: Contalibra usa `("admin", "operador", "cajero")` y Restolibra agrega
#: `"mozo"`. Por eso `ensure_demo_user` acepta `rol=` — ver su docstring.
ROL_DEMO = "staff"


def ensure_demo_user(repo: "UserRepository", *, rol: str = ROL_DEMO) -> str | None:
    """Crea el usuario del auto-login de la demo, si la instancia es una demo.

    Devuelve el username creado o ya existente, o `None` si esta instancia no
    es una demo (o sea: casi siempre). **Se guia por las mismas dos variables
    de entorno que registran `POST /auth/demo`**, y eso es a proposito — si el
    usuario y la ruta se decidieran por separado, existiria el par
    "ruta encendida sin usuario" y el par "usuario suelto en la base de un
    cliente", que son las dos formas de que esto salga mal.

    🔴 **Nunca admin.** El visitante no tiene que poder entrar a Configuracion,
    al ABM de usuarios ni al backup: ahi es donde rompe cosas que no se notan
    hasta el reset, y donde ve partes de la instancia que no son la muestra.

    **El rol lo elige el producto, pero NO sale del entorno**, asi que no hay
    `.env` que pueda pedir admin. Es un parametro y no una constante porque el
    vocabulario de roles no es el mismo en toda la familia: cuatro productos
    usan `("admin", "staff")`, pero Contalibra usa
    `("admin", "operador", "cajero")` y Restolibra agrega `"mozo"`. Con
    `"staff"` fijo, en esos dos el alta explotaba con
    `ValueError: invalid role: 'staff'` — lo encontro el bump del 2026-08-06.

    Un rol que el producto no conoce **corta el arranque con un mensaje que
    nombra los validos**, en vez de dejar la instancia sin usuario de demo y
    que el 503 aparezca recien cuando alguien toque el boton.

    La contrasena es aleatoria y **no se imprime**: nadie la necesita: al
    usuario de la demo se entra por `POST /auth/demo`, no tipeandola. Que sea
    inadivinable importa igual, porque el login normal sigue existiendo.

    Idempotente: si el usuario ya esta, no lo toca — ni siquiera le corrige el
    rol. Corregirlo en silencio taparia el caso que `POST /auth/demo` tiene que
    seguir rechazando (alguien lo promovio a admin desde el ABM), y ese caso se
    quiere ruidoso, no arreglado por atras.
    """
    username = demo_username()
    if not username:
        return None
    if rol in ROLES_PROHIBIDOS_EN_DEMO:
        raise RuntimeError(
            f"rol={rol!r} esta en ROLES_PROHIBIDOS_EN_DEMO: el usuario que se "
            "crearia no podria entrar nunca por POST /auth/demo."
        )
    validos = getattr(repo, "roles", ())
    if validos and rol not in validos:
        raise RuntimeError(
            f"rol={rol!r} no existe en este producto. Los validos son "
            f"{validos}. Pasar `rol=` a ensure_demo_user()."
        )
    if repo.get_by_username(username):
        return username
    repo.create(
        username=username,
        name=os.environ.get("DEMO_NAME", "Visitante de la demo"),
        password=secrets.token_urlsafe(24),
        role=rol,
    )
    print(f"[INFO] Usuario de demo '{username}' creado con rol {rol}.")
    return username


def ensure_default_admin(repo: "UserRepository", *, env_prefix: str) -> None:
    """Crea el admin inicial si la tabla usuarios todavia esta vacia.

    Fail-closed en produccion: sin `<env_prefix>_ADMIN_PASSWORD` la app no
    arranca (a diferencia del patron `ensure_admin_user()` que genera una
    contrasena aleatoria y solo loguea un warning — no se adopta ese
    comportamiento acá, mismo criterio que ya usaba
    `libracore.db.usuarios.ensure_default_admin`)."""
    if repo.list():
        return
    username = os.environ.get(f"{env_prefix}_ADMIN_USERNAME", "admin")
    password = os.environ.get(f"{env_prefix}_ADMIN_PASSWORD", "")
    if not password:
        if os.environ.get("ENV", "production") != "development":
            raise RuntimeError(
                f"{env_prefix}_ADMIN_PASSWORD no esta seteado. No se levanta la "
                "app sin una contrasena de admin inicial (setear ENV=development "
                "para desarrollo local)."
            )
        password = "admin"
    repo.create(username=username, name="Administrador", password=password, role="admin")


def ensure_admin_user(repo: "UserRepository") -> None:
    """Crea el admin inicial si la tabla usuarios todavia esta vacia.

    Portado de `libracore.db.usuarios.ensure_admin_user` **sin cambios de
    comportamiento** (2026-07-30): mismas env vars **sin prefijo de producto**
    (`ADMIN_USER` / `ADMIN_PASSWORD` / `ADMIN_NOMBRE`) y mismo fallback.

    A diferencia de `ensure_default_admin`, **no es fail-closed**: si no hay
    `ADMIN_PASSWORD` genera una aleatoria y la imprime por stdout.

    > Eso significa que la contrasena inicial **queda en los logs del
    > contenedor**, legible para cualquiera con acceso a ellos, y que una
    > instancia mal configurada arranca igual en vez de avisar. Se preserva
    > porque es el comportamiento que los productos server-rendered ya tienen y
    > cambiarlo de prepo podria dejar una instancia nueva sin poder arrancar;
    > pero para un producto nuevo conviene `ensure_default_admin`.
    """
    if repo.list():
        return
    username = os.environ.get("ADMIN_USER", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "")
    nombre = os.environ.get("ADMIN_NOMBRE", "Administrador")
    if not password:
        password = secrets.token_urlsafe(12)
        print(f"[WARN] ADMIN_PASSWORD no configurado. Contrasena generada: {password}")
    repo.create(username=username, name=nombre, password=password, role="admin", email="")
    print(f"[INFO] Usuario admin '{username}' creado.")
