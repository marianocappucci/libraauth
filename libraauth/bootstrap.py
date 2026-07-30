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
