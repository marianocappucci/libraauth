"""
Creacion del usuario admin inicial. Portado de
`libracore.db.usuarios.ensure_default_admin` sin cambios de
comportamiento — fail-closed en produccion.
"""
import os

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
