"""Una base de PostgreSQL por worker de pytest-xdist.

La suite corre con `pytest -n 4` (reglas/ci.md del wiki). Varios archivos usan la base
de `LIBRAAUTH_POSTGRES_URL` **tal cual**, con `drop_all()`/`create_all()` o
`DROP TABLE IF EXISTS` en cada test (`test_postgres_real`, `test_rate_limiting_ts_texto`,
`test_registrador_dbapi`): dos workers se pisarian las tablas. Los demas ya crean una base
con nombre al azar por test (`auth_mig_<uuid>`, `auth_cap_<uuid>`, ...) y no necesitan esto.

Cada worker usa `<base>_gwN` (`<base>_main` sin xdist), creada al arrancar y borrada al
salir, y la variable se pisa con esa URL **antes de que nadie la lea**: los archivos de
test la leen al importarse, y un `conftest.py` se carga antes que ellos.

🔴 Es la misma idea que `libracore.testing.pg_por_worker` (los productos la importan de
ahi), pero **copiada acá a proposito, sin plantillas**: libraauth es el motor de auth y
no depende de libracore, ni siquiera de test; sumarlo como dependencia de dev por quince
lineas ataria las dos versiones. Si algun dia hace falta algo mas que la base por worker
(plantillas), se evalua importarlo.

El proceso que lanza a xdist tambien importa este archivo y sus workers heredan su
entorno: por eso la URL original se guarda aparte (`_LIBRAAUTH_PG_ORIGINAL`) y lo que
decide "esta base ya esta creada" vive en `os.environ`, con el worker en la clave. Un
worker no deriva su nombre de la base del controlador, y un segundo import del
`conftest.py` no recrea (ni borra) una base que un test tiene en uso.
"""
import atexit
import os

from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import make_url

_VARIABLE = "LIBRAAUTH_POSTGRES_URL"


def _admin(url: str):
    # AUTOCOMMIT: `CREATE/DROP DATABASE` no pueden correr dentro de una transaccion. Se administra
    # conectado a la base ORIGINAL (existe: la crea el servicio de CI), no a la `postgres`.
    return create_engine(url, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)


def _soltar(url_original: str, nombre: str) -> None:
    admin = _admin(url_original)
    try:
        with admin.connect() as c:
            # `FORCE`: un test puede haber dejado una conexion viva.
            c.execute(text(f'DROP DATABASE IF EXISTS "{nombre}" WITH (FORCE)'))
    finally:
        admin.dispose()


def _base_por_worker() -> None:
    url = os.environ.get(_VARIABLE, "")
    if not url:
        return
    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    original = os.environ.setdefault("_LIBRAAUTH_PG_ORIGINAL", url)
    nombre = f"{make_url(original).database}_{worker}"
    marca = f"_LIBRAAUTH_PG_{worker}"
    if marca not in os.environ:
        _soltar(original, nombre)  # restos de una corrida interrumpida
        admin = _admin(original)
        try:
            with admin.connect() as c:
                c.execute(text(f'CREATE DATABASE "{nombre}"'))
        finally:
            admin.dispose()
        atexit.register(_soltar, original, nombre)
        os.environ[marca] = "1"
    os.environ[_VARIABLE] = make_url(original).set(database=nombre).render_as_string(hide_password=False)


_base_por_worker()
