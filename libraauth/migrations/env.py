"""Entorno de Alembic para el schema de auth.

Vive **adentro del paquete** (`libraauth/migrations/`) para viajar en el wheel:
un consumidor la aplica con `libraauth-migrar` sin clonar nada.

Tres cosas que lo distinguen de los `env.py` de LibraCore y LibraCommerce, y
salen de que aca la fuente de verdad son **modelos SQLAlchemy** y no DDL crudo:

1. **Hay `target_metadata`** (`libraauth.models.Base`), asi que
   `alembic revision --autogenerate` sirve para escribir la proxima revision. El
   test `test_modelo_y_cadena_coinciden` es lo que obliga a que la cabeza de la
   cadena y el modelo digan lo mismo.
2. **`include_object` acota todo a las seis tablas de auth.** La base es
   compartida con LibraCore, LibraCommerce y el producto: sin el filtro, el
   autogenerate propone borrar cada tabla ajena.
3. **La tabla de version es `alembic_version_libraauth`**, por el mismo motivo
   que la de LibraCommerce: `alembic_version` a secas ya es de LibraCore.

`actividad_log` (`libraauth.auditoria.AuditoriaBase`) **no** entra en esta
cadena, a proposito: vive en la base del DOMINIO, que en Gestiolibra, MedLibra y
VentaLibra no es la de `usuarios`. Una sola cadena no puede cubrir dos bases.
"""
import os

from alembic import context
from sqlalchemy import create_engine, pool

from libraauth.migrar import TABLA_DE_VERSION, _solo_tablas_de_auth, normalizar_url
from libraauth.models import Base

target_metadata = Base.metadata


def _destino() -> str:
    """La base contra la que se migra, en orden de precedencia.

    1. **`libraauth.url`**, que pone `libraauth.migrar.configuracion()` con el
       destino explicito. Va primero porque es la unica señal inequivoca de
       intencion: sin ella, adentro de un contenedor `DATABASE_URL` (la del
       dominio) ganaria en silencio.
    2. `DATABASE_URL` del entorno — un script parado en el host.
    3. `sqlalchemy.url` del `alembic.ini`, que en este repo es un placeholder.
    """
    destino = (
        context.config.get_main_option("libraauth.url", default="")
        or os.environ.get("DATABASE_URL")
        or context.config.get_main_option("sqlalchemy.url", default="")
    )
    if not destino or destino.startswith("postgresql://user:password@"):
        raise RuntimeError(
            "Falta el destino: DATABASE_URL o `libraauth-migrar --prefijo P --base "
            "core|dominio`. Acepta una URL PostgreSQL o la ruta de un archivo SQLite."
        )
    return normalizar_url(destino)


def run_migrations_online():
    connectable = create_engine(_destino(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table=TABLA_DE_VERSION,
            include_object=_solo_tablas_de_auth(set(target_metadata.tables)),
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    # `--sql` genera el SQL sin conectarse. La baseline no puede: decide que
    # crear mirando que tablas ya existen. Un modo offline que emitiera algo
    # estaria mintiendo sobre lo que haria contra una base real.
    raise RuntimeError(
        "El modo offline (--sql) no esta soportado: la baseline inspecciona la "
        "base antes de decidir que tablas crear."
    )

run_migrations_online()
