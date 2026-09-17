"""Aplicar la cadena de Alembic del schema de auth desde el paquete instalado.

Hasta aca las seis tablas de este motor (`usuarios`, `password_reset_tokens`,
`auth_log`, `smtp_settings`, `demo_codigos`, `aceptaciones_terminos`) las creaba
**solo** `Base.metadata.create_all()` en el arranque de cada producto. Eso
alcanza para una tabla nueva y para nada mas: `create_all` no altera una tabla
que ya existe, asi que cambiarle una columna a `usuarios` en produccion exigia
un `ALTER` a mano en cada instancia. Es el punto 2 de "Direccion de
persistencia" de la auditoria de septiembre.

Desde aca hay cadena, y **viaja en el wheel** (como LibraCore `v1.53.0` y
LibraCommerce P9-M0):

    libraauth-migrar upgrade --prefijo gestiolibra --base core
    python -m libraauth.migrar upgrade --prefijo libradesk --base dominio
    from libraauth.migrar import upgrade; upgrade(destino)

🔴 **La tabla de version es `alembic_version_libraauth`.** Las tablas de auth
conviven en la misma base que las de LibraCore (`alembic_version`), las de
LibraCommerce (`alembic_version_libracommerce`) y las del producto
(`alembic_version_<producto>`). Dos cadenas sobre la misma tabla de version se
pisan la revision, y la segunda en correr cree que la primera es suya.

🔴 **Y `--base` es obligatorio con `--prefijo`, a diferencia de los otros dos
motores.** Medido en los ocho productos (2026-09-11): el engine donde cada uno
corre el `create_all` de auth **no sigue una sola regla**.

| Base | Productos |
|---|---|
| la de LibraCore (`<PREFIJO>_LIBRACORE_DATABASE_URL`) | Gestiolibra, MedLibra, VentaLibra |
| la del dominio (`<PREFIJO>_DATABASE_URL`) | LibraCargo, LibraClub, LibraDesk |
| una sola base para todo | Contalibra, Restolibra (cualquiera de las dos da lo mismo) |

LibraCargo y LibraClub **tienen** base de LibraCore separada y aun asi ponen
auth en la del dominio. Una regla automatica como `libracore.migrar.url_de_core`
("la del core si existe") migraria la base equivocada en esos dos **sin
fallar**: crearia las seis tablas al lado de las del core y dejaria la real sin
tocar. Por eso aca la base se nombra, no se deduce.

🔑 **`script_location` se resuelve desde `__file__`, no desde el cwd**: es la
diferencia entre andar en el repo y andar en `site-packages`.

🔑 **El arranque ya no crea las tablas (2026-09-17, v0.45.0).** Los productos
llaman a `exigir_schema_al_dia(engine)` en lugar de `create_all()`: si la cadena
no corrió, la app no levanta y el error dice el comando. Para las suites está
`libraauth.testing.crear_schema_de_auth`.

**Nada de esto se importa al importar `libraauth`**, y alembic se importa recien
al correr un comando: un producto que sube el pin sin adoptar la cadena no
necesita alembic en su imagen y arranca exactamente igual que antes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

#: El directorio de migraciones **dentro del paquete**.
DIRECTORIO = Path(__file__).parent / "migrations"

#: La tabla de version de esta cadena. Ver el docstring del modulo.
TABLA_DE_VERSION = "alembic_version_libraauth"

#: Los valores de `--base`. Ver `url_de_auth`.
BASES = ("core", "dominio")


class SinURL(RuntimeError):
    """No hay contra que migrar: ni destino explicito ni variables del entorno."""


class SinAlembic(RuntimeError):
    """Falta el extra `[migrations]`, que es quien trae alembic."""


class SchemaDesactualizado(RuntimeError):
    """La base de auth no está en la cabeza de la cadena: el arranque no sigue."""


def _comandos():
    """`alembic.command`, importado tarde y con un error que dice que falta.

    Sin este envoltorio el console script muere con un `ModuleNotFoundError: No
    module named 'alembic'` en medio de un deploy, que manda a buscar el
    problema en el lugar equivocado.
    """
    try:
        from alembic import command
        from alembic.config import Config
    except ModuleNotFoundError as e:  # pragma: no cover - depende del entorno
        raise SinAlembic(
            "Falta alembic: libraauth no lo declara como dependencia, viene en el "
            "extra `[migrations]`. Instala `libraauth[migrations]` en la imagen "
            "del producto antes de declarar este comando en el deploy."
        ) from e
    return command, Config


def normalizar_url(destino: str) -> str:
    """El destino como URL de SQLAlchemy.

    Acepta las dos formas en que la familia nombra una base: URL PostgreSQL o
    **ruta de archivo** SQLite (la que todavia usan los `default=` de los
    productos para desarrollo local). `postgresql://` pelado se corrige porque
    SQLAlchemy lo resuelve a psycopg2 y la familia instala psycopg 3.
    """
    if destino.startswith("postgresql://"):
        return "postgresql+psycopg://" + destino[len("postgresql://"):]
    if "://" in destino:
        return destino
    return f"sqlite:///{Path(destino).expanduser().resolve()}"


def _url_de_instancia_de_libracore(prefijo, *, core, entorno):
    """`libracore.db.url_de_instancia`, importado tarde.

    Se usa la de LibraCore y no una copia porque ahi viven los **nombres
    historicos** de las variables (`VENTALIBRA_LIBRACORE_DB_PATH`, el
    `DATABASE_URL` a secas de LibraDesk...), en un solo lugar para que sacarlos
    sea una linea. Libraauth no depende de LibraCore; los ocho productos si, asi
    que adentro de un contenedor esto siempre resuelve.
    """
    try:
        from libracore.db.url_de_instancia import url_de_instancia
    except ModuleNotFoundError as e:  # pragma: no cover - depende del entorno
        raise SinURL(
            "--prefijo necesita libracore instalado (resuelve los nombres de las "
            "variables de la instancia). Sin el, pasa el destino por "
            "LIBRAAUTH_MIGRAR_URL."
        ) from e
    return url_de_instancia(prefijo, core=core, entorno=entorno)


def _comparte_base_segun_libracore(prefijo) -> bool:
    """`libracore.db.url_de_instancia.comparte_base_con_el_dominio`, importada tarde.

    Es la lista de productos de **una sola base**, y vive en LibraCore (desde
    `v1.103.0`) para que `libracore-migrar` y este comando no puedan divergir.
    Con una LibraCore anterior, o sin LibraCore, la respuesta es **no**: el
    default seguro es fallar, no caer a la base del dominio.
    """
    try:
        from libracore.db.url_de_instancia import comparte_base_con_el_dominio
    except ImportError:
        return False
    return comparte_base_con_el_dominio(prefijo)


def url_de_auth(prefijo: str | None = None, base: str | None = None, entorno=None,
                resolver=None, comparte_base=None) -> str:
    """La base donde viven las tablas de auth de esta instancia.

    El orden es:

    1. `LIBRAAUTH_MIGRAR_URL`, la salida de emergencia explicita.
    2. Con `prefijo`, **`base` es obligatorio** (ver el docstring del modulo):
       - `dominio`: `<PREFIJO>_DATABASE_URL` y sus nombres historicos.
       - `core`: `<PREFIJO>_LIBRACORE_DATABASE_URL` y los suyos. **Si no esta
         definida, cae a la del dominio SOLO en un producto de una sola base**
         (la lista de LibraCore: Contalibra, Restolibra, VentaLibra, LibraDesk).
         En cualquier otro **falla**: en Gestiolibra o MedLibra, que llevan el
         core aparte, la caida crearia las tablas de auth en la base del
         dominio y devolveria exito. Es la misma regla que
         `libracore.migrar.url_de_core` desde LibraCore `v1.103.0`
         (2026-09-16); hasta ese dia las dos caian siempre.
       Un prefijo que no resuelve **falla**, no cae a `DATABASE_URL`.
    3. Sin `prefijo`: `DATABASE_URL`, que es el caso de un script en el host.

    `resolver` y `comparte_base` existen para los tests: por defecto son las
    funciones de LibraCore.
    """
    env = os.environ if entorno is None else entorno
    resolver = resolver or _url_de_instancia_de_libracore
    comparte_base = comparte_base or _comparte_base_segun_libracore

    explicita = (env.get("LIBRAAUTH_MIGRAR_URL") or "").strip()
    if explicita:
        return explicita

    if prefijo:
        if base not in BASES:
            raise SinURL(
                f"Con --prefijo hay que decir en que base viven las tablas de auth: "
                f"--base core o --base dominio (se recibio {base!r}). No se deduce "
                "a proposito: LibraCargo y LibraClub tienen base de LibraCore "
                "aparte y aun asi ponen auth en la del dominio. Ver "
                "libraauth.migrar."
            )
        if base == "core":
            del_core = resolver(prefijo, core=True, entorno=env)
            if del_core:
                return del_core
            if not comparte_base(prefijo):
                raise SinURL(
                    f"No hay base de LibraCore para el prefijo '{prefijo}' (--base "
                    f"core): falta {prefijo.upper()}_LIBRACORE_DATABASE_URL (o su "
                    "nombre historico). No se cae a la del dominio porque este "
                    "producto no figura como de una sola base en LibraCore "
                    "(`comparte_base_con_el_dominio`, desde v1.103.0): ahi las "
                    "tablas de auth quedarian en la base equivocada sin fallar. "
                    "Defini la variable, o pasa el destino por LIBRAAUTH_MIGRAR_URL."
                )
        del_dominio = resolver(prefijo, core=False, entorno=env)
        if del_dominio:
            return del_dominio
        raise SinURL(
            f"No hay base para el prefijo '{prefijo}' (--base {base}): ni "
            + (f"{prefijo.upper()}_LIBRACORE_DATABASE_URL ni " if base == "core" else "")
            + f"{prefijo.upper()}_DATABASE_URL (ni sus nombres historicos) estan "
            "definidas en este entorno."
        )

    del_entorno = (env.get("DATABASE_URL") or "").strip()
    if del_entorno:
        return del_entorno

    raise SinURL(
        "Falta el destino: pasa --prefijo <producto> --base core|dominio para que "
        "salga de las variables de la instancia, o defini LIBRAAUTH_MIGRAR_URL o "
        "DATABASE_URL. Sin eso no hay base contra la cual migrar."
    )


def configuracion(destino: str):
    """El `Config` de Alembic apuntado al paquete instalado.

    No lee `alembic.ini`: ese archivo es del repo y no viaja en el wheel.
    """
    _, Config = _comandos()
    cfg = Config()
    cfg.set_main_option("script_location", str(DIRECTORIO))
    normalizado = normalizar_url(destino)
    # 🔴 **La que manda de verdad.** `env.py` la prefiere por sobre
    # `DATABASE_URL`: sin esta opcion propia, adentro de un contenedor el destino
    # explicito se ignoraria en silencio a favor de la base del dominio. Es el
    # defecto que LibraGenda encontro con un test que migra una base real.
    # (`%` se duplica porque el Config de alembic interpola: una contrasena con
    # `%` rompia el set_main_option.)
    cfg.set_main_option("libraauth.url", normalizado.replace("%", "%%"))
    cfg.set_main_option("sqlalchemy.url", normalizado.replace("%", "%%"))
    return cfg


def cabeza() -> str:
    """La revisión cabeza de la cadena que viaja en este paquete.

    Importa alembic recién acá, igual que `_comandos`: el producto que llama a
    `exigir_schema_al_dia` en su arranque ya tiene el extra `[migrations]`
    instalado —lo exige correr la cadena en el deploy—.
    """
    try:
        from alembic.script import ScriptDirectory
    except ModuleNotFoundError as e:  # pragma: no cover - depende del entorno
        raise SinAlembic(
            "Falta alembic para leer la cabeza de la cadena: instala "
            "`libraauth[migrations]`."
        ) from e
    cabezas = ScriptDirectory(str(DIRECTORIO)).get_heads()
    if len(cabezas) != 1:  # pragma: no cover - lo cubre test_una_sola_cabeza
        raise RuntimeError(f"La cadena de libraauth tiene {len(cabezas)} cabezas: {cabezas}")
    return cabezas[0]


def revision_actual(engine) -> str | None:
    """La revisión registrada en `alembic_version_libraauth`, o `None` si la
    tabla no existe o está vacía. No crea nada."""
    from sqlalchemy import inspect, text

    if not inspect(engine).has_table(TABLA_DE_VERSION):
        return None
    with engine.connect() as conn:
        fila = conn.execute(text(f"SELECT version_num FROM {TABLA_DE_VERSION}")).first()
    return fila[0] if fila else None


def exigir_schema_al_dia(engine, *, prefijo: str | None = None,
                         base: str | None = None) -> str:
    """Falla si la base de auth no está en la cabeza de la cadena. **No crea nada.**

    Reemplaza al `AuthBase.metadata.create_all(engine)` que cada producto corría
    al arrancar (2026-09-17). Desde que los ocho corren `libraauth-migrar` en el
    deploy, en el `command:` de dev y en el alta, el `create_all` del arranque
    sólo servía para **tapar** un camino que se olvidó de migrar: la app
    levantaba con las tablas de la forma del modelo y sin versión, y el próximo
    cambio de schema no tenía de dónde partir. Con esto la app no arranca y el
    error dice qué correr — el mismo criterio de fallar cerrado de LibraCargo
    con `init_core_schema()`.

    `prefijo` y `base` sólo arman el comando del mensaje. Devuelve la revisión.
    """
    actual = revision_actual(engine)
    esperada = cabeza()
    if actual == esperada:
        return actual
    comando = (f"libraauth-migrar upgrade --prefijo {prefijo} --base {base}"
               if prefijo and base else
               "libraauth-migrar upgrade --prefijo <producto> --base core|dominio")
    if actual is None:
        raise SchemaDesactualizado(
            f"La base de auth no tiene la cadena de libraauth ({TABLA_DE_VERSION} no "
            f"existe o está vacía). Corré `{comando}` antes de arrancar. Si es una "
            "base restaurada de un respaldo anterior al 2026-09-16, la baseline "
            f"{esperada} la adopta sin tocar las tablas que ya tiene."
        )
    raise SchemaDesactualizado(
        f"La base de auth está en la revisión {actual} y este libraauth espera "
        f"{esperada}. Corré `{comando}` antes de arrancar."
    )


def upgrade(destino: str, revision: str = "head") -> None:
    """Aplica la cadena. Es lo que corre el deploy de un consumidor.

    Sobre una instancia viva la baseline **no toca** ninguna tabla que ya
    exista: crea las que falten y registra la version. Aun asi, **backup
    antes**: es una operacion de schema.
    """
    command, _ = _comandos()
    command.upgrade(configuracion(destino), revision)


def stamp(destino: str, revision: str = "head") -> None:
    """Marca la base en una revision **sin ejecutar** nada.

    Casi nunca es lo que hace falta: la baseline ya es idempotente, asi que
    `upgrade` hace lo mismo sobre una base completa y ademas crea lo que falte.
    Estampar declara «esta base esta en esta revision» sin mirar si es cierto.
    """
    command, _ = _comandos()
    command.stamp(configuracion(destino), revision)


def current(destino: str) -> None:
    command, _ = _comandos()
    command.current(configuracion(destino))


def heads(destino: str) -> None:
    command, _ = _comandos()
    command.heads(configuracion(destino))


def _solo_tablas_de_auth(tablas):
    """El filtro de `include_object` que acota la comparacion a este motor.

    La base es compartida: tiene las tablas de LibraCore, de LibraCommerce, del
    producto y las tablas de version de cada cadena. Sin este filtro el
    autogenerate propone **borrarlas todas**, porque no estan en esta metadata.
    """
    def incluir(objeto, nombre, tipo, reflejado, comparado):
        if tipo == "table":
            return nombre in tablas
        tabla = getattr(objeto, "table", None)
        return tabla is None or tabla.name in tablas
    return incluir


def diferencias(destino: str) -> list:
    """Lo que separa la base real del modelo, **sin cambiar nada**.

    Es la medicion que va antes de adoptar la cadena en una instancia y antes de
    escribir una revision que altere una tabla existente: el schema de auth
    **no es el mismo en todas las bases de la familia**. `usuarios` y `auth_log`
    los declaran dos motores —este y el DDL crudo de LibraCore, que los crea
    con columnas `TEXT`— y en cada base quedo la forma de quien llego primero.
    Una revision que asuma la forma del modelo puede fallar, o peor, andar en
    unas y no en otras.

    Devuelve la lista de `compare_metadata` de Alembic (vacia = coincide).
    """
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import create_engine, pool

    from .models import Base

    _comandos()
    engine = create_engine(normalizar_url(destino), poolclass=pool.NullPool)
    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={
                "compare_type": True,
                "version_table": TABLA_DE_VERSION,
                "include_object": _solo_tablas_de_auth(set(Base.metadata.tables)),
            })
            return compare_metadata(ctx, Base.metadata)
    finally:
        engine.dispose()


def _parsear(argv: list[str]) -> tuple[str, str | None, str | None, str | None]:
    """`(accion, prefijo, base, revision)` — sin argparse, la forma de los otros dos.

    `--prefijo X` / `--prefijo=X`, `--base X` / `--base=X`; lo suelto es la
    revision.
    """
    accion = argv[0] if argv else "upgrade"
    opciones = {"--prefijo": None, "--base": None}
    revision = None
    resto = argv[1:]
    i = 0
    while i < len(resto):
        arg = resto[i]
        if arg in opciones:
            i += 1
            opciones[arg] = resto[i] if i < len(resto) else None
        elif arg.split("=", 1)[0] in opciones and "=" in arg:
            clave, valor = arg.split("=", 1)
            opciones[clave] = valor
        else:
            revision = arg
        i += 1
    return accion, opciones["--prefijo"], opciones["--base"], revision


def main(argv: list[str] | None = None) -> int:
    """CLI: `libraauth-migrar [upgrade|stamp|current|heads|diferencias] [--prefijo P --base core|dominio] [rev]`."""
    argv = list(sys.argv[1:] if argv is None else argv)
    accion, prefijo, base, revision = _parsear(argv)
    acciones = {"upgrade": upgrade, "stamp": stamp, "current": current,
                "heads": heads, "diferencias": diferencias}

    if accion in ("-h", "--help") or accion not in acciones:
        print(main.__doc__)
        print(f"  migraciones en: {DIRECTORIO}")
        print(f"  tabla de version: {TABLA_DE_VERSION}")
        print("  --base es obligatorio con --prefijo: dice si las tablas de auth "
              "viven en la base de LibraCore o en la del dominio. Ver libraauth.migrar")
        # Codigo 0 si la pidieron, 2 si el comando no existe: un typo no puede
        # leerse como exito desde un pipeline.
        return 0 if accion in ("-h", "--help") else 2

    try:
        destino = url_de_auth(prefijo, base)
        if accion == "diferencias":
            difs = diferencias(destino)
            for d in difs:
                print(f"  {d}")
            print(f"[{'OK' if not difs else 'DIFIERE'}] {len(difs)} diferencia(s) "
                  "entre la base y el modelo de libraauth.")
            # 🔑 Codigo propio y no 1: no es un error, es una medicion. Un
            # pipeline que la use como guarda distingue "difiere" (3) de
            # "no pude medir" (1).
            return 0 if not difs else 3
        if accion in ("upgrade", "stamp") and revision:
            acciones[accion](destino, revision)
        else:
            acciones[accion](destino)
    except (SinURL, SinAlembic) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
