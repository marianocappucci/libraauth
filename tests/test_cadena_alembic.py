"""La cadena de Alembic del schema de auth, EJECUTADA contra bases reales.

Cada garantia de la baseline se prueba corriendo `libraauth.migrar.upgrade`
contra una base de verdad —SQLite en un archivo y, con
`LIBRAAUTH_POSTGRES_URL`, una base PostgreSQL nueva por test— y midiendo el
catalogo y las filas antes y despues. Las tres formas de partida son las que
existen hoy en la familia:

1. **Base vacia** — un alta nueva: la cadena corre antes del primer arranque.
2. **Base creada por `create_all()`** — LibraDesk, LibraCargo, LibraClub y las
   tablas satelite de todos: el camino de hoy.
3. **`usuarios` y `auth_log` con la forma de LibraCore** — Contalibra,
   Restolibra y las bases de LibraCore de Gestiolibra, MedLibra y VentaLibra,
   donde el DDL crudo de ese motor llego primero. Mas `alembic_version` de
   LibraCore al lado, que la cadena no tiene que tocar.

En las dos ultimas el control que importa es el mismo que en las baselines de
LibraCore y LibraCommerce: **la base termina con una tabla mas —la de version—
y nada distinto**, con las filas intactas.

La parte PostgreSQL se saltea sin `LIBRAAUTH_POSTGRES_URL`; en CI la pone el
workflow y el paso "Confirmar que el gate de PostgreSQL corrio" nombra este
archivo, asi que alla un salteo es rojo.
"""
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, pool, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

import libraauth
from libraauth import migrar
from libraauth.models import (
    AceptacionTerminos,
    AuthEvent,
    Base,
    DemoCodigo,
    PasswordResetToken,
    SmtpSettings,
    Usuario,
)
from libraauth.repository import UserRepository

POSTGRES_URL = os.environ.get("LIBRAAUTH_POSTGRES_URL", "")
HEAD = "0001_baseline_libraauth"
TABLAS = set(Base.metadata.tables)
#: El id de la cabeza de LibraCore (`origin/develop`, 2026-09-11) — el id, no el
#: nombre del archivo, que es mas largo. El valor da igual: lo que se mide es
#: que nadie lo toque.
REVISION_DE_LIBRACORE = "0008_archivo_par_por_ambiente"


# ── Bases ────────────────────────────────────────────────────────────────────


@pytest.fixture(params=["sqlite", "postgresql"])
def fabrica(request, tmp_path):
    """Una funcion que devuelve la URL de una base NUEVA y vacia, en el motor
    del parametro. Una base por llamada y no un `drop_all` sobre la compartida:
    aca lo que se mide es justamente que hay y que no hay en la base, y un
    resto de otro test lo falsearia."""
    creadas = []

    if request.param == "sqlite":
        def nueva():
            url = f"sqlite:///{tmp_path}/auth_{len(creadas)}.db"
            creadas.append(url)
            return url
        yield nueva
        return

    if not POSTGRES_URL:
        pytest.skip("sin LIBRAAUTH_POSTGRES_URL: no hay PostgreSQL real contra el cual correr")
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)

    def nueva():
        nombre = f"auth_mig_{uuid.uuid4().hex[:12]}"
        with admin.connect() as c:
            c.execute(text(f'CREATE DATABASE "{nombre}"'))
        creadas.append(nombre)
        return make_url(POSTGRES_URL).set(database=nombre).render_as_string(hide_password=False)

    yield nueva
    with admin.connect() as c:
        for nombre in creadas:
            c.execute(text(f'DROP DATABASE IF EXISTS "{nombre}" WITH (FORCE)'))
    admin.dispose()


def _engine(url):
    return create_engine(url, poolclass=pool.NullPool)


def _es_pg(url):
    return url.startswith("postgresql")


def _tablas(url):
    e = _engine(url)
    try:
        return set(inspect(e).get_table_names())
    finally:
        e.dispose()


def _foto(url, tablas=TABLAS):
    """El catalogo de las tablas de auth: columnas con tipo, nulabilidad y
    DEFAULT, PK, FK con su `ON DELETE`, unicas e indices. Es lo que tiene que
    quedar igual cuando la baseline corre sobre una base que ya las tiene."""
    e = _engine(url)
    try:
        insp = inspect(e)
        existentes = set(insp.get_table_names())
        foto = {}
        for t in sorted(tablas & existentes):
            foto[t] = {
                "columnas": [
                    (c["name"], str(c["type"]), c["nullable"], str(c.get("default")))
                    for c in insp.get_columns(t)
                ],
                "pk": tuple(insp.get_pk_constraint(t)["constrained_columns"]),
                "fks": sorted(
                    (tuple(f["constrained_columns"]), f["referred_table"],
                     tuple(f["referred_columns"]), (f.get("options") or {}).get("ondelete"))
                    for f in insp.get_foreign_keys(t)
                ),
                "unicas": sorted(tuple(u["column_names"]) for u in insp.get_unique_constraints(t)),
                "indices": sorted(
                    (i["name"], tuple(i["column_names"]), bool(i["unique"]))
                    for i in insp.get_indexes(t)
                ),
            }
        return foto
    finally:
        e.dispose()


def _filas(url, tablas=TABLAS):
    e = _engine(url)
    try:
        existentes = set(inspect(e).get_table_names())
        with e.connect() as c:
            return {
                t: [tuple(f) for f in c.execute(text(f'SELECT * FROM "{t}" ORDER BY id'))]
                for t in sorted(tablas & existentes)
            }
    finally:
        e.dispose()


def _version(url, tabla=migrar.TABLA_DE_VERSION):
    e = _engine(url)
    try:
        with e.connect() as c:
            return [f[0] for f in c.execute(text(f"SELECT version_num FROM {tabla}"))]
    finally:
        e.dispose()


def _sembrar(url):
    """Una fila en cada una de las seis tablas, por el ORM — como las escribe
    un producto. Sin filas, "no se perdio nada" se cumple solo."""
    e = _engine(url)
    ahora = datetime(2026, 9, 11, 10, 30)
    try:
        with Session(e) as s:
            u = Usuario(username="ana", nombre="Ana Alvarez", email="ana@x.com",
                        password_hash="$argon2id$fijo", role="admin", activo=True)
            s.add(u)
            s.flush()
            s.add_all([
                PasswordResetToken(user_id=u.id, token_hash="a" * 64,
                                   expires_at=ahora + timedelta(hours=1)),
                AuthEvent(ts=ahora, evento="login", username="ana", ip="10.0.0.1"),
                SmtpSettings(id=1, host="smtp.x.com", port=587, user="u",
                             password_cifrada="blob", from_email="a@x.com", from_name="X"),
                DemoCodigo(codigo_hash="b" * 64, prefijo="ABCD", expires_at=ahora,
                           usos_max=10, usos=2, revocado=False),
                AceptacionTerminos(usuario_id=u.id, username="ana", nombre="Ana",
                                   version="v1", hash_texto="c" * 64, aceptado_at=ahora),
            ])
            s.commit()
    finally:
        e.dispose()


# ── La forma de LibraCore ────────────────────────────────────────────────────
#
# El DDL de `usuarios` y `auth_log` de `libracore.db.schema` (origin/develop,
# 2026-09-11), en la forma en que llega a cada motor: en PostgreSQL el adaptador
# de LibraCore traduce `AUTOINCREMENT` a serial y `datetime('now','localtime')`
# a `to_char(LOCALTIMESTAMP, ...)`. Es una reproduccion y no una llamada a
# `init_core_schema()` porque libraauth no depende de LibraCore; lo que importa
# para estas pruebas es que las columnas sean TEXT y no las del modelo.

_LIBRACORE_SQLITE = [
    """CREATE TABLE usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
        nombre TEXT NOT NULL, email TEXT DEFAULT '', password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'operador', activo BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TEXT DEFAULT (datetime('now','-3 hours')))""",
    """CREATE TABLE auth_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        evento TEXT NOT NULL, username TEXT NOT NULL, ip TEXT, detalle TEXT)""",
]
_LIBRACORE_PG = [
    """CREATE TABLE usuarios (
        id SERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE,
        nombre TEXT NOT NULL, email TEXT DEFAULT '', password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'operador', activo BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TEXT DEFAULT to_char(LOCALTIMESTAMP - interval '3 hours', 'YYYY-MM-DD HH24:MI:SS'))""",
    """CREATE TABLE auth_log (
        id SERIAL PRIMARY KEY,
        ts TEXT NOT NULL DEFAULT to_char(LOCALTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'),
        evento TEXT NOT NULL, username TEXT NOT NULL, ip TEXT, detalle TEXT)""",
]


def _base_con_forma_de_libracore(url):
    e = _engine(url)
    try:
        with e.begin() as c:
            for ddl in (_LIBRACORE_PG if _es_pg(url) else _LIBRACORE_SQLITE):
                c.execute(text(ddl))
            # La que crea alembic, tal cual: LibraCore mantiene sus ids en 32
            # caracteres o menos (lo custodia su propio test).
            c.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"))
            c.execute(text("INSERT INTO alembic_version VALUES (:v)"), {"v": REVISION_DE_LIBRACORE})
            # Filas escritas como las escribe LibraCore: `auth_log` sin `ts`,
            # contando con el DEFAULT (es el INSERT crudo de `libracore.db.logs`).
            c.execute(text("INSERT INTO usuarios (username, nombre, password_hash, role) "
                           "VALUES ('heredado', 'Usuario Heredado', '$pbkdf2$x', 'admin')"))
            c.execute(text("INSERT INTO auth_log (evento, username, ip, detalle) "
                           "VALUES ('login', 'heredado', '10.0.0.9', '')"))
    finally:
        e.dispose()


def _tabla_de(diferencia):
    """El nombre de la tabla a la que se refiere una entrada de `compare_metadata`."""
    if isinstance(diferencia, list):  # las modify_* vienen agrupadas por columna
        diferencia = diferencia[0]
    op, objeto = diferencia[0], diferencia[1]
    if op.startswith("modify_") or op in ("add_column", "remove_column"):
        return diferencia[2]
    if op in ("add_table", "remove_table"):
        return objeto.name
    if op in ("add_fk", "remove_fk"):
        return objeto.parent.name
    return objeto.table.name


# ── 1. Base vacia ────────────────────────────────────────────────────────────


def test_base_vacia_el_upgrade_crea_las_seis_tablas(fabrica):
    url = fabrica()
    migrar.upgrade(url)

    tablas = _tablas(url)
    assert TABLAS <= tablas, f"faltan: {TABLAS - tablas}"
    assert tablas == TABLAS | {migrar.TABLA_DE_VERSION}, "la cadena creo algo que no es de auth"
    assert _version(url) == [HEAD]
    # No usurpa la tabla de version de LibraCore.
    assert "alembic_version" not in tablas

    # Y la base sirve: el ORM escribe y lee en las seis.
    _sembrar(url)
    assert all(len(f) == 1 for f in _filas(url).values())


def test_despues_de_la_cadena_el_arranque_de_hoy_no_cambia_nada(fabrica):
    """El `create_all()` del arranque sigue en los ocho productos: sobre una base
    que ya paso por la cadena tiene que ser un no-op. Es lo que deja subir el pin
    sin tocar el arranque."""
    url = fabrica()
    migrar.upgrade(url)
    antes = _foto(url)
    e = _engine(url)
    Base.metadata.create_all(e)
    e.dispose()
    assert _foto(url) == antes


def test_modelo_y_cadena_coinciden(fabrica):
    """La cabeza de la cadena y el modelo dicen lo mismo, medido dos veces.

    - **autogenerate** (`libraauth-migrar diferencias`) no encuentra nada: es la
      comparacion que va a hacer quien escriba la `0002`.
    - **el catalogo entero** de una base migrada es identico al de una creada por
      `create_all()`: cubre lo que autogenerate no mira, como el nombre de los
      indices o el `ON DELETE` de las FK.
    """
    por_cadena, por_create_all = fabrica(), fabrica()
    migrar.upgrade(por_cadena)
    e = _engine(por_create_all)
    Base.metadata.create_all(e)
    e.dispose()

    assert migrar.diferencias(por_cadena) == []
    assert _foto(por_cadena) == _foto(por_create_all)


# ── 2. Base creada por el camino de hoy ──────────────────────────────────────


def test_base_de_create_all_se_estampa_sin_tocar_nada(fabrica):
    url = fabrica()
    e = _engine(url)
    Base.metadata.create_all(e)
    e.dispose()
    _sembrar(url)
    tablas_antes, foto_antes, filas_antes = _tablas(url), _foto(url), _filas(url)
    assert all(len(f) == 1 for f in filas_antes.values()), "sin filas el control no prueba nada"

    migrar.upgrade(url)

    assert _tablas(url) == tablas_antes | {migrar.TABLA_DE_VERSION}
    assert _foto(url) == foto_antes
    assert _filas(url) == filas_antes
    assert _version(url) == [HEAD]

    # Una segunda corrida —el proximo deploy— tampoco hace nada.
    migrar.upgrade(url)
    assert _filas(url) == filas_antes
    assert _version(url) == [HEAD]


def test_base_con_cuatro_de_las_seis_crea_solo_las_que_faltan(fabrica):
    """Una instancia en un pin anterior a `demo_codigos` (v0.26.0) y a
    `aceptaciones_terminos` (v0.30.0): la baseline completa, no tropieza."""
    url = fabrica()
    parciales = [Base.metadata.tables[t] for t in
                 ("usuarios", "password_reset_tokens", "auth_log", "smtp_settings")]
    e = _engine(url)
    Base.metadata.create_all(e, tables=parciales)
    e.dispose()
    foto_antes = _foto(url)

    migrar.upgrade(url)

    assert TABLAS <= _tablas(url)
    despues = _foto(url)
    assert {t: despues[t] for t in foto_antes} == foto_antes


# ── 3. La forma de LibraCore ─────────────────────────────────────────────────


def test_base_con_usuarios_de_libracore_se_estampa_sin_normalizar(fabrica):
    url = fabrica()
    _base_con_forma_de_libracore(url)
    heredadas = {"usuarios", "auth_log"}
    foto_antes, filas_antes = _foto(url, heredadas), _filas(url, heredadas)

    migrar.upgrade(url)

    # Las dos tablas de LibraCore quedan con SU forma y sus filas.
    assert _foto(url, heredadas) == foto_antes
    assert _filas(url, heredadas) == filas_antes
    # Las cuatro satelite se crean, con FK contra ESA `usuarios`.
    assert TABLAS <= _tablas(url)
    # La tabla de version de LibraCore no se toca, ni se le suma nada.
    assert _version(url, "alembic_version") == [REVISION_DE_LIBRACORE]
    assert _version(url) == [HEAD]

    # Y el codigo del motor lee al usuario heredado sobre la base estampada.
    e = _engine(url)
    try:
        repo = UserRepository(sessionmaker(bind=e, class_=Session))
        assert repo.get_by_username("heredado")["name"] == "Usuario Heredado"
    finally:
        e.dispose()


def test_diferencias_ve_la_forma_de_libracore_y_nada_ajeno(fabrica):
    """La medicion que va antes de alterar `usuarios`: tiene que ver que ahi la
    forma no es la del modelo, y NO tiene que mencionar las tablas de otros
    motores (sin el filtro de `include_object` propone borrarlas)."""
    url = fabrica()
    _base_con_forma_de_libracore(url)
    migrar.upgrade(url)

    difs = migrar.diferencias(url)
    assert difs, "la forma de LibraCore no es la del modelo: la medicion tiene que verlo"
    assert {_tabla_de(d) for d in difs} <= {"usuarios", "auth_log"}, difs


# ── Downgrade ────────────────────────────────────────────────────────────────


def test_la_baseline_no_se_baja_y_no_borra_nada(fabrica):
    """Mismo criterio que LibraCore y LibraCommerce: el rollback de la baseline es
    el backup. Se ejercita para ver que el rechazo no deja la base a medio borrar."""
    url = fabrica()
    migrar.upgrade(url)
    _sembrar(url)
    filas_antes = _filas(url)

    with pytest.raises(RuntimeError, match="no se baja"):
        command.downgrade(migrar.configuracion(url), "base")

    assert _filas(url) == filas_antes
    assert _version(url) == [HEAD]


# ── La cadena como paquete ───────────────────────────────────────────────────


def test_una_sola_cabeza_y_adentro_del_paquete():
    """Viaja en el wheel solo si vive adentro de `libraauth/`; y dos cabezas
    harian que `upgrade head` falle en el deploy."""
    paquete = Path(libraauth.__file__).parent
    assert migrar.DIRECTORIO.parent == paquete
    assert (migrar.DIRECTORIO / "env.py").is_file()
    script = ScriptDirectory.from_config(migrar.configuracion("sqlite://"))
    assert script.get_heads() == [HEAD]


def test_los_ids_de_revision_entran_en_la_tabla_de_version():
    """`alembic_version_libraauth.version_num` es `VARCHAR(32)` (lo crea alembic).
    Un id mas largo pasa en SQLite, que no aplica el largo, y en PostgreSQL mata
    el `upgrade` DESPUES de aplicar el DDL, al escribir la version. Es el mismo
    guard que tiene LibraCore (`tests/db/test_migraciones.py`)."""
    script = ScriptDirectory.from_config(migrar.configuracion("sqlite://"))
    largos = [r.revision for r in script.walk_revisions() if len(r.revision) > 32]
    assert not largos, f"ids de revision de mas de 32 caracteres: {largos}"


def test_el_modo_offline_falla_en_vez_de_mentir(tmp_path):
    """`--sql` no puede generar esta baseline: decide que crear mirando la base.
    Que falle es la respuesta correcta; emitir un DDL seria afirmar algo que la
    corrida real podria no hacer. Mismo criterio que LibraCore."""
    cfg = migrar.configuracion(f"sqlite:///{tmp_path}/offline.db")
    with pytest.raises(RuntimeError, match="offline"):
        command.upgrade(cfg, "head", sql=True)


# ── La guarda del arranque (v0.45.0) ─────────────────────────────────────────


def test_exigir_pasa_despues_de_la_cadena(fabrica):
    url = fabrica()
    migrar.upgrade(url)
    assert migrar.exigir_schema_al_dia(_engine(url)) == HEAD


def test_exigir_falla_sobre_una_base_sin_migrar_y_dice_el_comando(fabrica):
    """🔴 El control negativo: una base vacía, sin tabla de versión."""
    url = fabrica()
    with pytest.raises(migrar.SchemaDesactualizado) as e:
        migrar.exigir_schema_al_dia(_engine(url), prefijo="libracargo", base="dominio")
    msg = str(e.value)
    assert "libraauth-migrar upgrade --prefijo libracargo --base dominio" in msg
    assert "anterior al 2026-09-16" in msg, "nombra el caso del respaldo viejo"
    assert not _tablas(url) & TABLAS, "la guarda no crea nada"


def test_exigir_falla_sobre_la_forma_de_create_all_sin_version(fabrica):
    """Lo que dejaba el arranque de antes: las seis tablas, sin versión. Es
    exactamente lo que la guarda tiene que rechazar, y la baseline adoptar."""
    url = fabrica()
    Base.metadata.create_all(_engine(url))
    with pytest.raises(migrar.SchemaDesactualizado):
        migrar.exigir_schema_al_dia(_engine(url))
    migrar.upgrade(url)
    assert migrar.exigir_schema_al_dia(_engine(url)) == HEAD


def test_exigir_falla_sobre_una_revision_vieja(fabrica):
    """La base registra una revisión que no es la cabeza."""
    url = fabrica()
    migrar.upgrade(url)
    e = _engine(url)
    with e.begin() as c:
        c.execute(text(f"UPDATE {migrar.TABLA_DE_VERSION} SET version_num = '0000_vieja'"))
    with pytest.raises(migrar.SchemaDesactualizado, match="0000_vieja"):
        migrar.exigir_schema_al_dia(e, prefijo="gestiolibra", base="core")


def test_exigir_falla_cuando_el_paquete_trae_una_cabeza_nueva(fabrica, monkeypatch):
    """El caso real de mañana: sube el pin con una `0002` y el deploy no migró."""
    url = fabrica()
    migrar.upgrade(url)
    monkeypatch.setattr(migrar, "cabeza", lambda: "0002_futura")
    with pytest.raises(migrar.SchemaDesactualizado, match=f"{HEAD}.*0002_futura"):
        migrar.exigir_schema_al_dia(_engine(url))


def test_exigir_con_la_tabla_de_version_vacia_es_sin_migrar(fabrica):
    url = fabrica()
    migrar.upgrade(url)
    e = _engine(url)
    with e.begin() as c:
        c.execute(text(f"DELETE FROM {migrar.TABLA_DE_VERSION}"))
    assert migrar.revision_actual(e) is None
    with pytest.raises(migrar.SchemaDesactualizado, match="no existe o está vacía"):
        migrar.exigir_schema_al_dia(e)


def test_la_cabeza_es_la_de_la_cadena():
    assert migrar.cabeza() == HEAD


def test_crear_schema_de_auth_con_url_y_con_engine(fabrica):
    from libraauth.testing import crear_schema_de_auth

    url = fabrica()
    assert crear_schema_de_auth(url) == HEAD
    assert TABLAS <= _tablas(url)
    otra = fabrica()
    assert crear_schema_de_auth(_engine(otra)) == HEAD
    assert migrar.exigir_schema_al_dia(_engine(otra)) == HEAD


def test_crear_schema_de_auth_rechaza_sqlite_en_memoria():
    from libraauth.testing import crear_schema_de_auth

    with pytest.raises(ValueError, match="en memoria"):
        crear_schema_de_auth("sqlite:///:memory:")
    with pytest.raises(ValueError, match="en memoria"):
        crear_schema_de_auth(create_engine("sqlite://"))


def test_importar_libraauth_no_trae_alembic():
    """Un producto que sube el pin sin adoptar la cadena no tiene por que tener
    alembic: importar el paquete —y hasta `migrar`— no lo carga. En un proceso
    aparte porque en este la suite ya lo importo."""
    salida = subprocess.run(
        [sys.executable, "-c",
         "import sys, libraauth, libraauth.models, libraauth.migrar; "
         "print('alembic' in sys.modules)"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert salida == "False"


# ── Resolucion del destino ───────────────────────────────────────────────────


def _comparte_base(prefijo):
    """Lo que hace `libracore.db.url_de_instancia.comparte_base_con_el_dominio`."""
    return prefijo == "una"


def _resolver(prefijo, *, core, entorno):
    """Lo que hace `libracore.db.url_de_instancia` con el nombre normalizado."""
    p = prefijo.upper()
    return entorno.get(f"{p}_LIBRACORE_DATABASE_URL" if core else f"{p}_DATABASE_URL", "")


DOS_BASES = {"GL_DATABASE_URL": "postgresql://dominio", "GL_LIBRACORE_DATABASE_URL": "postgresql://core"}


@pytest.mark.parametrize("entorno,prefijo,base,esperada", [
    # Gestiolibra/MedLibra/VentaLibra: auth en la de LibraCore.
    (DOS_BASES, "gl", "core", "postgresql://core"),
    # 🔴 LibraCargo/LibraClub: tienen base de LibraCore y auth va en la del dominio.
    (DOS_BASES, "gl", "dominio", "postgresql://dominio"),
    # Contalibra/Restolibra: sin variable del core, "core" es la unica base
    # (el prefijo "una" figura como de una sola base, ver `_comparte_base`).
    ({"UNA_DATABASE_URL": "postgresql://unica"}, "una", "core", "postgresql://unica"),
    # La salida de emergencia gana a todo.
    ({**DOS_BASES, "LIBRAAUTH_MIGRAR_URL": "postgresql://explicita"}, "gl", "core",
     "postgresql://explicita"),
    # Sin prefijo, un script en el host.
    ({"DATABASE_URL": "postgresql://host"}, None, None, "postgresql://host"),
])
def test_url_de_auth(entorno, prefijo, base, esperada):
    assert migrar.url_de_auth(prefijo, base, entorno=entorno, resolver=_resolver,
                              comparte_base=_comparte_base) == esperada


@pytest.mark.parametrize("entorno,prefijo,base", [
    (DOS_BASES, "gl", None),          # --prefijo sin --base: no se deduce
    (DOS_BASES, "gl", "libracore"),   # base que no existe
    # Un prefijo que no resuelve NO cae a DATABASE_URL.
    ({"DATABASE_URL": "postgresql://otra"}, "gl", "dominio"),
    ({}, None, None),
])
def test_url_de_auth_falla_en_vez_de_adivinar(entorno, prefijo, base):
    with pytest.raises(migrar.SinURL):
        migrar.url_de_auth(prefijo, base, entorno=entorno, resolver=_resolver,
                           comparte_base=_comparte_base)


# ── La caida de --base core al dominio (2026-09-16) ──────────────────────────


def test_base_core_sin_variable_del_core_FALLA_en_un_producto_de_core_aparte():
    """🔴 El defecto que se cierra, gemelo del de `libracore.migrar.url_de_core`.
    Gestiolibra sin su variable del core: la regla vieja caia al dominio y
    creaba las tablas de auth ahi, **sin fallar**."""
    entorno = {"GL_DATABASE_URL": "postgresql://dominio"}
    with pytest.raises(migrar.SinURL, match="una sola base"):
        migrar.url_de_auth("gl", "core", entorno=entorno, resolver=_resolver,
                           comparte_base=_comparte_base)


def test_base_core_con_variable_del_core_no_consulta_la_lista():
    """Control: el caso normal no depende de la lista."""
    def explota(prefijo):
        raise AssertionError("no tenia que consultarse")
    assert migrar.url_de_auth("gl", "core", entorno=DOS_BASES, resolver=_resolver,
                              comparte_base=explota) == "postgresql://core"


def test_base_dominio_no_depende_de_la_lista():
    """Control: `--base dominio` (LibraCargo, LibraClub, LibraDesk, Contalibra,
    Restolibra) no cambia."""
    entorno = {"GL_DATABASE_URL": "postgresql://dominio"}
    assert migrar.url_de_auth("gl", "dominio", entorno=entorno, resolver=_resolver,
                              comparte_base=lambda p: False) == "postgresql://dominio"


def test_la_salida_de_emergencia_sigue_ganando_con_base_core():
    entorno = {"GL_DATABASE_URL": "postgresql://dominio",
               "LIBRAAUTH_MIGRAR_URL": "postgresql://explicita"}
    assert migrar.url_de_auth("gl", "core", entorno=entorno, resolver=_resolver,
                              comparte_base=lambda p: False) == "postgresql://explicita"


def test_sin_libracore_la_lista_dice_que_no(monkeypatch):
    """El default seguro: si no se puede preguntar, no se cae al dominio. Se
    simula una LibraCore ausente (o anterior a v1.103.0) tapando el modulo."""
    monkeypatch.setitem(sys.modules, "libracore.db.url_de_instancia", None)
    assert migrar._comparte_base_segun_libracore("contalibra") is False


def test_el_destino_explicito_le_gana_a_database_url(tmp_path, monkeypatch):
    """Adentro de un contenedor `DATABASE_URL` es la base del DOMINIO. En
    Gestiolibra, MedLibra y VentaLibra auth vive en la de LibraCore: si el
    `env.py` prefiriera la variable, `upgrade(url_del_core)` migraria la del
    dominio y devolveria exito. Es el defecto que LibraGenda encontro migrando
    una base real, y se mide igual: mirando en cual quedaron las tablas."""
    explicita = f"sqlite:///{tmp_path}/explicita.db"
    del_entorno = f"sqlite:///{tmp_path}/entorno.db"
    monkeypatch.setenv("DATABASE_URL", del_entorno)

    migrar.upgrade(explicita)

    assert TABLAS <= _tablas(explicita)
    assert not _tablas(del_entorno) & TABLAS


def test_normalizar_url():
    assert migrar.normalizar_url("postgresql://u@h/b") == "postgresql+psycopg://u@h/b"
    assert migrar.normalizar_url("postgresql+psycopg://u@h/b") == "postgresql+psycopg://u@h/b"
    assert migrar.normalizar_url("/tmp/x.db") == f"sqlite:///{Path('/tmp/x.db').resolve()}"


def test_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("LIBRAAUTH_MIGRAR_URL", raising=False)
    assert migrar.main(["no-existe"]) == 2
    assert migrar.main(["--help"]) == 0
    assert migrar.main(["upgrade", "--prefijo", "gl"]) == 1
    assert "--base" in capsys.readouterr().err
    assert migrar._parsear(["stamp", "--prefijo=gl", "--base", "core", "head"]) == (
        "stamp", "gl", "core", "head")

    url = f"sqlite:///{tmp_path}/cli.db"
    monkeypatch.setenv("LIBRAAUTH_MIGRAR_URL", url)
    assert migrar.main(["upgrade"]) == 0
    assert TABLAS <= _tablas(url)
    assert migrar.main(["diferencias"]) == 0

    divergente = f"sqlite:///{tmp_path}/divergente.db"
    _base_con_forma_de_libracore(divergente)
    monkeypatch.setenv("LIBRAAUTH_MIGRAR_URL", divergente)
    assert migrar.main(["diferencias"]) == 3
