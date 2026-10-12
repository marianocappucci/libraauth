"""El registrador para productos SIN ORM (v0.49.0, ADR-022).

Lo que fijan, en orden de lo que se rompe sin que se note:

1. **Paridad con el listener del ORM.** El mismo alta, edicion, baja y
   desactivacion por los dos caminos tiene que dejar filas iguales (salvo `id` y
   `ts`). Si no, "el formato del log" vuelve a ser dos cosas distintas, que es
   exactamente como divergio la copia de `libracommerce`.
2. Las reglas que el ORM ya tenia: ocultas tapadas, edicion sin diff sin fila,
   usuario del `ContextVar`, ids enteros y de texto, lista blanca.
3. Que el INSERT entre en las tres variantes de la tabla que hay en la familia:
   la de `libraauth` (`entidad_id` texto, `ts` DateTime), la de `libracommerce`
   (`entidad_id INTEGER`, `ts TEXT`) y la de PostgreSQL real.

El camino DB-API se prueba contra tablas reales de dominio, leyendo el antes y el
despues con un `SELECT` como lo hace `libracore.db.clients`; no se arman los
`antes/despues` a mano.
"""
import os
import sqlite3
from types import SimpleNamespace

import pytest
from sqlalchemy import Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from libraauth.auditoria import (
    BORRAR,
    CREAR,
    EDITAR,
    OCULTO,
    SISTEMA,
    AuditoriaBase,
    AuditoriaRepository,
    configurar_auditoria,
    crear_tabla_actividad_log,
    diff_de_valores,
    etiqueta_de_valores,
    fila_de_auditoria,
    registrador_dbapi,
    usuario_actual,
)

TABLA = "clientes_motor_demo"

# Como el modelo de clientes de LibraDesk sobre la tabla del motor: el producto
# dice `nombre` y la columna es `name`.
ATRIBUTOS = {TABLA: {"name": "nombre", "phone": "telefono", "secreto": "api_key"}}


class DominioBase(DeclarativeBase):
    pass


class ClienteDeMotor(DominioBase):
    __tablename__ = TABLA
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    nombre: Mapped[str | None] = mapped_column("name", String(100))
    telefono: Mapped[str | None] = mapped_column("phone", String(100))
    api_key: Mapped[str | None] = mapped_column("secreto", String(100))
    activo: Mapped[int] = mapped_column(Integer, default=1)
    tipo: Mapped[str | None] = mapped_column(String(50))
    marca: Mapped[str | None] = mapped_column(String(50))
    modelo: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[str | None] = mapped_column(String(30))


DDL_DOMINIO = f"""
    CREATE TABLE {TABLA} (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, phone TEXT, secreto TEXT,
        activo INTEGER DEFAULT 1, tipo TEXT, marca TEXT, modelo TEXT, created_at TEXT
    )
"""
COLUMNAS = ("id", "name", "phone", "secreto", "activo", "tipo", "marca", "modelo", "created_at")


@pytest.fixture(autouse=True)
def _usuario_limpio():
    token = usuario_actual.set(SISTEMA)
    yield
    usuario_actual.reset(token)


# ── Los dos caminos, sobre el mismo dominio ──────────────────────────────────

class CaminoORM:
    """Escribe con sesiones y deja que el listener arme la fila."""

    def __init__(self, tmp_path, **kwargs):
        engine = create_engine(f"sqlite:///{tmp_path}/orm.db")
        DominioBase.metadata.create_all(engine)
        AuditoriaBase.metadata.create_all(engine)
        self.sessions = sessionmaker(bind=engine)
        configurar_auditoria(self.sessions, {"ClienteDeMotor": "cliente"}, **kwargs)
        self.repo = AuditoriaRepository(self.sessions)

    def crear(self, **datos) -> int:
        with self.sessions.begin() as s:
            c = ClienteDeMotor(**datos)
            s.add(c)
            s.flush()
            return c.id

    def editar(self, id_, **cambios):
        with self.sessions.begin() as s:
            c = s.get(ClienteDeMotor, id_)
            for k, v in cambios.items():
                setattr(c, k, v)

    def borrar(self, id_):
        with self.sessions.begin() as s:
            s.delete(s.get(ClienteDeMotor, id_))

    def filas(self):
        return list(reversed(self.repo.listar()))


class CaminoDBAPI:
    """Escribe con SQL crudo sobre `sqlite3`, como `libracore.db.clients`: lee antes y
    despues con un SELECT y le pasa el cambio al registrador."""

    def __init__(self, tmp_path, **kwargs):
        engine = create_engine(f"sqlite:///{tmp_path}/dbapi.db")
        crear_tabla_actividad_log(engine)
        self.repo = AuditoriaRepository(sessionmaker(bind=engine))
        self.conn = sqlite3.connect(f"{tmp_path}/dbapi.db")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(DDL_DOMINIO)
        self.registrar = registrador_dbapi({TABLA: "cliente"}, atributos=ATRIBUTOS, **kwargs)

    def _leer(self, id_):
        fila = self.conn.execute(f"SELECT * FROM {TABLA} WHERE id = ?", (id_,)).fetchone()
        return dict(fila) if fila else None

    def _emitir(self, accion, id_, antes, despues):
        self.registrar(self.conn, SimpleNamespace(
            tabla=TABLA, accion=accion, id=id_, antes=antes, despues=despues))
        self.conn.commit()

    def crear(self, **datos) -> int:
        # El ORM guarda los atributos; el SQL, las columnas.
        columnas = {"nombre": "name", "telefono": "phone", "api_key": "secreto"}
        datos = {columnas.get(k, k): v for k, v in datos.items()}
        datos.setdefault("activo", 1)
        cur = self.conn.execute(
            f"INSERT INTO {TABLA} ({', '.join(datos)}) VALUES ({', '.join('?' * len(datos))})",
            tuple(datos.values()),
        )
        self._emitir(CREAR, cur.lastrowid, None, self._leer(cur.lastrowid))
        return cur.lastrowid

    def editar(self, id_, **cambios):
        columnas = {"nombre": "name", "telefono": "phone", "api_key": "secreto"}
        cambios = {columnas.get(k, k): v for k, v in cambios.items()}
        antes = self._leer(id_)
        sets = ", ".join(f"{c} = ?" for c in cambios)
        self.conn.execute(f"UPDATE {TABLA} SET {sets} WHERE id = ?", (*cambios.values(), id_))
        self._emitir(EDITAR, id_, antes, self._leer(id_))

    def borrar(self, id_):
        antes = self._leer(id_)
        self.conn.execute(f"DELETE FROM {TABLA} WHERE id = ?", (id_,))
        self._emitir(BORRAR, id_, antes, None)

    def filas(self):
        return list(reversed(self.repo.listar()))


def _sin_id_ni_ts(filas):
    return [{k: v for k, v in f.items() if k not in ("id", "ts")} for f in filas]


def _ambos(tmp_path, **kwargs):
    return CaminoORM(tmp_path, **kwargs), CaminoDBAPI(tmp_path, **kwargs)


def _hacer(escenario, *caminos):
    for camino in caminos:
        escenario(camino)


# ── 1. Paridad ───────────────────────────────────────────────────────────────

def test_alta_edicion_desactivacion_y_baja_dejan_las_mismas_filas(tmp_path):
    orm, dbapi = _ambos(tmp_path)

    def escenario(c):
        i = c.crear(nombre="Compulibra", telefono="111", created_at="2026-10-12")
        c.editar(i, nombre="Compulibra SA", telefono="222")
        c.editar(i, activo=0)  # la desactivacion es una edicion {activo: [1, 0]}
        c.editar(i, activo=1)
        c.borrar(i)

    _hacer(escenario, orm, dbapi)

    assert len(orm.filas()) == 5
    assert _sin_id_ni_ts(dbapi.filas()) == _sin_id_ni_ts(orm.filas())
    # Y no por casualidad: los campos que importan, a la vista.
    alta, ed1, des, rea, baja = orm.filas()
    assert (alta["accion"], alta["descripcion"], alta["cambios"]) == (CREAR, "Cliente — Compulibra", None)
    assert ed1["cambios"] == {"nombre": ["Compulibra", "Compulibra SA"], "telefono": ["111", "222"]}
    assert des["cambios"] == {"activo": [1, 0]}
    assert rea["cambios"] == {"activo": [0, 1]}
    assert (baja["accion"], baja["cambios"]) == (BORRAR, None)


def test_la_clave_del_diff_es_el_atributo_y_no_la_columna(tmp_path):
    """El caso LibraDesk: `name` en la base, `nombre` en el producto. El registrador
    renombra con `atributos`; la pantalla de logs sabe mostrar `nombre`."""
    dbapi = CaminoDBAPI(tmp_path)
    i = dbapi.crear(nombre="Ana")
    dbapi.editar(i, nombre="Ana B")

    assert dbapi.filas()[-1]["cambios"] == {"nombre": ["Ana", "Ana B"]}


def test_la_etiqueta_de_respaldo_es_la_misma_en_los_dos_caminos(tmp_path):
    """Sin nombre, el texto se arma con tipo/marca/modelo: una sola regla."""
    orm, dbapi = _ambos(tmp_path)

    def escenario(c):
        c.crear(tipo="Notebook", marca="Lenovo", modelo="T14")

    _hacer(escenario, orm, dbapi)

    assert orm.filas()[0]["descripcion"] == "Cliente — Notebook Lenovo T14"
    assert _sin_id_ni_ts(dbapi.filas()) == _sin_id_ni_ts(orm.filas())


def test_paridad_con_columnas_ocultas_del_producto(tmp_path):
    """`columnas_ocultas` del producto se compara contra columna y atributo en los dos."""
    orm, dbapi = _ambos(tmp_path, columnas_ocultas={"telefono"})

    def escenario(c):
        i = c.crear(nombre="Ana", telefono="111")
        c.editar(i, telefono="222")

    _hacer(escenario, orm, dbapi)

    assert orm.filas()[1]["cambios"] == {"telefono": [OCULTO, OCULTO]}
    assert _sin_id_ni_ts(dbapi.filas()) == _sin_id_ni_ts(orm.filas())


def test_paridad_con_la_columna_oculta_nombrada_por_su_columna_de_base(tmp_path):
    """El producto escribe `secreto` (la columna) y el atributo se llama `api_key`:
    se tapa por cualquiera de las dos formas, en los dos caminos."""
    orm, dbapi = _ambos(tmp_path, columnas_ocultas={"secreto"})

    def escenario(c):
        i = c.crear(nombre="Ana", api_key="a")
        c.editar(i, api_key="b")

    _hacer(escenario, orm, dbapi)

    assert orm.filas()[1]["cambios"] == {"api_key": [OCULTO, OCULTO]}
    assert _sin_id_ni_ts(dbapi.filas()) == _sin_id_ni_ts(orm.filas())


def test_paridad_del_usuario_del_contextvar(tmp_path):
    orm, dbapi = _ambos(tmp_path)
    token = usuario_actual.set("marcos")
    try:
        _hacer(lambda c: c.crear(nombre="Ana"), orm, dbapi)
    finally:
        usuario_actual.reset(token)

    assert orm.filas()[0]["usuario"] == "marcos"
    assert _sin_id_ni_ts(dbapi.filas()) == _sin_id_ni_ts(orm.filas())


# ── 2. Reglas ────────────────────────────────────────────────────────────────

def test_una_oculta_que_cambio_se_registra_tapada_y_una_que_no_cambio_no_entra(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    i = dbapi.crear(nombre="Ana", api_key="a")
    dbapi.editar(i, api_key="clave-nueva")
    dbapi.editar(i, api_key="clave-nueva", nombre="Ana B")  # la oculta ya no cambia

    alta, solo_oculta, mixta = dbapi.filas()
    assert alta["cambios"] is None
    assert solo_oculta["cambios"] == {"api_key": [OCULTO, OCULTO]}
    assert mixta["cambios"] == {"nombre": ["Ana", "Ana B"]}
    assert "clave-nueva" not in str(dbapi.filas())


def test_una_edicion_sin_nada_distinto_no_deja_fila(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    i = dbapi.crear(nombre="Ana")
    dbapi.editar(i, nombre="Ana")  # el UPDATE no cambio nada

    assert [f["accion"] for f in dbapi.filas()] == [CREAR]


def test_el_usuario_sale_del_contextvar_y_se_recorta_a_cien(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    dbapi.crear(nombre="a")
    assert dbapi.filas()[0]["usuario"] == SISTEMA
    token = usuario_actual.set("u" * 150)
    try:
        dbapi.crear(nombre="b")
    finally:
        usuario_actual.reset(token)
    assert dbapi.filas()[1]["usuario"] == "u" * 100


def test_una_tabla_fuera_de_la_lista_blanca_no_deja_fila(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    dbapi.registrar(dbapi.conn, SimpleNamespace(
        tabla="otra", accion=CREAR, id=1, antes=None, despues={"name": "x"}))
    dbapi.conn.commit()
    assert dbapi.filas() == []


def test_ids_enteros_y_de_texto_quedan_como_texto_y_el_cero_es_un_id(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    reg = registrador_dbapi({"pacientes": "paciente"})
    for id_ in (7, "patient-1", 0, None):
        reg(dbapi.conn, SimpleNamespace(
            tabla="pacientes", accion=CREAR, id=id_, antes=None, despues={"nombre": "Ana"}))
    dbapi.conn.commit()
    assert [f["entidad_id"] for f in dbapi.filas()] == ["7", "patient-1", "0", None]


def test_columnas_ignoradas_no_entran_al_diff_ni_dejan_una_edicion_vacia(tmp_path):
    dbapi = CaminoDBAPI(tmp_path, columnas_ignoradas={"created_at"})
    i = dbapi.crear(nombre="Ana", created_at="2026-10-12")
    dbapi.editar(i, created_at="2026-10-13")  # solo cambia una ignorada: sin fila
    dbapi.editar(i, created_at="2026-10-14", nombre="Ana B")

    assert [f["accion"] for f in dbapi.filas()] == [CREAR, EDITAR]
    assert dbapi.filas()[1]["cambios"] == {"nombre": ["Ana", "Ana B"]}


def test_etiqueta_propia_reemplaza_el_armado(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    reg = registrador_dbapi({"parties": "cliente/proveedor"},
                            etiqueta=lambda tabla, v: str(v.get("display_name") or ""))
    reg(dbapi.conn, SimpleNamespace(
        tabla="parties", accion=CREAR, id=3, antes=None, despues={"display_name": "Don Pepe"}))
    dbapi.conn.commit()
    assert dbapi.filas()[0]["descripcion"] == "Cliente/proveedor — Don Pepe"


def test_etiqueta_none_cae_en_el_armado_por_defecto_y_vacia_es_sin_etiqueta(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    reg = registrador_dbapi(
        {"a": "uno", "b": "dos"},
        etiqueta=lambda tabla, v: "" if tabla == "a" else None,
    )
    for tabla in ("a", "b"):
        reg(dbapi.conn, SimpleNamespace(
            tabla=tabla, accion=CREAR, id=1, antes=None, despues={"nombre": "Ana"}))
    dbapi.conn.commit()
    assert [f["descripcion"] for f in dbapi.filas()] == ["Uno", "Dos — Ana"]


def test_una_edicion_sin_antes_se_registra_sin_detalle(tmp_path):
    """No hay con que comparar (el repositorio no tiene como leer el estado previo): el
    hecho queda, el detalle no se inventa."""
    dbapi = CaminoDBAPI(tmp_path)
    reg = registrador_dbapi({"precios": "precio"})
    reg(dbapi.conn, SimpleNamespace(
        tabla="precios", accion=EDITAR, id=3, antes=None, despues={"valor": 10}))
    dbapi.conn.commit()
    (fila,) = dbapi.filas()
    assert (fila["accion"], fila["cambios"], fila["entidad_id"]) == (EDITAR, None, "3")


def test_la_baja_se_describe_con_lo_que_se_borro(tmp_path):
    dbapi = CaminoDBAPI(tmp_path)
    i = dbapi.crear(nombre="Ana")
    dbapi.borrar(i)
    assert dbapi.filas()[1]["descripcion"] == "Cliente — Ana"


def test_resumir_se_aplica_al_valor_pero_la_comparacion_es_sobre_el_crudo():
    """Dos colecciones del mismo largo pero con otro contenido SON una edicion."""
    cambios = diff_de_valores(
        {"items": (1, 2)}, {"items": (1, 3)},
        resumir=lambda v: f"{len(v)} items" if isinstance(v, (tuple, list)) else v,
    )
    assert cambios == {"items": ["2 items", "2 items"]}


# ── Las piezas puras ─────────────────────────────────────────────────────────

def test_fila_de_auditoria_es_la_definicion_del_formato():
    fila = fila_de_auditoria(
        entidad="lista_de_precios", accion=EDITAR, entidad_id=0, etiqueta="Mayorista",
        cambios={"x": [1, 2]}, usuario="u" * 120,
    )
    assert fila["descripcion"] == "Lista de precios — Mayorista"
    assert fila["entidad_id"] == "0"
    assert fila["usuario"] == "u" * 100
    assert fila["cambios"] == '{"x": [1, 2]}'
    sin = fila_de_auditoria(entidad="cliente", accion=CREAR)
    assert (sin["descripcion"], sin["entidad_id"], sin["cambios"], sin["usuario"]) == (
        "Cliente", None, None, SISTEMA)


def test_etiqueta_de_valores_respeta_el_orden_y_el_respaldo():
    assert etiqueta_de_valores({"nombre": "A", "name": "B"}.get) == "A"
    assert etiqueta_de_valores({"tipo": "PC", "modelo": "X"}.get) == "PC X"
    assert etiqueta_de_valores({}.get) == ""


# ── 3. Las tablas reales de la familia ───────────────────────────────────────

def test_crear_tabla_actividad_log_es_idempotente_y_no_pisa_una_existente(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/x.db")
    crear_tabla_actividad_log(engine)
    crear_tabla_actividad_log(engine)
    with engine.connect() as c:
        crear_tabla_actividad_log(c)


def test_entra_en_la_tabla_que_crea_libracommerce(tmp_path):
    """`entidad_id INTEGER` y `ts TEXT`: el DDL de `libracommerce.db.schema`, que es la
    que tienen hoy Contalibra, Restolibra y VentaLibra."""
    conn = sqlite3.connect(f"{tmp_path}/c.db")
    conn.execute(
        "CREATE TABLE actividad_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
        " usuario TEXT NOT NULL DEFAULT 'Sistema', accion TEXT NOT NULL, entidad TEXT NOT NULL,"
        " entidad_id INTEGER, descripcion TEXT NOT NULL DEFAULT '', cambios TEXT)"
    )
    reg = registrador_dbapi({"clients": "cliente"})
    reg(conn, SimpleNamespace(tabla="clients", accion=CREAR, id=5, antes=None, despues={"name": "Ana"}))

    fila = conn.execute("SELECT ts, entidad_id, descripcion FROM actividad_log").fetchone()
    assert fila[1] == 5  # la afinidad INTEGER lo convierte
    assert len(fila[0]) == 19 and fila[0][10] == " "  # YYYY-MM-DD HH:MM:SS
    assert fila[2] == "Cliente — Ana"


# ── PostgreSQL real ──────────────────────────────────────────────────────────

POSTGRES_URL = os.environ.get("LIBRAAUTH_POSTGRES_URL", "")
necesita_postgres = pytest.mark.skipif(
    not POSTGRES_URL, reason="sin LIBRAAUTH_POSTGRES_URL: no hay PostgreSQL real")


class _ConexionPsycopg:
    """Lo minimo del `ConnectionWrapper` de libracore: `?` -> `%s` sobre una conexion
    psycopg. Alcanza para ejercitar los tipos de las columnas; la traduccion real la
    prueba `libracore` en su propia suite."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        return self._conn.execute(sql.replace("?", "%s"), params)


@pytest.fixture
def pg():
    psycopg = pytest.importorskip("psycopg")
    url = POSTGRES_URL.replace("postgresql+psycopg://", "postgresql://", 1)
    conn = psycopg.connect(url)
    conn.execute("DROP TABLE IF EXISTS actividad_log")
    conn.commit()
    yield conn
    conn.execute("DROP TABLE IF EXISTS actividad_log")
    conn.commit()
    conn.close()


@necesita_postgres
@pytest.mark.parametrize("entidad_id_ddl, ts_ddl", [
    ("VARCHAR(100)", "TIMESTAMP"),  # la de libraauth (AuditoriaBase)
    ("INTEGER", "TEXT"),            # la de libracommerce (init_schema)
])
def test_postgres_el_insert_entra_en_las_dos_variantes_de_la_tabla(pg, entidad_id_ddl, ts_ddl):
    pg.execute(
        f"CREATE TABLE actividad_log (id SERIAL PRIMARY KEY, ts {ts_ddl} NOT NULL,"
        " usuario VARCHAR(100) NOT NULL DEFAULT 'Sistema', accion VARCHAR(20) NOT NULL,"
        f" entidad VARCHAR(50) NOT NULL, entidad_id {entidad_id_ddl},"
        " descripcion VARCHAR(500) NOT NULL DEFAULT '', cambios TEXT)"
    )
    reg = registrador_dbapi({"clients": "cliente"}, atributos={"clients": {"name": "nombre"}})
    conn = _ConexionPsycopg(pg)
    reg(conn, SimpleNamespace(tabla="clients", accion=CREAR, id=12, antes=None, despues={"name": "Ana"}))
    reg(conn, SimpleNamespace(tabla="clients", accion=EDITAR, id=12,
                              antes={"name": "Ana"}, despues={"name": "Ana B"}))
    pg.commit()

    filas = pg.execute(
        "SELECT accion, entidad_id::text, descripcion, cambios FROM actividad_log ORDER BY id"
    ).fetchall()
    assert filas == [
        ("crear", "12", "Cliente — Ana", None),
        ("editar", "12", "Cliente — Ana B", '{"nombre": ["Ana", "Ana B"]}'),
    ]


@necesita_postgres
def test_postgres_un_id_de_texto_entra_en_la_tabla_de_libraauth(pg):
    engine = create_engine(POSTGRES_URL)
    try:
        crear_tabla_actividad_log(engine)
        reg = registrador_dbapi({"pacientes": "paciente"})
        reg(_ConexionPsycopg(pg), SimpleNamespace(
            tabla="pacientes", accion=CREAR, id="patient-1", antes=None, despues={"nombre": "Ana"}))
        pg.commit()
        fila = AuditoriaRepository(sessionmaker(bind=engine)).listar()[0]
        assert (fila["entidad_id"], fila["ts"][:2]) == ("patient-1", "20")
    finally:
        engine.dispose()
