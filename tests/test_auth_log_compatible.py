"""`auth_log` creada por `create_all()` tiene que aceptar el INSERT crudo.

**El caso que esto arregla.** En Contalibra y Restolibra hay **dos escritores**
sobre la misma tabla: el ORM de este paquete y `libracore.db.logs`, que hace

    INSERT INTO auth_log (evento, username, ip, detalle) VALUES (?,?,?,?)

sin `ts`, contando con el `DEFAULT` de la tabla. El modelo declaraba el default
de `ts` **sólo en Python**, que no genera cláusula SQL: una tabla creada por
`create_all()` salía sin DEFAULT y ese INSERT moría con
`NOT NULL constraint failed: auth_log.ts`.

🔴 **No se veía en ninguna instancia existente.** Ahí la tabla la había creado
LibraCore, con su DEFAULT, y `create_all()` no altera tablas que ya existen. Se
veía sólo en bases **nuevas** — o sea en cada instancia que se creara de ahí en
adelante, incluidas las seis demos— y recién cuando alguien intentara entrar.
Lo encontró el bump de Contalibra el 2026-08-06: 148 tests verdes pasaron a 101
errores de golpe.

Lo que fijan estos tests:

1. 🔴 Que el INSERT crudo sin `ts` funcione contra una tabla creada por
   `create_all()`. Es la compatibilidad que el docstring del modelo promete.
2. Que el `ts` que pone la base sea hora **local**, no UTC: si los dos
   escritores usaran husos distintos, la mitad de los eventos quedaría tres
   horas corrida y el log se leería mal justo cuando alguien busca quién entró.
3. Que las escrituras del ORM sigan funcionando.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable

from libraauth.models import AuthEvent, Base

#: El INSERT literal de `libracore.db.logs.registrar_auth_event`.
INSERT_CRUDO = (
    "INSERT INTO auth_log (evento, username, ip, detalle) VALUES (?,?,?,?)"
)


@pytest.fixture
def base_nueva(tmp_path):
    """Una base **vacía**, con el schema creado por `create_all()`.

    Es el caso que importa: una instancia nueva. En las que ya existen la tabla
    la creó LibraCore y `create_all` no la toca.
    """
    ruta = tmp_path / "nueva.db"
    engine = create_engine(f"sqlite:///{ruta}")
    Base.metadata.create_all(engine)
    return engine, ruta


def test_el_insert_crudo_sin_ts_funciona(base_nueva):
    """🔴 El caso que rompía. `libracore.db.logs` omite `ts` a propósito."""
    import sqlite3

    _, ruta = base_nueva
    con = sqlite3.connect(ruta)
    con.execute(INSERT_CRUDO, ("login", "alguien", "1.2.3.4", ""))
    con.commit()

    fila = con.execute("SELECT evento, username, ts FROM auth_log").fetchone()
    assert fila[0] == "login"
    assert fila[1] == "alguien"
    assert fila[2], "ts quedó vacío: la tabla se creó sin DEFAULT"


def test_el_ddl_declara_el_default_y_es_hora_local(base_nueva):
    """La aserción va sobre el **DDL** y no sobre el valor de una fila, por dos
    motivos distintos:

    - Una fila escrita por el ORM tendría `ts` igual aunque la tabla no tuviera
      DEFAULT, así que no distinguiría nada.
    - ⚠️ Y comparar el valor escrito contra `datetime.now()` **no distingue
      hora local de UTC en una máquina en UTC**, que es lo que corre el CI.
      Una primera versión de este test hacía justamente eso y pasaba con
      `server_default=func.now()` puesto —o sea, con la defensa rota—. Lo
      delató el arnés.

    Que sea `localtime` importa porque el otro escritor de esta tabla
    (`libracore.db.logs`) usa `datetime('now','localtime')`: con
    `CURRENT_TIMESTAMP` —que en SQLite es UTC— una base escrita desde los dos
    lados quedaría con la mitad de los eventos tres horas corrida, y un log de
    accesos con la hora mal se lee justo cuando alguien busca quién entró.
    """
    _, ruta = base_nueva
    import sqlite3

    ddl = sqlite3.connect(ruta).execute(
        "SELECT sql FROM sqlite_master WHERE name='auth_log'").fetchone()[0]

    assert "DEFAULT" in ddl.upper()
    assert "localtime" in ddl
    assert "CURRENT_TIMESTAMP" not in ddl.upper()


def test_el_valor_que_escribe_la_base_es_una_fecha_de_ahora(base_nueva):
    """Complementa al de arriba: el DDL puede estar bien y el literal ser
    inservible. Esto no distingue husos —la máquina puede estar en UTC— pero sí
    detecta un DEFAULT que no produzca una fecha usable."""
    import sqlite3

    _, ruta = base_nueva
    con = sqlite3.connect(ruta)
    con.execute(INSERT_CRUDO, ("login", "alguien", "", ""))
    con.commit()

    escrito = datetime.fromisoformat(
        con.execute("SELECT ts FROM auth_log").fetchone()[0])
    assert abs(escrito - datetime.now()) < timedelta(hours=24)


def test_ip_y_detalle_aceptan_null(base_nueva):
    """La tabla de LibraCore las tiene nulables. Si el modelo las declarara NOT
    NULL, `create_all` crearía una tabla más estricta que la de las instancias
    que ya existen — y las dos dejarían de ser la misma tabla."""
    import sqlite3

    _, ruta = base_nueva
    con = sqlite3.connect(ruta)
    con.execute(
        "INSERT INTO auth_log (evento, username, ip, detalle) VALUES (?,?,NULL,NULL)",
        ("login", "alguien"),
    )
    con.commit()

    assert con.execute("SELECT COUNT(*) FROM auth_log").fetchone()[0] == 1


def test_el_orm_escribe_sobre_una_tabla_creada_SIN_default(tmp_path):
    """🔴 Por qué los DOS defaults hacen falta, y no alcanza con el de la base.

    En LibraDesk la tabla ya existe creada por `create_all()` de una versión
    anterior de este modelo, o sea **`ts DATETIME NOT NULL` sin ningún
    DEFAULT** (medido el 2026-08-06: 22 filas en dev, 2 en producción).
    `create_all` no la va a alterar. Ahí las escrituras del ORM funcionan
    únicamente gracias al `default=datetime.now` de Python.

    ⚠️ La primera versión de este test escribía contra una tabla **nueva**, que
    ya trae el `server_default`: pasaba con el default de Python sacado, porque
    lo ponía la base. Lo delató el arnés.
    """
    import sqlite3

    ruta = tmp_path / "sin_default.db"
    sqlite3.connect(ruta).executescript("""
        CREATE TABLE auth_log (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       DATETIME NOT NULL,
            evento   VARCHAR(50) NOT NULL,
            username VARCHAR(100) NOT NULL,
            ip       VARCHAR(64),
            detalle  VARCHAR(500)
        );
    """)

    engine = create_engine(f"sqlite:///{ruta}")
    with sessionmaker(bind=engine)() as s:
        s.add(AuthEvent(evento="logout", username="alguien"))
        s.commit()
        evento = s.query(AuthEvent).one()

        assert evento.ts is not None
        assert abs(evento.ts - datetime.now()) < timedelta(minutes=5)


def test_los_dos_escritores_conviven_en_la_misma_tabla(base_nueva):
    """Que es el punto de que la tabla se llame `auth_log` y no `auth_events`."""
    import sqlite3

    engine, ruta = base_nueva
    con = sqlite3.connect(ruta)
    con.execute(INSERT_CRUDO, ("login_fallido", "intruso", "9.9.9.9", ""))
    con.commit()
    with sessionmaker(bind=engine)() as s:
        s.add(AuthEvent(evento="login", username="alguien"))
        s.commit()

    with sessionmaker(bind=engine)() as s:
        eventos = {e.evento for e in s.query(AuthEvent).all()}

    assert eventos == {"login_fallido", "login"}


def test_una_tabla_que_ya_existe_no_se_altera(tmp_path):
    """El otro lado de la moneda, y el motivo de que esto no se viera en
    producción: `create_all` respeta la tabla que ya creó LibraCore."""
    import sqlite3

    ruta = tmp_path / "existente.db"
    con = sqlite3.connect(ruta)
    # El DDL literal de `libracore.db.schema`.
    con.executescript("""
        CREATE TABLE auth_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            evento     TEXT NOT NULL,
            username   TEXT NOT NULL,
            ip         TEXT,
            detalle    TEXT
        );
    """)
    con.execute(INSERT_CRUDO, ("login", "de-antes", "", ""))
    con.commit()
    ddl_antes = con.execute(
        "SELECT sql FROM sqlite_master WHERE name='auth_log'").fetchone()[0]

    Base.metadata.create_all(create_engine(f"sqlite:///{ruta}"))

    con = sqlite3.connect(ruta)
    assert con.execute(
        "SELECT sql FROM sqlite_master WHERE name='auth_log'").fetchone()[0] == ddl_antes
    assert con.execute("SELECT COUNT(*) FROM auth_log").fetchone()[0] == 1


def test_una_fila_vieja_sigue_siendo_legible_por_el_ORM(tmp_path):
    """Las 92 filas de Contalibra y las 31 de Restolibra las escribió LibraCore
    antes de que este modelo existiera."""
    import sqlite3

    ruta = tmp_path / "legado.db"
    con = sqlite3.connect(ruta)
    con.executescript("""
        CREATE TABLE auth_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            evento     TEXT NOT NULL,
            username   TEXT NOT NULL,
            ip         TEXT,
            detalle    TEXT
        );
    """)
    con.execute(INSERT_CRUDO, ("login", "de-antes", "1.1.1.1", "algo"))
    con.commit()

    engine = create_engine(f"sqlite:///{ruta}")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as s:
        evento = s.query(AuthEvent).one()

    assert evento.evento == "login"
    assert evento.username == "de-antes"
    assert evento.ip == "1.1.1.1"


# --- el mismo DEFAULT, en los dos motores ------------------------------------

def _ddl_de_ts(dialecto) -> str:
    """La linea de `ts` del CREATE TABLE, tal como la veria ese motor."""
    ddl = str(CreateTable(AuthEvent.__table__).compile(dialect=dialecto))
    lineas = [l.strip() for l in ddl.splitlines() if l.strip().startswith("ts ")]
    assert len(lineas) == 1, f"se esperaba una sola linea de `ts`, salieron {lineas}"
    return lineas[0]


def test_en_sqlite_el_default_sigue_siendo_el_literal_de_libracore():
    """Lo que NO puede cambiar.

    `libracore.db.schema` crea esta misma tabla con
    `DEFAULT (datetime('now','localtime'))`. Si el DDL de este paquete dejara
    de emitir exactamente eso, las bases donde escriben los dos lados podrian
    quedar con la mitad de los eventos en otro huso — el punto 2 del docstring
    de arriba. Por eso se compara la linea entera y no un `in`.
    """
    assert _ddl_de_ts(sqlite.dialect()) == \
        "ts DATETIME DEFAULT (datetime('now','localtime')) NOT NULL,"


def test_en_postgres_el_default_es_localtimestamp_y_no_la_funcion_de_sqlite():
    """🔴 `datetime('now','localtime')` no existe en PostgreSQL.

    Estaba escrito como `text(...)`, o sea SQLite puro, y contra PostgreSQL el
    `CREATE TABLE` moria con *"function datetime(unknown, unknown) does not
    exist"* — la instancia no arrancaba. Lo encontro el gate PostgreSQL del
    piloto LibraDesk el 2026-08-08, despues de que la cadena de migraciones del
    producto ya pasara entera.

    `LOCALTIMESTAMP` es el equivalente: timestamp sin zona, en hora local. Se
    exige ademas que no quede rastro de la funcion de SQLite, que es la forma
    concreta en que esto se rompio.
    """
    linea = _ddl_de_ts(postgresql.dialect())

    assert linea == "ts TIMESTAMP WITHOUT TIME ZONE DEFAULT LOCALTIMESTAMP NOT NULL,"
    assert "datetime(" not in linea
