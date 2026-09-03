"""La superficie de este paquete, EJECUTADA contra un PostgreSQL real.

**Por que hace falta un archivo aparte.** Hasta ahora la unica cobertura
PostgreSQL de este repo era `test_auth_log_compatible.py`, y compara el
**texto del DDL compilado** (`CreateTable` contra `postgresql.dialect()`). Eso
atrapa una clase de defecto -- el literal que no existe en el otro dialecto --
y es ciego a la otra: el SQL que compila y despues revienta, o peor, que
devuelve algo distinto.

El piloto de LibraDesk lo dejo medido el 2026-08-09: sus tres gates estaban en
verde -- la app arrancaba, el schema se creaba entero, el traductor
transformaba bien el texto -- y **5 de las 7 lecturas de LibraCore fallaban
contra PostgreSQL real**, porque ninguno de los tres ejecutaba una consulta.

De ahi la regla que sigue este archivo: *sembrar filas, ejecutar las lecturas y
comparar el resultado ENTERO contra SQLite*. "Arranca y no explota" no es un
gate.

**Y solo aparece con filas.** Sobre una tabla vacia una comprension de lista no
itera nada: las mismas lecturas devuelven `[]` en los dos motores y la
comparacion pasa. Por eso cada comparacion va acompanada de la contraprueba de
que trajo filas.

Se saltea si no hay `LIBRAAUTH_POSTGRES_URL`. En CI la pone el workflow.
"""
import os

import pytest
from sqlalchemy import String, create_engine
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from libraauth.models import Base
from libraauth.repository import UsernameTaken, UserRepository

POSTGRES_URL = os.environ.get("LIBRAAUTH_POSTGRES_URL", "")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="sin LIBRAAUTH_POSTGRES_URL: no hay PostgreSQL real contra el cual correr",
)

#: Los mismos usuarios en los dos motores. El orden de alta esta salteado a
#: proposito para que no coincida con ningun orden de lectura, y las mayusculas
#: y el acento estan puestos para ejercitar el collation: SQLite ordena por
#: bytes (todas las mayusculas antes que cualquier minuscula) y PostgreSQL por
#: locale. Si `list()` ordenara distinto segun el motor, la pantalla de usuarios
#: de un producto migrado cambiaria de orden sin que nadie toque el codigo.
SEMILLA = [
    # username, nombre, role
    ("beto",   "Beto Bianchi",   "staff"),
    ("Ana",    "Ana Alvarez",    "admin"),
    ("carlos", "Carlos Cabral",  "staff"),
    ("Alicia", "Alicia Acuna",   "staff"),
    # 🔴 `Zulema` con mayuscula NO es decorativo: es el unico par de esta lista
    # que distingue orden de bytes de orden por locale. Con `zulema` en
    # minuscula los dos motores coinciden pase lo que pase, y la comparacion de
    # orden seria vacua. Medido el 2026-08-09: con la semilla en minuscula los
    # dos ordenes daban iguales tambien contra un PostgreSQL con collation de
    # locale real, o sea que el test no habria podido fallar nunca.
    ("Zulema", "Zulema Zapata",  "admin"),
]

CLAVE = "una-clave-cualquiera-123"


def _repo(url: str) -> UserRepository:
    """Un repositorio sobre un schema recien creado en `url`."""
    engine = create_engine(url)
    # `drop_all` primero: la base de CI sobrevive entre modulos de test, y un
    # schema con filas de otra corrida haria que las comparaciones midan contra
    # datos que este archivo no sembro.
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return UserRepository(sessionmaker(bind=engine, class_=Session))


@pytest.fixture
def dos_motores(tmp_path):
    """El mismo repositorio, sembrado igual, sobre los dos motores."""
    pg = _repo(POSTGRES_URL)
    lite = _repo(f"sqlite:///{tmp_path}/libraauth.db")
    for username, nombre, role in SEMILLA:
        for repo in (pg, lite):
            repo.create(username=username, name=nombre, password=CLAVE, role=role)
    return pg, lite


def test_list_devuelve_lo_mismo_en_los_dos_motores(dos_motores):
    """La lectura de mas superficie del paquete, comparada ENTERA.

    No `len()`: dos listas de 5 elementos pueden diferir en el orden o en el
    contenido de cada fila. `list()` ordena por `role` descendente y despues por
    `username`, y el segundo criterio es justamente el que depende del
    collation del motor.
    """
    pg, lite = dos_motores

    filas_pg, filas_lite = pg.list(), lite.list()

    # Contraprueba: sin esto la comparacion pasa con las dos listas vacias.
    assert len(filas_pg) == len(SEMILLA), filas_pg

    # El `id` es lo unico que puede diferir legitimamente -- son dos secuencias
    # independientes -- asi que se compara todo lo demas.
    sin_id = lambda fs: [{k: v for k, v in f.items() if k != "id"} for f in fs]  # noqa: E731
    assert sin_id(filas_pg) == sin_id(filas_lite)


def test_el_orden_por_username_es_el_de_bytes_y_no_el_del_locale(dos_motores):
    """🔴 Que los dos motores ordenen igual es un accidente de la IMAGEN.

    Medido el 2026-08-09, sembrando `Alicia, Ana, Zulema, beto, carlos` y
    pidiendo `ORDER BY username`:

    | Imagen | `datcollate` | Orden |
    |---|---|---|
    | `postgres:16-alpine` (musl) | `en_US.utf8` | `Alicia, Ana, Zulema, beto, carlos` |
    | `postgres:16` (glibc) | `en_US.utf8` | `Alicia, Ana, beto, carlos, Zulema` |

    **El mismo collation declarado, dos ordenes distintos.** Alpine usa musl,
    que no implementa locales de verdad, asi que `en_US.utf8` colaciona como C
    -- o sea por bytes, igual que el BINARY de SQLite. Los sidecars del VPS son
    `postgres:16-alpine`, y por eso hoy una instancia migrada devuelve la lista
    de usuarios en el mismo orden que antes.

    Ese "hoy" es lo que fija este test: no depende de una linea de codigo sino
    de la imagen base, asi que el dia que alguien pase un sidecar a la imagen
    Debian -- o a `postgres:17`, o declare otro `LC_COLLATE` al crear el
    cluster -- las pantallas de usuarios de los productos migrados cambian de
    orden sin que nadie toque el codigo. Este test se pone rojo ahi, que es
    justo cuando hace falta enterarse.
    """
    _, lite = dos_motores
    from sqlalchemy import select

    from libraauth.models import Usuario

    def por_username(repo):
        with repo.session_factory() as s:
            return list(s.execute(
                select(Usuario.username).order_by(Usuario.username)
            ).scalars())

    pg_orden = por_username(dos_motores[0])
    lite_orden = por_username(lite)

    # Contraprueba: sin filas, dos listas vacias comparan iguales.
    assert len(pg_orden) == len(SEMILLA), pg_orden
    # Y que la semilla efectivamente mezcle mayusculas y minusculas, que es lo
    # unico que hace discriminante a la comparacion.
    assert any(u[0].isupper() for u in pg_orden) and any(u[0].islower() for u in pg_orden)

    assert pg_orden == lite_orden, (
        "PostgreSQL dejo de ordenar como SQLite. Si el sidecar cambio de imagen "
        "(alpine/musl -> glibc) esto es esperable y hay que decidir que hacer "
        f"con el orden de las listas.\nPG:     {pg_orden}\nSQLite: {lite_orden}"
    )


def test_get_by_username_devuelve_lo_mismo_en_los_dos_motores(dos_motores):
    pg, lite = dos_motores

    encontrados = 0
    for username, _, _ in SEMILLA:
        u_pg, u_lite = pg.get_by_username(username), lite.get_by_username(username)
        assert u_pg is not None, f"PostgreSQL no encontro {username!r}"
        assert u_lite is not None, f"SQLite no encontro {username!r}"
        assert {k: v for k, v in u_pg.items() if k != "id"} == \
               {k: v for k, v in u_lite.items() if k != "id"}
        encontrados += 1

    assert encontrados == len(SEMILLA)


def test_get_by_username_distingue_mayusculas_igual_en_los_dos(dos_motores):
    """`Ana` esta sembrada; `ana` no.

    Un `==` sobre texto es sensible a mayusculas en los dos motores, pero es
    exactamente el tipo de cosa que cambia al migrar (`LIKE` en SQLite es
    case-insensitive y en PostgreSQL no), y una busqueda que deja de encontrar
    **no da ningun error**: da una pantalla vacia.
    """
    pg, lite = dos_motores

    assert pg.get_by_username("Ana") is not None
    assert lite.get_by_username("Ana") is not None
    assert pg.get_by_username("ana") is None
    assert lite.get_by_username("ana") is None


def test_check_credentials_funciona_contra_postgres(dos_motores):
    """Que el hash guardado se lea de vuelta y valide.

    Es la operacion por la que existe el paquete, y la unica que toca
    `password_hash` -- una columna `String(200)` que en PostgreSQL tiene largo
    exigido de verdad, no como en SQLite.
    """
    pg, lite = dos_motores

    ok_pg = pg.check_credentials("beto", CLAVE)
    ok_lite = lite.check_credentials("beto", CLAVE)
    assert ok_pg is not None and ok_lite is not None
    assert {k: v for k, v in ok_pg.items() if k != "id"} == \
           {k: v for k, v in ok_lite.items() if k != "id"}

    # La contraprueba del caso feliz: con la clave mal, los dos dicen que no.
    assert pg.check_credentials("beto", "la-que-no-es") is None
    assert lite.check_credentials("beto", "la-que-no-es") is None


def test_username_repetido_levanta_UsernameTaken_tambien_en_postgres(dos_motores):
    """🔴 El caso mas fragil del paquete al cambiar de motor.

    `create()` decide si una `IntegrityError` es un username repetido mirando
    el **texto** del error del driver:

        if "username" in str(exc.orig).lower():

    En SQLite ese texto es `UNIQUE constraint failed: usuarios.username`. En
    PostgreSQL es `duplicate key value violates unique constraint
    "<nombre>"`, y que ahi aparezca la palabra depende del NOMBRE que le haya
    puesto al constraint quien creo la tabla -- no del codigo de este paquete.

    Si no aparece, la excepcion sale como `IntegrityError` cruda en vez de
    `UsernameTaken`, y el producto que la atrapa para mostrar *"ese usuario ya
    existe"* devuelve un 500 en su lugar. Ninguna comparacion de DDL lo ve.
    """
    pg, lite = dos_motores

    with pytest.raises(UsernameTaken):
        pg.create(username="beto", name="Otro Beto", password=CLAVE, role="staff")
    with pytest.raises(UsernameTaken):
        lite.create(username="beto", name="Otro Beto", password=CLAVE, role="staff")


def test_el_log_de_actividad_acepta_un_id_de_texto_contra_postgres(tmp_path):
    """🔴 El defecto de mas alcance de la F3, y el unico lugar donde se prueba.

    `actividad_log.entidad_id` estuvo declarada `Integer` hasta el 2026-08-09.
    Los ids de MedLibra (`patient-1`), Gestiolibra y LibraGenda son de texto, y
    **SQLite los aceptaba por tipado dinamico**: guarda texto en una columna
    INTEGER sin decir nada. Por eso `test_auditoria.py` -- que corre sobre
    SQLite-- no podia ver nada, ni siquiera despues del arreglo: ahi el test
    pasa con la columna declarada de cualquiera de las dos formas.

    Contra PostgreSQL no hay tipado dinamico:

        psycopg.errors.InvalidTextRepresentation:
        invalid input syntax for type integer: "patient-1"

    Y como el log se escribe en la MISMA transaccion que la operacion auditada,
    no se perdia una fila de auditoria: **el alta entera devolvia 500**. El
    producto no podia escribir.

    Este test es el que decide si el arreglo sirve, porque es el unico que
    ejecuta el INSERT contra un motor con tipos de verdad.
    """
    from sqlalchemy.orm import DeclarativeBase

    from libraauth.auditoria import (
        AuditoriaBase,
        AuditoriaRepository,
        configurar_auditoria,
    )

    class DominioBase(DeclarativeBase):
        pass

    class Paciente(DominioBase):
        __tablename__ = "pacientes_pg_demo"
        id: Mapped[str] = mapped_column(String(100), primary_key=True)
        nombre: Mapped[str] = mapped_column(String(100))

    engine = create_engine(POSTGRES_URL)
    DominioBase.metadata.drop_all(engine)
    AuditoriaBase.metadata.drop_all(engine)
    DominioBase.metadata.create_all(engine)
    AuditoriaBase.metadata.create_all(engine)

    sessions = sessionmaker(bind=engine)
    configurar_auditoria(sessions, {"Paciente": "paciente"})

    with sessions.begin() as s:
        s.add(Paciente(id="patient-1", nombre="Ana"))

    filas = AuditoriaRepository(sessions).listar()
    # Contraprueba: sin filas, cualquier asercion sobre el contenido pasa sola.
    assert len(filas) == 1, filas
    assert filas[0]["entidad_id"] == "patient-1"


def test_created_at_lo_escribe_la_base_en_los_dos_motores(dos_motores):
    """`created_at` es `server_default=func.now()`: lo pone el motor.

    No se comparan los VALORES -- las dos corridas ocurren en momentos
    distintos -- sino que los dos motores lo hayan escrito. Un `server_default`
    que no compila en un dialecto deja la columna en NULL o rompe el INSERT.
    """
    from sqlalchemy import func, select

    from libraauth.models import Usuario

    for repo in dos_motores:
        with repo.session_factory() as s:
            nulos = s.execute(
                select(func.count()).select_from(Usuario)
                .where(Usuario.created_at.is_(None))
            ).scalar_one()
            total = s.execute(select(func.count()).select_from(Usuario)).scalar_one()
        assert total == len(SEMILLA), total
        assert nulos == 0, f"{nulos} filas sin created_at"
