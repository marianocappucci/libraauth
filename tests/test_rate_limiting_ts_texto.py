"""El rate limiting del login, contra las DOS formas de la columna `ts`.

🔴 **El defecto que esto fija estuvo vivo en producción, en tres productos.**
`auth_log.ts` es `TEXT` donde la tabla la crea el DDL crudo de LibraCore
—Gestiolibra, MedLibra y VentaLibra— y `timestamp` donde la crea `create_all()`
—LibraDesk, Contalibra, Restolibra, LibraClub—. Las dos formas son legítimas y
`ts_legible` ya toleraba las dos **al leer**; `contar_fallidos_recientes`
mandaba siempre un `datetime`, y contra una columna `TEXT` en PostgreSQL la
consulta moría con *operator does not exist: text >= timestamp*.

Como `contar_fallidos_seguro` se traga los errores y devuelve 0 —que significa
"nadie agotó intentos"— **el bloqueo por fuerza bruta nunca disparaba**. Medido
en vivo el 2026-08-22 contra una demo: nueve intentos fallidos seguidos, los
nueve anotados con la IP real, ni un solo 429.

⚠️ **Y no se veía en la suite, que era toda SQLite.** SQLite es dinámicamente
tipado: la misma comparación pasa igual contra una columna TEXT. Por eso estos
tests exigen PostgreSQL real y se saltean sin él — un test de esto sobre SQLite
sería verde y vacío.
"""
import os
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from libraauth.auth_events import (
    FORMATO_TS,
    LOGIN_FALLIDO,
    AuthEventRepository,
    verificar_registro_de_accesos,
)
from libraauth.models import AuthEvent, Base

POSTGRES_URL = os.environ.get("LIBRAAUTH_POSTGRES_URL", "")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="sin LIBRAAUTH_POSTGRES_URL: contra SQLite este defecto no se puede reproducir",
)

#: La tabla como la deja el DDL crudo de LibraCore traducido a PostgreSQL: `ts`
#: es **TEXT**. Es la forma que tienen hoy Gestiolibra, MedLibra y VentaLibra
#: en producción, verificada contra sus bases el 2026-08-22.
DDL_LIBRACORE = """
DROP TABLE IF EXISTS auth_log;
CREATE TABLE auth_log (
    id         SERIAL PRIMARY KEY,
    ts         TEXT NOT NULL DEFAULT to_char(LOCALTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'),
    evento     TEXT NOT NULL,
    username   TEXT NOT NULL,
    ip         TEXT,
    detalle    TEXT
);
"""

IP = "203.0.113.7"


def _repo(engine):
    return AuthEventRepository(sessionmaker(engine, expire_on_commit=False))


def _sembrar_texto(engine, cuantos: int, hace_minutos: int) -> None:
    """Intentos fallidos con `ts` escrito como TEXTO, que es como los escriben
    los dos escritores reales."""
    cuando = (datetime.now() - timedelta(minutes=hace_minutos)).strftime(FORMATO_TS)
    with engine.begin() as con:
        for _ in range(cuantos):
            con.execute(
                text("INSERT INTO auth_log (ts, evento, username, ip, detalle) "
                     "VALUES (:ts, :ev, 'quien-sea', :ip, '')"),
                {"ts": cuando, "ev": LOGIN_FALLIDO, "ip": IP},
            )


@pytest.fixture
def engine_ts_texto():
    """`auth_log` con `ts TEXT`, como la deja LibraCore."""
    engine = create_engine(POSTGRES_URL)
    with engine.begin() as con:
        for sentencia in DDL_LIBRACORE.strip().split(";"):
            if sentencia.strip():
                con.execute(text(sentencia))
    return engine


@pytest.fixture
def engine_ts_timestamp():
    """`auth_log` con `ts timestamp`, como la deja `create_all()`."""
    engine = create_engine(POSTGRES_URL)
    with engine.begin() as con:
        con.execute(text("DROP TABLE IF EXISTS auth_log"))
    Base.metadata.tables[AuthEvent.__tablename__].create(engine)
    return engine


def test_cuenta_los_fallidos_con_ts_de_texto(engine_ts_texto):
    """🔴 El caso que rompía. Sin el arreglo esto no da 0: **levanta**
    `ProgrammingError: operator does not exist: text >= timestamp`."""
    _sembrar_texto(engine_ts_texto, 5, hace_minutos=1)

    assert _repo(engine_ts_texto).contar_fallidos_recientes(IP) == 5


def test_con_ts_de_texto_los_viejos_quedan_fuera_de_la_ventana(engine_ts_texto):
    """🔴 **El control que impide el arreglo tramposo.** Sacar el filtro de
    fecha también haría pasar el test de arriba —contaría los 5— y dejaría el
    rate limiting contando intentos de hace un año: un usuario que falló seis
    veces en marzo quedaría bloqueado para siempre.

    La ventana es de 15 minutos; estos son de hace 60.
    """
    _sembrar_texto(engine_ts_texto, 3, hace_minutos=1)
    _sembrar_texto(engine_ts_texto, 4, hace_minutos=60)

    assert _repo(engine_ts_texto).contar_fallidos_recientes(IP) == 3


def test_sigue_funcionando_con_ts_timestamp(engine_ts_timestamp):
    """El otro lado: el arreglo no puede romper a los cuatro productos que hoy
    sí bloquean. Acá el `ts` lo pone el modelo, o sea un `datetime`."""
    repo = _repo(engine_ts_timestamp)
    for _ in range(5):
        repo.registrar(LOGIN_FALLIDO, "quien-sea", IP)

    assert repo.contar_fallidos_recientes(IP) == 5


def test_con_ts_timestamp_los_viejos_tambien_quedan_afuera(engine_ts_timestamp):
    """El mismo control, del lado del timestamp."""
    repo = _repo(engine_ts_timestamp)
    for _ in range(2):
        repo.registrar(LOGIN_FALLIDO, "quien-sea", IP)
    viejo = datetime.now() - timedelta(minutes=60)
    with engine_ts_timestamp.begin() as con:
        con.execute(
            text("INSERT INTO auth_log (ts, evento, username, ip, detalle) "
                 "VALUES (:ts, :ev, 'viejo', :ip, '')"),
            {"ts": viejo, "ev": LOGIN_FALLIDO, "ip": IP},
        )

    assert repo.contar_fallidos_recientes(IP) == 2


def test_la_ip_sigue_discriminando_con_ts_de_texto(engine_ts_texto):
    """Que el arreglo no haya convertido la cuenta en global: bloquear a todos
    porque uno falló es peor que no bloquear."""
    _sembrar_texto(engine_ts_texto, 5, hace_minutos=1)

    assert _repo(engine_ts_texto).contar_fallidos_recientes("198.51.100.1") == 0


def test_el_chequeo_de_arranque_da_verde_cuando_esta_todo_bien(engine_ts_texto):
    """El control positivo: sobre una tabla sana no inventa problemas. Sin
    esto, una función que devolviera siempre un problema pasaría los casos
    negativos de abajo."""
    assert verificar_registro_de_accesos(_repo(engine_ts_texto)) == ""


def test_el_chequeo_de_arranque_EJECUTA_la_comparacion_de_ts(engine_ts_texto):
    """🔴 El que de verdad mide, y que me faltaba.

    El caso de arriba pasaba igual con un chequeo que **no ejecutara** la
    cuenta de fallidos: lo comprobé mutándolo. Y ése es justamente el modo en
    que este chequeo sería inútil — el defecto que vino a detectar es una
    consulta que revienta, no una tabla que falta.

    Acá `ts` es un `integer`: `contar()` funciona —no toca esa columna— pero la
    comparación de la ventana no. Un chequeo que sólo lea la tabla lo da por
    bueno; uno que ejecute la comparación tiene que reportarlo.
    """
    with engine_ts_texto.begin() as con:
        con.execute(text("DROP TABLE IF EXISTS auth_log"))
        con.execute(text(
            "CREATE TABLE auth_log (id SERIAL PRIMARY KEY, ts INTEGER NOT NULL DEFAULT 0, "
            "evento TEXT NOT NULL, username TEXT NOT NULL, ip TEXT, detalle TEXT)"))

    problema = verificar_registro_de_accesos(_repo(engine_ts_texto))

    assert problema, "el chequeo no ejecutó la comparación de `ts`"
    assert "rate limiting" in problema and "INERTE" in problema


def test_el_chequeo_de_arranque_avisa_si_no_hay_tabla(engine_ts_texto):
    """Y el negativo: sin tabla, tiene que decirlo. Sin este caso, el test de
    arriba pasaría igual con una función que devuelve `""` siempre."""
    with engine_ts_texto.begin() as con:
        con.execute(text("DROP TABLE auth_log"))

    problema = verificar_registro_de_accesos(_repo(engine_ts_texto))
    assert problema, "el chequeo no detectó que la tabla no existe"
    assert "auth_log" in problema


def test_el_chequeo_de_arranque_avisa_si_el_producto_no_lo_configuro():
    """El caso de LibraCargo: `app.state.auth_events` sin configurar. No es un
    error de base, es que el producto nunca lo cableó — y apaga las dos cosas."""
    problema = verificar_registro_de_accesos(None)
    assert "rate limiting" in problema
