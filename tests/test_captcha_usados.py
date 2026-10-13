"""El anti-replay del captcha, con los desafios usados **compartidos** (ADR-023).

`Captcha` anotaba los desafios resueltos en la memoria del proceso: con `uvicorn --workers N` cada worker tenia su lista,
y un desafio resuelto servia una vez **por worker**. `UsadosEnBase` los anota en la tabla `libraauth_captcha_usados` con
un `INSERT ... ON CONFLICT DO NOTHING`, que decide atomicamente quien fue el primero.

SQLite se prueba siempre; PostgreSQL (incluidos DOS PROCESOS de verdad, con `multiprocessing`) con
`LIBRAAUTH_POSTGRES_URL`. En CI el paso "Confirmar que el gate de PostgreSQL corrio" nombra este archivo: alla un salteo
es rojo.
"""
import multiprocessing
import os
import threading
import uuid

import pytest
from altcha import Challenge, Payload, solve_challenge
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, pool, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from libraauth.captcha import Captcha, UsadosEnBase, UsadosEnMemoria
from libraauth.models import Base, CaptchaUsado
from libraauth.session_auth import build_json_api_auth_router

POSTGRES_URL = os.environ.get("LIBRAAUTH_POSTGRES_URL", "")
SECRETO = "clave-de-la-instancia-a"
VENCE = 4_000_000_000.0
AHORA = 2_000_000_000.0

requiere_pg = pytest.mark.skipif(
    not POSTGRES_URL, reason="sin LIBRAAUTH_POSTGRES_URL: no hay PostgreSQL real contra el cual correr")


def _captcha(usados=None, **kw):
    return Captcha(SECRETO, costo=1, contador_min=1, contador_rango=5, usados=usados, **kw)


def _resolver(desafio: dict) -> str:
    ch = Challenge.from_dict(desafio)
    return Payload(ch, solve_challenge(ch)).to_base64()


@pytest.fixture
def sessions_sqlite(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/captcha.db", connect_args={"timeout": 30})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def url_pg():
    """Una base PostgreSQL nueva con las tablas de auth, borrada al terminar."""
    if not POSTGRES_URL:
        pytest.skip("sin LIBRAAUTH_POSTGRES_URL")
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    nombre = f"auth_cap_{uuid.uuid4().hex[:12]}"
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{nombre}"'))
    url = make_url(POSTGRES_URL).set(database=nombre).render_as_string(hide_password=False)
    motor = create_engine(url, poolclass=pool.NullPool)
    Base.metadata.create_all(motor)
    motor.dispose()
    yield url
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{nombre}" WITH (FORCE)'))
    admin.dispose()


# ── UsadosEnMemoria: lo de siempre ──────────────────────────────────────────

def test_en_memoria_la_primera_vez_si_y_la_segunda_no():
    usados = UsadosEnMemoria()
    assert usados.usar("f1", VENCE, AHORA) is True
    assert usados.usar("f1", VENCE, AHORA) is False
    assert usados.usar("f2", VENCE, AHORA) is True


def test_el_default_de_captcha_es_en_memoria():
    assert isinstance(_captcha()._usados, UsadosEnMemoria)


# ── UsadosEnBase (SQLite) ───────────────────────────────────────────────────

def test_en_base_la_primera_vez_si_y_la_segunda_no(sessions_sqlite):
    usados = UsadosEnBase(sessions_sqlite)
    assert usados.usar("f1", VENCE, AHORA) is True
    assert usados.usar("f1", VENCE, AHORA) is False
    assert usados.usar("f2", VENCE, AHORA) is True


def test_en_base_veinte_hilos_con_la_misma_firma_la_aceptan_una_sola_vez(sessions_sqlite):
    usados = UsadosEnBase(sessions_sqlite)
    resultados = []
    barrera = threading.Barrier(20)

    def correr():
        barrera.wait()
        resultados.append(usados.usar("misma", VENCE, AHORA))

    hilos = [threading.Thread(target=correr) for _ in range(20)]
    [h.start() for h in hilos]
    [h.join() for h in hilos]
    assert sorted(resultados) == [False] * 19 + [True]


def test_la_poda_borra_los_vencidos_y_deja_los_vigentes(sessions_sqlite):
    usados = UsadosEnBase(sessions_sqlite, poda=1.0)          # poda siempre
    usados.usar("vieja", AHORA - 10, AHORA - 100)
    usados.usar("vigente", AHORA + 600, AHORA - 100)
    assert usados.usar("nueva", AHORA + 600, AHORA) is True    # esta llamada poda con `ahora` = AHORA
    with sessions_sqlite() as s:
        assert set(s.scalars(select(CaptchaUsado.firma))) == {"vigente", "nueva"}


def test_sin_poda_no_se_borra_nada(sessions_sqlite):
    usados = UsadosEnBase(sessions_sqlite, poda=0.0)
    usados.usar("vieja", AHORA - 10, AHORA - 100)
    usados.usar("nueva", AHORA + 600, AHORA)
    with sessions_sqlite() as s:
        assert s.scalar(select(func.count()).select_from(CaptchaUsado)) == 2


def test_si_la_base_falla_no_deja_pasar_el_desafio(tmp_path):
    """Sin tabla, `usar` levanta: un captcha que no se puede validar no se da por bueno."""
    engine = create_engine(f"sqlite:///{tmp_path}/vacia.db")          # sin `create_all`
    c = _captcha(usados=UsadosEnBase(sessionmaker(bind=engine)))
    payload = _resolver(c.emitir())
    with pytest.raises(Exception, match="libraauth_captcha_usados"):
        c.verificar(payload)


# ── Dentro de Captcha y del router ──────────────────────────────────────────

def test_dos_captcha_con_la_misma_base_comparten_los_usados(sessions_sqlite):
    """Dos procesos, en chiquito: dos `Captcha` distintos sobre la misma tabla."""
    uno = _captcha(usados=UsadosEnBase(sessions_sqlite))
    otro = _captcha(usados=UsadosEnBase(sessions_sqlite))
    payload = _resolver(uno.emitir())
    assert uno.verificar(payload) is True
    assert otro.verificar(payload) is False


def test_sin_base_cada_captcha_tiene_su_lista_que_es_el_defecto_que_se_corrige():
    uno, otro = _captcha(), _captcha()
    payload = _resolver(uno.emitir())
    assert uno.verificar(payload) is True
    assert otro.verificar(payload) is True


def test_los_usados_sobreviven_a_un_reinicio(sessions_sqlite):
    payload = _resolver(_captcha().emitir())
    assert _captcha(usados=UsadosEnBase(sessions_sqlite)).verificar(payload) is True
    assert _captcha(usados=UsadosEnBase(sessions_sqlite)).verificar(payload) is False


def test_el_router_usa_los_usados_que_se_le_pasan(sessions_sqlite, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", SECRETO)
    from tests.test_login_rate_limiting import _SessionAuthFalso, _UsersFalso

    app = FastAPI()
    app.state.users = _UsersFalso()
    app.state.session_auth = type("SA", (_SessionAuthFalso,), {"secret_key": SECRETO})()
    app.include_router(build_json_api_auth_router(captcha=True, captcha_usados=UsadosEnBase(sessions_sqlite)))
    cliente = TestClient(app, base_url="https://producto.test")

    assert getattr(app.state, "captcha", None) is None
    desafio = cliente.get("/auth/captcha").json()
    assert isinstance(app.state.captcha._usados, UsadosEnBase)
    # El captcha del router es el real (costo de produccion): se reemplaza por uno barato con los MISMOS usados.
    app.state.captcha = _captcha(usados=app.state.captcha._usados)
    payload = _resolver(app.state.captcha.emitir())
    assert desafio and app.state.captcha.verificar(payload) is True
    with sessions_sqlite() as s:
        assert s.scalar(select(func.count()).select_from(CaptchaUsado)) == 1


# ── PostgreSQL: dos procesos de verdad ──────────────────────────────────────

def _usar_el_mismo_desafio(url, payloads, barrera, cola):
    """Cada proceso arma su propio `Captcha` (su propio engine y sus propios usados en memoria, vacios) y prueba los
    mismos desafios a la vez. Devuelve cuantos acepto de cada uno."""
    sesiones = sessionmaker(bind=create_engine(url))
    captcha = _captcha(usados=UsadosEnBase(sesiones))
    aceptados = []
    for payload in payloads:
        barrera.wait()
        aceptados.append(captcha.verificar(payload))
    cola.put(aceptados)


@requiere_pg
def test_dos_procesos_aceptan_cada_desafio_una_sola_vez(url_pg):
    emisor = _captcha()
    payloads = [_resolver(emisor.emitir()) for _ in range(15)]
    ctx = multiprocessing.get_context("spawn")
    barrera, cola = ctx.Barrier(2), ctx.Queue()
    procesos = [ctx.Process(target=_usar_el_mismo_desafio, args=(url_pg, payloads, barrera, cola)) for _ in range(2)]
    [p.start() for p in procesos]
    [p.join(120) for p in procesos]
    assert [p.exitcode for p in procesos] == [0, 0]

    por_proceso = [cola.get(timeout=10) for _ in range(2)]
    for i in range(len(payloads)):
        aceptaron = sum(1 for p in por_proceso if p[i])
        assert aceptaron == 1, f"desafio {i}: lo aceptaron {aceptaron} procesos, tenia que ser 1"


@requiere_pg
def test_en_postgres_veinte_hilos_con_la_misma_firma_la_aceptan_una_sola_vez(url_pg):
    usados = UsadosEnBase(sessionmaker(bind=create_engine(url_pg, pool_size=20)))
    resultados = []
    barrera = threading.Barrier(20)

    def correr():
        barrera.wait()
        resultados.append(usados.usar("misma", VENCE, AHORA))

    hilos = [threading.Thread(target=correr) for _ in range(20)]
    [h.start() for h in hilos]
    [h.join() for h in hilos]
    assert sorted(resultados) == [False] * 19 + [True]


@requiere_pg
def test_en_postgres_la_poda_borra_los_vencidos(url_pg):
    sesiones = sessionmaker(bind=create_engine(url_pg))
    usados = UsadosEnBase(sesiones, poda=1.0)
    usados.usar("vieja", AHORA - 10, AHORA - 100)
    assert usados.usar("nueva", AHORA + 600, AHORA) is True
    with sesiones() as s:
        assert list(s.scalars(select(CaptchaUsado.firma))) == ["nueva"]
