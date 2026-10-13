"""El bloqueo por IP del login cuenta sobre `auth_log`, asi que lo comparten todos los procesos (ADR-023).

No se tocó para los varios workers: ya cuenta en la base. Este test lo fija, porque es lo que alguien podria "arreglar"
sin saberlo pasandolo a memoria. Dos procesos de verdad (`multiprocessing`, `spawn`) contra una PostgreSQL: cada uno
falla 2 veces —4 entre los dos, menos que el tope de 5, asi que nadie se topa con el bloqueo mientras corre—; un
tercero falla una vez mas (5) y el intento siguiente, con la clave buena, tiene que dar 429. Si cada proceso contara
por su cuenta, el tercero vería 1 fallo y entraría. Se saltea sin `LIBRAAUTH_POSTGRES_URL`; en CI el paso del gate de PostgreSQL lo nombra.
"""
import multiprocessing
import os
import uuid

import pytest
from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from libraauth.models import Base
from tests.test_login_rate_limiting import CLAVE_BUENA, CLAVE_MALA, _app, _cliente

POSTGRES_URL = os.environ.get("LIBRAAUTH_POSTGRES_URL", "")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL, reason="sin LIBRAAUTH_POSTGRES_URL: no hay PostgreSQL real contra el cual correr")

FALLOS_POR_PROCESO = 2          # el tope es 5: ni los dos juntos (4) lo alcanzan mientras corren


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-rate-limiting")


@pytest.fixture
def url_pg():
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    nombre = f"auth_rl_{uuid.uuid4().hex[:12]}"
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


def _fallar(url, cantidad):
    os.environ["SECRET_KEY"] = "test-secret-rate-limiting"
    cliente = _cliente(_app(sessionmaker(bind=create_engine(url))))
    for _ in range(cantidad):
        assert cliente.post("/auth/login", json=CLAVE_MALA).status_code == 401


def _desde_procesos(url, cantidades):
    ctx = multiprocessing.get_context("spawn")
    procesos = [ctx.Process(target=_fallar, args=(url, n)) for n in cantidades]
    [p.start() for p in procesos]
    [p.join(120) for p in procesos]
    assert [p.exitcode for p in procesos] == [0] * len(procesos)


def test_dos_procesos_suman_sus_fallos_y_el_tercero_recibe_429(url_pg):
    _desde_procesos(url_pg, [FALLOS_POR_PROCESO, FALLOS_POR_PROCESO])

    cliente = _cliente(_app(sessionmaker(bind=create_engine(url_pg))))
    assert cliente.post("/auth/login", json=CLAVE_MALA).status_code == 401      # el quinto fallo
    assert cliente.post("/auth/login", json=CLAVE_BUENA).status_code == 429


def test_contraprueba_con_un_solo_proceso_que_falla_dos_veces_todavia_se_entra(url_pg):
    _desde_procesos(url_pg, [FALLOS_POR_PROCESO])

    cliente = _cliente(_app(sessionmaker(bind=create_engine(url_pg))))
    assert cliente.post("/auth/login", json=CLAVE_MALA).status_code == 401      # el tercero
    assert cliente.post("/auth/login", json=CLAVE_BUENA).status_code == 200
