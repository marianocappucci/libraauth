"""`AdminAuth` con **varios procesos** compartiendo el archivo de estado (ADR-023).

Con `uvicorn --workers N` el backoffice tiene N procesos escribiendo el mismo `ADMIN_PANEL_ESTADO_PATH`. Antes cada
uno leia el JSON, sumaba lo suyo y lo reemplazaba entero: el ultimo en escribir pisaba al otro (se perdian intentos
fallidos), y el mismo codigo TOTP lo aceptaban los dos (leian el mismo `ultimo_paso_totp` antes de que alguno lo
marcara). Ahora cada leer-modificar-escribir corre bajo un `flock` sobre `<estado>.lock`.

Los tests levantan procesos de verdad (`multiprocessing`, `spawn`): con hilos el GIL y el `threading.Lock` de la clase
taparian exactamente lo que se quiere medir. No necesitan PostgreSQL.
"""
import base64
import logging
import multiprocessing
import os

import pytest

from libraauth import totp
from libraauth.admin_auth import AdminAuth, _EstadoLogin

SECRETO = base64.b32encode(b"12345678901234567890").decode()
AHORA = 1234567890
IP = "203.0.113.7"
PROCESOS = 2
FALLIDOS_POR_PROCESO = 50


@pytest.fixture(autouse=True)
def entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ADMIN_PANEL_USER", "superadmin")
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "clave-del-panel")
    monkeypatch.delenv("ADMIN_PANEL_TOTP_SECRET", raising=False)
    monkeypatch.delenv("ADMIN_PANEL_ESTADO_PATH", raising=False)
    monkeypatch.delenv("ADMIN_PANEL_TOTP_PATH", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)


# ── Lo que corre en cada proceso hijo ───────────────────────────────────────

def _fallidos(estado, barrera, cantidad):
    estado_login = _EstadoLogin(estado)
    barrera.wait()
    for _ in range(cantidad):
        estado_login.registrar_fallido(IP, 3600, 1_000_000.0)


def _totp(estado, barrera, cola):
    # El reloj del codigo, fijo, para que los pasos validos sean siempre los mismos tres.
    totp.time.time = lambda: AHORA
    auth = AdminAuth(dev_secret_fallback="dev-only", totp_secret=SECRETO, estado_path=estado)
    clave = totp.decodificar_secreto(SECRETO)
    paso = AHORA // totp.PASO_SEGUNDOS
    aceptados = []
    for p in (paso - 1, paso, paso + 1):          # de menor a mayor: cada uno invalida a los anteriores
        barrera.wait()                            # los dos procesos prueban el MISMO codigo a la vez
        aceptados.append(auth.verificar_codigo_totp(totp.codigo(clave, p)))
    cola.put(aceptados)


def _correr(objetivo, *args_por_proceso):
    ctx = multiprocessing.get_context("spawn")
    barrera = ctx.Barrier(PROCESOS)
    procesos = [ctx.Process(target=objetivo, args=(args[0], barrera, *args[1:])) for args in args_por_proceso]
    for p in procesos:
        p.start()
    for p in procesos:
        p.join(60)
        assert p.exitcode == 0, f"el proceso {p.pid} termino con {p.exitcode}"


# ── Tests ───────────────────────────────────────────────────────────────────

def test_dos_procesos_cuentan_cien_intentos_fallidos_sin_perder_ninguno(tmp_path):
    estado = str(tmp_path / "estado.json")
    _correr(_fallidos, *[(estado, FALLIDOS_POR_PROCESO)] * PROCESOS)

    contados = _EstadoLogin(estado).intentos_vigentes(IP, 3600, 1_000_000.0)
    assert contados == PROCESOS * FALLIDOS_POR_PROCESO, (
        f"se contaron {contados} de {PROCESOS * FALLIDOS_POR_PROCESO}: los procesos se pisaron el estado")


def test_el_mismo_paso_totp_lo_acepta_un_solo_proceso(tmp_path):
    estado = str(tmp_path / "estado.json")
    ctx = multiprocessing.get_context("spawn")
    cola = ctx.Queue()
    _correr(_totp, *[(estado, cola)] * PROCESOS)

    por_proceso = [cola.get(timeout=10) for _ in range(PROCESOS)]
    for ronda in range(3):
        aceptaron = sum(1 for proceso in por_proceso if proceso[ronda])
        assert aceptaron == 1, f"ronda {ronda}: {aceptaron} procesos aceptaron el mismo codigo, tenia que ser 1"


def test_reclamar_un_paso_es_de_una_sola_vez_y_solo_hacia_adelante(tmp_path):
    estado = _EstadoLogin(tmp_path / "estado.json")
    assert estado.reclamar_paso_totp(10) is True
    assert estado.reclamar_paso_totp(10) is False        # el mismo
    assert estado.reclamar_paso_totp(9) is False         # uno anterior
    assert estado.reclamar_paso_totp(11) is True
    assert estado.ultimo_paso_totp() == 11


def test_el_estado_en_memoria_tambien_reclama_una_vez():
    estado = _EstadoLogin(None)
    assert estado.reclamar_paso_totp(5) is True
    assert estado.reclamar_paso_totp(5) is False


def test_el_cerrojo_deja_su_archivo_al_lado_del_estado(tmp_path):
    estado = _EstadoLogin(tmp_path / "estado.json")
    estado.registrar_fallido(IP, 3600, 1.0)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["estado.json", "estado.json.lock"]


def test_los_temporales_no_se_comparten_entre_procesos(tmp_path, monkeypatch):
    """Antes el temporal era siempre `<archivo>.tmp`: dos procesos escribiendo a la vez se lo pisaban."""
    visto = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda origen, destino: (visto.append(str(origen)), real(origen, destino))[1])
    _EstadoLogin(tmp_path / "estado.json").registrar_fallido(IP, 3600, 1.0)
    assert visto and str(os.getpid()) in visto[0]
    assert not any(p.suffix == ".tmp" for p in tmp_path.iterdir()), "no tiene que quedar el temporal"


# ── El aviso ────────────────────────────────────────────────────────────────

def test_con_varios_workers_y_sin_archivo_de_estado_avisa(monkeypatch, caplog):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    with caplog.at_level(logging.WARNING, logger="libraauth.admin_auth"):
        AdminAuth(dev_secret_fallback="dev-only")
    avisos = [r.getMessage() for r in caplog.records if "WEB_CONCURRENCY=4" in r.getMessage()]
    assert avisos and "ADMIN_PANEL_ESTADO_PATH" in avisos[0]


@pytest.mark.parametrize("valor", ["1", "", "abc", "0", "-3"])
def test_con_un_solo_worker_o_un_valor_raro_no_avisa(monkeypatch, caplog, valor):
    monkeypatch.setenv("WEB_CONCURRENCY", valor)
    with caplog.at_level(logging.WARNING, logger="libraauth.admin_auth"):
        AdminAuth(dev_secret_fallback="dev-only")
    assert not [r for r in caplog.records if "WEB_CONCURRENCY" in r.getMessage()]


def test_con_varios_workers_y_archivo_de_estado_no_avisa(monkeypatch, caplog, tmp_path):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    with caplog.at_level(logging.WARNING, logger="libraauth.admin_auth"):
        AdminAuth(dev_secret_fallback="dev-only", estado_path=str(tmp_path / "estado.json"))
    assert not [r for r in caplog.records if "WEB_CONCURRENCY" in r.getMessage()]
