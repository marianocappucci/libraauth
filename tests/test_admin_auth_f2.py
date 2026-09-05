"""`AdminAuth` despues de la F2 (2026-09-05): segundo factor TOTP y estado del
login que sobrevive al reinicio del proceso.

Separado de `test_admin_auth.py`, que sigue cubriendo el comportamiento
original sin tocar una linea — lo que prueba que sin las dos variables de
entorno nuevas nada cambia."""
import base64
import json
import logging

import pytest

from libraauth import totp
from libraauth.admin_auth import AdminAuth

SECRETO = base64.b32encode(b"12345678901234567890").decode()
AHORA = 1234567890
CODIGO_AHORA = "005924"


@pytest.fixture(autouse=True)
def entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ADMIN_PANEL_USER", "superadmin")
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "clave-del-panel")
    monkeypatch.delenv("ADMIN_PANEL_TOTP_SECRET", raising=False)
    monkeypatch.delenv("ADMIN_PANEL_ESTADO_PATH", raising=False)


def _auth(**kw):
    return AdminAuth(dev_secret_fallback="dev-only", **kw)


def _fijar_reloj(monkeypatch, segundos):
    monkeypatch.setattr("libraauth.totp.time.time", lambda: segundos)


# ── sin variables nuevas, nada cambia ───────────────────────────────────

def test_sin_secreto_no_hay_2fa_y_el_codigo_se_ignora():
    a = _auth()
    assert a.totp_habilitado is False
    assert a.check_credentials("superadmin", "clave-del-panel") is True
    assert a.check_credentials("superadmin", "clave-del-panel", codigo="000000") is True


# ── TOTP ─────────────────────────────────────────────────────────────────

def test_con_secreto_en_el_entorno_el_login_exige_el_codigo(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    _fijar_reloj(monkeypatch, AHORA)
    a = _auth()
    assert a.totp_habilitado is True
    assert a.check_credentials("superadmin", "clave-del-panel") is False
    assert a.check_credentials("superadmin", "clave-del-panel", codigo="123456") is False
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=CODIGO_AHORA) is True


def test_clave_mal_con_codigo_bien_es_el_mismo_False(monkeypatch):
    """Un solo `False`: quien llama no distingue cual de los dos fallo."""
    _fijar_reloj(monkeypatch, AHORA)
    a = _auth(totp_secret=SECRETO)
    assert a.check_credentials("superadmin", "otra", codigo=CODIGO_AHORA) is False
    assert a.check_credentials("otro", "clave-del-panel", codigo=CODIGO_AHORA) is False


def test_el_codigo_no_se_quema_si_la_clave_estaba_mal(monkeypatch):
    """Un error de tipeo en la contrasena no obliga a esperar el proximo codigo."""
    _fijar_reloj(monkeypatch, AHORA)
    a = _auth(totp_secret=SECRETO)
    assert a.check_credentials("superadmin", "mal-tipeada", codigo=CODIGO_AHORA) is False
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=CODIGO_AHORA) is True


def test_un_codigo_aceptado_no_vale_dos_veces(monkeypatch):
    _fijar_reloj(monkeypatch, AHORA)
    a = _auth(totp_secret=SECRETO)
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=CODIGO_AHORA) is True
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=CODIGO_AHORA) is False
    # El paso siguiente si vale (el reloj avanza 30 s).
    _fijar_reloj(monkeypatch, AHORA + 30)
    siguiente = totp.codigo(totp.decodificar_secreto(SECRETO), (AHORA + 30) // 30)
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=siguiente) is True


def test_sin_password_configurada_rechaza_aunque_el_codigo_valga(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "")
    _fijar_reloj(monkeypatch, AHORA)
    assert _auth(totp_secret=SECRETO).check_credentials("superadmin", "", codigo=CODIGO_AHORA) is False


@pytest.mark.parametrize("malo", ["no-es-base32!!", "ABCD"])
def test_secreto_invalido_frena_el_arranque(monkeypatch, malo):
    """Fail-fast: un 2FA mal cargado que nunca valida parece que esta y no esta."""
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", malo)
    with pytest.raises(RuntimeError, match="ADMIN_PANEL_TOTP_SECRET"):
        _auth()


def test_secreto_en_blanco_es_lo_mismo_que_ninguno(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", "   ")
    assert _auth().totp_habilitado is False


# ── estado persistido ────────────────────────────────────────────────────

def test_los_intentos_fallidos_sobreviven_a_una_instancia_nueva(tmp_path):
    """El criterio de salida de la F2: bloqueado DESPUES de reiniciar."""
    archivo = tmp_path / "estado" / "login.json"
    a = _auth(login_max_intentos=3, estado_path=archivo)
    for _ in range(3):
        a.registrar_intento_fallido("1.2.3.4")
    assert a.rate_limit_excedido("1.2.3.4") is True
    # "Reinicio": otra instancia, mismo archivo.
    b = _auth(login_max_intentos=3, estado_path=archivo)
    assert b.rate_limit_excedido("1.2.3.4") is True
    assert b.rate_limit_excedido("5.6.7.8") is False
    guardado = json.loads(archivo.read_text())
    assert len(guardado["intentos"]["1.2.3.4"]) == 3


def test_la_ruta_se_toma_del_entorno(monkeypatch, tmp_path):
    archivo = tmp_path / "login.json"
    monkeypatch.setenv("ADMIN_PANEL_ESTADO_PATH", str(archivo))
    a = _auth(login_max_intentos=1)
    a.registrar_intento_fallido("1.2.3.4")
    assert archivo.exists()
    assert _auth(login_max_intentos=1).rate_limit_excedido("1.2.3.4") is True


def test_el_paso_totp_usado_tambien_sobrevive(monkeypatch, tmp_path):
    """Reiniciar el backoffice no reabre la ventana de reuso del ultimo codigo."""
    _fijar_reloj(monkeypatch, AHORA)
    archivo = tmp_path / "login.json"
    assert _auth(totp_secret=SECRETO, estado_path=archivo).check_credentials(
        "superadmin", "clave-del-panel", codigo=CODIGO_AHORA) is True
    assert _auth(totp_secret=SECRETO, estado_path=archivo).check_credentials(
        "superadmin", "clave-del-panel", codigo=CODIGO_AHORA) is False


def test_los_intentos_viejos_se_podan_del_archivo(monkeypatch, tmp_path):
    archivo = tmp_path / "login.json"
    a = _auth(login_max_intentos=2, login_ventana_segundos=60, estado_path=archivo)
    reloj = {"t": 1000.0}
    monkeypatch.setattr("libraauth.admin_auth.time.time", lambda: reloj["t"])
    a.registrar_intento_fallido("1.2.3.4")
    a.registrar_intento_fallido("1.2.3.4")
    assert a.rate_limit_excedido("1.2.3.4") is True
    reloj["t"] = 1061.0
    assert a.rate_limit_excedido("1.2.3.4") is False
    a.registrar_intento_fallido("9.9.9.9")
    assert "1.2.3.4" not in json.loads(archivo.read_text())["intentos"]


def test_archivo_corrupto_falla_abierto_y_avisa(tmp_path, caplog):
    """Fallar cerrado seria dejar a todos afuera porque se rompio el que cuenta."""
    archivo = tmp_path / "login.json"
    archivo.write_text("{esto no es json")
    with caplog.at_level(logging.WARNING, logger="libraauth.admin_auth"):
        a = _auth(login_max_intentos=1, estado_path=archivo)
        assert a.rate_limit_excedido("1.2.3.4") is False
        a.registrar_intento_fallido("1.2.3.4")
    assert "ilegible" in caplog.text
    # Y despues de la primera escritura el archivo vuelve a ser valido.
    assert json.loads(archivo.read_text())["intentos"]["1.2.3.4"]


def test_archivo_con_forma_inesperada_se_ignora(tmp_path, caplog):
    archivo = tmp_path / "login.json"
    archivo.write_text(json.dumps({"intentos": "no-es-un-dict"}))
    with caplog.at_level(logging.WARNING, logger="libraauth.admin_auth"):
        assert _auth(login_max_intentos=1, estado_path=archivo).rate_limit_excedido("1.2.3.4") is False
    assert "forma inesperada" in caplog.text


def test_ruta_no_escribible_sigue_en_memoria_y_avisa_una_vez(tmp_path, caplog):
    """La defensa no se apaga; solo deja de persistir, y el log lo dice."""
    bloqueado = tmp_path / "archivo-no-directorio"
    bloqueado.write_text("x")
    archivo = bloqueado / "login.json"  # el padre es un archivo: mkdir falla
    with caplog.at_level(logging.WARNING, logger="libraauth.admin_auth"):
        a = _auth(login_max_intentos=2, estado_path=archivo)
        a.registrar_intento_fallido("1.2.3.4")
        a.registrar_intento_fallido("1.2.3.4")
    assert a.rate_limit_excedido("1.2.3.4") is True
    assert caplog.text.count("NO sobrevive a un reinicio") == 1
