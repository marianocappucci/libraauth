"""`AdminAuth`: login en dos pasos (F4, 2026-09-13) -- usuario+contrasena
primero, un desafio firmado de vida corta despues, y recien entonces el
codigo TOTP contra ese desafio.

Separado de `test_admin_auth.py` (cubre `check_credentials` de un paso, que
no se toca) y de `test_admin_auth_totp_archivo.py` (enrolamiento por
archivo). Este archivo cubre `verificar_clave`, `emitir_desafio_totp`,
`validar_desafio_totp` y `verificar_codigo_totp`."""
import base64

import pytest
from starlette.requests import Request
from starlette.responses import Response

from libraauth import totp
from libraauth.admin_auth import DESAFIO_TOTP_SEGUNDOS, AdminAuth

SECRETO = base64.b32encode(b"12345678901234567890").decode()
AHORA = 1234567890


@pytest.fixture(autouse=True)
def entorno(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ADMIN_PANEL_USER", "superadmin")
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "clave-del-panel")
    monkeypatch.delenv("ADMIN_PANEL_TOTP_SECRET", raising=False)
    monkeypatch.delenv("ADMIN_PANEL_ESTADO_PATH", raising=False)
    monkeypatch.delenv("ADMIN_PANEL_TOTP_PATH", raising=False)


def _auth(**kw):
    return AdminAuth(dev_secret_fallback="dev-only", **kw)


def _fijar_reloj_totp(monkeypatch, segundos):
    """El reloj que usa `Totp.paso_valido` (la ventana de 30s del codigo)."""
    monkeypatch.setattr("libraauth.totp.time.time", lambda: segundos)


def _fijar_reloj_admin(monkeypatch, segundos):
    """El reloj que usa `AdminAuth` para el vencimiento del pendiente TOTP."""
    monkeypatch.setattr("libraauth.admin_auth.time.time", lambda: segundos)


def _fijar_reloj_desafio(monkeypatch, segundos):
    """El reloj que usa `itsdangerous` para firmar y vencer el desafio
    (`TimestampSigner.get_timestamp`, definido en `itsdangerous.timed` sobre
    el modulo `time` que importa ese archivo)."""
    monkeypatch.setattr("itsdangerous.timed.time.time", lambda: segundos)


def _codigo(secreto, epoch):
    return totp.codigo(totp.decodificar_secreto(secreto), epoch // 30)


def _request_con_cookie(nombre, valor):
    scope = {
        "type": "http", "method": "GET", "path": "/", "headers":
        [(b"cookie", f"{nombre}={valor}".encode())],
    }
    return Request(scope)


# ── verificar_clave (paso 1) ─────────────────────────────────────────────

def test_verificar_clave_ok():
    assert _auth().verificar_clave("superadmin", "clave-del-panel") is True


@pytest.mark.parametrize("user,password", [
    ("superadmin", "otra"),
    ("otro", "clave-del-panel"),
    ("", ""),
])
def test_verificar_clave_mal(user, password):
    assert _auth().verificar_clave(user, password) is False


def test_verificar_clave_sin_password_configurada_rechaza_todo(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_PASSWORD", "")
    a = _auth()
    assert a.verificar_clave("superadmin", "") is False
    assert a.verificar_clave("superadmin", "cualquiera") is False


def test_verificar_clave_no_mira_totp(tmp_path, monkeypatch):
    """A diferencia de `check_credentials`, `verificar_clave` no exige codigo
    aunque haya 2FA activo -- es solo el paso 1."""
    a = _auth(estado_path=tmp_path / "login.json")
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    datos = a.iniciar_totp("superadmin")
    assert a.confirmar_totp(_codigo(datos["secreto"], AHORA)) is True
    assert a.totp_habilitado is True
    assert a.verificar_clave("superadmin", "clave-del-panel") is True


# ── desafio: ida y vuelta, vencimiento, firma ─────────────────────────────

def test_desafio_ida_y_vuelta(monkeypatch):
    a = _auth()
    _fijar_reloj_desafio(monkeypatch, AHORA)
    desafio = a.emitir_desafio_totp("superadmin")
    assert a.validar_desafio_totp(desafio) == "superadmin"


def test_desafio_vencido(monkeypatch):
    a = _auth()
    _fijar_reloj_desafio(monkeypatch, AHORA)
    desafio = a.emitir_desafio_totp("superadmin")
    _fijar_reloj_desafio(monkeypatch, AHORA + DESAFIO_TOTP_SEGUNDOS + 1)
    assert a.validar_desafio_totp(desafio) is None


def test_desafio_al_borde_del_vencimiento_todavia_vale(monkeypatch):
    a = _auth()
    _fijar_reloj_desafio(monkeypatch, AHORA)
    desafio = a.emitir_desafio_totp("superadmin")
    _fijar_reloj_desafio(monkeypatch, AHORA + DESAFIO_TOTP_SEGUNDOS)
    assert a.validar_desafio_totp(desafio) == "superadmin"


def test_desafio_con_firma_alterada(monkeypatch):
    a = _auth()
    _fijar_reloj_desafio(monkeypatch, AHORA)
    desafio = a.emitir_desafio_totp("superadmin")
    roto = desafio[:-3] + ("aaa" if not desafio.endswith("aaa") else "bbb")
    assert a.validar_desafio_totp(roto) is None


@pytest.mark.parametrize("entrada", [None, "", 123, [], {}, "no-firmado"])
def test_desafio_entrada_invalida_nunca_lanza(entrada):
    assert _auth().validar_desafio_totp(entrada) is None


def test_desafio_con_forma_de_payload_inesperada(monkeypatch):
    """Firmado con el mismo signer y salt, pero sin la forma `{"u": str}`."""
    a = _auth()
    _fijar_reloj_desafio(monkeypatch, AHORA)
    sin_forma_de_dict = a._signer_totp_desafio.dumps("no-es-un-dict")
    sin_clave_u = a._signer_totp_desafio.dumps({"otra_clave": "superadmin"})
    u_no_texto = a._signer_totp_desafio.dumps({"u": 123})
    assert a.validar_desafio_totp(sin_forma_de_dict) is None
    assert a.validar_desafio_totp(sin_clave_u) is None
    assert a.validar_desafio_totp(u_no_texto) is None


# ── el salt propio separa el desafio de la cookie de sesion ──────────────

def test_desafio_no_sirve_como_cookie_de_sesion(monkeypatch):
    a = _auth()
    _fijar_reloj_desafio(monkeypatch, AHORA)
    desafio = a.emitir_desafio_totp("superadmin")
    assert a.current_user(_request_con_cookie(a.cookie_name, desafio)) is None


def test_cookie_de_sesion_no_sirve_como_desafio():
    a = _auth()
    r = Response()
    a.create_session_cookie(r, "superadmin")
    cookie = r.headers["set-cookie"].split("=", 1)[1].split(";")[0]
    assert a.validar_desafio_totp(cookie) is None


# ── verificar_codigo_totp (paso 2) ────────────────────────────────────────

def test_verificar_codigo_totp_por_entorno(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    a = _auth()
    _fijar_reloj_totp(monkeypatch, AHORA)
    codigo = _codigo(SECRETO, AHORA)
    assert a.verificar_codigo_totp(codigo) is True


def test_verificar_codigo_totp_por_archivo(tmp_path, monkeypatch):
    a = _auth(estado_path=tmp_path / "login.json")
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    datos = a.iniciar_totp("superadmin")
    assert a.confirmar_totp(_codigo(datos["secreto"], AHORA)) is True
    _fijar_reloj_totp(monkeypatch, AHORA + 30)
    siguiente = _codigo(datos["secreto"], AHORA + 30)
    assert a.verificar_codigo_totp(siguiente) is True


def test_verificar_codigo_totp_no_sirve_dos_veces(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    a = _auth()
    _fijar_reloj_totp(monkeypatch, AHORA)
    codigo = _codigo(SECRETO, AHORA)
    assert a.verificar_codigo_totp(codigo) is True
    assert a.verificar_codigo_totp(codigo) is False


def test_codigo_usado_en_verificar_codigo_totp_no_sirve_en_check_credentials(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    a = _auth()
    _fijar_reloj_totp(monkeypatch, AHORA)
    codigo = _codigo(SECRETO, AHORA)
    assert a.verificar_codigo_totp(codigo) is True
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=codigo) is False


def test_codigo_usado_en_check_credentials_no_sirve_en_verificar_codigo_totp(monkeypatch):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    a = _auth()
    _fijar_reloj_totp(monkeypatch, AHORA)
    codigo = _codigo(SECRETO, AHORA)
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=codigo) is True
    assert a.verificar_codigo_totp(codigo) is False


def test_verificar_codigo_totp_sin_totp_activo_da_false():
    assert _auth().verificar_codigo_totp("000000") is False


def test_verificar_codigo_totp_con_archivo_roto_da_false(tmp_path):
    archivo = tmp_path / "totp.json"
    archivo.write_text("{esto no es json")
    a = _auth(totp_path=archivo)
    assert a.totp_habilitado is True
    assert a.verificar_codigo_totp("000000") is False


# ── check_credentials de un solo paso sigue igual ─────────────────────────

def test_check_credentials_de_un_paso_sigue_funcionando(monkeypatch):
    """Sanity check de compatibilidad -- el grueso de la cobertura del camino
    de un paso sigue en `test_admin_auth.py` y `test_admin_auth_totp_archivo.py`,
    sin tocar."""
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    a = _auth()
    _fijar_reloj_totp(monkeypatch, AHORA)
    codigo = _codigo(SECRETO, AHORA)
    assert a.check_credentials("superadmin", "mal", codigo=codigo) is False
    assert a.check_credentials("superadmin", "clave-del-panel", codigo="000000") is False
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=codigo) is True
