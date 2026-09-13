"""`AdminAuth`: segundo factor TOTP enrolable en runtime, guardado en un
archivo aparte del estado de login (F3, 2026-09-13).

Separado de `test_admin_auth_f2.py`, que cubre el origen "entorno"
(`ADMIN_PANEL_TOTP_SECRET`) sin tocarlo -- lo que prueba que sin la ruta de
archivo nada cambia respecto de la F2."""
import base64
import json
import logging
import os
import stat

import pytest

from libraauth import totp
from libraauth.admin_auth import TOTP_PENDIENTE_SEGUNDOS, AdminAuth, TotpNoEnrolable

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
    monkeypatch.delenv("ADMIN_PANEL_TOTP_PATH", raising=False)


def _auth(**kw):
    return AdminAuth(dev_secret_fallback="dev-only", **kw)


def _fijar_reloj_totp(monkeypatch, segundos):
    """El reloj que usa `Totp.paso_valido` (la ventana de 30s del codigo)."""
    monkeypatch.setattr("libraauth.totp.time.time", lambda: segundos)


def _fijar_reloj_admin(monkeypatch, segundos):
    """El reloj que usa `AdminAuth` para el vencimiento del pendiente."""
    monkeypatch.setattr("libraauth.admin_auth.time.time", lambda: segundos)


def _codigo(secreto, epoch):
    return totp.codigo(totp.decodificar_secreto(secreto), epoch // 30)


def _enrolar(a, monkeypatch, ahora=AHORA):
    """Enrola y confirma de punta a punta; devuelve (secreto, codigo_usado)."""
    _fijar_reloj_totp(monkeypatch, ahora)
    _fijar_reloj_admin(monkeypatch, float(ahora))
    datos = a.iniciar_totp("superadmin")
    codigo = _codigo(datos["secreto"], ahora)
    assert a.confirmar_totp(codigo) is True
    return datos["secreto"], codigo


# ── sin configuracion, nada cambia ──────────────────────────────────────

def test_sin_ruta_no_es_enrolable_y_no_hay_2fa():
    a = _auth()
    assert a.totp_enrolable is False
    assert a.totp_habilitado is False
    assert a.totp_origen is None
    assert a.check_credentials("superadmin", "clave-del-panel") is True
    with pytest.raises(TotpNoEnrolable):
        a.iniciar_totp("superadmin")


def test_totp_path_vacio_apaga_aunque_haya_estado_path(tmp_path):
    """Misma convencion que `estado_path`: `""` apaga, no delega al entorno."""
    a = _auth(estado_path=tmp_path / "login.json", totp_path="")
    assert a.totp_enrolable is False
    assert a.totp_habilitado is False


# ── de donde sale la ruta del archivo ───────────────────────────────────

def test_ruta_totp_se_deriva_de_estado_path(tmp_path, monkeypatch):
    estado = tmp_path / "estado" / "login.json"
    a = _auth(estado_path=estado)
    assert a.totp_enrolable is True
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    a.iniciar_totp("superadmin")
    assert (estado.parent / "totp.json").exists()


def test_ADMIN_PANEL_TOTP_PATH_explicito_gana_a_la_derivacion(monkeypatch, tmp_path):
    estado = tmp_path / "login.json"
    propio = tmp_path / "otro" / "totp.json"
    monkeypatch.setenv("ADMIN_PANEL_ESTADO_PATH", str(estado))
    monkeypatch.setenv("ADMIN_PANEL_TOTP_PATH", str(propio))
    a = _auth()
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    a.iniciar_totp("superadmin")
    assert propio.exists()
    assert not (estado.parent / "totp.json").exists()


def test_formato_del_archivo(tmp_path, monkeypatch):
    archivo = tmp_path / "totp.json"
    a = _auth(totp_path=archivo)
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    datos = a.iniciar_totp("superadmin")
    contenido = json.loads(archivo.read_text())
    assert contenido == {
        "secreto": None,
        "pendiente": {"secreto": datos["secreto"], "creado": float(AHORA)},
    }
    a.confirmar_totp(_codigo(datos["secreto"], AHORA))
    contenido = json.loads(archivo.read_text())
    assert contenido == {"secreto": datos["secreto"], "pendiente": None}


# ── iniciar -> confirmar activa, y el login pasa a exigir codigo ───────

def test_iniciar_confirmar_activa_y_el_login_exige_codigo(tmp_path, monkeypatch):
    a = _auth(estado_path=tmp_path / "login.json")
    assert a.check_credentials("superadmin", "clave-del-panel") is True
    secreto, _ = _enrolar(a, monkeypatch)
    assert a.totp_habilitado is True
    assert a.totp_origen == "archivo"
    assert a.check_credentials("superadmin", "clave-del-panel") is False
    # El paso siguiente (30s despues del usado para confirmar) si vale.
    _fijar_reloj_totp(monkeypatch, AHORA + 30)
    siguiente = _codigo(secreto, AHORA + 30)
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=siguiente) is True


def test_el_codigo_de_confirmacion_no_sirve_despues_para_loguearse(tmp_path, monkeypatch):
    a = _auth(estado_path=tmp_path / "login.json")
    _, codigo_usado = _enrolar(a, monkeypatch)
    assert a.check_credentials("superadmin", "clave-del-panel", codigo=codigo_usado) is False


def test_pendiente_vencido_no_confirma(tmp_path, monkeypatch):
    a = _auth(estado_path=tmp_path / "login.json")
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    datos = a.iniciar_totp("superadmin")
    despues = AHORA + TOTP_PENDIENTE_SEGUNDOS + 1
    _fijar_reloj_totp(monkeypatch, despues)
    _fijar_reloj_admin(monkeypatch, float(despues))
    assert a.confirmar_totp(_codigo(datos["secreto"], despues)) is False
    assert a.totp_habilitado is False


def test_iniciar_con_activo_rechaza(tmp_path, monkeypatch):
    a = _auth(estado_path=tmp_path / "login.json")
    _enrolar(a, monkeypatch)
    with pytest.raises(TotpNoEnrolable):
        a.iniciar_totp("superadmin")


# ── desactivar ───────────────────────────────────────────────────────────

def test_desactivar_con_codigo_valido_apaga_con_invalido_no(tmp_path, monkeypatch):
    a = _auth(estado_path=tmp_path / "login.json")
    secreto, _ = _enrolar(a, monkeypatch)
    assert a.desactivar_totp("000000") is False
    assert a.totp_habilitado is True
    _fijar_reloj_totp(monkeypatch, AHORA + 30)
    codigo = _codigo(secreto, AHORA + 30)
    assert a.desactivar_totp(codigo) is True
    assert a.totp_habilitado is False
    assert a.totp_origen is None
    # Y ahora se puede volver a enrolar.
    assert a.totp_enrolable is True


# ── el entorno manda ─────────────────────────────────────────────────────

def test_entorno_manda_y_rechaza_enrolar_y_desactivar(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_PANEL_TOTP_SECRET", SECRETO)
    a = _auth(estado_path=tmp_path / "login.json")
    assert a.totp_origen == "entorno"
    assert a.totp_enrolable is False
    with pytest.raises(TotpNoEnrolable, match="ADMIN_PANEL_TOTP_SECRET"):
        a.iniciar_totp("superadmin")
    with pytest.raises(TotpNoEnrolable, match="ADMIN_PANEL_TOTP_SECRET"):
        a.confirmar_totp("000000")
    with pytest.raises(TotpNoEnrolable, match="ADMIN_PANEL_TOTP_SECRET"):
        a.desactivar_totp("000000")


# ── archivo roto: fail CLOSED ────────────────────────────────────────────

def test_archivo_corrupto_login_cerrado_fail_closed(tmp_path, caplog):
    archivo = tmp_path / "totp.json"
    archivo.write_text("{esto no es json")
    a = _auth(totp_path=archivo)
    with caplog.at_level(logging.ERROR, logger="libraauth.admin_auth"):
        assert a.totp_habilitado is True
        assert a.totp_origen == "archivo"
        assert a.check_credentials("superadmin", "clave-del-panel") is False
        assert a.check_credentials("superadmin", "clave-del-panel", codigo="000000") is False
    assert "ilegible" in caplog.text
    assert a.totp_enrolable is False
    with pytest.raises(TotpNoEnrolable, match="roto"):
        a.iniciar_totp("superadmin")


def test_archivo_con_forma_inesperada_tambien_falla_cerrado(tmp_path, caplog):
    archivo = tmp_path / "totp.json"
    archivo.write_text(json.dumps({"otra_forma": True}))
    with caplog.at_level(logging.ERROR, logger="libraauth.admin_auth"):
        a = _auth(totp_path=archivo)
        assert a.totp_habilitado is True
        assert a.check_credentials("superadmin", "clave-del-panel") is False
    assert "forma inesperada" in caplog.text


@pytest.mark.parametrize("secreto", [123, ["ABCD"], {"x": 1}, True])
def test_secreto_que_no_es_texto_falla_cerrado_sin_reventar(tmp_path, secreto):
    """Un archivo editado a mano con un `secreto` que no es texto: login
    cerrado y controlado, no un `AttributeError` (un 500) dentro de `Totp()`."""
    archivo = tmp_path / "totp.json"
    archivo.write_text(json.dumps({"secreto": secreto, "pendiente": None}))
    a = _auth(totp_path=archivo)
    assert a.totp_habilitado is True
    assert a.check_credentials("superadmin", "clave-del-panel", codigo="000000") is False
    assert a.totp_enrolable is False


@pytest.mark.parametrize(
    "pendiente",
    [{"secreto": 5, "creado": AHORA}, {"secreto": SECRETO, "creado": "ayer"}, ["x"]],
)
def test_pendiente_malformado_se_descarta_sin_cerrar_el_login(tmp_path, monkeypatch, pendiente):
    archivo = tmp_path / "totp.json"
    archivo.write_text(json.dumps({"secreto": None, "pendiente": pendiente}))
    a = _auth(totp_path=archivo)
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    assert a.totp_habilitado is False
    assert a.check_credentials("superadmin", "clave-del-panel") is True
    assert a.confirmar_totp(CODIGO_AHORA) is False
    # Y se puede volver a iniciar por encima.
    assert "secreto" in a.iniciar_totp("superadmin")


# ── permisos y persistencia ──────────────────────────────────────────────

@pytest.mark.skipif(os.name == "nt", reason="permisos POSIX")
def test_permisos_0600_del_archivo(tmp_path, monkeypatch):
    archivo = tmp_path / "totp.json"
    a = _auth(totp_path=archivo)
    _enrolar(a, monkeypatch)
    modo = stat.S_IMODE(archivo.stat().st_mode)
    assert modo == 0o600


def test_reinicio_otra_instancia_conserva_el_activo(tmp_path, monkeypatch):
    """'Reinicio' = otra instancia de AdminAuth, mismo archivo."""
    ruta_estado = tmp_path / "login.json"
    a = _auth(estado_path=ruta_estado)
    secreto, _ = _enrolar(a, monkeypatch)
    b = _auth(estado_path=ruta_estado)
    assert b.totp_habilitado is True
    assert b.totp_origen == "archivo"
    _fijar_reloj_totp(monkeypatch, AHORA + 30)
    codigo = _codigo(secreto, AHORA + 30)
    assert b.check_credentials("superadmin", "clave-del-panel", codigo=codigo) is True


# ── la escritura se verifica: nunca "activado" si no persistio ─────────

def test_falla_de_escritura_en_confirmar_lanza_y_no_queda_activo(tmp_path, monkeypatch):
    archivo = tmp_path / "totp.json"
    a = _auth(totp_path=archivo)
    _fijar_reloj_totp(monkeypatch, AHORA)
    _fijar_reloj_admin(monkeypatch, float(AHORA))
    datos = a.iniciar_totp("superadmin")

    guardar_real = a._totp_archivo.guardar

    def guardar_roto(*, secreto, pendiente):
        if secreto is not None:
            return False  # simula que la escritura del ACTIVO no persistio
        return guardar_real(secreto=secreto, pendiente=pendiente)

    monkeypatch.setattr(a._totp_archivo, "guardar", guardar_roto)

    codigo = _codigo(datos["secreto"], AHORA)
    with pytest.raises(RuntimeError):
        a.confirmar_totp(codigo)

    # Se lee directo del archivo (no via `a`, cuyo guardar sigue parcheado).
    contenido = json.loads(archivo.read_text())
    assert contenido["secreto"] is None
    assert a.totp_habilitado is False  # solo lee, no usa el guardar parcheado
