"""Captcha ALTCHA (v0.40.0, ADR-014): el modulo y su cableado en el router.

Lo que se fija, en orden de lo que se rompe sin que se note:

1. 🔴 **Que un desafio resuelto sirva UNA vez.** Sin eso se resuelve uno y se
   lo reusa para cada contrasena durante diez minutos: el costo por intento,
   que es todo lo que un captcha de prueba de trabajo aporta, desaparece.
2. Que no pase lo que no emitio esta instancia: otra clave, vencido,
   manipulado, basura.
3. Que un payload roto sea un 400 y no un 500.
4. Que con `captcha=False` el router quede exactamente como antes: es lo que
   ven los productos que todavia no lo adoptaron.
5. Que el bloqueo por IP siga cortando **antes** que el captcha, y que un
   captcha invalido no cuente como intento fallido.
"""
import base64
import json

import pytest
from altcha import Challenge, Payload, solve_challenge
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth.auth_events import AuthEventRepository
from libraauth.captcha import COSTO, PAYLOAD_MAXIMO, VIGENCIA_SEGUNDOS, Captcha
from libraauth.models import Base
from libraauth.session_auth import build_json_api_auth_router


def _barato(secret="clave-de-la-instancia-a", **kwargs):
    """El mismo mecanismo con un costo que no gasta CPU en cada test."""
    return Captcha(secret, costo=1, contador_min=1, contador_rango=5, **kwargs)


def _resolver(desafio: dict, derived_key: str | None = None) -> str:
    """Lo que hace el navegador: resolver el desafio y armar el payload."""
    ch = Challenge.from_dict(desafio)
    solucion = solve_challenge(ch)
    if derived_key is not None:
        solucion.derived_key = derived_key
    return Payload(ch, solucion).to_base64()


# ── El modulo ───────────────────────────────────────────────────────────────

def test_un_desafio_resuelto_verifica():
    c = _barato()
    assert c.verificar(_resolver(c.emitir())) is True


def test_un_desafio_resuelto_sirve_una_sola_vez():
    c = _barato()
    payload = _resolver(c.emitir())
    assert c.verificar(payload) is True
    assert c.verificar(payload) is False


def test_lo_que_emitio_otra_instancia_no_pasa():
    """Cada instancia deriva sus claves de su propio SECRET_KEY."""
    payload = _resolver(_barato("clave-de-la-instancia-a").emitir())
    assert _barato("clave-de-la-instancia-b").verificar(payload) is False


def test_un_desafio_vencido_no_pasa():
    # Emitido con un reloj de 1970: vencio hace decadas.
    c = _barato(reloj=lambda: 1_000_000)
    assert c.verificar(_resolver(c.emitir())) is False


def test_un_desafio_manipulado_no_pasa():
    """Estirarle la vigencia a un desafio ya resuelto rompe la firma: es la
    manipulacion que querria quien lo resolvio para reusarlo mas tarde."""
    c = _barato()
    ch = Challenge.from_dict(c.emitir())
    solucion = solve_challenge(ch)
    ch.parameters.expires_at += 3600
    assert c.verificar(Payload(ch, solucion).to_base64()) is False


def test_una_solucion_equivocada_no_pasa():
    c = _barato()
    assert c.verificar(_resolver(c.emitir(), derived_key="00" * 32)) is False


def test_un_derived_key_que_no_es_hex_es_invalido_y_no_revienta():
    """`verify_solution` no atrapa este caso: con la firma del desafio bien, un
    `derivedKey` que no es hex le hace lanzar. Si se escapara, el login
    contestaria 500 en vez de rechazar."""
    c = _barato()
    assert c.verificar(_resolver(c.emitir(), derived_key="zz")) is False


@pytest.mark.parametrize("payload", [
    "",
    "no-es-base64",
    base64.b64encode(b"{}").decode(),
    base64.b64encode(json.dumps({"challenge": 1, "solution": 2}).encode()).decode(),
    "x" * (PAYLOAD_MAXIMO + 1),
])
def test_la_basura_no_pasa(payload):
    assert _barato().verificar(payload) is False


def test_el_desafio_tiene_la_forma_que_espera_el_widget():
    desafio = Captcha("clave").emitir()
    assert set(desafio) == {"parameters", "signature"}
    parametros = desafio["parameters"]
    assert parametros["algorithm"] == "PBKDF2/SHA-256"
    assert parametros["cost"] == COSTO
    # Vence, y trae la firma de la clave: es lo que deja verificar en 0,1 ms
    # sin volver a derivar.
    assert "expiresAt" in parametros and "keySignature" in parametros


def test_sin_secret_key_no_se_puede_construir():
    with pytest.raises(ValueError):
        Captcha("")


def test_los_usados_se_olvidan_cuando_vencen():
    reloj = {"ahora": 2_000_000_000.0}
    c = _barato(reloj=lambda: reloj["ahora"])
    assert c.verificar(_resolver(c.emitir()))
    assert len(c._usados) == 1
    reloj["ahora"] += VIGENCIA_SEGUNDOS + 1
    assert c.verificar(_resolver(c.emitir()))
    # El primero ya vencio: se purga en vez de acumularse para siempre.
    assert len(c._usados) == 1


# ── El router ───────────────────────────────────────────────────────────────

CLAVE_BUENA = {"username": "admin", "password": "correcta"}
CLAVE_MALA = {"username": "admin", "password": "incorrecta"}
_ADMIN = {"id": "1", "username": "admin", "name": "Admin", "role": "admin", "active": True}


class _UsersFalso:
    def check_credentials(self, username, password):
        if username == "admin" and password == "correcta":
            return dict(_ADMIN)
        return None

    def get_by_username(self, username):
        return dict(_ADMIN)


class _SessionAuthFalso:
    secret_key = "secreto-de-la-instancia"

    def create_session_cookie(self, response, username):
        response.set_cookie("sesion", username)

    def get_current_user(self, request):
        return request.cookies.get("sesion")

    def clear_session_cookie(self, response):
        response.delete_cookie("sesion")


class _RecuperacionFalsa:
    def __init__(self):
        self.pedidos = []

    def request_reset(self, identificador):
        self.pedidos.append(identificador)


@pytest.fixture
def sessions(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/captcha_test.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _app(*, captcha=True, inyectar=True, sessions=None, recuperacion=None):
    app = FastAPI()
    app.state.users = _UsersFalso()
    app.state.session_auth = _SessionAuthFalso()
    if inyectar:
        app.state.captcha = _barato()
    if sessions is not None:
        app.state.auth_events = AuthEventRepository(sessions)
    if recuperacion is not None:
        app.state.password_reset = recuperacion
    app.include_router(build_json_api_auth_router(
        captcha=captcha, incluir_password_reset=recuperacion is not None,
    ))
    return app


def _cliente(app):
    return TestClient(app, base_url="https://producto.test")


def _captcha(cliente) -> str:
    return _resolver(cliente.get("/auth/captcha").json())


def _con(credenciales, captcha):
    return {**credenciales, "captcha": captcha}


def test_con_el_flag_apagado_el_router_queda_como_antes():
    c = _cliente(_app(captcha=False, inyectar=False))
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 200
    assert c.get("/auth/captcha").status_code == 404


def test_login_sin_captcha_es_400():
    r = _cliente(_app()).post("/auth/login", json=CLAVE_BUENA)
    assert r.status_code == 400, r.text


def test_login_con_captcha_resuelto_entra():
    c = _cliente(_app())
    r = c.post("/auth/login", json=_con(CLAVE_BUENA, _captcha(c)))
    assert r.status_code == 200, r.text


def test_el_mismo_captcha_no_sirve_para_un_segundo_intento():
    """🔴 Cada contrasena probada cuesta un desafio resuelto."""
    c = _cliente(_app())
    payload = _captcha(c)
    assert c.post("/auth/login", json=_con(CLAVE_MALA, payload)).status_code == 401
    assert c.post("/auth/login", json=_con(CLAVE_BUENA, payload)).status_code == 400


def test_un_payload_roto_es_400_y_no_500():
    c = _cliente(_app())
    r = c.post("/auth/login", json=_con(CLAVE_BUENA, "no-es-un-payload"))
    assert r.status_code == 400, r.text


def test_el_bloqueo_corta_antes_que_el_captcha(sessions):
    """Una IP bloqueada recibe 429 con o sin captcha: si el captcha se
    chequeara antes, el bloqueo dejaria de ser la primera respuesta."""
    c = _cliente(_app(sessions=sessions))
    for _ in range(5):
        assert c.post("/auth/login", json=_con(CLAVE_MALA, _captcha(c))).status_code == 401
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 429


def test_un_captcha_invalido_no_cuenta_como_intento_fallido(sessions):
    """Sin captcha no se llego a probar ninguna contrasena, y anotarlo
    permitiria bloquear una IP compartida sin gastar nada."""
    c = _cliente(_app(sessions=sessions))
    for _ in range(8):
        assert c.post("/auth/login", json=CLAVE_MALA).status_code == 400
    assert c.post("/auth/login", json=_con(CLAVE_BUENA, _captcha(c))).status_code == 200


def test_el_desafio_no_se_cachea():
    r = _cliente(_app()).get("/auth/captcha")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"


def test_sin_captcha_inyectado_sale_del_secret_key_de_la_instancia():
    app = _app(inyectar=False)
    r = _cliente(app).get("/auth/captcha")
    assert r.status_code == 200
    assert r.json()["parameters"]["cost"] == COSTO
    # Y queda uno solo por app: la lista de usados no puede partirse en dos.
    assert app.state.captcha is not None
    primero = app.state.captcha
    _cliente(app).get("/auth/captcha")
    assert app.state.captcha is primero


def test_olvide_mi_contrasena_exige_captcha():
    """Sin captcha, el endpoint sirve para mandar correos en nombre de la
    instancia a cualquier usuario, a la velocidad que se quiera."""
    recuperacion = _RecuperacionFalsa()
    c = _cliente(_app(recuperacion=recuperacion))
    assert c.post("/auth/forgot-password", json={"identificador": "ana"}).status_code == 400
    assert recuperacion.pedidos == []
    r = c.post("/auth/forgot-password",
               json={"identificador": "ana", "captcha": _captcha(c)})
    assert r.status_code == 200, r.text
    assert recuperacion.pedidos == ["ana"]
