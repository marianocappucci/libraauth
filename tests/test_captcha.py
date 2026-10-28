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
6. (v0.55.0, ADR-028) Que **en un nodo de LibraEdge no se pida captcha**, que el
   desafio lo diga (`{"requerido": false}`), que un frontend viejo que lo mande
   igual no rompa nada, y que el bloqueo por IP siga cortando. Cada caso lleva su
   contraprueba fuera de un nodo.
"""
import base64
import json

import pytest
from altcha import Challenge, Payload, solve_challenge
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth.auth_events import AuthEventRepository
from libraauth.captcha import COSTO, PAYLOAD_MAXIMO, VIGENCIA_SEGUNDOS, Captcha
from libraauth.models import Base
from libraauth.nodo import NODE_ID_ENV
from libraauth.session_auth import CAPTCHA_INVALIDO, build_json_api_auth_router, verificar_captcha


@pytest.fixture(autouse=True)
def _fuera_de_un_nodo(monkeypatch):
    """Por defecto, esto es el central: el nodo se prende en cada test que lo pide (`nodo`)."""
    monkeypatch.delenv(NODE_ID_ENV, raising=False)


@pytest.fixture
def nodo(monkeypatch):
    monkeypatch.setenv(NODE_ID_ENV, "nodo-del-local-1")


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

    def get_current_user(self, request, response=None):
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


# ── En un nodo de LibraEdge no se pide captcha (v0.55.0, ADR-028) ───────────

def test_en_un_nodo_el_desafio_dice_que_no_hace_falta(nodo):
    r = _cliente(_app()).get("/auth/captcha")
    assert r.status_code == 200, r.text
    assert r.json() == {"requerido": False}
    assert r.headers["cache-control"] == "no-store"


def test_en_un_nodo_el_login_entra_sin_captcha(nodo):
    r = _cliente(_app()).post("/auth/login", json=CLAVE_BUENA)
    assert r.status_code == 200, r.text


def test_fuera_de_un_nodo_el_desafio_sigue_siendo_un_desafio_y_sin_captcha_es_400():
    """La contraprueba de los dos de arriba: sin `LIBRAEDGE_NODE_ID` nada cambia."""
    c = _cliente(_app())
    desafio = c.get("/auth/captcha").json()
    assert "requerido" not in desafio
    assert "parameters" in desafio and "signature" in desafio
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 400


def test_en_un_nodo_un_frontend_viejo_que_manda_captcha_igual_entra_y_no_gasta_el_desafio(nodo):
    """Un frontend de antes de libra-ui 0.177.0 contra un nodo nuevo: el campo `captcha` se ignora, venga bueno o basura."""
    app = _app()
    c = _cliente(app)
    assert c.post("/auth/login", json=_con(CLAVE_BUENA, "no-es-un-payload")).status_code == 200
    # Un desafio emitido fuera del nodo y resuelto sigue sin consumirse: el nodo no lo mira.
    capt = app.state.captcha
    payload = _resolver(capt.emitir())
    assert c.post("/auth/login", json=_con(CLAVE_BUENA, payload)).status_code == 200
    assert capt.verificar(payload) is True


def test_en_un_nodo_la_clave_mala_sigue_siendo_401(nodo):
    """Sin captcha la clave es lo que queda: sigue verificandose."""
    assert _cliente(_app()).post("/auth/login", json=CLAVE_MALA).status_code == 401


def test_en_un_nodo_el_bloqueo_por_intentos_fallidos_sigue_cortando(nodo, sessions):
    """🔴 Lo unico que frena la fuerza bruta en el nodo: cinco fallidos desde una IP en 15 minutos y el sexto es 429, aun con
    la clave buena. Los fallidos se anotan igual que con captcha."""
    c = _cliente(_app(sessions=sessions))
    for _ in range(5):
        assert c.post("/auth/login", json=CLAVE_MALA).status_code == 401
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 429


def test_con_el_flag_apagado_un_nodo_tampoco_tiene_desafio(nodo):
    """El nodo no prende el endpoint: sólo deja de exigirlo donde el producto lo prendió."""
    c = _cliente(_app(captcha=False, inyectar=False))
    assert c.get("/auth/captcha").status_code == 404
    assert c.post("/auth/login", json=CLAVE_BUENA).status_code == 200


def test_en_un_nodo_olvide_mi_contrasena_sigue_cerrado(nodo):
    """No hay recupero por correo en un nodo (ADR-027): 409, no 200 ni 400 de captcha."""
    recuperacion = _RecuperacionFalsa()
    c = _cliente(_app(recuperacion=recuperacion))
    r = c.post("/auth/forgot-password", json={"identificador": "ana"})
    assert r.status_code == 409, r.text
    assert recuperacion.pedidos == []


# --- `verificar_captcha`, la verificación pública para rutas propias del producto (ADR-029) ---------------------------


def _app_con_ruta_propia(**kw):
    """El router de `/auth` y una ruta del producto que verifica con `verificar_captcha`, como el portal de LibraClub."""
    app = _app(**kw)

    @app.post("/portal/login")
    def portal_login(request: Request, cuerpo: dict):
        if not verificar_captcha(request, cuerpo.get("captcha", "")):
            raise HTTPException(400, CAPTCHA_INVALIDO)
        return {"ok": True}

    return app


def test_verificar_captcha_acepta_el_desafio_de_auth_captcha():
    c = _cliente(_app_con_ruta_propia())
    assert c.post("/portal/login", json={"captcha": _captcha(c)}).status_code == 200


def test_verificar_captcha_sin_respuesta_es_falso():
    c = _cliente(_app_con_ruta_propia())
    assert c.post("/portal/login", json={}).status_code == 400


def test_un_desafio_usado_en_el_portal_no_sirve_para_el_login():
    """🔴 Un solo `Captcha` de proceso: el anti-replay no se parte entre la ruta del producto y el login."""
    c = _cliente(_app_con_ruta_propia())
    payload = _captcha(c)
    assert c.post("/portal/login", json={"captcha": payload}).status_code == 200
    assert c.post("/auth/login", json=_con(CLAVE_BUENA, payload)).status_code == 400


def test_sin_captcha_inyectado_crea_el_del_proceso_con_los_usados_del_producto():
    """Si a la ruta propia le toca crear el `Captcha` del proceso, lo crea con los `usados` que le pasa el producto."""
    from libraauth.captcha import UsadosEnMemoria

    usados = UsadosEnMemoria()
    app = _app(inyectar=False)

    @app.get("/probar")
    def probar(request: Request):
        verificar_captcha(request, "basura", usados)
        return {}

    _cliente(app).get("/probar")
    assert app.state.captcha._usados is usados


def test_verificar_captcha_respeta_el_parche_de_captcha_de(monkeypatch):
    """Las suites de los productos parchean `libraauth.session_auth._captcha_de`: la función pública lo tiene que ver."""
    class _Aprueba:
        def verificar(self, respuesta):
            return True

    monkeypatch.setattr("libraauth.session_auth._captcha_de", lambda request, usados=None: _Aprueba())
    c = _cliente(_app_con_ruta_propia())
    assert c.post("/portal/login", json={"captcha": "cualquier-cosa"}).status_code == 200
