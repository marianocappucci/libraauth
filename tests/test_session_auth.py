import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from libraauth.session_auth import SessionAuth


@pytest.fixture(autouse=True)
def _default_secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "autoused-test-secret")


# ── SessionAuth ───────────────────────────────────────────────────────────

_USERS = {
    "admin1":  {"username": "admin1",  "role": "admin", "_password": "adminpw"},
    "oper1":   {"username": "oper1",   "role": "staff",  "_password": "operpw"},
    "cajero1": {"username": "cajero1", "role": "cajero", "_password": "cajpw"},
}


def _make_session_auth(**overrides):
    def get_user_by_username(username):
        return _USERS.get(username)

    def check_credentials(username, password):
        user = _USERS.get(username)
        if user and user["_password"] == password:
            return user
        return None

    kwargs = dict(
        dev_secret_fallback="test-secret",
        get_user_by_username=get_user_by_username,
        check_credentials=check_credentials,
    )
    kwargs.update(overrides)
    return SessionAuth(**kwargs)


def _make_session_app(session_auth):
    async def protected(request):
        user = session_auth.require_auth(request)
        return PlainTextResponse(f"hello {user}")

    async def admin_only(request):
        user = session_auth.require_admin(request)
        return JSONResponse(user)

    role_dep = session_auth.require_role("admin", "staff")

    async def role_only(request):
        user = role_dep(request)
        return JSONResponse(user)

    async def login(request):
        resp = PlainTextResponse("ok")
        session_auth.create_session_cookie(resp, request.query_params["username"])
        return resp

    async def logout(request):
        resp = PlainTextResponse("ok")
        session_auth.clear_session_cookie(resp)
        return resp

    return Starlette(
        routes=[
            Route("/protected", protected),
            Route("/admin-only", admin_only),
            Route("/role-only", role_only),
            Route("/login", login),
            Route("/logout", logout),
        ]
    )


def _client(session_auth):
    app = _make_session_app(session_auth)
    return TestClient(app, base_url="https://testserver")


def test_require_auth_redirects_without_session():
    client = _client(_make_session_auth())
    r = client.get("/protected", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/login"


def test_login_then_require_auth_succeeds():
    client = _client(_make_session_auth())
    client.get("/login?username=oper1")
    r = client.get("/protected")
    assert r.status_code == 200
    assert r.text == "hello oper1"


def test_logout_clears_session():
    client = _client(_make_session_auth())
    client.get("/login?username=oper1")
    client.get("/logout")
    r = client.get("/protected", follow_redirects=False)
    assert r.status_code == 307


def test_require_admin_redirects_non_admin_to_dashboard():
    client = _client(_make_session_auth())
    client.get("/login?username=oper1")
    r = client.get("/admin-only", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/dashboard"


def test_require_admin_passes_for_admin():
    client = _client(_make_session_auth())
    client.get("/login?username=admin1")
    r = client.get("/admin-only")
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_require_role_accepts_any_listed_role():
    client = _client(_make_session_auth())
    client.get("/login?username=oper1")
    r = client.get("/role-only")
    assert r.status_code == 200


def test_require_role_rejects_role_not_listed():
    client = _client(_make_session_auth())
    client.get("/login?username=cajero1")
    r = client.get("/role-only", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/dashboard"


def test_check_credentials_true_for_valid_password():
    auth = _make_session_auth()
    assert auth.check_credentials("admin1", "adminpw") is True


def test_check_credentials_false_for_invalid_password():
    auth = _make_session_auth()
    assert auth.check_credentials("admin1", "wrong") is False


def test_check_credentials_false_for_unknown_user():
    auth = _make_session_auth()
    assert auth.check_credentials("nadie", "x") is False


def test_tampered_cookie_treated_as_anonymous():
    client = _client(_make_session_auth())
    client.get("/login?username=oper1")
    client.cookies.set("libra_session", client.cookies.get("libra_session") + "tampered")
    r = client.get("/protected", follow_redirects=False)
    assert r.status_code == 307


def test_secret_key_dev_fallback_when_env_development(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ENV", "development")
    auth = _make_session_auth(dev_secret_fallback="dev-fallback-key")
    assert auth.secret_key == "dev-fallback-key"


def test_secret_key_fail_fast_without_env_development(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY no está seteado"):
        _make_session_auth()


def test_secret_key_from_env_takes_priority(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "from-env")
    monkeypatch.setenv("ENV", "development")
    auth = _make_session_auth(dev_secret_fallback="dev-fallback-key")
    assert auth.secret_key == "from-env"
    monkeypatch.delenv("SECRET_KEY", raising=False)


# ── Dependencias JSON API ────────────────────────────────────────────────

from fastapi import Depends, FastAPI, Response
from fastapi.testclient import TestClient as FastAPITestClient

from libraauth.session_auth import (
    build_json_api_auth_router,
    json_api_require_admin,
    json_api_require_staff,
)


class _FakeJsonApiUsers:
    def __init__(self):
        self._users = {
            "admin":    {"id": "1", "username": "admin",    "name": "Admin",    "role": "admin", "active": True,  "_password": "adminpw"},
            "staffer":  {"id": "2", "username": "staffer",  "name": "Staffer",  "role": "staff",  "active": True,  "_password": "staffpw"},
            "disabled": {"id": "3", "username": "disabled", "name": "Disabled", "role": "staff",  "active": False, "_password": "pw"},
        }

    def _public(self, u):
        return {k: v for k, v in u.items() if k != "_password"}

    def get_by_username(self, username):
        u = self._users.get(username)
        return self._public(u) if u else None

    def get_by_id(self, user_id):
        for u in self._users.values():
            if u["id"] == user_id:
                return self._public(u)
        return None

    def check_credentials(self, username, password):
        u = self._users.get(username)
        if u and u["_password"] == password:
            return self._public(u)
        return None

    def update_password(self, user_id, new_password):
        for u in self._users.values():
            if u["id"] == user_id:
                u["_password"] = new_password
                return
        raise KeyError(user_id)

    def deactivate(self, username):
        self._users[username]["active"] = False


def _make_json_api_app(users=None):
    app = FastAPI()
    users = users or _FakeJsonApiUsers()
    app.state.users = users
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="test-secret",
        get_user_by_username=users.get_by_username,
        check_credentials=users.check_credentials,
        cookie_name="test_json_session",
    )
    app.include_router(build_json_api_auth_router())

    @app.get("/admin-only", dependencies=[Depends(json_api_require_admin)])
    def admin_only():
        return {"ok": True}

    @app.get("/staff-only", dependencies=[Depends(json_api_require_staff)])
    def staff_only():
        return {"ok": True}

    return app


def test_json_api_login_success_sets_cookie():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    r = client.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    assert r.status_code == 200
    assert r.json()["username"] == "admin"
    assert "test_json_session" in r.cookies


def test_json_api_login_wrong_password_401():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    r = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_json_api_login_unknown_username_401():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    r = client.post("/auth/login", json={"username": "ghost", "password": "x"})
    assert r.status_code == 401


def test_json_api_me_without_session_401():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    assert client.get("/auth/me").status_code == 401


def test_json_api_me_after_login_returns_current_user():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    client.post("/auth/login", json={"username": "staffer", "password": "staffpw"})
    r = client.get("/auth/me")
    assert r.status_code == 200
    assert r.json()["role"] == "staff"


def test_json_api_logout_clears_the_session():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    client.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    assert client.get("/auth/me").status_code == 200
    assert client.post("/auth/logout").status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_json_api_get_current_user_rejects_user_deactivated_after_login():
    users = _FakeJsonApiUsers()
    client = FastAPITestClient(_make_json_api_app(users), base_url="https://testserver")
    client.post("/auth/login", json={"username": "staffer", "password": "staffpw"})
    assert client.get("/auth/me").status_code == 200
    users.deactivate("staffer")
    assert client.get("/auth/me").status_code == 401


def test_json_api_get_current_user_acepta_el_orden_viejo_por_posicion():
    """`response` se agrego AL FINAL de la firma (ADR-017): quien la llamaba
    como `json_api_get_current_user(request, auth)` tiene que seguir andando.
    Con `response` en segundo lugar, el `auth` caia en `response` y el
    `auth` real quedaba en el `Depends` por defecto: un `AttributeError`."""
    from fastapi import Request as FastAPIRequest

    from libraauth.session_auth import json_api_get_current_user

    app = _make_json_api_app()

    @app.get("/directo")
    def directo(request: FastAPIRequest):
        usuario = json_api_get_current_user(request, request.app.state.session_auth)
        return {"username": usuario["username"]}

    client = FastAPITestClient(app, base_url="https://testserver")
    client.post("/auth/login", json={"username": "staffer", "password": "staffpw"})
    r = client.get("/directo")
    assert r.status_code == 200
    assert r.json() == {"username": "staffer"}


def test_json_api_require_admin_blocks_staff():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    client.post("/auth/login", json={"username": "staffer", "password": "staffpw"})
    assert client.get("/admin-only").status_code == 403


def test_json_api_require_admin_allows_admin():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    client.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    assert client.get("/admin-only").status_code == 200


def test_json_api_require_staff_allows_both_admin_and_staff():
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    client.post("/auth/login", json={"username": "staffer", "password": "staffpw"})
    assert client.get("/staff-only").status_code == 200


# ── POST /auth/verify (opt-in) ───────────────────────────────────────────

def _make_verify_app():
    """Igual que _make_json_api_app pero con el router opt-in de /verify."""
    app = FastAPI()
    users = _FakeJsonApiUsers()
    app.state.users = users
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="test-secret",
        get_user_by_username=users.get_by_username,
        check_credentials=users.check_credentials,
        cookie_name="test_json_session",
    )
    app.include_router(build_json_api_auth_router(incluir_verify=True))
    return app


def test_verify_no_se_monta_por_defecto():
    """Es opt-in: un consumidor sin landing no expone el endpoint."""
    client = FastAPITestClient(_make_json_api_app(), base_url="https://testserver")
    r = client.post("/auth/verify", json={"username": "admin", "password": "adminpw"})
    assert r.status_code == 404


def test_verify_credenciales_correctas(monkeypatch):
    monkeypatch.setenv("DOCS_AUTH_SECRET", "secreto-compartido")
    client = FastAPITestClient(_make_verify_app(), base_url="https://testserver")
    r = client.post("/auth/verify", json={"username": "admin", "password": "adminpw"},
                    headers={"X-Internal-Auth": "secreto-compartido"})
    assert r.status_code == 200
    assert r.json() == {"valid": True}


def test_verify_password_incorrecta_no_es_401_sino_valid_false(monkeypatch):
    """El 401 esta reservado al secreto server-to-server; una credencial mala
    del usuario final es una respuesta valida con valid=false."""
    monkeypatch.setenv("DOCS_AUTH_SECRET", "secreto-compartido")
    client = FastAPITestClient(_make_verify_app(), base_url="https://testserver")
    r = client.post("/auth/verify", json={"username": "admin", "password": "no-es"},
                    headers={"X-Internal-Auth": "secreto-compartido"})
    assert r.status_code == 200
    assert r.json() == {"valid": False}


def test_verify_sin_header_da_401(monkeypatch):
    monkeypatch.setenv("DOCS_AUTH_SECRET", "secreto-compartido")
    client = FastAPITestClient(_make_verify_app(), base_url="https://testserver")
    r = client.post("/auth/verify", json={"username": "admin", "password": "adminpw"})
    assert r.status_code == 401


def test_verify_con_header_equivocado_da_401(monkeypatch):
    monkeypatch.setenv("DOCS_AUTH_SECRET", "secreto-compartido")
    client = FastAPITestClient(_make_verify_app(), base_url="https://testserver")
    r = client.post("/auth/verify", json={"username": "admin", "password": "adminpw"},
                    headers={"X-Internal-Auth": "otro-secreto"})
    assert r.status_code == 401


def test_verify_falla_cerrado_sin_secreto_configurado(monkeypatch):
    """Si DOCS_AUTH_SECRET esta vacio NO se valida a nadie, ni siquiera con el
    header vacio: sin esto, una instancia mal configurada quedaria como oraculo
    de credenciales abierto."""
    monkeypatch.delenv("DOCS_AUTH_SECRET", raising=False)
    client = FastAPITestClient(_make_verify_app(), base_url="https://testserver")
    for headers in ({}, {"X-Internal-Auth": ""}, {"X-Internal-Auth": "cualquiera"}):
        r = client.post("/auth/verify", json={"username": "admin", "password": "adminpw"},
                        headers=headers)
        assert r.status_code == 401, headers


def test_verify_no_crea_cookie_de_sesion(monkeypatch):
    """Es server-to-server: no debe dejar sesion abierta."""
    monkeypatch.setenv("DOCS_AUTH_SECRET", "secreto-compartido")
    client = FastAPITestClient(_make_verify_app(), base_url="https://testserver")
    r = client.post("/auth/verify", json={"username": "admin", "password": "adminpw"},
                    headers={"X-Internal-Auth": "secreto-compartido"})
    assert r.json() == {"valid": True}
    assert "test_json_session" not in client.cookies
    assert client.get("/auth/me").status_code == 401


# --- POST /auth/change-password -------------------------------------------
#
# La unica forma de cambiar la propia clave estando adentro. Antes habia que
# salir de la aplicacion y esperar el mail de `/auth/forgot-password`, o sea
# depender del SMTP para algo que no lo necesita.
#
# Lo que estos tests tienen que sostener, en orden de gravedad:
#   1. Que el cambio SIRVA -- que la nueva loguee y la vieja deje de loguear.
#      Un 200 no prueba nada: el endpoint podria no haber tocado nada.
#   2. Que no se le pueda cambiar la clave a OTRO.
#   3. Que cada rechazo deje la contrasena como estaba.


def _logueado(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return client


def _puede_entrar(app, username, password):
    """Login en un cliente NUEVO, sin la cookie del anterior."""
    otro = FastAPITestClient(app, base_url="https://testserver")
    return otro.post(
        "/auth/login", json={"username": username, "password": password}
    ).status_code == 200


def test_cambiar_la_propia_password_deja_entrar_con_la_nueva():
    app = _make_json_api_app()
    client = _logueado(FastAPITestClient(app, base_url="https://testserver"), "admin", "adminpw")

    r = client.post("/auth/change-password",
                    json={"current_password": "adminpw", "new_password": "clave-nueva"})
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "admin"

    # 🔑 Las dos mitades. Sin la segunda, un endpoint que agrega una clave sin
    # sacar la vieja pasaria igual.
    assert _puede_entrar(app, "admin", "clave-nueva")
    assert not _puede_entrar(app, "admin", "adminpw")


def test_cambiar_la_password_no_cierra_la_sesion_en_curso():
    """Quien acaba de cambiarla sigue trabajando: dejarlo afuera justo despues
    de un cambio exitoso se lee como un error."""
    app = _make_json_api_app()
    client = _logueado(FastAPITestClient(app, base_url="https://testserver"), "admin", "adminpw")
    client.post("/auth/change-password",
                json={"current_password": "adminpw", "new_password": "clave-nueva"})
    assert client.get("/auth/me").status_code == 200


def test_sin_sesion_no_se_puede_cambiar_nada():
    app = _make_json_api_app()
    client = FastAPITestClient(app, base_url="https://testserver")
    r = client.post("/auth/change-password",
                    json={"current_password": "adminpw", "new_password": "clave-nueva"})
    assert r.status_code == 401
    assert _puede_entrar(app, "admin", "adminpw")


def test_con_la_actual_equivocada_no_cambia_nada():
    """Es lo que hace que una sesion robada no alcance para apropiarse de la
    cuenta: sin pedir la actual, una cookie olvidada seria una toma definitiva."""
    app = _make_json_api_app()
    client = _logueado(FastAPITestClient(app, base_url="https://testserver"), "admin", "adminpw")

    r = client.post("/auth/change-password",
                    json={"current_password": "la-que-no-es", "new_password": "clave-nueva"})
    assert r.status_code == 400
    # La afirmacion que importa no es el codigo: es que la clave siga siendo la
    # de antes y la propuesta no sirva.
    assert _puede_entrar(app, "admin", "adminpw")
    assert not _puede_entrar(app, "admin", "clave-nueva")


def test_no_se_le_puede_cambiar_la_password_a_otro():
    """El usuario sale de la cookie, nunca del cuerpo. Se mandan `username`,
    `user_id` y `id` a proposito: si alguno se leyera, un staff cualquiera
    podria quedarse con la cuenta del admin."""
    app = _make_json_api_app()
    client = _logueado(FastAPITestClient(app, base_url="https://testserver"), "staffer", "staffpw")

    r = client.post("/auth/change-password", json={
        "current_password": "staffpw", "new_password": "clave-nueva",
        "username": "admin", "user_id": "1", "id": "1",
    })
    assert r.status_code == 200
    assert r.json()["username"] == "staffer"

    assert _puede_entrar(app, "admin", "adminpw")          # el admin, intacto
    assert not _puede_entrar(app, "admin", "clave-nueva")
    assert _puede_entrar(app, "staffer", "clave-nueva")    # el suyo si cambio


def test_la_password_nueva_tiene_un_minimo():
    app = _make_json_api_app()
    client = _logueado(FastAPITestClient(app, base_url="https://testserver"), "admin", "adminpw")

    r = client.post("/auth/change-password",
                    json={"current_password": "adminpw", "new_password": "abc"})
    assert r.status_code == 422
    assert _puede_entrar(app, "admin", "adminpw")
    assert not _puede_entrar(app, "admin", "abc")


def test_la_password_nueva_tiene_que_ser_distinta():
    """Aceptar la misma devolveria "listo" sin haber cambiado nada, y quien la
    cambio por sospecha de filtracion se quedaria creyendo que la roto."""
    app = _make_json_api_app()
    client = _logueado(FastAPITestClient(app, base_url="https://testserver"), "admin", "adminpw")

    r = client.post("/auth/change-password",
                    json={"current_password": "adminpw", "new_password": "adminpw"})
    assert r.status_code == 422


# --- empresa_nombre en el usuario ------------------------------------------
#
# El sidebar de libra-ui muestra `getUserSubtitle(user)` debajo del nombre del
# producto, y Contalibra/Restolibra lo vienen usando para el nombre de la
# empresa. Los cuatro productos que usan ESTE router no tenian de donde sacarlo
# -- y eran exactamente los cuatro que no lo mostraban.


def _app_con_empresa(nombre="Lagrace Comunicaciones"):
    app = FastAPI()
    users = _FakeJsonApiUsers()
    app.state.users = users
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="test-secret",
        get_user_by_username=users.get_by_username,
        check_credentials=users.check_credentials,
        cookie_name="test_json_session",
    )
    app.include_router(
        build_json_api_auth_router(get_empresa_nombre=lambda request: nombre)
    )
    return app


def test_el_login_y_el_me_traen_el_nombre_de_la_empresa():
    """Los DOS, no solo `/me`. Si estuviera unicamente en `/me`, el sidebar
    aparecería sin subtitulo al loguearse y con subtitulo despues de recargar:
    cambiaria de forma sin que nadie tocara nada."""
    client = FastAPITestClient(_app_con_empresa(), base_url="https://testserver")

    login = client.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    assert login.json()["empresa_nombre"] == "Lagrace Comunicaciones"
    assert client.get("/auth/me").json()["empresa_nombre"] == "Lagrace Comunicaciones"


def test_el_cambio_de_password_tambien_lo_devuelve():
    """Devuelve un usuario completo, asi que tiene que ser el mismo usuario que
    devuelven los otros dos: si le faltara el campo, el frontend que refresca su
    estado con esta respuesta se quedaria sin subtitulo despues de cambiar la
    clave."""
    client = FastAPITestClient(_app_con_empresa(), base_url="https://testserver")
    client.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    r = client.post("/auth/change-password",
                    json={"current_password": "adminpw", "new_password": "clave-nueva"})
    assert r.json()["empresa_nombre"] == "Lagrace Comunicaciones"


def test_sin_get_empresa_nombre_el_campo_va_en_none():
    """El comportamiento de siempre: un producto que no lo configura sigue
    andando y el sidebar no dibuja subtitulo. Es lo que permite que esto entre
    sin tocar a los productos que todavia no lo usan."""
    app = _make_json_api_app()
    client = FastAPITestClient(app, base_url="https://testserver")
    r = client.post("/auth/login", json={"username": "admin", "password": "adminpw"})
    assert r.json()["empresa_nombre"] is None


def test_la_empresa_sale_de_la_instancia_y_no_de_la_fila_del_usuario():
    """Dos usuarios distintos de la misma instancia ven la misma empresa.

    ⚠️ **Este test no puede fallar mientras la firma sea `(Request) -> str`**:
    la funcion no recibe el usuario, asi que no tiene con que depender de el.
    Se intento romperlo a proposito y siguio verde. Queda igual porque documenta
    la decision y **si** se pondria rojo el dia que alguien cambie la firma a
    una que reciba el usuario — que es exactamente el cambio que haria que la
    empresa pasara a depender de la persona en vez de la instalacion.
    """
    app = _app_con_empresa("Estudio Sur")
    for usuario, clave in (("admin", "adminpw"), ("staffer", "staffpw")):
        client = FastAPITestClient(app, base_url="https://testserver")
        r = client.post("/auth/login", json={"username": usuario, "password": clave})
        assert r.json()["empresa_nombre"] == "Estudio Sur", usuario


# ── Sesion por inactividad y renovacion deslizante (ADR-017) ───────────────
#
# El reloj se controla parcheando `TimestampSigner.get_timestamp` -- el unico
# punto de itsdangerous que lee la hora, tanto al firmar (`sign`) como al
# validar (`unsign`, de donde sale `return_timestamp`). No se usa freezegun:
# pydantic v2 (que FastAPI trae) tiene problemas conocidos con el patcheo
# global del reloj que hace freezegun, y este mecanismo alcanza sin tocar
# nada fuera de itsdangerous.

from http.cookies import SimpleCookie

import itsdangerous.timed
from starlette.requests import Request

from libraauth.session_auth import (
    INACTIVIDAD_MAXIMA_SEGUNDOS,
    RENOVACION_MINIMA_SEGUNDOS,
)


class _RelojFalso:
    """Segundos desde un origen arbitrario. `avanzar` es la unica forma de
    moverlo -- nada corre en tiempo real durante estos tests."""

    def __init__(self):
        self.ahora = 1_800_000_000  # epoch arbitrario, sin significado

    def avanzar(self, segundos: float) -> None:
        self.ahora += segundos


@pytest.fixture
def reloj(monkeypatch):
    r = _RelojFalso()
    monkeypatch.setattr(
        itsdangerous.timed.TimestampSigner,
        "get_timestamp",
        lambda self: int(r.ahora),
    )
    return r


def _cookie_valor(set_cookie_header: str, nombre: str) -> str:
    c = SimpleCookie()
    c.load(set_cookie_header)
    return c[nombre].value


def _make_sliding_app(session_auth):
    """Una app FastAPI chica, con una ruta protegida por `require_auth` --
    la misma dependencia que usan los 8 productos-- para probar la
    renovacion deslizante tal como la ve un consumidor real: via `Depends`,
    sin que la ruta declare `response` ella misma."""
    app = FastAPI()

    @app.get("/ping")
    def ping(user: str = Depends(session_auth.require_auth)):
        return {"user": user}

    @app.post("/login")
    def login(username: str, response: Response):
        session_auth.create_session_cookie(response, username)
        return {"ok": True}

    @app.post("/logout")
    def logout(response: Response):
        session_auth.clear_session_cookie(response)
        return {"ok": True}

    return app


def test_sesion_usada_cada_hora_durante_10h_sigue_viva(reloj):
    """(a) Un usuario activo -- un pedido por hora-- nunca deberia ver
    cerrada su sesion: cada pedido la renueva antes de que llegue a las 8h
    sin uso."""
    auth = _make_session_auth()
    client = FastAPITestClient(_make_sliding_app(auth), base_url="https://testserver")
    assert client.post("/login", params={"username": "oper1"}).status_code == 200

    r = None
    for _ in range(10):
        reloj.avanzar(3600)
        r = client.get("/ping")
        assert r.status_code == 200, r.text
    assert r.json()["user"] == "oper1"


def test_sesion_sin_uso_8h_mas_1s_se_rechaza(reloj):
    """(b) Sin pedidos de por medio, la ventana de inactividad corta justo
    despues de las 8 horas pedidas por el humano.

    🔴 El avance usa el LITERAL `8 * 3600 + 1`, no la constante
    `INACTIVIDAD_MAXIMA_SEGUNDOS` -- si usara la constante, este test seria
    tautologico: correria igual de "verde" con cualquier valor que alguien le
    ponga a la constante, porque el avance y el limite serian siempre el
    mismo numero. Con el literal, cambiar la constante (una regresion real)
    efectivamente pone esto en rojo -- verificado por mutacion. La constante
    se sigue comprobando aparte, en `test_constante_de_inactividad_es_8_horas`."""
    auth = _make_session_auth()
    client = FastAPITestClient(_make_sliding_app(auth), base_url="https://testserver")
    client.post("/login", params={"username": "oper1"})

    reloj.avanzar(8 * 3600 + 1)
    r = client.get("/ping", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/login"


def test_constante_de_inactividad_es_8_horas():
    """El valor concreto que decidio el humano (2026-09-13): 8 horas, ni una
    mas ni una menos -- lo que hace que el literal de arriba y la constante de
    produccion sean, hoy, el mismo numero."""
    assert INACTIVIDAD_MAXIMA_SEGUNDOS == 8 * 3600


def test_renovacion_reemite_cookie_con_los_mismos_atributos(reloj):
    """(c) La cookie renovada tiene que salir de `create_session_cookie`,
    literalmente -- por eso mismo trae httponly/secure/samesite/nombre
    identicos a la de un login nuevo."""
    auth = _make_session_auth()
    client = FastAPITestClient(_make_sliding_app(auth), base_url="https://testserver")
    client.post("/login", params={"username": "oper1"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS + 1)
    r = client.get("/ping")
    assert r.status_code == 200
    set_cookie = r.headers["set-cookie"]
    minuscula = set_cookie.lower()
    assert "httponly" in minuscula
    assert "secure" in minuscula
    assert "samesite=lax" in minuscula
    assert set_cookie.split("=", 1)[0] == auth.cookie_name
    # Y la sesion renovada sigue identificando al mismo usuario.
    assert _cookie_valor(set_cookie, auth.cookie_name) != ""


def test_no_renueva_antes_de_n_minutos(reloj):
    """(d) Por debajo del piso de renovacion, la respuesta no trae ninguna
    cookie nueva -- ni CPU de mas ni un Set-Cookie en cada pedido."""
    auth = _make_session_auth()
    client = FastAPITestClient(_make_sliding_app(auth), base_url="https://testserver")
    client.post("/login", params={"username": "oper1"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS - 1)
    r = client.get("/ping")
    assert r.status_code == 200
    assert "set-cookie" not in r.headers


def test_logout_no_resucita_la_cookie_borrada(reloj):
    """(e) Aunque hayan pasado mas de `RENOVACION_MINIMA_SEGUNDOS` desde el
    login -- la ventana en la que CUALQUIER otro pedido renovaria-- logout
    tiene que borrar la cookie sin que nada la vuelva a firmar."""
    auth = _make_session_auth()
    client = FastAPITestClient(_make_sliding_app(auth), base_url="https://testserver")
    client.post("/login", params={"username": "oper1"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS + 1)
    r = client.post("/logout")
    set_cookie = r.headers["set-cookie"]
    assert _cookie_valor(set_cookie, auth.cookie_name) == ""

    r2 = client.get("/ping", follow_redirects=False)
    assert r2.status_code == 307


def test_cookie_firmada_hace_9h_se_rechaza_aunque_falten_dias_para_los_7(reloj):
    """(g) Antes de esta version, `max_age` eran 7 dias ABSOLUTOS: una firma
    de 9 horas todavia hubiera sido valida. Con la ventana de inactividad
    tiene que rechazarse igual, aunque falten dias para los 7."""
    auth = _make_session_auth()
    client = FastAPITestClient(_make_sliding_app(auth), base_url="https://testserver")
    client.post("/login", params={"username": "oper1"})

    reloj.avanzar(9 * 3600)
    r = client.get("/ping", follow_redirects=False)
    assert r.status_code == 307


def test_json_api_logout_no_renueva_la_cookie(reloj):
    """(e), version JSON API: mismo chequeo contra el router real
    (`build_json_api_auth_router`), no contra la app de juguete de arriba."""
    app = _make_json_api_app()
    client = FastAPITestClient(app, base_url="https://testserver")
    client.post("/auth/login", json={"username": "admin", "password": "adminpw"})

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS + 1)
    r = client.post("/auth/logout")
    set_cookie = r.headers["set-cookie"]
    assert _cookie_valor(set_cookie, "test_json_session") == ""
    assert client.get("/auth/me").status_code == 401


def test_no_renueva_si_la_respuesta_ya_trae_set_cookie_para_el_mismo_nombre(reloj):
    """Segunda linea de defensa (`_ya_tiene_set_cookie`): si algo ya emitio un
    Set-Cookie con este nombre en la MISMA respuesta, `get_current_user` no
    lo pisa con una renovacion. No hay ruta real de la libreria que llegue a
    este caso hoy -- login/demo no le pasan `response` a `get_current_user`,
    y por eso no interactuan-- pero es la garantia de que agregar una manana
    no puede convertirse en un bug de resurreccion de cookie."""
    auth = _make_session_auth()
    r = Response()
    auth.create_session_cookie(r, "oper1")
    valor_original = _cookie_valor(r.headers["set-cookie"], auth.cookie_name)

    reloj.avanzar(RENOVACION_MINIMA_SEGUNDOS + 1)
    request = Request({
        "type": "http", "method": "GET", "path": "/",
        "headers": [(b"cookie", f"{auth.cookie_name}={valor_original}".encode())],
    })
    # `r` YA trae un Set-Cookie de este nombre (el del login de arriba) antes
    # de pasar por get_current_user.
    username = auth.get_current_user(request, r)
    assert username == "oper1"
    # Sigue habiendo un solo Set-Cookie para este nombre, con el valor
    # original -- no se agrego ni se piso con uno renovado.
    set_cookies = [v for k, v in r.raw_headers if k == b"set-cookie"]
    assert len(set_cookies) == 1
    assert _cookie_valor(set_cookies[0].decode("latin-1"), auth.cookie_name) == valor_original
