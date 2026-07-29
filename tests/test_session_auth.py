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

from fastapi import Depends, FastAPI
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

    def check_credentials(self, username, password):
        u = self._users.get(username)
        if u and u["_password"] == password:
            return self._public(u)
        return None

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
