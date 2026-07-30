"""Tests de UserRepository/ensure_default_admin sobre SQLAlchemy — misma
cobertura que tests/db/test_usuarios.py de libracore, adaptada al backend
nuevo."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from libraauth.bootstrap import ensure_default_admin
from libraauth.models import Base
from libraauth.repository import UserRepository, UsernameTaken


@pytest.fixture
def repo(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/usuarios_test.db")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    return UserRepository(session_factory)


def test_create_returns_json_contract(repo):
    user = repo.create(username="staff-1", name="Empleada", password="s3cret", role="staff")
    assert user == {
        "id": user["id"], "username": "staff-1", "name": "Empleada",
        "role": "staff", "active": True,
    }
    assert "password" not in user and "password_hash" not in user


def test_create_rejects_invalid_role(repo):
    with pytest.raises(ValueError):
        repo.create(username="x", name="X", password="pw", role="owner")


def test_create_respects_custom_roles_tuple(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/custom_roles.db")
    Base.metadata.create_all(engine)
    custom_repo = UserRepository(sessionmaker(bind=engine), roles=("admin", "vendedor"))
    assert custom_repo.create(username="v1", name="V", password="pw", role="vendedor")["role"] == "vendedor"
    with pytest.raises(ValueError):
        custom_repo.create(username="v2", name="V2", password="pw", role="staff")


def test_get_by_id_and_get_by_username(repo):
    created = repo.create(username="staff-1", name="Empleada", password="pw", role="staff")
    assert repo.get_by_id(created["id"])["username"] == "staff-1"
    assert repo.get_by_username("staff-1")["id"] == created["id"]
    assert repo.get_by_username("missing") is None
    assert repo.get_by_id("not-a-number") is None


def test_list_returns_all_users(repo):
    repo.create(username="a", name="A", password="pw", role="staff")
    repo.create(username="b", name="B", password="pw", role="admin")
    assert {u["username"] for u in repo.list()} == {"a", "b"}


def test_update_changes_name_role_and_active(repo):
    created = repo.create(username="staff-1", name="Empleada", password="pw", role="staff")
    updated = repo.update(created["id"], name="Empleada Senior", role="admin", active=False)
    assert updated["name"] == "Empleada Senior"
    assert updated["role"] == "admin"
    assert updated["active"] is False


def test_update_rejects_invalid_role(repo):
    created = repo.create(username="staff-1", name="Empleada", password="pw", role="staff")
    with pytest.raises(ValueError):
        repo.update(created["id"], name="X", role="owner", active=True)


def test_update_unknown_id_raises_keyerror(repo):
    with pytest.raises(KeyError):
        repo.update("999999", name="X", role="staff", active=True)


def test_update_password_then_check_credentials(repo):
    created = repo.create(username="staff-1", name="Empleada", password="old-pass", role="staff")
    repo.update_password(created["id"], "new-pass")
    assert repo.check_credentials("staff-1", "old-pass") is None
    assert repo.check_credentials("staff-1", "new-pass")["username"] == "staff-1"


def test_delete_removes_user(repo):
    created = repo.create(username="staff-1", name="Empleada", password="pw", role="staff")
    repo.delete(created["id"])
    assert repo.get_by_id(created["id"]) is None


def test_delete_unknown_id_raises_keyerror(repo):
    with pytest.raises(KeyError):
        repo.delete("999999")


def test_check_credentials_rejects_deactivated_user(repo):
    created = repo.create(username="staff-1", name="Empleada", password="pw", role="staff")
    repo.update(created["id"], name="Empleada", role="staff", active=False)
    assert repo.check_credentials("staff-1", "pw") is None


def test_check_credentials_rejects_unknown_username(repo):
    assert repo.check_credentials("ghost", "whatever") is None


# ── ensure_default_admin ────────────────────────────────────────────────

def test_ensure_default_admin_creates_admin_from_env(repo, monkeypatch):
    monkeypatch.setenv("ACME_ADMIN_USERNAME", "root")
    monkeypatch.setenv("ACME_ADMIN_PASSWORD", "s3cret-pw")
    ensure_default_admin(repo, env_prefix="ACME")
    users = repo.list()
    assert len(users) == 1
    assert users[0]["username"] == "root"
    assert users[0]["role"] == "admin"


def test_ensure_default_admin_noop_if_users_exist(repo, monkeypatch):
    monkeypatch.setenv("ACME_ADMIN_PASSWORD", "s3cret-pw")
    repo.create(username="existing", name="X", password="pw", role="staff")
    ensure_default_admin(repo, env_prefix="ACME")
    assert len(repo.list()) == 1


def test_ensure_default_admin_fails_closed_in_production_without_password(repo, monkeypatch):
    monkeypatch.delenv("ACME_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ENV", "production")
    with pytest.raises(RuntimeError):
        ensure_default_admin(repo, env_prefix="ACME")


def test_ensure_default_admin_allows_fallback_password_in_development(repo, monkeypatch):
    monkeypatch.delenv("ACME_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ENV", "development")
    ensure_default_admin(repo, env_prefix="ACME")
    assert repo.check_credentials("admin", "admin") is not None


def test_create_con_username_duplicado_levanta_UsernameTaken(repo):
    """Antes de v0.1.1 esto propagaba sqlalchemy.exc.IntegrityError, y los
    routers de la familia —que venian de libracore y capturaban
    sqlite3.IntegrityError— devolvian 500 en vez de 409. El motor ahora expone
    una excepcion de dominio para que el consumidor no conozca el storage."""
    repo.create(username="repetido", name="Primero", password="x", role="admin")

    with pytest.raises(UsernameTaken) as exc:
        repo.create(username="repetido", name="Segundo", password="y", role="admin")
    assert "repetido" in str(exc.value)

    # La sesion quedo usable despues del rollback: el repo sigue funcionando.
    assert len(repo.list()) == 1
    assert repo.check_credentials("repetido", "x")


def test_username_duplicado_se_detecta_con_espacios(repo):
    """`create` hace strip del username, asi que " repetido " choca igual."""
    repo.create(username="conespacios", name="Primero", password="x", role="admin")
    with pytest.raises(UsernameTaken):
        repo.create(username="  conespacios  ", name="Segundo", password="y", role="admin")
