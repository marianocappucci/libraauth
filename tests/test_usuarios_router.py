"""Tests de `build_users_router()` (ver `libraauth.usuarios`): el router de
usuarios único que reemplaza las ocho copias de la familia.

Estructura: una app de FastAPI de prueba, con un `admin_guard` de juguete que
lee el "actor" actual de `app.state.actor` -- lo que permite simular, sin
tocar cookies ni tokens, tanto un admin editándose a sí mismo como una
identidad de token (`id=None`, como `SERVICE_USER`/`PANEL_USER` de
`session_auth`) editando a otro."""
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import ForeignKey, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from libraauth.models import Base, Usuario
from libraauth.repository import UserRepository
from libraauth.testing import verificar_contrato_de_usuarios
from libraauth.usuarios import (
    MIN_PASSWORD_LENGTH,
    UsuarioAlta,
    UsuarioClaveNueva,
    UsuarioEdicion,
    UsuarioSalida,
    build_users_router,
)

ROLES = ("admin", "staff")


def _admin_guard(request: Request) -> dict:
    """Guard de juguete: exige rol admin, salvo que el actor sea una
    identidad de token (`id=None`, como `SERVICE_USER`/`PANEL_USER` de
    `session_auth`), que siempre pasa. El actor lo pone cada test antes de
    llamar -- así se simula "quién está haciendo el pedido" sin cookies."""
    actor = getattr(request.app.state, "actor", None)
    if not actor:
        raise HTTPException(403, "forbidden")
    if actor.get("id") is None:
        return actor
    if actor.get("role") != "admin":
        raise HTTPException(403, "forbidden")
    return actor


def _actor_sin_admin(request: Request) -> dict:
    """Guard que deja pasar a cualquiera con sesión, admin o no -- usado
    sólo en el test de mutación, para probar que el guard real (arriba) hace
    falta."""
    return getattr(request.app.state, "actor", {"id": None, "role": "staff", "active": True})


def _app(*, guard=_admin_guard, roles: tuple[str, ...] = ROLES, prefix: str = "/usuarios"):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    repo = UserRepository(session_factory, roles=roles)

    app = FastAPI()
    app.state.users = repo
    app.state.actor = {"id": None, "username": "@servicio", "role": "admin", "active": True}
    app.include_router(build_users_router(prefix=prefix, roles=roles, admin_guard=guard))
    return app, repo


def _set_actor(app: FastAPI, actor: dict) -> None:
    app.state.actor = actor


@pytest.fixture
def app_y_repo():
    return _app()


@pytest.fixture
def client(app_y_repo):
    app, _ = app_y_repo
    return TestClient(app)


@pytest.fixture
def repo(app_y_repo):
    return app_y_repo[1]


# ── Contrato básico (listar/alta/edición/obtener/password/borrado) ─────────


def test_listar_vacio_devuelve_lista_vacia(client):
    r = client.get("/usuarios")
    assert r.status_code == 200
    assert r.json() == []


def test_crear_devuelve_201_y_el_contrato_publico(client):
    r = client.post("/usuarios", json={
        "username": "empleada", "name": "Empleada", "password": "s3cret1", "role": "staff",
    })
    assert r.status_code == 201, r.json()
    body = r.json()
    assert set(body) == set(UsuarioSalida.model_fields)
    assert body["username"] == "empleada" and body["role"] == "staff" and body["active"] is True


def test_crear_username_duplicado_409(client):
    payload = {"username": "dup", "name": "A", "password": "s3cret1", "role": "staff"}
    assert client.post("/usuarios", json=payload).status_code == 201
    r = client.post("/usuarios", json={**payload, "name": "B"})
    assert r.status_code == 409


def test_crear_password_corta_422(client):
    r = client.post("/usuarios", json={
        "username": "x", "name": "X", "password": "abc", "role": "staff",
    })
    assert r.status_code == 422
    assert "6" in r.json()["detail"]


def test_crear_password_justo_en_el_minimo_pasa(client):
    r = client.post("/usuarios", json={
        "username": "x", "name": "X", "password": "a" * MIN_PASSWORD_LENGTH, "role": "staff",
    })
    assert r.status_code == 201


def test_crear_rol_invalido_422(client):
    r = client.post("/usuarios", json={
        "username": "x", "name": "X", "password": "s3cret1", "role": "dueño",
    })
    assert r.status_code == 422
    assert "dueño" in r.json()["detail"]


def test_obtener_por_id_ok_y_404(client):
    creado = client.post("/usuarios", json={
        "username": "u1", "name": "U1", "password": "s3cret1", "role": "staff",
    }).json()
    assert client.get(f"/usuarios/{creado['id']}").status_code == 200
    assert client.get("/usuarios/999999").status_code == 404


def test_editar_persiste_cambios_releidos_por_get(client):
    creado = client.post("/usuarios", json={
        "username": "u2", "name": "Antes", "password": "s3cret1", "role": "staff",
    }).json()
    r = client.put(f"/usuarios/{creado['id']}", json={
        "name": "Despues", "role": "staff", "active": True,
    })
    assert r.status_code == 200
    assert client.get(f"/usuarios/{creado['id']}").json()["name"] == "Despues"


def test_editar_usuario_inexistente_404(client):
    r = client.put("/usuarios/999999", json={"name": "X", "role": "staff", "active": True})
    assert r.status_code == 404


def test_editar_rol_invalido_422_no_500(client):
    """Regresión del bug de Contalibra: su PUT dejaba escapar el `ValueError`
    de rol inválido como 500. Acá tiene que ser 422, igual que en el alta."""
    creado = client.post("/usuarios", json={
        "username": "u3", "name": "U3", "password": "s3cret1", "role": "staff",
    }).json()
    r = client.put(f"/usuarios/{creado['id']}", json={
        "name": "U3", "role": "dueño", "active": True,
    })
    assert r.status_code == 422
    assert r.status_code != 500


def test_password_reset_corta_422(client):
    creado = client.post("/usuarios", json={
        "username": "u4", "name": "U4", "password": "s3cret1", "role": "staff",
    }).json()
    r = client.put(f"/usuarios/{creado['id']}/password", json={"password": "ab"})
    assert r.status_code == 422


def test_password_reset_ok_204(client, repo):
    creado = client.post("/usuarios", json={
        "username": "u5", "name": "U5", "password": "s3cret1", "role": "staff",
    }).json()
    r = client.put(f"/usuarios/{creado['id']}/password", json={"password": "nueva11"})
    assert r.status_code == 204
    assert repo.check_credentials("u5", "nueva11") is not None


def test_password_reset_usuario_inexistente_404(client):
    r = client.put("/usuarios/999999/password", json={"password": "nueva11"})
    assert r.status_code == 404


def test_borrado_ok_204_y_desaparece(client):
    creado = client.post("/usuarios", json={
        "username": "u6", "name": "U6", "password": "s3cret1", "role": "staff",
    }).json()
    assert client.delete(f"/usuarios/{creado['id']}").status_code == 204
    assert client.get(f"/usuarios/{creado['id']}").status_code == 404


def test_borrado_usuario_inexistente_404(client):
    assert client.delete("/usuarios/999999").status_code == 404


# ── Borrar un usuario con historial (FK desde otra tabla) da 409 ───────────


class _HistorialBase(DeclarativeBase):
    pass


class TurnoCaja(_HistorialBase):
    """Tabla de prueba que imita `turnos_caja.usuario_id REFERENCES
    usuarios(id)` -- el caso real de libracore/ventas/movimientos de caja
    que motiva `UsuarioConHistorial` (ver `repository.py`).

    `ForeignKey(Usuario.id)` y no la forma en string ("usuarios.id"): la
    tabla vive en una `DeclarativeBase` propia, sin la `MetaData` de
    `libraauth.models.Base` -- pasar la `Column` directamente resuelve la FK
    sin necesitar que las dos tablas compartan `MetaData`."""

    __tablename__ = "turnos_caja"

    id: Mapped[int] = mapped_column(primary_key=True)
    usuario_id: Mapped[int] = mapped_column(ForeignKey(Usuario.id), nullable=False)


def _app_con_historial():
    """Igual que `_app()`, pero con `turnos_caja` creada en el mismo engine y
    `PRAGMA foreign_keys=ON` -- SQLite no lo prende solo, y sin esto el
    `INSERT` con FK a un usuario borrado no fallaría nunca."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_con, _con_record):
        dbapi_con.cursor().execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    _HistorialBase.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    repo = UserRepository(session_factory, roles=ROLES)

    app = FastAPI()
    app.state.users = repo
    app.state.actor = {"id": None, "username": "@servicio", "role": "admin", "active": True}
    app.include_router(build_users_router(prefix="/usuarios", roles=ROLES, admin_guard=_admin_guard))
    return app, repo, session_factory


def test_borrar_usuario_con_historial_da_409_con_el_mensaje():
    app, repo, session_factory = _app_con_historial()
    usuario = repo.create(username="cajera", name="Cajera", password="s3cret1", role="staff")
    with session_factory() as s:
        s.add(TurnoCaja(usuario_id=int(usuario["id"])))
        s.commit()
    client = TestClient(app)

    r = client.delete(f"/usuarios/{usuario['id']}")

    assert r.status_code == 409
    assert "historial" in r.json()["detail"]
    assert "desactiv" in r.json()["detail"]


def test_borrar_usuario_con_historial_no_lo_borra():
    app, repo, session_factory = _app_con_historial()
    usuario = repo.create(username="cajera2", name="Cajera Dos", password="s3cret1", role="staff")
    with session_factory() as s:
        s.add(TurnoCaja(usuario_id=int(usuario["id"])))
        s.commit()
    client = TestClient(app)

    client.delete(f"/usuarios/{usuario['id']}")

    assert client.get(f"/usuarios/{usuario['id']}").status_code == 200


def test_borrar_usuario_con_historial_no_deja_la_sesion_inservible():
    """Sin el `rollback()` de `UserRepository.delete()`, un pedido siguiente
    sobre la misma app puede salir mal -- en PostgreSQL, directamente con
    "current transaction is aborted". Este test corre sobre la MISMA app
    (mismo `session_factory`) que el borrado fallido, para probar que un
    pedido posterior funciona."""
    app, repo, session_factory = _app_con_historial()
    usuario = repo.create(username="cajera3", name="Cajera Tres", password="s3cret1", role="staff")
    with session_factory() as s:
        s.add(TurnoCaja(usuario_id=int(usuario["id"])))
        s.commit()
    client = TestClient(app)

    assert client.delete(f"/usuarios/{usuario['id']}").status_code == 409

    r = client.get("/usuarios")
    assert r.status_code == 200
    assert any(u["id"] == usuario["id"] for u in r.json())


# ── Protecciones: no te podés desactivar/degradar/borrar a vos mismo ───────


def test_no_te_podes_desactivar_a_vos_mismo(app_y_repo):
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="Admin Uno", password="s3cret1", role="admin")
    _set_actor(app, {"id": admin["id"], "username": "admin1", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{admin['id']}", json={
        "name": "Admin Uno", "role": "admin", "active": False,
    })
    assert r.status_code == 409
    assert "desactivar" in r.json()["detail"]


def test_no_te_podes_sacar_el_rol_de_admin_a_vos_mismo(app_y_repo):
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="Admin Uno", password="s3cret1", role="admin")
    _set_actor(app, {"id": admin["id"], "username": "admin1", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{admin['id']}", json={
        "name": "Admin Uno", "role": "staff", "active": True,
    })
    assert r.status_code == 409
    assert "admin" in r.json()["detail"]


def test_autoproteccion_es_incondicional_aunque_haya_otro_admin_activo(app_y_repo):
    """A diferencia de la protección del único admin (abajo), ésta corre
    SIEMPRE, exista o no otro admin activo -- mismo criterio que
    LibraCargo/LibraClub."""
    app, repo = app_y_repo
    admin1 = repo.create(username="admin1", name="A1", password="s3cret1", role="admin")
    repo.create(username="admin2", name="A2", password="s3cret1", role="admin")
    _set_actor(app, {"id": admin1["id"], "username": "admin1", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{admin1['id']}", json={
        "name": "A1", "role": "staff", "active": True,
    })
    assert r.status_code == 409


def test_editar_nombre_propio_sin_tocar_rol_ni_activo_esta_permitido(app_y_repo):
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="Antes", password="s3cret1", role="admin")
    _set_actor(app, {"id": admin["id"], "username": "admin1", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{admin['id']}", json={
        "name": "Despues", "role": "admin", "active": True,
    })
    assert r.status_code == 200
    assert r.json()["name"] == "Despues"


def test_no_te_podes_borrar_a_vos_mismo(app_y_repo):
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="A1", password="s3cret1", role="admin")
    _set_actor(app, {"id": admin["id"], "username": "admin1", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.delete(f"/usuarios/{admin['id']}")
    assert r.status_code == 409
    assert "borrar" in r.json()["detail"]


def test_una_identidad_de_token_no_dispara_la_autoproteccion(app_y_repo):
    """`id=None` (SERVICE_USER/PANEL_USER de session_auth) no es "uno mismo"
    de nadie: el backoffice tiene que poder editar/borrar cualquier fila,
    incluida una que -si el guard devolviera un id real- matchearía."""
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="A1", password="s3cret1", role="admin")
    repo.create(username="admin2", name="A2", password="s3cret1", role="admin")
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{admin['id']}", json={
        "name": "A1", "role": "staff", "active": True,
    })
    assert r.status_code == 200


# ── Protección del único admin ACTIVO (edición) y del único admin (borrado) ─


def test_no_se_puede_degradar_al_unico_admin_activo(app_y_repo):
    """Dos admins, uno de ellos ya inactivo: degradar al que queda activo
    tiene que fallar aunque quien pide sea una identidad de token (no "uno
    mismo") -- es la protección de Contalibra/Restolibra, no la de arriba."""
    app, repo = app_y_repo
    activo = repo.create(username="admin-activo", name="Activo", password="s3cret1", role="admin")
    inactivo = repo.create(username="admin-inactivo", name="Inactivo", password="s3cret1", role="admin")
    repo.update(inactivo["id"], name="Inactivo", role="admin", active=False)
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{activo['id']}", json={
        "name": "Activo", "role": "staff", "active": True,
    })
    assert r.status_code == 422
    assert "único" in r.json()["detail"]


def test_no_se_puede_desactivar_al_unico_admin_activo(app_y_repo):
    """El caso que NINGUNO de los ocho routers de referencia cubría: sólo
    guardaban la degradación de rol, no la desactivación."""
    app, repo = app_y_repo
    activo = repo.create(username="admin-activo", name="Activo", password="s3cret1", role="admin")
    inactivo = repo.create(username="admin-inactivo", name="Inactivo", password="s3cret1", role="admin")
    repo.update(inactivo["id"], name="Inactivo", role="admin", active=False)
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{activo['id']}", json={
        "name": "Activo", "role": "admin", "active": False,
    })
    assert r.status_code == 422
    assert "único" in r.json()["detail"]


def test_degradar_un_admin_esta_permitido_si_queda_otro_activo(app_y_repo):
    app, repo = app_y_repo
    uno = repo.create(username="admin1", name="Uno", password="s3cret1", role="admin")
    repo.create(username="admin2", name="Dos", password="s3cret1", role="admin")
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.put(f"/usuarios/{uno['id']}", json={
        "name": "Uno", "role": "staff", "active": True,
    })
    assert r.status_code == 200


def test_no_se_puede_eliminar_al_unico_admin(app_y_repo):
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="A1", password="s3cret1", role="admin")
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.delete(f"/usuarios/{admin['id']}")
    assert r.status_code == 422
    assert "único" in r.json()["detail"]


def test_eliminar_admin_inactivo_cuenta_para_el_unico_admin(app_y_repo):
    """La protección de borrado NO filtra por activo -- borrar la última
    fila admin (aunque esté inactiva) es peor que dejarla desactivada, mismo
    criterio que ya tenían Contalibra/Restolibra."""
    app, repo = app_y_repo
    admin = repo.create(username="admin1", name="A1", password="s3cret1", role="admin")
    repo.update(admin["id"], name="A1", role="admin", active=False)
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.delete(f"/usuarios/{admin['id']}")
    assert r.status_code == 422


def test_eliminar_un_admin_esta_permitido_si_queda_otro(app_y_repo):
    app, repo = app_y_repo
    uno = repo.create(username="admin1", name="Uno", password="s3cret1", role="admin")
    repo.create(username="admin2", name="Dos", password="s3cret1", role="admin")
    _set_actor(app, {"id": None, "username": "@servicio", "role": "admin", "active": True})
    client = TestClient(app)
    r = client.delete(f"/usuarios/{uno['id']}")
    assert r.status_code == 204


# ── El guard se aplica de verdad (mutación: sacarlo y ver que cambia) ──────


def test_el_guard_real_rechaza_a_un_actor_no_admin():
    app, repo = _app()
    staff = repo.create(username="staff1", name="Staff", password="s3cret1", role="staff")
    # `id` real (no `None`): una sesión de usuario de verdad, no una
    # identidad de token -- ésas siempre pasan, ver `_admin_guard`.
    _set_actor(app, {"id": staff["id"], "username": "staff1", "role": "staff", "active": True})
    client = TestClient(app)
    assert client.get("/usuarios").status_code == 403


def test_mutacion_sin_admin_guard_la_misma_request_pasa():
    """La prueba de que el test de arriba prueba algo: con un guard que NO
    exige admin (`_actor_sin_admin`), la MISMA request de un actor `staff`
    deja de dar 403. Si este test también diera 403, `_admin_guard` no
    estaría haciendo ninguna diferencia y el test de arriba sería un verde
    que no prueba nada (ver `leccion-verificacion-el-verde-que-no-prueba`)."""
    app, repo = _app(guard=_actor_sin_admin)
    staff = repo.create(username="staff1", name="Staff", password="s3cret1", role="staff")
    _set_actor(app, {"id": staff["id"], "username": "staff1", "role": "staff", "active": True})
    client = TestClient(app)
    assert client.get("/usuarios").status_code == 200


# ── El helper de contrato (libraauth.testing) contra esta misma factory ───


def test_verificar_contrato_de_usuarios_pasa_contra_la_factory(client, repo):
    # Un usuario ya cargado antes de correr el helper: el listado inicial
    # que arma no queda vacío, y el helper de verdad recorre `{name, active,
    # role}` de una fila real (y no de una lista vacía que pasaría igual).
    repo.create(username="previa", name="Previa", password="s3cret1", role="staff")
    verificar_contrato_de_usuarios(client, "/usuarios", role="staff")


def test_testing_importa_los_mismos_modelos_publicos_que_usuarios():
    """Garantiza que `libraauth.testing` no pueda divergir de
    `libraauth.usuarios`: son el MISMO objeto de clase, no una redefinición
    con la misma forma."""
    import libraauth.testing as t
    import libraauth.usuarios as u

    assert t.UsuarioAlta is u.UsuarioAlta
    assert t.UsuarioEdicion is u.UsuarioEdicion
    assert t.UsuarioClaveNueva is u.UsuarioClaveNueva
    assert t.MIN_PASSWORD_LENGTH == u.MIN_PASSWORD_LENGTH


# ── Configuración: prefijo y roles son del producto, no de la factory ─────


def test_prefijo_configurable():
    app, repo = _app(prefix="/api/usuarios")
    repo.create(username="a", name="A", password="s3cret1", role="staff")
    client = TestClient(app)
    assert client.get("/api/usuarios").status_code == 200
    assert client.get("/usuarios").status_code == 404


def test_get_repository_personalizado_se_usa_en_vez_de_app_state():
    """La mayoría de los productos guarda el repositorio en
    `request.app.state.users` (default), pero la factory acepta otro lugar
    -- se prueba con un repo que NO está en `app.state` en absoluto."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    repo_alterno = UserRepository(sessionmaker(bind=engine), roles=ROLES)

    app = FastAPI()
    app.state.actor = {"id": None, "username": "@servicio", "role": "admin", "active": True}
    app.include_router(build_users_router(
        prefix="/usuarios", roles=ROLES, admin_guard=_admin_guard,
        get_repository=lambda request: repo_alterno,
    ))
    client = TestClient(app)

    r = client.post("/usuarios", json={
        "username": "alterno", "name": "Alterno", "password": "s3cret1", "role": "staff",
    })
    assert r.status_code == 201
    assert repo_alterno.get_by_username("alterno") is not None
    # Y NO llegó a `app.state.users`, que ni siquiera existe en esta app.
    assert not hasattr(app.state, "users")


class _RepoQueMiente(UserRepository):
    """Redes de seguridad de la factory: un repositorio cuyo `roles=` quedó
    DESALINEADO con el que se le pasó a `build_users_router`, y uno cuyo
    `update`/`delete` avisan `KeyError` aunque `get_by_id` diga que el
    usuario existe (condición de carrera: alguien más lo borró entre el
    chequeo y la escritura). Ninguno de los dos es el caso normal -- son las
    dos ramas defensivas que estos tests cubren a propósito."""

    def __init__(self, session_factory, *, mentir_en=()):
        super().__init__(session_factory, roles=("admin",))  # más angosto que el de la factory
        self._mentir_en = mentir_en

    def update(self, *a, **kw):
        if "update" in self._mentir_en:
            raise KeyError("borrado justo antes")
        return super().update(*a, **kw)

    def delete(self, *a, **kw):
        if "delete" in self._mentir_en:
            raise KeyError("borrado justo antes")
        return super().delete(*a, **kw)


def _app_con_repo_mentiroso(*, mentir_en=()):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    repo = _RepoQueMiente(sessionmaker(bind=engine), mentir_en=mentir_en)
    app = FastAPI()
    app.state.users = repo
    app.state.actor = {"id": None, "username": "@servicio", "role": "admin", "active": True}
    app.include_router(build_users_router(prefix="/usuarios", roles=ROLES, admin_guard=_admin_guard))
    return app, repo


def test_crear_con_repo_desalineado_da_422_y_no_500():
    """El rol pasa la validación de la factory (`roles=ROLES`, "staff" es
    válido) pero el repositorio de esta app sólo acepta `("admin",)`: el
    `ValueError` que tira `UserRepository.create` tiene que llegar como 422,
    no como 500."""
    app, _ = _app_con_repo_mentiroso()
    client = TestClient(app)
    r = client.post("/usuarios", json={
        "username": "x", "name": "X", "password": "s3cret1", "role": "staff",
    })
    assert r.status_code == 422
    assert r.status_code != 500


def test_editar_con_repo_desalineado_da_422_y_no_500():
    """Misma red de seguridad que en `crear`, ahora en `editar`: el rol pasa
    la validación de la factory pero `UserRepository.update` lo rechaza
    porque el repo de esta app quedó configurado más angosto."""
    app, repo = _app_con_repo_mentiroso()
    creado = repo.create(username="u", name="U", password="s3cret1", role="admin")
    # Un segundo admin activo, para no chocar antes con el 422 del único
    # administrador activo -- lo que este test quiere ejercer es el OTRO
    # 422, el de la red de seguridad del `ValueError`.
    repo.create(username="u2", name="U2", password="s3cret1", role="admin")
    client = TestClient(app)
    r = client.put(f"/usuarios/{creado['id']}", json={
        "name": "U", "role": "staff", "active": True,
    })
    assert r.status_code == 422
    assert r.status_code != 500


def test_editar_con_update_que_lanza_keyerror_da_404():
    """`objetivo = usuarios.get_by_id(...)` dijo que existía, pero
    `usuarios.update(...)` avisa `KeyError` -- el `except KeyError` de
    `editar` es la red de seguridad para esa carrera, y tiene que dar 404 y
    no un 500."""
    app, repo = _app_con_repo_mentiroso(mentir_en=("update",))
    creado = repo.create(username="u", name="U", password="s3cret1", role="admin")
    client = TestClient(app)
    r = client.put(f"/usuarios/{creado['id']}", json={
        "name": "U", "role": "admin", "active": True,
    })
    assert r.status_code == 404


def test_eliminar_con_delete_que_lanza_keyerror_da_404():
    app, repo = _app_con_repo_mentiroso(mentir_en=("delete",))
    creado = repo.create(username="u", name="U", password="s3cret1", role="admin")
    repo.create(username="u2", name="U2", password="s3cret1", role="admin")  # evita el 422 de único admin
    client = TestClient(app)
    r = client.delete(f"/usuarios/{creado['id']}")
    assert r.status_code == 404


def test_roles_configurables_como_contalibra():
    roles = ("admin", "operador", "cajero")
    app, _ = _app(roles=roles)
    client = TestClient(app)
    r = client.post("/usuarios", json={
        "username": "op1", "name": "Op", "password": "s3cret1", "role": "operador",
    })
    assert r.status_code == 201
    r_malo = client.post("/usuarios", json={
        "username": "st1", "name": "St", "password": "s3cret1", "role": "staff",
    })
    assert r_malo.status_code == 422
