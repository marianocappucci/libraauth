"""Tests del log de actividad (v0.9.0).

Lo que fijan, en orden de lo que se rompe sin que se note:

1. Que la escritura quede registrada **sin que el repositorio haga nada** — es
   toda la premisa: el registro cuelga del flush.
2. Que la lista blanca sea blanca de verdad: un modelo que no esta declarado
   **no** entra al log.
3. Que el diff no copie una columna secreta.
4. Que la tabla pueda vivir en una base **distinta** de la de `usuarios`, que es
   el caso de tres de los cuatro consumidores.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import DateTime, ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from libraauth.auditoria import (
    BORRAR,
    CREAR,
    EDITAR,
    SISTEMA,
    ActividadLog,
    AuditoriaBase,
    AuditoriaRepository,
    configurar_auditoria,
    usuario_actual,
)


# ── Un dominio de juguete, que hace las veces del producto consumidor ──────

class DominioBase(DeclarativeBase):
    pass


class Cliente(DominioBase):
    __tablename__ = "clientes_demo"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    nombre: Mapped[str] = mapped_column(String(100))
    ciudad: Mapped[str | None] = mapped_column(String(100))
    api_key: Mapped[str | None] = mapped_column(String(100))


class Movimiento(DominioBase):
    """Hace de tabla-historial: existe para comprobar que NO se audita."""

    __tablename__ = "movimientos_demo"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cliente_id: Mapped[int] = mapped_column(ForeignKey("clientes_demo.id"))
    detalle: Mapped[str] = mapped_column(String(100))


class Turno(DominioBase):
    """Modelo con nombres en ingles, como los de LibraGenda/LibraCommerce."""

    __tablename__ = "turnos_demo"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(100))
    starts_at: Mapped[datetime | None] = mapped_column(DateTime)


AUDITABLES = {"Cliente": "cliente", "Turno": "turno"}


@pytest.fixture
def sessions(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/dominio.db")
    DominioBase.metadata.create_all(engine)
    AuditoriaBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    configurar_auditoria(factory, AUDITABLES)
    return factory


@pytest.fixture
def repo(sessions):
    return AuditoriaRepository(sessions)


@pytest.fixture(autouse=True)
def _usuario_limpio():
    token = usuario_actual.set(SISTEMA)
    yield
    usuario_actual.reset(token)


def _crear_cliente(sessions, nombre="Compulibra", **extra) -> int:
    with sessions() as s:
        c = Cliente(nombre=nombre, **extra)
        s.add(c)
        s.commit()
        return c.id


# ── El registro automatico ────────────────────────────────────────────────

def test_crear_deja_fila_sin_que_nadie_la_pida(sessions, repo):
    cid = _crear_cliente(sessions)
    fila = repo.listar()[0]
    assert (fila["accion"], fila["entidad"], fila["entidad_id"]) == (CREAR, "cliente", cid)
    assert fila["descripcion"] == "Cliente — Compulibra"


def test_el_id_de_una_creacion_no_queda_vacio(sessions, repo):
    """En `before_flush` el objeto nuevo todavia no tiene id: si la fila se
    escribiera ahi, el log no serviria para buscar nada."""
    cid = _crear_cliente(sessions)
    assert repo.listar()[0]["entidad_id"] == cid


def test_editar_guarda_antes_y_despues(sessions, repo):
    cid = _crear_cliente(sessions, ciudad="Suipacha")
    with sessions() as s:
        s.get(Cliente, cid).ciudad = "Mercedes"
        s.commit()
    edicion = [f for f in repo.listar() if f["accion"] == EDITAR][0]
    assert edicion["cambios"] == {"ciudad": ["Suipacha", "Mercedes"]}


def test_editar_sin_cambios_reales_no_deja_fila(sessions, repo):
    cid = _crear_cliente(sessions, ciudad="Suipacha")
    with sessions() as s:
        s.get(Cliente, cid).ciudad = "Suipacha"
        s.commit()
    assert [f for f in repo.listar() if f["accion"] == EDITAR] == []


def test_borrar_conserva_id_y_etiqueta(sessions, repo):
    """Es el caso que motiva la pantalla: despues del borrado la fila ya no
    esta, asi que si el log no guardo el id y el nombre no quedo nada."""
    cid = _crear_cliente(sessions, nombre="Cliente que se va")
    with sessions() as s:
        s.delete(s.get(Cliente, cid))
        s.commit()
    borrado = [f for f in repo.listar() if f["accion"] == BORRAR][0]
    assert borrado["entidad_id"] == cid
    assert "Cliente que se va" in borrado["descripcion"]


def test_la_lista_blanca_es_blanca(sessions, repo):
    """`Movimiento` no esta declarado: es una tabla-historial y su ficha ya la
    muestra. Auditarla pondria el mismo hecho dos veces en la pantalla."""
    cid = _crear_cliente(sessions)
    with sessions() as s:
        s.add(Movimiento(cliente_id=cid, detalle="salio a service"))
        s.commit()
    assert {f["entidad"] for f in repo.listar()} == {"cliente"}


def test_etiqueta_de_un_modelo_en_ingles(sessions, repo):
    """Los modelos de LibraGenda y LibraCommerce usan `title`/`name`, no
    `titulo`/`nombre`."""
    with sessions() as s:
        s.add(Turno(title="Consulta de control"))
        s.commit()
    assert repo.listar()[0]["descripcion"] == "Turno — Consulta de control"


# ── Seguridad y ruido ─────────────────────────────────────────────────────

def test_una_columna_secreta_no_entra_al_diff(sessions, repo):
    cid = _crear_cliente(sessions, api_key="secreto-viejo")
    with sessions() as s:
        c = s.get(Cliente, cid)
        c.api_key = "secreto-nuevo"
        c.ciudad = "Lujan"
        s.commit()
    edicion = [f for f in repo.listar() if f["accion"] == EDITAR][0]
    # Igualdad exacta, no `not in`: fija que la columna secreta no esta **y**
    # que la que si cambio se registro. Un `not in` solo pasaria igual con el
    # diff vacio, que seria otro defecto.
    assert edicion["cambios"] == {"ciudad": [None, "Lujan"]}
    assert "secreto" not in str(edicion)


def test_el_producto_puede_ocultar_columnas_propias(tmp_path):
    """MedLibra lo usa para que el contenido clinico no se copie al log."""
    engine = create_engine(f"sqlite:///{tmp_path}/otro.db")
    DominioBase.metadata.create_all(engine)
    AuditoriaBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    configurar_auditoria(factory, AUDITABLES, columnas_ocultas={"ciudad"})

    with factory() as s:
        c = Cliente(nombre="X", ciudad="Suipacha")
        s.add(c)
        s.commit()
        cid = c.id
    with factory() as s:
        s.get(Cliente, cid).ciudad = "Mercedes"
        s.commit()

    repo = AuditoriaRepository(factory)
    assert [f for f in repo.listar() if f["accion"] == EDITAR] == []


def test_el_producto_puede_reemplazar_la_etiqueta(tmp_path):
    """No alcanza con `columnas_ocultas`: la etiqueta se arma leyendo
    atributos directamente, asi que ocultar una columna del diff no impide que
    su valor termine en la descripcion. MedLibra lo necesita para que el
    titulo de un documento clinico no quede escrito en el log."""
    engine = create_engine(f"sqlite:///{tmp_path}/etiqueta.db")
    DominioBase.metadata.create_all(engine)
    AuditoriaBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    configurar_auditoria(
        factory, {"Turno": "turno"},
        etiqueta=lambda obj: "" if type(obj).__name__ == "Turno" else "x",
    )

    with factory() as s:
        s.add(Turno(title="Interconsulta cardiologia"))
        s.commit()

    fila = AuditoriaRepository(factory).listar()[0]
    assert fila["descripcion"] == "Turno"
    assert "cardiologia" not in str(fila)


def test_se_puede_apagar_por_sesion(sessions, repo):
    """`session.info['auditoria'] = False` — para un seed o una migracion de
    datos, que no son actividad de nadie."""
    with sessions() as s:
        s.info["auditoria"] = False
        s.add(Cliente(nombre="Carga inicial"))
        s.commit()
    assert repo.listar() == []


# ── El usuario ────────────────────────────────────────────────────────────

def test_sin_request_la_fila_queda_a_nombre_del_sistema(sessions, repo):
    """Un seed o un script es actividad legitima y tiene que distinguirse de
    'no se supo quien fue'."""
    _crear_cliente(sessions)
    assert repo.listar()[0]["usuario"] == SISTEMA


def test_con_usuario_sellado_la_fila_lo_dice(sessions, repo):
    token = usuario_actual.set("tecnico1")
    try:
        _crear_cliente(sessions)
    finally:
        usuario_actual.reset(token)
    assert repo.listar()[0]["usuario"] == "tecnico1"


def test_el_middleware_sella_al_usuario_de_la_cookie(sessions, repo, monkeypatch):
    """La pieza de la que depende que la fila diga quien fue. Sin esto el log
    entero queda a nombre de `Sistema`, que es peor que no tenerlo: parece que
    funciona."""
    monkeypatch.setenv("SECRET_KEY", "test-secret-auditoria")
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from libraauth.auditoria import agregar_middleware_de_usuario
    from libraauth.session_auth import SessionAuth

    usuarios = {"ana": {"username": "ana", "role": "admin"}}
    app = FastAPI()
    app.state.session_auth = SessionAuth(
        dev_secret_fallback="dev",
        get_user_by_username=usuarios.get,
        check_credentials=lambda u, p: usuarios.get(u),
    )
    agregar_middleware_de_usuario(app)

    @app.post("/alta")
    def alta():
        with sessions() as s:
            s.add(Cliente(nombre="Alta con sesion"))
            s.commit()
        return {"ok": True}

    @app.get("/quien")
    def quien():
        return {"usuario": usuario_actual.get()}

    client = TestClient(app, base_url="https://testserver")
    from starlette.responses import JSONResponse
    resp = JSONResponse({})
    app.state.session_auth.create_session_cookie(resp, "ana")
    cookie = resp.headers["set-cookie"].split(";")[0].split("=", 1)
    client.cookies.set(cookie[0], cookie[1])

    assert client.post("/alta").status_code == 200
    assert repo.listar()[0]["usuario"] == "ana"

    # Y sin cookie vuelve al default: el token se resetea al terminar la
    # request, asi que el usuario de una no queda pegado para la siguiente.
    client.cookies.clear()
    assert client.get("/quien").json()["usuario"] == SISTEMA


def test_el_middleware_no_explota_sin_session_auth(sessions):
    """Un producto que agregue el middleware antes de setear `session_auth`
    —o un endpoint publico como el health— no puede romperse por esto."""
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from libraauth.auditoria import agregar_middleware_de_usuario

    app = FastAPI()
    agregar_middleware_de_usuario(app)

    @app.get("/health")
    def health():
        return {"usuario": usuario_actual.get()}

    assert TestClient(app).get("/health").json() == {"usuario": SISTEMA}


def test_un_valor_no_serializable_no_rompe_el_diff(sessions, repo):
    """El diff va a JSON: una fecha o un objeto raro tienen que salir como
    texto en vez de tumbar el flush que los produjo."""
    with sessions() as s:
        t = Turno(title="Con fecha")
        s.add(t)
        s.commit()
        tid = t.id
    with sessions() as s:
        s.get(Turno, tid).starts_at = datetime(2026, 8, 6, 9, 30)
        s.commit()

    edicion = [f for f in repo.listar() if f["accion"] == EDITAR][0]
    assert edicion["cambios"]["starts_at"] == [None, "2026-08-06 09:30:00"]


# ── Consultas ─────────────────────────────────────────────────────────────

def test_filtros_y_total(sessions, repo):
    _crear_cliente(sessions, nombre="Uno")
    _crear_cliente(sessions, nombre="Dos")
    with sessions() as s:
        s.add(Turno(title="Un turno"))
        s.commit()

    assert repo.contar() == 3
    assert repo.contar(entidad="cliente") == 2
    assert repo.contar(accion=EDITAR) == 0
    assert {f["entidad"] for f in repo.listar(entidad="turno")} == {"turno"}


def test_filtro_por_usuario(sessions, repo):
    token = usuario_actual.set("ana")
    try:
        _crear_cliente(sessions, nombre="De Ana")
    finally:
        usuario_actual.reset(token)
    _crear_cliente(sessions, nombre="Del sistema")

    assert repo.contar(usuario="ana") == 1
    assert repo.usuarios() == ["Sistema", "ana"]


def test_filtro_hasta_incluye_todo_el_dia(sessions, repo):
    """`hasta` es un dia, no un instante: sin el ajuste, filtrar 'hasta hoy'
    dejaria afuera todo lo de hoy salvo lo de las 00:00:00."""
    _crear_cliente(sessions)
    hoy = datetime.now().date().isoformat()
    assert repo.contar(hasta=hoy) == 1
    ayer = (datetime.now() - timedelta(days=1)).date().isoformat()
    assert repo.contar(hasta=ayer) == 0


def test_lo_mas_reciente_primero_y_paginado(sessions, repo):
    for n in range(5):
        _crear_cliente(sessions, nombre=f"Cliente {n}")
    assert repo.listar()[0]["descripcion"].endswith("Cliente 4")
    assert [f["descripcion"][-1] for f in repo.listar(limit=2, offset=1)] == ["3", "2"]


# ── El router ─────────────────────────────────────────────────────────────

def _app_con_logs(sessions, auditables=None):
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from libraauth.auditoria import build_logs_router

    class AccesosFalsos:
        def listar(self, limit=100, offset=0):
            return [{"id": 1, "ts": "2026-08-06 09:00:00", "evento": "login",
                     "username": "ana", "ip": "203.0.113.7", "detalle": ""}]

    app = FastAPI()
    app.state.auditoria = AuditoriaRepository(sessions)
    app.state.auth_events = AccesosFalsos()
    app.include_router(build_logs_router(auditables or AUDITABLES))
    return TestClient(app)


def test_el_router_devuelve_las_dos_fuentes(sessions):
    _crear_cliente(sessions, nombre="Del router")
    datos = _app_con_logs(sessions).get("/logs").json()

    assert datos["actividad"][0]["descripcion"] == "Cliente — Del router"
    assert datos["accesos"][0]["evento"] == "login"
    assert datos["total"] == 1


def test_las_entidades_salen_de_lo_declarado_y_no_del_log(sessions):
    """Si salieran de un `SELECT DISTINCT`, el filtro no ofreceria una entidad
    hasta que alguien la tocara por primera vez."""
    datos = _app_con_logs(sessions).get("/logs").json()
    assert datos["entidades"] == ["cliente", "turno"]
    assert datos["actividad"] == []


def test_el_router_filtra_y_pagina(sessions):
    for n in range(3):
        _crear_cliente(sessions, nombre=f"C{n}")
    with sessions() as s:
        s.add(Turno(title="Un turno"))
        s.commit()

    client = _app_con_logs(sessions)
    assert client.get("/logs", params={"entidad": "turno"}).json()["total"] == 1
    assert client.get("/logs", params={"accion": EDITAR}).json()["total"] == 0
    # `page=0` no puede devolver un offset negativo.
    assert client.get("/logs", params={"page": 0}).json()["page"] == 1


def test_el_prefijo_es_parametrizable(sessions):
    """LibraDesk monta su API bajo `/api`, los otros tres en la raiz."""
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from libraauth.auditoria import build_logs_router

    app = FastAPI()
    app.state.auditoria = AuditoriaRepository(sessions)
    app.state.auth_events = type("A", (), {"listar": lambda self, limit=100: []})()
    app.include_router(build_logs_router(AUDITABLES, prefix="/api/logs"))
    client = TestClient(app)

    assert client.get("/api/logs").status_code == 200
    assert client.get("/logs").status_code == 404


# ── La tabla vive en la base del dominio ──────────────────────────────────

def test_la_tabla_no_cuelga_del_base_de_usuarios(tmp_path):
    """En Gestiolibra, MedLibra y VentaLibra `usuarios` vive en la base de
    LibraCore y el dominio en otra. Si `actividad_log` colgara de
    `models.Base`, quedaria del lado equivocado en tres de los cuatro
    consumidores."""
    from libraauth.models import Base as ModelsBase

    assert "actividad_log" not in ModelsBase.metadata.tables
    assert "actividad_log" in AuditoriaBase.metadata.tables
    # Y al reves: las tablas de auth no viajan con la de auditoria.
    assert "usuarios" not in AuditoriaBase.metadata.tables


def test_se_crea_en_una_base_distinta_de_la_de_auth(tmp_path):
    dominio = create_engine(f"sqlite:///{tmp_path}/dom.db")
    auth = create_engine(f"sqlite:///{tmp_path}/auth.db")
    DominioBase.metadata.create_all(dominio)
    AuditoriaBase.metadata.create_all(dominio)
    from libraauth.models import Base as ModelsBase
    ModelsBase.metadata.create_all(auth)

    factory = sessionmaker(bind=dominio)
    configurar_auditoria(factory, AUDITABLES)
    with factory() as s:
        s.add(Cliente(nombre="En el dominio"))
        s.commit()

    with factory() as s:
        assert s.execute(select(ActividadLog)).scalars().all()
