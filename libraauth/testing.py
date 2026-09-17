"""
Helper de contrato para que cada producto verifique, desde su PROPIA suite,
que su instancia de `build_users_router()` (ver `libraauth.usuarios`) sigue
sirviendo lo que el backoffice (`libra-backoffice`) y la pantalla compartida
(`Usuarios` de `libra-ui`) esperan.

`verificar_contrato_de_usuarios()` ejerce el mismo ciclo que hace el
backoffice cuando administra una instancia por `/api/instancias/{slug}/
usuarios`: listar, alta, edición, releer por `GET /{id}` y borrado. Arma los
payloads con los MISMOS modelos públicos que usa la factory
(`UsuarioAlta`/`UsuarioEdicion`/`UsuarioClaveNueva`, importados de
`libraauth.usuarios` y no redefinidos acá) -- así el test de contrato y la
factory no pueden divergir: si alguien le cambia un campo a un modelo, este
helper cambia con él en el mismo commit, no dos semanas después en cada
producto.

Importable sin las dependencias pesadas de test de cada producto (no importa
`pytest` ni un `TestClient` propio): sólo necesita un cliente con
`.get/.post/.put/.delete` que devuelvan algo con `.status_code` y `.json()`
-- un `fastapi.testclient.TestClient`, un `httpx.Client`, o el cliente propio
que ya arma la suite de cada producto para su cliente admin o su token de
servicio (`X-Internal-Auth`, que es como entra el backoffice -- ver
`session_auth.SERVICE_TOKEN_HEADER`).
"""
from typing import Protocol

from .usuarios import (
    MIN_PASSWORD_LENGTH,
    UsuarioAlta,
    UsuarioClaveNueva,
    UsuarioEdicion,
)


class _RespuestaHTTP(Protocol):
    status_code: int

    def json(self) -> object: ...


class _ClienteHTTP(Protocol):
    """Lo mínimo que hace falta: cualquier cliente de test de FastAPI/httpx
    lo cumple sin adaptador."""

    def get(self, url: str, **kw: object) -> _RespuestaHTTP: ...
    def post(self, url: str, **kw: object) -> _RespuestaHTTP: ...
    def put(self, url: str, **kw: object) -> _RespuestaHTTP: ...
    def delete(self, url: str, **kw: object) -> _RespuestaHTTP: ...


def verificar_contrato_de_usuarios(
    client: _ClienteHTTP,
    path: str,
    *,
    role: str = "staff",
    username: str = "contrato-libraauth",
    headers: dict[str, str] | None = None,
) -> None:
    """Ejerce el ciclo completo de ABM que usa el backoffice contra `path`
    (el `USERS_PATH`/`UsuarioIn`/`UsuarioUpdate` de `libra-backoffice`, ver
    `config_instancia.py`).

    `role` tiene que ser un rol NO admin de la instancia que llama (el
    default `"staff"` sirve para los seis productos con ese vocabulario;
    Contalibra/Restolibra tienen que pasar `role="operador"` o similar). Es a
    propósito que el ciclo no toque el rol admin: la protección del único
    admin activo se prueba aparte, con mutación de estado, en
    `tests/test_usuarios_router.py` del propio `libraauth` -- acá se prueba
    el contrato que ve el backoffice, no las reglas de negocio de la
    factory.

    `client` ya tiene que estar autenticado como admin de esa instancia (o
    llevar el header del token de servicio) -- este helper no arma
    credenciales, las recibe.

    Lanza `AssertionError` con la respuesta completa en el mensaje ante
    cualquier desvío del contrato: quién llama lo corre dentro de su propia
    suite de pytest, así que el traceback de `assert` ya dice qué falló y en
    qué llamada.
    """
    kw: dict[str, object] = {"headers": headers} if headers else {}

    listado = client.get(path, **kw)
    assert listado.status_code == 200, (listado.status_code, listado.json())
    for usuario in listado.json():
        # Lo que `Usuarios` de `libra-ui` lee de cada fila (ver su
        # `columns`): sin estas tres claves la grilla se rompe en tiempo de
        # render, no con un error legible.
        assert {"name", "active", "role"} <= usuario.keys(), usuario

    alta = UsuarioAlta(
        username=username, name="Usuario de contrato", password="x" * MIN_PASSWORD_LENGTH,
        role=role,
    )
    r = client.post(path, json=alta.model_dump(), **kw)
    assert r.status_code == 201, (r.status_code, r.json())
    creado = r.json()
    assert creado["username"] == username
    assert creado["name"] == "Usuario de contrato"
    assert creado["role"] == role
    assert creado["active"] is True
    user_id = creado["id"]

    edicion = UsuarioEdicion(name="Usuario Editado", role=role, active=True)
    r = client.put(f"{path}/{user_id}", json=edicion.model_dump(exclude_none=True), **kw)
    assert r.status_code == 200, (r.status_code, r.json())
    assert r.json()["name"] == "Usuario Editado"

    # 🔑 Releído por GET, no sólo lo que devolvió el PUT: es lo que separa
    # "el handler devuelve bien" de "el cambio quedó guardado". Ver el punto
    # 4 de la tarea que originó este archivo.
    releido = client.get(f"{path}/{user_id}", **kw)
    assert releido.status_code == 200, (releido.status_code, releido.json())
    assert releido.json()["name"] == "Usuario Editado"

    nueva_clave = UsuarioClaveNueva(password="y" * MIN_PASSWORD_LENGTH)
    r = client.put(f"{path}/{user_id}/password", json=nueva_clave.model_dump(), **kw)
    assert r.status_code == 204, (r.status_code, getattr(r, "text", None))

    r = client.delete(f"{path}/{user_id}", **kw)
    assert r.status_code == 204, (r.status_code, getattr(r, "text", None))

    releido = client.get(f"{path}/{user_id}", **kw)
    assert releido.status_code == 404, (releido.status_code, releido.json())


def crear_schema_de_auth(destino) -> str:
    """Deja la base de auth como la deja el deploy: la cadena en la cabeza.

    Reemplaza, en los tests, al `AuthBase.metadata.create_all(engine)` que los
    productos usaban para armar las seis tablas. Desde v0.45.0 el arranque exige
    la tabla de versión (`libraauth.migrar.exigir_schema_al_dia`), y
    `create_all` no la crea. El resultado de la cadena es el mismo que el del
    modelo —lo fija `test_modelo_y_cadena_coinciden`— más la versión.

    `destino` es una URL o un `Engine`. Un SQLite **en memoria** no sirve: la
    cadena abre su propia conexión y vería otra base vacía. Importa alembic
    recién al llamarla (extra `[migrations]`).
    """
    from libraauth import migrar

    url = destino
    if not isinstance(destino, str):
        url = destino.url.render_as_string(hide_password=False)
    if url.startswith("sqlite") and (":memory:" in url or url.rstrip("/") in ("sqlite:", "sqlite://")):
        raise ValueError(
            "crear_schema_de_auth no puede migrar un SQLite en memoria: la cadena "
            "abre otra conexión. Usá un archivo o un PostgreSQL."
        )
    migrar.upgrade(url)
    return migrar.cabeza()
