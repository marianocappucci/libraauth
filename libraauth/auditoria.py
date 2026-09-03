"""
Log de actividad: quien creo, edito o borro que, y que cambio (v0.9.0).

**Por que es automatico y no una llamada en cada servicio.** La alternativa era
sembrar `registrar(...)` en cada metodo de escritura de cada repositorio. Eso
funciona el primer dia y se degrada solo: el metodo que se agrega el mes que
viene no lo lleva, nadie se entera —un log incompleto se ve igual que uno
completo— y el dia que alguien pregunta "quien borro este equipo" la respuesta
es "no quedo registrado". Aca el registro cuelga del `flush` de SQLAlchemy, asi
que **una escritura que no pase por esto no existe**: no hay forma de olvidarse.

**Por que vive en este paquete y no en cada producto.** Nacio en LibraDesk el
2026-08-05 y se extrajo un dia despues, al ir a repetirlo en Gestiolibra,
MedLibra y VentaLibra: el codigo es identico salvo la lista de que se audita.
Vive aca —y no en `libracore`— por dos razones concretas: **libracore no declara
SQLAlchemy** (su `db/` es sqlite3 crudo) y este paquete si; y el dato que la
auditoria necesita para ser util —quien es el usuario de la request— sale de la
sesion, que es justamente lo que este motor administra.

**El `Base` es propio y no el de `models.py`, a proposito.** La tabla tiene que
quedar en la base del **dominio**, que es donde ocurren las escrituras que se
auditan y donde vive la transaccion. En LibraDesk esa es la misma base que la de
`usuarios`, pero en Gestiolibra, MedLibra y VentaLibra **no**: ahi `usuarios`
vive en la base de LibraCore y el dominio en la de LibraGenda/LibraCommerce.
Colgar `actividad_log` de `models.Base` la habria puesto del lado equivocado en
tres de los cuatro consumidores.

**Los dos listeners son uno solo partido en dos, y el orden importa:**

- `before_flush` es el unico momento en que el historial de cada atributo
  todavia esta intacto (`get_history`), asi que ahi se calcula el diff.
- Pero ahi los objetos nuevos **todavia no tienen `id`** (lo asigna el INSERT),
  y un log de auditoria sin el id de la fila que describe no sirve para buscar
  nada. Por eso las filas se completan y se escriben en `after_flush`, cuando el
  id ya existe.

El INSERT final va por Core (`table.insert()`) y no por el ORM: agregar objetos
a la sesion dentro de `after_flush` no los incluiria en el flush en curso, y
ademas dispararia el listener de nuevo.

Uso tipico en el `create_app()` del producto:

    from libraauth.auditoria import (
        AuditoriaBase, AuditoriaRepository, agregar_middleware_de_usuario,
        configurar_auditoria,
    )

    AuditoriaBase.metadata.create_all(engine_del_dominio)
    configurar_auditoria(sessions, {"Cliente": "cliente", "Equipo": "equipo"})
    app.state.auditoria = AuditoriaRepository(sessions)
    agregar_middleware_de_usuario(app)
"""
from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from contextvars import ContextVar
from datetime import datetime

# FastAPI a nivel de modulo y NO dentro de `build_logs_router`: este archivo
# tiene `from __future__ import annotations`, asi que todas las anotaciones son
# strings y FastAPI las resuelve contra los globals del modulo. Con el import
# adentro de la funcion, `Request` no existe ahi y FastAPI lo toma como un query
# param obligatorio — el sintoma es un 422 pidiendo "request", no un ImportError.
from fastapi import APIRouter, Depends
from sqlalchemy import DateTime, Integer, String, Text, event, func, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from starlette.requests import Request

CREAR = "crear"
EDITAR = "editar"
BORRAR = "borrar"

# Quien esta haciendo la escritura, resuelto por el middleware a partir de la
# cookie de sesion. Es un ContextVar y no un parametro porque el dato tiene que
# llegar hasta el `flush`, que ocurre dentro del repositorio, tres capas mas
# abajo del router — pasarlo a mano obligaria a agregarle un argumento `usuario`
# a cada metodo de cada repositorio.
#
# El default no es "" sino este texto: una fila escrita fuera de una request (un
# seed, una migracion, un script) es legitima y tiene que poder distinguirse de
# "no se supo quien fue".
SISTEMA = "Sistema"
usuario_actual: ContextVar[str] = ContextVar("usuario_actual", default=SISTEMA)


class AuditoriaBase(DeclarativeBase):
    """Metadata propia: el producto la crea contra el engine de su dominio, que
    no siempre es el mismo donde vive `usuarios`. Ver el docstring del modulo."""


class ActividadLog(AuditoriaBase):
    """Una fila por cambio. `cambios` es JSON y no columnas fijas porque cada
    entidad tiene los suyos; se lee solo para mostrarlo, nunca se filtra por
    adentro."""

    __tablename__ = "actividad_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # Hora local, igual que `auth_log`: las dos se muestran en la misma pantalla
    # y una en UTC quedaria tres horas corrida contra la otra. Ver
    # `models.AuthEvent` para el detalle de por que `func.now()` no sirve aca.
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.now, index=True)
    usuario: Mapped[str] = mapped_column(String(100), nullable=False, default=SISTEMA)
    accion: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    entidad: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    #: 🔴 **Texto, no entero.** Se llena con el id de la entidad auditada, y en
    #: esta familia los ids son heterogeneos: enteros en LibraDesk y VentaLibra,
    #: cadenas en MedLibra (`patient-1`), Gestiolibra y LibraGenda.
    #:
    #: Estuvo declarada `Integer` hasta el 2026-08-09 y **SQLite lo venia
    #: tapando**: por tipado dinamico guarda texto en una columna INTEGER sin
    #: decir nada. Medido ese dia en produccion, la columna ya tenia mas texto
    #: que enteros -- 48 de 86 filas en la demo de Gestiolibra, 58 de 95 en la
    #: de MedLibra. El tipo declarado nunca describio lo que habia adentro.
    #:
    #: Contra PostgreSQL no hay tipado dinamico: `invalid input syntax for type
    #: integer`. Y como el log se escribe en la MISMA transaccion que la
    #: operacion auditada, no se perdia una fila de auditoria -- **el alta
    #: entera devolvia 500**.
    #:
    #: Se puede cambiar sin consecuencias porque la columna se usa en un solo
    #: lugar, serializada para mostrarla: ni filtros, ni joins, ni orden.
    entidad_id: Mapped[str | None] = mapped_column(String(100))
    descripcion: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    cambios: Mapped[str | None] = mapped_column(Text)


def _id_como_texto(obj: object) -> str | None:
    """El id de la entidad auditada, como texto.

    La conversion es explicita y no implicita a proposito. `entidad_id` es una
    columna de texto y los ids de LibraDesk y VentaLibra son enteros: dejar que
    el driver los adapte solo funciona hasta que deja de funcionar, y falla en
    el momento mas caro -- dentro de la transaccion de una escritura real.

    Un `0` es un id valido, asi que la guarda mira `is None` y no la verdad del
    valor: con un `if not id` se perderia el id de la primera fila de cualquier
    tabla que empiece en cero.
    """
    valor = getattr(obj, "id", None)
    return None if valor is None else str(valor)


# Columnas que nunca entran al diff, en cualquier producto. Un log de auditoria
# no puede ser el lugar donde termina en claro un secreto que el resto del
# sistema se ocupa de hashear o cifrar.
#
# El producto suma las suyas con `columnas_ocultas=` — MedLibra lo usa para que
# el contenido clinico no se copie al log.
COLUMNAS_OCULTAS = frozenset({
    "password", "password_hash", "password_cifrada", "token", "token_hash",
    "secret", "secret_key", "access_token", "api_key",
})

# Lo que se escribe en lugar del valor de una columna oculta que SI cambio.
#
# 🔴 Hasta v0.11.0 una columna oculta se salteaba entera, y si era la unica que
# habia cambiado el diff quedaba vacio — con lo cual la edicion **no se
# registraba en absoluto**. O sea: cambiar solo la contrasena de un usuario no
# dejaba ninguna fila en el log, en ninguno de los seis productos. Un log de
# auditoria que no puede contestar "quien cambio esa contrasena y cuando" no
# esta ocultando un secreto: esta ocultando el hecho.
#
# Desde v0.12.0 la fila se registra igual y lo unico que se tapa es el valor.
# Se distingue de un `dirty` que no cambio nada, que sigue sin registrarse
# porque eso si es ruido — ver `_diff`.
OCULTO = "(oculto)"

# En orden: el primero que exista y tenga valor es la etiqueta de la fila. Estan
# los nombres en castellano (dominio propio de los productos) y en ingles (los
# modelos de LibraGenda y LibraCommerce, que son los que auditan Gestiolibra,
# MedLibra y VentaLibra).
ATRIBUTOS_ETIQUETA = (
    "titulo", "title", "numero", "number", "nombre", "name", "razon_social",
    "patente", "codigo_interno", "code", "sku", "serial", "descripcion",
)

# Ultimo recurso cuando ninguno de los anteriores existe: se arma con lo que
# haya. Un equipo, por ejemplo, no tiene nombre — tiene tipo, marca y modelo.
ATRIBUTOS_ARMADO = ("tipo", "type", "marca", "brand", "modelo", "model")


def _etiqueta(obj) -> str:
    for attr in ATRIBUTOS_ETIQUETA:
        valor = getattr(obj, attr, None)
        if valor:
            return str(valor)[:200]
    partes = [str(getattr(obj, a, "") or "") for a in ATRIBUTOS_ARMADO]
    armado = " ".join(p for p in partes if p).strip()
    return armado[:200] if armado else ""


# Nombre publico de `_etiqueta`, para el producto que quiera reusarla dentro de
# su propio `etiqueta=`: MedLibra la usa para las entidades NO clinicas y
# devuelve cadena vacia para el resto. Sin esto tendria que importar un nombre
# privado de este modulo.
def etiqueta_por_defecto(obj) -> str:
    return _etiqueta(obj)


def _valor_legible(valor):
    if isinstance(valor, datetime):
        return valor.strftime("%Y-%m-%d %H:%M:%S")
    if valor is None or isinstance(valor, (str, int, float, bool)):
        return valor
    return str(valor)


def ts_legible(valor) -> str:
    """El `ts` de una fila de log como texto, venga como venga.

    🔴 **Puede venir de las dos formas, y no es un descuido de quien lee.** El
    modelo de aca declara `ts` como `DateTime`, pero en los productos que crean
    la tabla con **DDL crudo** la columna es `TEXT` -- en esta familia los
    timestamps de la capa cruda son texto a proposito, porque las fechas se
    filtran comparando lexicograficamente.

    Contra SQLite el desacuerdo no se ve: el dialecto de SQLAlchemy parsea el
    texto y devuelve un `datetime`. Contra PostgreSQL **no** lo hace -- da por
    hecho que el driver ya devuelve `datetime` -- y llega el `str` crudo. Medido
    en VentaLibra el 2026-08-10: 19 apariciones de *'str' object has no
    attribute 'strftime'*, todas por esto.

    Se tolera en la lectura en vez de unificar el tipo de la columna porque
    unificarlo significaria romper el filtrado lexicografico de la capa cruda,
    que es mucho mas que estas dos lineas. El texto que sale es el mismo en los
    dos casos.
    """
    if valor is None or valor == "":
        return ""
    if isinstance(valor, datetime):
        return valor.strftime("%Y-%m-%d %H:%M:%S")
    return str(valor)


def _diff(obj, ocultas: frozenset) -> dict:
    """`{atributo: [antes, despues]}` de lo que realmente cambio.

    Solo columnas: las relaciones quedan afuera porque cargarlas aca dispararia
    un SELECT por atributo en medio del flush.

    Una columna oculta que cambio entra como `[OCULTO, OCULTO]`, no se saltea:
    el log tiene que poder decir que ese campo se toco. Lo que se descarta —y
    por eso el chequeo de `antes == despues` va **antes** de tapar el valor— es
    la columna que quedo igual, que es ruido en cualquier caso.

    🔴 **Se recorre `column_attrs`, no `__table__.columns`** (2026-08-12).
    `estado.attrs` esta indexado por **nombre de atributo**; `__table__.columns`
    devuelve **nombres de columna**. En los seis productos de la familia esos
    dos nombres coincidieron siempre, asi que la version anterior —que iteraba
    columnas y las buscaba en `attrs`— funcionaba por casualidad.

    El primer modelo donde difieren es el de clientes de LibraDesk, que mapea
    `nombre` a la columna `name` del motor: ahi `attrs["name"]` tira
    `KeyError: 'name'`. Y como el log se escribe en la MISMA transaccion que la
    operacion auditada, no se pierde una linea de auditoria: **la operacion
    entera devuelve 404**. Un PUT que falla mientras el GET del mismo recurso
    anda, que no se parece en nada a su causa.

    **La clave del diff pasa a ser el atributo**, que es el vocabulario del
    producto y lo que la pantalla de logs sabe mostrar. `ocultas` se compara
    contra **las dos** formas para que ninguna configuracion existente cambie
    de comportamiento: hoy los productos la escriben con nombres que son los
    dos a la vez, y cual eligieron no esta escrito en ningun lado.
    """
    estado = inspect(obj)
    cambios = {}
    for attr in inspect(type(obj)).column_attrs:
        historial = estado.attrs[attr.key].history
        if not historial.has_changes():
            continue
        antes = historial.deleted[0] if historial.deleted else None
        despues = historial.added[0] if historial.added else None
        if antes == despues:
            continue
        nombres_de_columna = {c.name for c in attr.columns}
        if attr.key in ocultas or nombres_de_columna & set(ocultas):
            cambios[attr.key] = [OCULTO, OCULTO]
            continue
        cambios[attr.key] = [_valor_legible(antes), _valor_legible(despues)]
    return cambios


def configurar_auditoria(
    session_factory,
    auditables: dict[str, str],
    columnas_ocultas: frozenset | set | tuple = (),
    etiqueta: Callable[[object], str] | None = None,
) -> None:
    """Engancha los listeners al `session_factory` del dominio.

    `auditables` es la lista blanca: `{nombre de la clase del modelo: nombre
    logico}`, por ejemplo `{"Cliente": "cliente", "Appointment": "turno"}`. Se
    indexa por **nombre de clase** y no por la clase para que el producto no
    tenga que importar los 12 modulos de modelos solo para declararla — y para
    que funcione igual con modelos que viven en un motor (LibraGenda,
    LibraCommerce) y no en el producto.

    Es una lista blanca y no una negra a proposito: una tabla nueva no entra
    sola al log. Las tablas que YA son historial de algo (los movimientos de un
    equipo, la linea de tiempo de un ticket) tienen que quedar afuera, porque su
    ficha ya las muestra y auditarlas pondria el mismo hecho dos veces.

    `columnas_ocultas` se SUMA a las que este modulo oculta siempre
    (contrasenas, tokens, secretos). Es para lo que solo el producto sabe que
    es sensible: MedLibra la usa para que el texto de una nota clinica o la
    medicacion de una receta **no se copien al log**.

    `etiqueta` reemplaza el armado del texto que describe la fila. Existe por
    el mismo motivo, y no alcanza con `columnas_ocultas`: la etiqueta se arma
    leyendo atributos directamente, asi que ocultar una columna del diff no
    impide que su valor termine en la descripcion. El titulo de un documento
    clinico ("Interconsulta cardiologia") ya dice algo del paciente.

    Idempotente: llamarla dos veces —los tests arman varias apps en el mismo
    proceso— no duplica filas.
    """
    ocultas = COLUMNAS_OCULTAS | frozenset(columnas_ocultas)
    armar_etiqueta = etiqueta or _etiqueta

    def _auditable(obj) -> bool:
        return type(obj).__name__ in auditables

    def _fila(obj, accion: str, cambios: dict | None) -> dict:
        entidad = auditables[type(obj).__name__]
        etiqueta = armar_etiqueta(obj)
        titulo = entidad.replace("_", " ").capitalize()
        return {
            "ts": datetime.now(),
            "usuario": usuario_actual.get()[:100],
            "accion": accion,
            "entidad": entidad,
            # Se completa en after_flush para las creaciones: en before_flush el
            # INSERT todavia no corrio y el id no existe.
            "_obj": obj,
            "descripcion": (f"{titulo} — {etiqueta}" if etiqueta else titulo)[:500],
            "cambios": json.dumps(cambios, ensure_ascii=False) if cambios else None,
        }

    def _antes_del_flush(session: Session, flush_context, instances):  # noqa: ARG001
        if session.info.get("auditoria") is False:
            return
        pendientes = []
        for obj in session.new:
            if _auditable(obj):
                pendientes.append(_fila(obj, CREAR, None))
        for obj in session.dirty:
            if _auditable(obj) and session.is_modified(obj, include_collections=False):
                cambios = _diff(obj, ocultas)
                # Un `dirty` sin columnas cambiadas es un objeto que alguien
                # toco y dejo igual. Registrarlo llenaria el log de "editar"
                # vacios.
                if cambios:
                    pendientes.append(_fila(obj, EDITAR, cambios))
        for obj in session.deleted:
            if _auditable(obj):
                fila = _fila(obj, BORRAR, None)
                # El id se lee ACA y no despues: tras el flush el objeto queda
                # desatachado y `obj.id` puede venir vacio.
                fila["entidad_id"] = _id_como_texto(obj)
                fila["_obj"] = None
                pendientes.append(fila)
        if pendientes:
            session.info.setdefault("_auditoria", []).extend(pendientes)

    def _despues_del_flush(session: Session, flush_context):  # noqa: ARG001
        pendientes = session.info.pop("_auditoria", None)
        if not pendientes:
            return
        filas = []
        for fila in pendientes:
            obj = fila.pop("_obj", None)
            if obj is not None:
                fila["entidad_id"] = _id_como_texto(obj)
            filas.append(fila)
        # Core y no ORM: `session.add()` aca no entraria en este flush, y
        # volveria a disparar estos mismos listeners.
        session.execute(ActividadLog.__table__.insert(), filas)

    if not event.contains(session_factory, "before_flush", _antes_del_flush):
        event.listen(session_factory, "before_flush", _antes_del_flush)
    if not event.contains(session_factory, "after_flush", _despues_del_flush):
        event.listen(session_factory, "after_flush", _despues_del_flush)


def agregar_middleware_de_usuario(app) -> None:
    """Deja el usuario de la request al alcance del `flush`, que ocurre tres
    capas mas abajo (router → repositorio → sesion).

    Sale de la cookie firmada y no de la base: `get_current_user` solo verifica
    la firma, asi que esto no agrega una consulta por request. Un request sin
    sesion (el login, el health) deja el default `Sistema`.

    Espera `app.state.session_auth`, igual que el resto de las dependencias de
    este paquete.
    """

    @app.middleware("http")
    async def _sellar_usuario(request, call_next):
        usuario = None
        auth = getattr(request.app.state, "session_auth", None)
        if auth is not None:
            usuario = auth.get_current_user(request)
        token = usuario_actual.set(usuario) if usuario else None
        try:
            return await call_next(request)
        finally:
            # El `reset` no es opcional aunque el server sea async: los workers
            # reusan el contexto entre requests, y sin esto el usuario de una
            # request podria quedar pegado para la siguiente que entrara sin
            # sesion.
            if token is not None:
                usuario_actual.reset(token)


PAGE_SIZE = 100

# El color lo elige el backend, igual que en Contalibra: asi la pantalla no
# tiene que conocer el vocabulario, y una accion nueva no obliga a tocar el
# frontend para que se vea.
ACCION_META = {
    CREAR: {"label": "Creado", "color": "#198754"},
    EDITAR: {"label": "Editado", "color": "#0d6efd"},
    BORRAR: {"label": "Borrado", "color": "#dc3545"},
}


def build_logs_router(auditables: dict[str, str], *, prefix: str = "/logs") -> APIRouter:
    """Router de lectura de los dos logs, para la pantalla compartida
    (`libra-ui/Logs`).

    **No se gatea a si mismo**: el producto lo monta con la dependencia de rol
    que le corresponda —en los cuatro consumidores es `require_admin`—. Ponerle
    el gate adentro obligaria a este paquete a conocer el vocabulario de roles
    de cada producto, que no siempre es el mismo.

    Espera `app.state.auditoria` (`AuditoriaRepository`) y `app.state.auth_events`
    (`AuthEventRepository`).

    Devuelve las dos fuentes por separado a proposito: la actividad del sistema
    y los accesos son dos preguntas distintas ("quien borro esto" / "quien
    entro"), se filtran distinto y se miran en momentos distintos.
    """
    router = APIRouter(prefix=prefix, tags=["logs"])

    def _auditoria(request: Request) -> AuditoriaRepository:
        return request.app.state.auditoria

    def _accesos(request: Request):
        return request.app.state.auth_events

    @router.get("")
    def listar(
        entidad: str = "",
        accion: str = "",
        usuario: str = "",
        desde: str = "",
        hasta: str = "",
        page: int = 1,
        auditoria: AuditoriaRepository = Depends(_auditoria),
        accesos=Depends(_accesos),
    ):
        page = max(1, page)
        filtros = dict(entidad=entidad, accion=accion, usuario=usuario, desde=desde, hasta=hasta)
        total = auditoria.contar(**filtros)
        return {
            "actividad": auditoria.listar(**filtros, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE),
            "total": total,
            "total_pages": max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            "page": page,
            # La lista sale de lo declarado por el producto y no de un `SELECT
            # DISTINCT` sobre el log: asi el filtro ofrece las entidades
            # auditables aunque todavia no haya actividad de alguna.
            "entidades": sorted(set(auditables.values())),
            "acciones": ACCION_META,
            "usuarios": auditoria.usuarios(),
            # Los accesos no se paginan ni se filtran: son la segunda mitad de
            # la pantalla, no su contenido principal, y 100 filas cubren varios
            # dias de una instancia con un puñado de usuarios.
            "accesos": accesos.listar(limit=100),
        }

    return router


class AuditoriaRepository:
    """Lectura del log. No expone ningun metodo de escritura a proposito: lo que
    se escribe lo decide el flush, no un llamador."""

    def __init__(self, session_factory: Callable[[], AbstractContextManager[Session]]):
        self.session_factory = session_factory

    def listar(self, *, entidad: str = "", accion: str = "", usuario: str = "",
               desde: str = "", hasta: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
        with self.session_factory() as session:
            filas = session.execute(
                self._filtrada(entidad, accion, usuario, desde, hasta)
                .order_by(ActividadLog.id.desc()).limit(limit).offset(offset)
            ).scalars()
            return [{
                "id": f.id,
                "ts": ts_legible(f.ts),
                "usuario": f.usuario,
                "accion": f.accion,
                "entidad": f.entidad,
                "entidad_id": f.entidad_id,
                "descripcion": f.descripcion,
                "cambios": json.loads(f.cambios) if f.cambios else None,
            } for f in filas]

    def contar(self, *, entidad: str = "", accion: str = "", usuario: str = "",
               desde: str = "", hasta: str = "") -> int:
        with self.session_factory() as session:
            sub = self._filtrada(entidad, accion, usuario, desde, hasta).subquery()
            return int(session.execute(select(func.count()).select_from(sub)).scalar_one())

    def usuarios(self) -> list[str]:
        """Los usuarios que aparecen en el log — para poblar el filtro sin
        mostrar a los que nunca escribieron nada."""
        with self.session_factory() as session:
            return [u for (u,) in session.execute(
                select(ActividadLog.usuario).distinct().order_by(ActividadLog.usuario)
            )]

    def _filtrada(self, entidad: str, accion: str, usuario: str, desde: str, hasta: str):
        consulta = select(ActividadLog)
        if entidad:
            consulta = consulta.where(ActividadLog.entidad.in_(entidad.split(",")))
        if accion:
            consulta = consulta.where(ActividadLog.accion == accion)
        if usuario:
            consulta = consulta.where(ActividadLog.usuario == usuario)
        if desde:
            consulta = consulta.where(ActividadLog.ts >= datetime.fromisoformat(desde))
        if hasta:
            # `hasta` es un dia, no un instante: sin esto, filtrar "hasta hoy"
            # dejaria afuera todo lo de hoy salvo lo de las 00:00:00.
            consulta = consulta.where(ActividadLog.ts < datetime.fromisoformat(hasta).replace(
                hour=23, minute=59, second=59))
        return consulta
