"""
Terminos y Condiciones del Servicio: el texto, su hash, la prueba de la
aceptacion y el gate que corta el acceso hasta que exista (v0.30.0).

**Que resuelve.** El contrato de la Suite Libra tiene que estar publicado en la
web del producto y aceptado adentro del sistema antes de poder operar. Las dos
mitades tienen que mirar el MISMO texto: si la web publica un archivo y el
backend guarda el hash de otro, la clausula 30.3 no prueba nada.

**Por que vive en libraauth y no en libracore ni en libra-web-kit.** Los ocho
productos dependen de los dos motores, asi que cualquiera de los dos alcanzaba
para llegarles. Se eligio este porque el gate ES una condicion del ingreso: se
resuelve en las mismas dependencias que ya deciden quien pasa
(`json_api_require_role`, `SessionAuth.require_*`) y necesita la misma
`usuarios` que este paquete ya modela. En libracore habria quedado el texto de
un lado y el guard del otro. `libra-web-kit` importa **este** modulo para
generar las paginas publicas, y por eso el hash que se publica es, por
construccion, el que el backend exige.

**La aceptacion es de la instancia, no de cada usuario.** Ver el docstring de
`models.AceptacionTerminos`.

Como lo cablea un producto, en su factory::

    from libraauth.terminos import TerminosRepository, build_terminos_router

    app.state.terminos = TerminosRepository(sessions)
    app.include_router(build_terminos_router())

`app.state.terminos` es lo que enciende el gate. Sin el, el resto del paquete se
comporta como antes de esta version — ver `hay_terminos_pendientes`.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime
from pathlib import Path

# FastAPI a nivel de modulo y NO dentro de `build_terminos_router`, por lo mismo
# que `auditoria.py`: este archivo tiene `from __future__ import annotations`, asi
# que las anotaciones son strings y FastAPI las resuelve contra los globals del
# modulo. Con el import adentro de la funcion, `Request` no existe ahi y FastAPI
# lo toma como query param obligatorio — el sintoma es un 422 pidiendo "request".
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException
from starlette.requests import Request

from .models import AceptacionTerminos

#: Version vigente del contrato. **Subirla es el disparador de la re-aceptacion**
#: (clausula 29.3): al arrancar con una version que la instancia no tiene
#: aceptada, el gate vuelve a cortar. No tocarla por una correccion de tipeo que
#: no cambie el sentido — cada cambio de este numero le frena la operacion a los
#: ocho productos hasta que alguien con rol admin entre y acepte.
VERSION_VIGENTE = "1.0"

#: Fecha de entrada en vigencia de `VERSION_VIGENTE`, en el formato de la familia
#: (`dd-mm-aaaa`, ver `estandares-desarrollo`). Es dato de pantalla y de la
#: pagina publica; no interviene en el hash.
VIGENTE_DESDE = "22-08-2026"

#: El texto, empaquetado como dato del wheel. `packages = ["libraauth"]` de
#: hatchling se lleva todo lo que cuelga del paquete, asi que el `.md` viaja.
ARCHIVO_TERMINOS = Path(__file__).parent / "legal" / "terminos_v1.md"

#: Codigo que devuelve el gate en el `detail` del 403. El frontend matchea por
#: esto y no por el texto del mensaje.
CODIGO_PENDIENTE = "terminos_pendientes"

#: Roles que pueden aceptar. Clausula 30.5: solo obliga al Cliente quien tiene
#: facultades para hacerlo. Un operador ve la pantalla pero no el boton.
#:
#: `"admin"` es el unico rol que existe con ese nombre en los ocho productos —
#: el resto del vocabulario si cambia (`staff`, `operador`, `cajero`, `mozo`).
ROLES_QUE_ACEPTAN = ("admin",)


def texto_vigente() -> str:
    """El texto del contrato, normalizado a LF.

    🔴 **La normalizacion no es cosmetica: es lo que hace estable al hash.**
    El archivo puede llegar con CRLF a cualquier checkout con
    `core.autocrlf=true` (todo Windows), y ahi el sha256 del mismo contrato
    daria distinto que en el contenedor Linux que lo sirve. El resultado seria
    una instancia exigiendo un hash que la pagina publica no reproduce, sin
    ningun sintoma mas que dos cadenas de 64 caracteres que no coinciden.

    Se lee en **binario y se normaliza a mano**, y no con `read_text()`, aunque
    el modo texto de Python ya traduzca los finales de linea: por ese camino la
    normalizacion es un efecto colateral del modo de apertura —invisible en la
    linea que la produce, y facil de perder si alguien cambia la lectura—. Aca
    es explicita, y por eso un test puede ponerse rojo si desaparece.
    """
    crudo = ARCHIVO_TERMINOS.read_bytes().decode("utf-8")
    return crudo.replace("\r\n", "\n").replace("\r", "\n")


def texto_html() -> str:
    """El mismo contrato, convertido a HTML.

    🔑 **Existe para que haya UN solo convertidor.** Lo consumen los dos lados:
    la pantalla de aceptacion de `libra-ui` (que lo inserta tal cual) y
    `libra_web_kit.legal_gen`, que genera las paginas publicas. Si cada uno
    convirtiera por su cuenta, el cliente podria estar leyendo un contrato con
    otras negritas, otras listas o —peor— una tabla que en un lado se ve y en el
    otro no, sin que nada falle.

    Devuelve HTML **pelado**, sin clases: el estilo lo pone cada consumidor, que
    es lo unico que legitimamente cambia entre una landing y una SPA.

    **No interviene en el hash.** Lo que se firma es el Markdown; esto es
    presentacion.
    """
    import markdown  # local: solo lo necesita quien va a mostrar el texto

    return markdown.markdown(texto_vigente(), extensions=["tables", "sane_lists"])


def hash_vigente() -> str:
    """sha256 hex del texto vigente. Es la huella de la clausula 30.3."""
    return hashlib.sha256(texto_vigente().encode("utf-8")).hexdigest()


class TerminosRepository:
    """Lectura y escritura de la prueba de aceptacion.

    `session_factory` es el mismo que recibe `UserRepository`: el engine donde
    vive `usuarios`, no el del dominio del producto.
    """

    def __init__(
        self,
        session_factory: Callable[[], AbstractContextManager[Session]],
        *,
        version: str = VERSION_VIGENTE,
    ):
        self.session_factory = session_factory
        self.version = version
        # Cache de "esta instancia ya acepto la version vigente". Se prende una
        # sola vez y no se vuelve a apagar: una aceptacion no se deshace, y la
        # unica forma de volver a pendiente es subir `VERSION_VIGENTE`, que llega
        # con una imagen nueva y por lo tanto con un proceso nuevo.
        #
        # Existe porque el gate corre en CADA request gateada: sin cache seria una
        # consulta mas por request para leer un booleano que casi siempre es True.
        self._aceptada = False

    def aceptacion_vigente(self) -> dict | None:
        """La aceptacion de la version vigente, o None si la instancia no tiene."""
        with self.session_factory() as session:
            fila = session.execute(
                select(AceptacionTerminos)
                .where(AceptacionTerminos.version == self.version)
                .order_by(AceptacionTerminos.id.desc())
            ).scalars().first()
            return _a_dict(fila) if fila else None

    def esta_aceptada(self) -> bool:
        if self._aceptada:
            return True
        hay = self.aceptacion_vigente() is not None
        if hay:
            self._aceptada = True
        return hay

    def registrar(
        self, *, usuario_id: int | None, username: str, nombre: str,
        ip: str = "", user_agent: str = "",
    ) -> dict:
        """Deja la fila probatoria. Idempotente por instancia: si ya hay una
        aceptacion de esta version, la devuelve sin escribir otra.

        No es una constraint UNIQUE porque el historial de versiones **si** tiene
        que poder tener varias filas (una por version aceptada), y porque una
        segunda aceptacion de la misma version no es un error del que haya que
        avisar: es alguien que apreto dos veces.
        """
        ya = self.aceptacion_vigente()
        if ya is not None:
            self._aceptada = True
            return ya
        with self.session_factory() as session:
            fila = AceptacionTerminos(
                usuario_id=usuario_id,
                username=(username or "")[:100],
                nombre=(nombre or "")[:200],
                version=self.version,
                hash_texto=hash_vigente(),
                aceptado_at=datetime.now(),
                ip=(ip or "")[:64],
                user_agent=(user_agent or "")[:400],
            )
            session.add(fila)
            session.commit()
            session.refresh(fila)
            self._aceptada = True
            return _a_dict(fila)

    def historial(self) -> list[dict]:
        """Todas las aceptaciones, la mas reciente primero. Es la copia del
        registro que la clausula 30.3 le permite pedir al Cliente."""
        with self.session_factory() as session:
            filas = session.execute(
                select(AceptacionTerminos).order_by(AceptacionTerminos.id.desc())
            ).scalars()
            return [_a_dict(f) for f in filas]


def _a_dict(f: AceptacionTerminos) -> dict:
    return {
        "id": f.id,
        "usuario_id": f.usuario_id,
        "username": f.username,
        "nombre": f.nombre,
        "version": f.version,
        "hash_texto": f.hash_texto,
        "aceptado_at": f.aceptado_at.isoformat() if f.aceptado_at else None,
        "ip": f.ip,
        "user_agent": f.user_agent,
    }


def exige_aceptacion() -> bool:
    """Si esta instancia tiene contrato que aceptar. **Las demos no.**

    Una demo publica no es una instancia de cliente: no hay Cliente, no hay
    contrato y no hay responsable de la cuenta que pueda obligarse. Exigirle la
    aceptacion es pedirle a nadie que firme por nadie.

    🔴 **Esto ya estaba a medias, y por eso fallaba.** Hasta la v0.34.0 la
    excepcion vivia en `exigir_terminos` y cubria **solo al visitante**, con
    este mismo argumento escrito en su docstring. Pero el resto de la instancia
    quedaba gateada, y ahi el argumento se da vuelta solo: `ROLES_QUE_ACEPTAN`
    es `("admin",)`, el visitante de la demo es `staff`, y **el auto-login se
    niega a entregar `admin`** (`ROLES_PROHIBIDOS_EN_DEMO`) — asi que en una
    demo no habia por donde aceptar nada. La exencion del visitante tapaba lo
    justo para que la pantalla publica anduviera.

    Lo que quedaba roto era todo lo demas, y esta medido: el reset nocturno
    borra el schema —`aceptaciones_terminos` incluida— y despues la siembra, que
    entra como `admin`, chocaba contra el 403. La corrida del cron del
    2026-08-25 fallo en **los ocho productos** y las ocho demos amanecieron
    vacias.

    La marca de instancia es `demo_username()`, que exige **dos** cerrojos
    (`DEMO_MODE` y `DEMO_USERNAME`) justamente para que no se prenda por copiar
    un `.env` de una instancia a otra. Medido sobre las 10 instancias vivas:
    devuelve el usuario en las 8 demos y `None` en las 2 de cliente.
    """
    from .session_auth import demo_username  # circular: session_auth importa este modulo

    return demo_username() is None


def hay_terminos_pendientes(request: Request) -> bool:
    """`True` si esta instancia todavia no acepto la version vigente.

    🔴 **Sin `app.state.terminos` devuelve `False`, o sea NO gatea.** Es un
    opt-in por ausencia y hay que decirlo fuerte: un producto que se olvide de
    cablear el repositorio no falla, se queda sin gate y nadie se entera. La
    contramedida no es tecnica sino de verificacion — cada producto tiene que
    probar el corte, no asumirlo. Se eligio asi igual porque la alternativa
    (fallar duro si no esta cableado) rompe el arranque de cualquier consumidor
    que suba el pin sin tocar su factory, incluido el backoffice de superadmin,
    que no es una instancia de cliente y no tiene contrato que aceptar.

    Una demo tampoco tiene nada pendiente — ver `exige_aceptacion`. La exencion
    va **aca** y no solo en `exigir_terminos` porque esta funcion decide tambien
    el `pendiente` que devuelve el estado, y **el frontend bloquea la aplicacion
    entera con ese booleano** (`GateTerminos`, de libra-ui): exceptuar el 403 y
    dejar el estado en `true` cambiaria un muro del backend por uno del
    navegador.
    """
    if not exige_aceptacion():
        return False
    repo = getattr(request.app.state, "terminos", None)
    if repo is None:
        return False
    return not repo.esta_aceptada()


def exigir_terminos(request: Request, user: dict | None = None) -> None:
    """Corta con 403 si la instancia no acepto. La usan las dependencias de
    `session_auth` que gatean las APIs JSON.

    `user` ya no se mira: desde la v0.34.0 la exencion de la demo es **de la
    instancia** y la resuelve `hay_terminos_pendientes`. El parametro se
    conserva porque las tres dependencias de `session_auth` lo pasan, y sacarlo
    obligaria a tocarlas sin que cambie nada.
    """
    if hay_terminos_pendientes(request):
        raise HTTPException(
            status_code=403,
            detail={
                "code": CODIGO_PENDIENTE,
                "version": VERSION_VIGENTE,
                "mensaje": (
                    "Los Términos y Condiciones del Servicio están pendientes de "
                    "aceptación por el responsable de la cuenta."
                ),
            },
        )


class _EstadoTerminos(BaseModel):
    version: str
    vigente_desde: str
    hash_texto: str
    pendiente: bool
    puede_aceptar: bool
    aceptada_por: str | None = None
    aceptada_at: str | None = None
    #: 🔴 **Solo con `?texto=1`.** El contrato son ~30 KB y el frontend consulta
    #: este endpoint **en cada carga de la aplicacion** para saber si tiene que
    #: mostrar la pantalla bloqueante. Mandarlo siempre seria pagar el contrato
    #: entero, para todos los usuarios, todos los dias, para casi siempre
    #: contestar `pendiente: false` — y el texto solo lo necesita la pantalla
    #: que lo muestra, que se abre una vez por instancia.
    texto: str | None = None
    #: El mismo contrato en HTML, tambien solo con `?texto=1`. Va junto al
    #: Markdown y no en su lugar: el Markdown es lo que se hashea y lo que se
    #: puede verificar, el HTML es lo que la pantalla dibuja.
    texto_html: str | None = None


class _AceptarRequest(BaseModel):
    #: La version que el usuario tenia delante. Se compara con la vigente y se
    #: rechaza si no coinciden: sin esto, una pestania abierta desde antes de un
    #: deploy podria aceptar una version que ya no es la que se le mostro.
    version: str


def build_terminos_router(*, prefix: str = "/terminos") -> APIRouter:
    """Router de lectura y aceptacion.

    **No se gatea a si mismo** — y no es un detalle de estilo: si las rutas de
    este router pasaran por el mismo guard que el resto, el gate se cerraria
    sobre si mismo y no habria forma de aceptar. Por eso usa
    `json_api_get_current_user` (identidad, sin gate) y nunca
    `json_api_require_role` (identidad + gate).

    `prefix` configurable por la misma razon que en `build_json_api_auth_router`:
    Contalibra y Restolibra sirven su API bajo `/api`.
    """
    from .session_auth import json_api_get_current_user

    router = APIRouter(prefix=prefix, tags=["terminos"])

    def _repo(request: Request) -> TerminosRepository:
        repo = getattr(request.app.state, "terminos", None)
        if repo is None:
            # 500 y no 404: que el router este montado y el repositorio no
            # cableado es un error de armado del producto, no del que llama.
            raise HTTPException(
                status_code=500,
                detail="app.state.terminos no está configurado en esta instancia.",
            )
        return repo

    def _estado(request: Request, user: dict, incluir_texto: bool) -> dict:
        repo = _repo(request)
        aceptacion = repo.aceptacion_vigente()
        return {
            "version": VERSION_VIGENTE,
            "vigente_desde": VIGENTE_DESDE,
            "hash_texto": hash_vigente(),
            # 🔴 `exige_aceptacion()` y no solo `aceptacion is None`: en una demo
            # no hay contrato que aceptar, y **el frontend bloquea la aplicacion
            # entera con este booleano** (`GateTerminos`). Sin esto, exceptuar el
            # 403 del gate no alcanzaria: la demo quedaria trabada igual, del
            # lado del navegador y sin un solo 403 en los logs que lo explique.
            "pendiente": aceptacion is None and exige_aceptacion(),
            "puede_aceptar": user.get("role") in ROLES_QUE_ACEPTAN,
            "aceptada_por": (aceptacion or {}).get("nombre") or (aceptacion or {}).get("username"),
            "aceptada_at": (aceptacion or {}).get("aceptado_at"),
            "texto": texto_vigente() if incluir_texto else None,
            "texto_html": texto_html() if incluir_texto else None,
        }

    @router.get("", response_model=_EstadoTerminos)
    def estado(
        request: Request, texto: bool = False,
        user: dict = Depends(json_api_get_current_user),
    ):
        """El estado. Con `?texto=1` incluye el contrato completo — ver el
        comentario del campo `texto` en `_EstadoTerminos`."""
        return _estado(request, user, texto)

    @router.post("/aceptar", response_model=_EstadoTerminos)
    def aceptar(
        data: _AceptarRequest, request: Request,
        user: dict = Depends(json_api_get_current_user),
    ):
        repo = _repo(request)
        if user.get("role") not in ROLES_QUE_ACEPTAN:
            raise HTTPException(
                status_code=403,
                detail="Sólo el responsable de la cuenta puede aceptar los Términos.",
            )
        if data.version != VERSION_VIGENTE:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"La versión vigente es {VERSION_VIGENTE} y se intentó aceptar "
                    f"{data.version}. Recargá la página para ver el texto actual."
                ),
            )
        repo.registrar(
            usuario_id=_id_int(user.get("id")),
            username=user.get("username", ""),
            nombre=user.get("name", ""),
            ip=_ip_de(request),
            user_agent=request.headers.get("user-agent", ""),
        )
        # Sin texto: quien acaba de aceptar ya lo tiene en pantalla.
        return _estado(request, user, False)

    @router.get("/historial")
    def historial(request: Request, user: dict = Depends(json_api_get_current_user)):
        if user.get("role") not in ROLES_QUE_ACEPTAN:
            raise HTTPException(status_code=403, detail="Sólo el responsable de la cuenta.")
        return _repo(request).historial()

    return router


def _id_int(valor) -> int | None:
    """El repositorio devuelve `id` como **texto** (ver `_to_json_dict`), y la
    columna es entera. Sin esta conversion la FK guardaria una cadena, que en
    SQLite entra igual y en PostgreSQL corta el insert."""
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def _ip_de(request: Request) -> str:
    """La IP del cliente, mirando primero `X-Forwarded-For`.

    Las ocho instancias viven detras de Nginx Proxy Manager: sin este encabezado
    la IP registrada seria siempre la del proxy, y la prueba de la clausula 30.3
    quedaria diciendo lo mismo para todas las aceptaciones del VPS. Se toma el
    **primer** valor de la lista, que es el cliente original.
    """
    reenviada = request.headers.get("x-forwarded-for", "")
    if reenviada:
        return reenviada.split(",")[0].strip()
    return request.client.host if request.client else ""
