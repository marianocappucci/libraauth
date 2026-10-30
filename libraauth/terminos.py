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
import logging
import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import date, datetime, timedelta, timezone
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

from .auth_events import ip_del_request
from .models import AceptacionTerminos
from .nodo import error_solo_en_el_central, es_nodo

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

#: **La próxima versión**, publicada pero todavía NO vigente (cláusula 29.2: se publica en el sitio y se notifica con
#: treinta días de anticipación). Mientras está acá el gate y el hash que se guarda como prueba siguen siendo los de
#: `VERSION_VIGENTE`; la publica `libra_web_kit.legal_gen`, al lado de la vigente, y el estado de `GET /terminos` la
#: anuncia como `proxima`, que el responsable puede aceptar por adelantado (ADR-024). El día que entra en vigencia se pasa a `VERSION_VIGENTE`/`VIGENTE_DESDE`/`ARCHIVO_TERMINOS` y estas tres
#: vuelven a `None`: recién ahí el sistema pide la nueva aceptación (cláusula 29.3).
#:
#: 1.1 (decisión del dueño, 2026-10-10): la cláusula 5.1 pasa de «más IVA» a «precio final con el IVA incluido» para
#: los ocho productos. Única diferencia con la 1.0.
VERSION_PROXIMA: str | None = "1.1"
PROXIMA_DESDE: str | None = "09-11-2026"
ARCHIVO_PROXIMA: Path | None = Path(__file__).parent / "legal" / "terminos_v1_1.md"

#: Una línea con lo que cambia, para el aviso de adentro del sistema (ADR-024). Va junto a la versión porque es del mismo
#: anuncio: el día que la próxima rige deja de mostrarse, igual que `VERSION_PROXIMA`. Texto plano, sin HTML.
RESUMEN_PROXIMA: str | None = "El abono mensual pasa a ser precio final con IVA incluido."

#: Argentina no tiene horario de verano: un desfase fijo, sin depender de la base de zonas de la imagen.
_ZONA_AR = timezone(timedelta(hours=-3))


def _hoy_argentina() -> date:
    """El día de hoy en Argentina. Es el punto que los tests fijan (`monkeypatch`)."""
    return datetime.now(_ZONA_AR).date()


def _fecha(ddmmaaaa: str) -> date:
    return datetime.strptime(ddmmaaaa, "%d-%m-%Y").date()


def _rige_la_proxima(hoy: date | None = None) -> bool:
    """`True` desde el `PROXIMA_DESDE` (00:00 de Argentina) en adelante (ADR-021).

    🔑 **La versión vigente se decide por fecha, no al desplegar.** La 1.1 se publica con los 30 días de la cláusula 29.2 y
    entra en vigencia sola ese día, en cada instancia, sin redeploy: el gate empieza a pedir la nueva aceptación aunque el
    proceso venga corriendo desde antes."""
    if not (VERSION_PROXIMA and PROXIMA_DESDE and ARCHIVO_PROXIMA):
        return False
    return (hoy or _hoy_argentina()) >= _fecha(PROXIMA_DESDE)


def version_vigente(hoy: date | None = None) -> str:
    """La versión que rige hoy: `VERSION_PROXIMA` desde su fecha, `VERSION_VIGENTE` antes. Usar esto y no la constante."""
    return VERSION_PROXIMA if _rige_la_proxima(hoy) else VERSION_VIGENTE  # type: ignore[return-value]


def vigente_desde(hoy: date | None = None) -> str:
    return PROXIMA_DESDE if _rige_la_proxima(hoy) else VIGENTE_DESDE  # type: ignore[return-value]


def _archivo_vigente(hoy: date | None = None) -> Path:
    return ARCHIVO_PROXIMA if _rige_la_proxima(hoy) else ARCHIVO_TERMINOS  # type: ignore[return-value]

#: Codigo que devuelve el gate en el `detail` del 403. El frontend matchea por
#: esto y no por el texto del mensaje.
CODIGO_PENDIENTE = "terminos_pendientes"

logger = logging.getLogger(__name__)


class ContratoSinCargar(RuntimeError):
    """La instancia debe tener Términos propios (marca blanca, ADR-030) y todavía no los cargó: no hay nada que registrar."""


#: Lo que ve quien entra a una instancia de revendedor cuyos Términos todavía no se cargaron. Sin nombre de proveedor a propósito:
#: este paquete no sabe quién es.
MENSAJE_SIN_CONTRATO = (
    "Esta cuenta todavía no tiene cargados sus Términos y Condiciones del Servicio, así que no se puede continuar. "
    "Avisale a tu proveedor."
)

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
    crudo = _archivo_vigente().read_bytes().decode("utf-8")
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


def _normalizado(archivo: Path) -> str:
    """El mismo tratamiento que `texto_vigente`: binario y CRLF/CR a LF a mano, para que el hash no dependa del checkout."""
    return archivo.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def texto_proximo() -> str | None:
    """El texto de la próxima versión (`VERSION_PROXIMA`), normalizado igual que el vigente; `None` si no hay una."""
    # Una vez que rige, deja de ser «próxima»: es la vigente.
    return _normalizado(ARCHIVO_PROXIMA) if VERSION_PROXIMA and ARCHIVO_PROXIMA and not _rige_la_proxima() else None


def texto_html_proximo() -> str | None:
    """La próxima versión en HTML, con el mismo convertidor que `texto_html`; `None` si no hay una."""
    texto = texto_proximo()
    if texto is None:
        return None
    import markdown  # local: solo lo necesita quien va a mostrar el texto

    return markdown.markdown(texto, extensions=["tables", "sane_lists"])


def hash_proximo() -> str | None:
    """sha256 hex de la próxima versión: el que se va a guardar como prueba cuando entre en vigencia."""
    texto = texto_proximo()
    return hashlib.sha256(texto.encode("utf-8")).hexdigest() if texto is not None else None


def proxima_anunciada() -> dict | None:
    """La próxima versión anunciada que todavía NO rige, o `None` (ADR-024).

    Es lo que ofrece el estado como `proxima` y lo que `POST /aceptar` admite además de la vigente. Una vez que la
    próxima rige deja de ser «próxima» y esto devuelve `None`: pasa a ser la vigente (`version_vigente`).
    **No mira si la instancia exige aceptación**: eso es de la instancia (`exige_aceptacion`), no del anuncio.
    """
    hash_texto = hash_proximo()
    if hash_texto is None or not (VERSION_PROXIMA and PROXIMA_DESDE):
        return None
    return {
        "version": VERSION_PROXIMA,
        "vigente_desde": PROXIMA_DESDE,
        "hash_texto": hash_texto,
        "resumen_del_cambio": RESUMEN_PROXIMA or None,
    }


#: Una versión propia es un identificador corto, no una frase: va en la fila probatoria y en la URL de la aceptación.
_VERSION_PROPIA = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,19}")

#: Tope del texto propio (en caracteres). El de la familia pesa ~30 KB; esto da mucho margen y acota lo que se lee y se hashea.
MAX_TEXTO_PROPIO = 300_000


def normalizar_texto(texto: str) -> str:
    """CRLF/CR a LF: lo que hace estable al hash, venga el texto de un archivo, de un formulario o de un `PUT` (ver `texto_vigente`)."""
    return texto.replace("\r\n", "\n").replace("\r", "\n")


class Contrato:
    """El contrato que rige en UNA instancia: versión, desde cuándo, el texto y su huella (ADR-030).

    Hay dos orígenes. **El de la familia** (`contrato_de_la_familia`) es el de siempre, el de los módulos de arriba. **Uno propio**
    (`propio=True`) es el que un revendedor de marca blanca carga para sus clientes: el producto lo entrega por el gancho
    `contrato_propio` de `TerminosRepository`.

    🔑 **El texto es perezoso a propósito.** El gate corre en CADA pedido gateado y casi siempre sólo necesita la versión; leer y
    hashear ~30 KB por cada uno sería pagar el contrato entero para contestar un booleano. `texto` puede ser un `str` o una función que
    lo trae, y se normaliza y se hashea una sola vez, la primera vez que alguien lo pide.
    """

    def __init__(self, *, version: str, vigente_desde: str, texto: str | Callable[[], str], propio: bool = False):
        self.version = version
        self.vigente_desde = vigente_desde
        self.propio = propio
        self._origen_del_texto = texto
        self._texto: str | None = None
        self._hash: str | None = None

    @property
    def texto(self) -> str:
        if self._texto is None:
            crudo = self._origen_del_texto() if callable(self._origen_del_texto) else self._origen_del_texto
            self._texto = normalizar_texto(crudo)
        return self._texto

    @property
    def hash(self) -> str:
        """sha256 hex del texto normalizado: la huella de la cláusula 30.3 (la de este contrato, no la de la familia)."""
        if self._hash is None:
            self._hash = hashlib.sha256(self.texto.encode("utf-8")).hexdigest()
        return self._hash

    def html(self) -> str:
        """El mismo texto en HTML, con el mismo convertidor que `texto_html` (ver ahí por qué es uno solo). No interviene en el hash."""
        import markdown  # local: solo lo necesita quien va a mostrar el texto

        return markdown.markdown(self.texto, extensions=["tables", "sane_lists"])

    @classmethod
    def propio_desde(cls, datos: Contrato | Mapping[str, object]) -> Contrato:
        """Un contrato propio a partir de lo que entrega el producto (un `dict` con `version`, `vigente_desde` y `texto`).

        Valida la forma: `ValueError` con una frase para mostrar si no cumple. **No valida el contenido legal**, eso es del humano.
        """
        if isinstance(datos, Contrato):
            return datos
        version = datos.get("version")
        desde = datos.get("vigente_desde")
        texto = datos.get("texto")
        if not isinstance(version, str) or not _VERSION_PROPIA.fullmatch(version):
            raise ValueError("version: hasta 20 caracteres (letras, números, punto, guion).")
        if not isinstance(desde, str):
            raise ValueError("vigente_desde: se espera dd-mm-aaaa.")
        try:
            _fecha(desde)
        except ValueError:
            raise ValueError("vigente_desde: se espera una fecha dd-mm-aaaa.") from None
        if not isinstance(texto, str) or not texto.strip():
            raise ValueError("texto: no puede estar vacío.")
        if len(texto) > MAX_TEXTO_PROPIO:
            raise ValueError(f"texto: máximo {MAX_TEXTO_PROPIO} caracteres.")
        return cls(version=version, vigente_desde=desde, texto=texto, propio=True)


def contrato_de_la_familia(version: str | None = None) -> Contrato:
    """El contrato de siempre, el de los módulos de arriba. Con `version` fija (`TerminosRepository(version=...)`), esa versión."""
    return Contrato(
        version=version or version_vigente(), vigente_desde=vigente_desde(), texto=texto_vigente, propio=False,
    )


class TerminosRepository:
    """Lectura y escritura de la prueba de aceptacion.

    `session_factory` es el mismo que recibe `UserRepository`: el engine donde
    vive `usuarios`, no el del dominio del producto.

    **Términos propios (ADR-030, marca blanca).** Dos ganchos opcionales; sin ellos el repositorio es el de siempre:

    - `contrato_propio`: función sin argumentos que devuelve el contrato de ESTA instancia (un `Contrato` o un `dict` con `version`,
      `vigente_desde` y `texto`) o `None` si no tiene uno. Se llama en cada pedido gateado: tiene que ser barata (el motor
      `libracore.terminos_propios` cachea por fecha de modificación del archivo).
    - `exigir_propio`: función sin argumentos; si devuelve `True` y no hay contrato propio, **no hay contrato**: el gate corta y nadie
      puede aceptar. Es lo que impide que la instancia de un revendedor caiga, por un descuido, a los términos de Libra.
    """

    def __init__(
        self,
        session_factory: Callable[[], AbstractContextManager[Session]],
        *,
        version: str | None = None,
        contrato_propio: Callable[[], Contrato | Mapping[str, object] | None] | None = None,
        exigir_propio: Callable[[], bool] | None = None,
    ):
        self.session_factory = session_factory
        # Sin `version` explícita, la que rige HOY (`version_vigente()`), resuelta en cada llamada: el día que entra la
        # próxima, el gate vuelve a pedir aceptación sin reiniciar el proceso (ADR-021).
        self._version_fija = version
        self._contrato_propio = contrato_propio
        self._exigir_propio = exigir_propio
        # El último contrato propio armado y la cosa de la que salió: si el producto devuelve el MISMO objeto (el caché de
        # `libracore.terminos_propios`), no se vuelve a armar ni a hashear.
        self._ultimo_origen: object | None = None
        self._ultimo_contrato: Contrato | None = None
        # Cache de "esta instancia ya acepto la version vigente". Se prende una
        # sola vez y no se vuelve a apagar: una aceptacion no se deshace, y la
        # unica forma de volver a pendiente es subir `VERSION_VIGENTE`, que llega
        # con una imagen nueva y por lo tanto con un proceso nuevo.
        #
        # Existe porque el gate corre en CADA request gateada: sin cache seria una
        # consulta mas por request para leer un booleano que casi siempre es True.
        self._aceptada_en: str | None = None

    def contrato(self) -> Contrato | None:
        """El contrato que rige en esta instancia, o `None` si **debería tener uno propio y todavía no lo cargó**."""
        propio = self._propio()
        if propio is not None:
            return propio
        if self._exigir_propio is not None and self._exigir_propio():
            return None
        return contrato_de_la_familia(self._version_fija)

    def _propio(self) -> Contrato | None:
        if self._contrato_propio is None:
            return None
        origen = self._contrato_propio()
        if origen is None:
            return None
        if origen is self._ultimo_origen and self._ultimo_contrato is not None:
            return self._ultimo_contrato
        try:
            contrato = Contrato.propio_desde(origen)
        except ValueError as exc:
            # Un texto propio roto NO puede tumbar cada pedido ni, peor, hacer caer a la instancia a otro contrato: se trata como
            # «sin contrato propio» y, si `exigir_propio` manda, la instancia queda frenada con el motivo en el log.
            logger.error("Los términos propios de la instancia no son válidos y se ignoran: %s", exc)
            return None
        self._ultimo_origen, self._ultimo_contrato = origen, contrato
        return contrato

    @property
    def version(self) -> str:
        contrato = self.contrato()
        return contrato.version if contrato is not None else ""

    def _clave_de_cache(self, contrato: Contrato) -> str:
        # Un contrato propio se identifica por versión Y hash: dos textos distintos con la misma versión no son «el mismo aceptado».
        return f"{contrato.version}#{contrato.hash}" if contrato.propio else contrato.version

    def aceptacion_de(self, version: str) -> dict | None:
        """La aceptacion de ESA version, o None si la instancia no la tiene."""
        with self.session_factory() as session:
            fila = session.execute(
                select(AceptacionTerminos)
                .where(AceptacionTerminos.version == version)
                .order_by(AceptacionTerminos.id.desc())
            ).scalars().first()
            return _a_dict(fila) if fila else None

    def aceptacion_vigente(self) -> dict | None:
        """La aceptacion de la version vigente, o None si la instancia no tiene.

        🔑 **Busca por versión, sin mirar cuándo se aceptó.** Por eso una aceptación adelantada de la próxima (ADR-024)
        vale sola el día que esa versión pasa a regir: la fila ya está, con su versión y su hash.
        """
        contrato = self.contrato()
        if contrato is None:
            return None
        if not contrato.propio:
            return self.aceptacion_de(contrato.version)
        # 🔑 Un contrato propio se busca por versión Y hash: si el revendedor cambia el texto sin cambiar la versión (o cambia de los
        # términos de Libra a los suyos con el mismo número, "1.0"), la aceptación vieja NO vale para el texto nuevo.
        with self.session_factory() as session:
            fila = session.execute(
                select(AceptacionTerminos)
                .where(AceptacionTerminos.version == contrato.version, AceptacionTerminos.hash_texto == contrato.hash)
                .order_by(AceptacionTerminos.id.desc())
            ).scalars().first()
            return _a_dict(fila) if fila else None

    def esta_aceptada(self) -> bool:
        # La cache es POR VERSIÓN: «ya aceptó la 1.0» no dice nada de la 1.1. (Sin contrato —un revendedor que todavía no cargó el
        # suyo— nada está aceptado, y no se toca la cache.)
        contrato = self.contrato()
        if contrato is None:
            return False
        clave = self._clave_de_cache(contrato)
        if self._aceptada_en == clave:
            return True
        hay = self.aceptacion_vigente() is not None
        if hay:
            self._aceptada_en = clave
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
        contrato = self.contrato()
        if contrato is None:
            raise ContratoSinCargar("Esta instancia debe tener Términos propios y todavía no los cargó.")
        clave = self._clave_de_cache(contrato)
        ya = self.aceptacion_vigente()
        if ya is not None:
            self._aceptada_en = clave
            return ya
        fila = self._guardar(
            version=contrato.version, hash_texto=contrato.hash, usuario_id=usuario_id,
            username=username, nombre=nombre, ip=ip, user_agent=user_agent,
        )
        self._aceptada_en = clave
        return fila

    def registrar_proxima(
        self, *, usuario_id: int | None, username: str, nombre: str,
        ip: str = "", user_agent: str = "",
    ) -> dict:
        """Deja la fila probatoria de la PRÓXIMA versión, aceptada por adelantado (ADR-024). Idempotente igual que `registrar`.

        Es la misma fila que una aceptación normal —versión, hash del texto, quién, IP, cuándo— y se lee en el mismo
        `historial`. **No toca la memoria de `esta_aceptada`**: aceptar la 1.1 no dice nada de la vigente. Levanta
        `ValueError` si ya no hay próxima (rige desde hoy, o se quitó): quien llama contesta 409.
        """
        contrato = self.contrato()
        # La próxima versión es de la familia: una instancia con términos propios (o que debería tenerlos) no la anuncia ni la acepta.
        proxima = proxima_anunciada() if contrato is not None and not contrato.propio else None
        if proxima is None:
            raise ValueError("No hay una próxima versión anunciada.")
        ya = self.aceptacion_de(proxima["version"])
        if ya is not None:
            return ya
        return self._guardar(
            version=proxima["version"], hash_texto=proxima["hash_texto"], usuario_id=usuario_id,
            username=username, nombre=nombre, ip=ip, user_agent=user_agent,
        )

    def _guardar(
        self, *, version: str, hash_texto: str, usuario_id: int | None, username: str, nombre: str,
        ip: str, user_agent: str,
    ) -> dict:
        with self.session_factory() as session:
            fila = AceptacionTerminos(
                usuario_id=usuario_id,
                username=(username or "")[:100],
                nombre=(nombre or "")[:200],
                version=version,
                hash_texto=hash_texto,
                aceptado_at=datetime.now(),
                ip=(ip or "")[:64],
                user_agent=(user_agent or "")[:400],
            )
            session.add(fila)
            session.commit()
            session.refresh(fila)
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

    **Un nodo de LibraEdge tampoco exige aceptar** (ADR-027). La aceptación es la prueba de la cláusula 30.3 y se hace
    una vez, en el central: una fila escrita en el nodo no llegaría a ningún lado (o la pisaría el espejo) y, mientras no
    bajara una, el gate dejaría al local entero sin poder vender por un contrato que el cliente ya aceptó en la web. Si
    el espejo trae la aceptación, `GET /terminos` la sigue mostrando.
    """
    from .session_auth import demo_username  # circular: session_auth importa este modulo

    return demo_username() is None and not es_nodo()


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
        contrato = request.app.state.terminos.contrato()
        if contrato is None:
            # Un revendedor de marca blanca cuya instancia todavía no tiene sus Términos: el mismo código (el frontend ya lo sabe
            # frenar) más `sin_contrato`. Nadie puede aceptar nada hasta que se carguen; NO se cae a los de Libra.
            raise HTTPException(
                status_code=403,
                detail={
                    "code": CODIGO_PENDIENTE,
                    "version": "",
                    "sin_contrato": True,
                    "mensaje": MENSAJE_SIN_CONTRATO,
                },
            )
        raise HTTPException(
            status_code=403,
            detail={
                "code": CODIGO_PENDIENTE,
                "version": contrato.version if contrato.propio else version_vigente(),
                "mensaje": (
                    "Los Términos y Condiciones del Servicio están pendientes de "
                    "aceptación por el responsable de la cuenta."
                ),
            },
        )


class _ProximaVersion(BaseModel):
    """El anuncio de la próxima versión dentro del estado (ADR-024). Sin próxima, el estado trae `proxima: null`."""

    version: str
    vigente_desde: str
    hash_texto: str
    #: Si esta instancia ya la aceptó por adelantado. El aviso del frontend se esconde con esto.
    aceptada: bool
    aceptada_por: str | None = None
    aceptada_at: str | None = None
    #: Una línea con lo que cambia (`RESUMEN_PROXIMA`).
    resumen_del_cambio: str | None = None
    #: Sólo con `?texto=1`, por la misma razón que los de la vigente: ~30 KB que el gate no necesita en cada carga.
    texto: str | None = None
    texto_html: str | None = None


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
    #: La próxima versión anunciada que todavía no rige, o `None` (ADR-024). Los campos de arriba no cambian por esto.
    proxima: _ProximaVersion | None = None
    #: `True` si el contrato de esta instancia es PROPIO (marca blanca, ADR-030) y no el de la familia.
    propio: bool = False
    #: `True` si la instancia debe tener Términos propios y todavía no los cargó: no hay nada que aceptar, `version` y `hash_texto`
    #: vienen vacíos y `puede_aceptar` es `False`. El frontend lo trata como una instancia frenada, igual que a `pendiente`.
    sin_contrato: bool = False


class _AceptarRequest(BaseModel):
    #: La version que el usuario tenia delante. Se compara con la vigente (o con la
    #: proxima anunciada, ADR-024) y se rechaza si no coincide con ninguna: sin esto,
    #: una pestania abierta desde antes de un deploy podria aceptar una version que
    #: ya no es la que se le mostro.
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

    def _proxima_para_esta_instancia(repo: TerminosRepository) -> dict | None:
        """El anuncio, o `None` si no hay, si esta instancia no tiene contrato que aceptar (una demo, ADR-024) o si su contrato es
        propio (ADR-030): la próxima versión es de la familia, y no se le anuncia a quien no se rige por ella."""
        contrato = repo.contrato()
        if contrato is None or contrato.propio:
            return None
        return proxima_anunciada() if exige_aceptacion() else None

    def _bloque_proxima(repo: TerminosRepository, incluir_texto: bool) -> dict | None:
        anuncio = _proxima_para_esta_instancia(repo)
        if anuncio is None:
            return None
        aceptacion = repo.aceptacion_de(anuncio["version"])
        return {
            **anuncio,
            "aceptada": aceptacion is not None,
            "aceptada_por": (aceptacion or {}).get("nombre") or (aceptacion or {}).get("username"),
            "aceptada_at": (aceptacion or {}).get("aceptado_at"),
            "texto": texto_proximo() if incluir_texto else None,
            "texto_html": texto_html_proximo() if incluir_texto else None,
        }

    def _estado(request: Request, user: dict, incluir_texto: bool) -> dict:
        repo = _repo(request)
        contrato = repo.contrato()
        if contrato is None:
            # Debe tener Términos propios y no los cargó (ADR-030): no hay nada que aceptar y nadie puede aceptar.
            return {
                "version": "", "vigente_desde": "", "hash_texto": "",
                "pendiente": exige_aceptacion(), "puede_aceptar": False,
                "aceptada_por": None, "aceptada_at": None, "texto": None, "texto_html": None,
                "proxima": None, "propio": True, "sin_contrato": True,
            }
        aceptacion = repo.aceptacion_vigente()
        if contrato.propio:
            version, desde, huella = contrato.version, contrato.vigente_desde, contrato.hash
            texto, html = (contrato.texto, contrato.html()) if incluir_texto else (None, None)
        else:
            version, desde, huella = version_vigente(), vigente_desde(), hash_vigente()
            texto, html = (texto_vigente(), texto_html()) if incluir_texto else (None, None)
        return {
            "version": version,
            "vigente_desde": desde,
            "hash_texto": huella,
            # 🔴 `exige_aceptacion()` y no solo `aceptacion is None`: en una demo
            # no hay contrato que aceptar, y **el frontend bloquea la aplicacion
            # entera con este booleano** (`GateTerminos`). Sin esto, exceptuar el
            # 403 del gate no alcanzaria: la demo quedaria trabada igual, del
            # lado del navegador y sin un solo 403 en los logs que lo explique.
            "pendiente": aceptacion is None and exige_aceptacion(),
            # En un nodo no se acepta (ADR-027): el boton no tiene que aparecer.
            "puede_aceptar": user.get("role") in ROLES_QUE_ACEPTAN and not es_nodo(),
            "aceptada_por": (aceptacion or {}).get("nombre") or (aceptacion or {}).get("username"),
            "aceptada_at": (aceptacion or {}).get("aceptado_at"),
            "texto": texto,
            "texto_html": html,
            "proxima": _bloque_proxima(repo, incluir_texto),
            "propio": contrato.propio,
            "sin_contrato": False,
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
        if es_nodo():
            raise error_solo_en_el_central("Los Términos se aceptan desde la versión web.")
        if user.get("role") not in ROLES_QUE_ACEPTAN:
            raise HTTPException(
                status_code=403,
                detail="Sólo el responsable de la cuenta puede aceptar los Términos.",
            )
        ident = dict(
            usuario_id=_id_int(user.get("id")),
            username=user.get("username", ""),
            nombre=user.get("name", ""),
            ip=ip_del_request(request),
            user_agent=request.headers.get("user-agent", ""),
        )
        contrato = repo.contrato()
        if contrato is None:
            raise HTTPException(status_code=409, detail=MENSAJE_SIN_CONTRATO)
        anuncio = _proxima_para_esta_instancia(repo)
        vigente = contrato.version if contrato.propio else version_vigente()
        if data.version == vigente:
            repo.registrar(**ident)
        elif anuncio is not None and data.version == anuncio["version"]:
            # Aceptación por adelantado (ADR-024): la misma fila y la misma regla de roles. El día que esta versión
            # rige, `aceptacion_vigente` la encuentra y la instancia no vuelve a quedar pendiente.
            try:
                repo.registrar_proxima(**ident)
            except ValueError:  # pasó a regir entre la lectura de arriba y el registro
                raise HTTPException(
                    status_code=409, detail="La versión cambió mientras se aceptaba. Recargá la página.",
                ) from None
        else:
            proxima_txt = f" y la próxima es {anuncio['version']}" if anuncio else ""
            raise HTTPException(
                status_code=409,
                detail=(
                    f"La versión vigente es {vigente}{proxima_txt} y se intentó aceptar "
                    f"{data.version}. Recargá la página para ver el texto actual."
                ),
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
