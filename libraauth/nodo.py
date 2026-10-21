"""
Cómo se reconoce un **nodo de LibraEdge** y la guarda que le cierra las escrituras
de usuarios (v0.54.0, ADR-027).

**Qué es un nodo.** La PC del local que sirve el producto sin depender de internet
y espeja del central las tablas de referencia, entre ellas `usuarios`. Decisión del
humano (2026-10-21): **los usuarios del nodo son los del central**. Cada cajero entra
con su usuario y su clave de siempre aunque no haya conexión, y todo cambio de
usuarios se hace en el central y baja al volver la red. Una escritura sobre
`usuarios` hecha en el nodo es, entonces, un error en el mejor de los casos (la pisa
el espejo en la próxima bajada) y en el peor una cuña (un `admin` local con otro id
choca con `UNIQUE(username)` cuando baja el del central y traba el espejo).

**Cómo se lo reconoce.** Por `LIBRAEDGE_NODE_ID`, la misma variable con la que el
nodo se registra en el central (libraedge). Este módulo la lee por su cuenta y no
importa libraedge: libraauth es el motor de auth y no depende de nada de la familia.
Se lee en cada llamada, como el resto de las variables del paquete, así que un
cambio de entorno no depende de cuándo arrancó el proceso.

**Una sola guarda.** `exigir_central` (una dependencia de FastAPI, que también se
puede llamar a mano dentro de un handler) y `exigir_central_si_escribe` (la misma,
pero deja pasar las lecturas, para colgarla de un router entero). Contestan **409**
con `detail = {"code": "solo_en_el_central", "mensaje": ...}`: el frontend matchea
por el código y no por el texto, igual que con `terminos_pendientes`.
"""
import os

from fastapi import HTTPException, Request

#: La variable que define a un nodo. Definida y no vacía = esto es un nodo.
NODE_ID_ENV = "LIBRAEDGE_NODE_ID"

#: `detail["code"]` del 409. Es parte del contrato con el frontend.
CODIGO_SOLO_CENTRAL = "solo_en_el_central"

#: Mensaje humano de las escrituras de usuarios.
MENSAJE_USUARIOS_SOLO_CENTRAL = "Los usuarios se administran desde la versión web."

_METODOS_DE_LECTURA = frozenset({"GET", "HEAD", "OPTIONS"})


def es_nodo() -> bool:
    """`True` si este proceso es un nodo de LibraEdge (`LIBRAEDGE_NODE_ID` definida y no vacía)."""
    return bool(os.environ.get(NODE_ID_ENV, "").strip())


def error_solo_en_el_central(mensaje: str = MENSAJE_USUARIOS_SOLO_CENTRAL) -> HTTPException:
    """El 409 de «esto se hace en el central». Existe para que quien necesite otro mensaje (los Términos) no arme el
    `detail` a mano y el contrato con el frontend siga siendo uno solo."""
    return HTTPException(
        status_code=409,
        detail={"code": CODIGO_SOLO_CENTRAL, "mensaje": mensaje},
    )


def exigir_central() -> None:
    """Corta con 409 `solo_en_el_central` si esto es un nodo; en el central no hace nada.

    Sirve como dependencia (`Depends(exigir_central)`) y como llamada directa dentro de un handler, después de la
    identidad: así quien no tiene sesión sigue recibiendo su 401 y no se entera de si el servidor es un nodo."""
    if es_nodo():
        raise error_solo_en_el_central()


def exigir_central_si_escribe(request: Request) -> None:
    """`exigir_central`, pero sólo para los métodos que escriben. Se cuelga de un router entero (`dependencies=[...]`)
    y cubre también las rutas que se le agreguen mañana: las lecturas (`GET`) siguen andando en el nodo."""
    if request.method not in _METODOS_DE_LECTURA:
        exigir_central()
