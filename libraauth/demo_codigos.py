"""
Codigos de acceso a la demo publica: emitirlos, listarlos, revocarlos y
consumirlos.

**Por que existe.** Hasta v0.25.x la demo se abria con `POST /auth/demo` sin
nada: cualquiera que supiera la URL entraba. Eso convertia a una instancia con
datos de muestra —que se arma para mostrarsela a un cliente concreto— en una
aplicacion abierta a internet. Desde v0.26.0 la demo pide un codigo, y los
codigos los emite el backoffice.

**De la base no sale ningun codigo usable.** Se guarda solo su sha256, igual
que `password_reset.py` y por el mismo motivo: un backup, un dump o el `.db` de
una instancia no tienen que alcanzar para entrar. El valor original existe una
sola vez, en la respuesta del alta — quien lo emite lo copia ahi o genera otro.

> ⚠️ Esa decision tiene un costo operativo real y conviene saberlo antes de
> apoyarse en esto: **un codigo emitido no se puede volver a leer**. Si se
> perdio, se revoca y se emite uno nuevo, que cuesta un click. La alternativa
> —guardarlo en claro para poder releerlo— deja credenciales de acceso
> legibles en todos los respaldos, que es un precio mucho mas alto por una
> comodidad que el boton "emitir otro" ya cubre.

**El hash es sha256 pelado y no PBKDF2**, a diferencia de las contrasenas. No
es un descuido: un codigo de estos son 12 caracteres aleatorios de un alfabeto
de 31 (~59 bits), no una palabra que alguien eligio. El estiramiento de clave
existe para compensar entropia baja, y aca no hay entropia baja que compensar.
Ademas permite buscar por indice: con PBKDF2 —salt distinto por fila— habria
que probar el codigo contra **todas** las filas activas, 260k iteraciones cada
una, en cada intento de ingreso.
"""
import hashlib
import secrets
from contextlib import AbstractContextManager
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import DemoCodigo

#: Alfabeto de los codigos. **Sin `I`, `L`, `O`, `0` ni `1`**: estos codigos se
#: dictan por telefono y se copian de un mensaje de WhatsApp, asi que un
#: caracter que se confunde con otro se paga en un cliente potencial que no
#: puede entrar y se va.
ALFABETO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

#: Largo del codigo sin separadores. 12 sobre un alfabeto de 31 son ~59 bits:
#: no es una contrasena maestra, es un codigo con vencimiento y tope de usos.
LARGO = 12

#: Cada cuantos caracteres va un guion al mostrarlo (`H7KQ-9MRT-2XVB`). Es
#: presentacion: `normalizar()` los ignora, asi que el visitante puede
#: tipearlo con guiones, sin guiones o en minuscula.
GRUPO = 4

#: Defaults del alta. Una semana y diez ingresos alcanzan para que alguien
#: recorra el sistema con calma, y son cortos como para que un codigo filtrado
#: deje de servir solo.
DIAS_DEFECTO = 7
USOS_DEFECTO = 10


class CodigoInvalido(Exception):
    """El codigo no sirve. `motivo` dice por que, para el log del servidor.

    🔴 **El motivo NO se le devuelve a quien intenta entrar.** La respuesta
    publica es siempre la misma, porque distinguir "no existe" de "vencio"
    le dice a quien esta probando codigos al azar cual de sus intentos estuvo
    cerca — el mismo criterio que `InvalidResetToken`.
    """

    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


def _utcnow() -> datetime:
    # Naive-UTC, igual que `password_reset._utcnow`: es lo que guarda
    # `server_default=func.now()` en SQLite, y mezclar aware con naive en la
    # misma columna hace que las comparaciones exploten.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generar_codigo() -> str:
    """Un codigo nuevo, ya formateado con guiones."""
    crudo = "".join(secrets.choice(ALFABETO) for _ in range(LARGO))
    return "-".join(crudo[i:i + GRUPO] for i in range(0, LARGO, GRUPO))


def normalizar(codigo: str) -> str:
    """Saca guiones, espacios y mayusculiza. **No descarta lo que no conoce**:
    un caracter raro llega hasta la comparacion y falla ahi.

    Que no descarte es deliberado. Filtrar los caracteres fuera del alfabeto
    haria que `H7KQ-9MRT-2XVB!` y `H7KQ-9MRT-2XVB` fueran el mismo codigo, y
    peor: que un codigo tipeado con una `O` donde va un `0` se "arregle"
    corriendose un lugar y falle sin que se entienda por que.
    """
    return "".join(c for c in (codigo or "").upper() if c not in " -_\t\n")


def hash_codigo(codigo: str) -> str:
    return hashlib.sha256(normalizar(codigo).encode()).hexdigest()


class DemoCodigoRepository:
    """ABM de codigos sobre la base de la propia instancia demo.

    Recibe el mismo `session_factory` que `UserRepository`, y por el mismo
    motivo: la tabla vive en el engine donde esta `usuarios`, que en
    Gestiolibra/MedLibra/VentaLibra no es la base del dominio.
    """

    def __init__(
        self,
        session_factory: Callable[[], AbstractContextManager[Session]],
        *,
        now: Callable[[], datetime] = _utcnow,
    ):
        self._sessions = session_factory
        self._now = now

    # ── Emitir ──────────────────────────────────────────────────────────────

    def crear(self, *, etiqueta: str = "", dias: int = DIAS_DEFECTO,
              usos_max: int = USOS_DEFECTO, emitido_por: str = "") -> dict:
        """Emite un codigo y lo devuelve **en claro, una sola vez**.

        `etiqueta` es a quien se le dio ("Estudio Perez", "feria de octubre").
        No la usa ninguna validacion: existe para que la lista del backoffice
        se pueda leer, porque una grilla de prefijos sin nombre no permite
        decidir cual revocar.
        """
        if dias < 1:
            raise ValueError("dias tiene que ser al menos 1")
        if usos_max < 1:
            raise ValueError("usos_max tiene que ser al menos 1")

        codigo = generar_codigo()
        ahora = self._now()
        with self._sessions() as s:
            fila = DemoCodigo(
                codigo_hash=hash_codigo(codigo),
                # Los primeros 4 caracteres, en claro. Es lo que permite
                # reconocer una fila en la lista sin guardar el codigo entero:
                # quien lo emitio lo tiene anotado y ubica cual es. Cuatro
                # caracteres de 12 no acortan una fuerza bruta a nada util.
                prefijo=normalizar(codigo)[:GRUPO],
                etiqueta=etiqueta.strip()[:200],
                emitido_por=emitido_por.strip()[:100],
                creado_at=ahora,
                expires_at=ahora + timedelta(days=dias),
                usos_max=usos_max,
                usos=0,
            )
            s.add(fila)
            s.commit()
            s.refresh(fila)
            datos = _a_dict(fila, ahora)
        # El codigo va aparte del resto: es la unica vez que se devuelve, y
        # queda claro en la firma que `listar()` no lo trae.
        return {**datos, "codigo": codigo}

    # ── Consultar y revocar ─────────────────────────────────────────────────

    def listar(self) -> list[dict]:
        """Todos los codigos, el mas nuevo primero. **Sin el codigo.**"""
        ahora = self._now()
        with self._sessions() as s:
            filas = s.scalars(
                select(DemoCodigo).order_by(DemoCodigo.id.desc())
            ).all()
            return [_a_dict(f, ahora) for f in filas]

    def revocar(self, codigo_id: int) -> dict:
        """Lo deja inservible sin borrar la fila: interesa saber que existio."""
        with self._sessions() as s:
            fila = s.get(DemoCodigo, codigo_id)
            if fila is None:
                raise LookupError(f"no existe el codigo {codigo_id}")
            fila.revocado = True
            s.commit()
            s.refresh(fila)
            return _a_dict(fila, self._now())

    def purgar(self) -> int:
        """Borra los vencidos hace mas de 30 dias. Opcional: nada depende de
        que se corra, igual que `PasswordResetService.purgar`."""
        corte = self._now() - timedelta(days=30)
        with self._sessions() as s:
            filas = s.scalars(
                select(DemoCodigo).where(DemoCodigo.expires_at <= corte)
            ).all()
            for f in filas:
                s.delete(f)
            s.commit()
            return len(filas)

    # ── Usar ────────────────────────────────────────────────────────────────

    def consumir(self, codigo: str) -> dict:
        """Valida el codigo y le suma un uso. Lanza `CodigoInvalido` si no
        sirve.

        🔴 **El chequeo y el incremento van en la misma transaccion.** Con dos
        pasos, dos ingresos simultaneos con el mismo codigo leen `usos=9` de
        un tope de 10 y los dos escriben 10: el tope se pasa por uno. Es el
        caso que un codigo de un solo uso vuelve visible.
        """
        if not normalizar(codigo):
            raise CodigoInvalido("vacio")
        ahora = self._now()
        with self._sessions() as s:
            fila = s.scalars(
                select(DemoCodigo)
                .where(DemoCodigo.codigo_hash == hash_codigo(codigo))
                .with_for_update()
            ).first()
            if fila is None:
                raise CodigoInvalido("desconocido")
            if fila.revocado:
                raise CodigoInvalido("revocado")
            if fila.expires_at <= ahora:
                raise CodigoInvalido("vencido")
            if fila.usos >= fila.usos_max:
                raise CodigoInvalido("agotado")
            fila.usos += 1
            fila.ultimo_uso = ahora
            s.commit()
            s.refresh(fila)
            return _a_dict(fila, ahora)


def _a_dict(f: DemoCodigo, ahora: datetime) -> dict:
    """La fila como la ve el backoffice. **Nunca incluye el codigo.**

    `estado` se calcula acá y no en el frontend porque depende del reloj del
    servidor: un navegador con la hora corrida mostraria "vigente" un codigo
    que la instancia ya rechaza.
    """
    if f.revocado:
        estado = "revocado"
    elif f.expires_at <= ahora:
        estado = "vencido"
    elif f.usos >= f.usos_max:
        estado = "agotado"
    else:
        estado = "vigente"
    return {
        "id": f.id,
        "prefijo": f.prefijo,
        "etiqueta": f.etiqueta or "",
        "emitido_por": f.emitido_por or "",
        "creado_at": f.creado_at.isoformat() if f.creado_at else None,
        "expires_at": f.expires_at.isoformat() if f.expires_at else None,
        "ultimo_uso": f.ultimo_uso.isoformat() if f.ultimo_uso else None,
        "usos": f.usos,
        "usos_max": f.usos_max,
        "estado": estado,
    }
