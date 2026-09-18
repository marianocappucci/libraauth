"""
Almacen de secretos de terceros de la instancia, cifrados en reposo (v0.46.0).

**Que problema resuelve.** El 2026-09-17 se midio que los tres secretos que
administra `libracore.config_manager` —`mp_access_token`, `mp_webhook_secret` y
`email_smtp_password`— vivian en `DATA_DIR/config.json` en texto plano, y se
decidio moverlos a la tabla cifrada de este paquete. El detalle de por que esa
tabla y no un cifrado propio del JSON esta en el docstring de
`models.SecretoInstancia`; el resumen es que un cuarto mecanismo de cifrado
habria traido su propio formato, su propio ciclo de rotacion y su propia sonda.

## Este repositorio no sabe que es cada secreto, y es a proposito

Guarda pares `clave -> valor`, cifra el valor y lo devuelve. No conoce
MercadoPago ni SMTP, no valida el formato de un token ni sabe cuales claves
existen: **quien las declara es el consumidor**. La lista canonica de las tres
de arriba vive en `libracore.config_manager.CLAVES_SECRETAS`, al lado del
codigo que las usa.

Esa ignorancia es la que permite que `libracore` —que **no depende de
libraauth**, y no va a empezar a depender (ver `comprobantes_router`)— use esto
igual: la clase de abajo expone `get`/`set` y nada mas, asi que el producto,
que ya tiene los dos paquetes, la pasa como almacen sin que ninguno de los dos
motores importe al otro.

## Lo que NUNCA sale de aca

El valor en claro hacia una respuesta HTTP. `estado()` devuelve si hay algo
cargado y si se puede leer, nunca el valor ni su largo; el descifrado se usa
solo para entregarselo al codigo que va a hablar con el tercero. Es el mismo
criterio que `smtp_settings`.
"""
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import SecretoIndescifrable, cifrar, descifrar_al_dia
from .models import SecretoInstancia


class SecretosRepository:
    """`session_factory` es el mismo del `UserRepository` del producto — el que
    apunta a la base donde este motor crea sus tablas."""

    def __init__(self, session_factory: Callable[[], AbstractContextManager[Session]]):
        self.session_factory = session_factory

    # ── Lectura ─────────────────────────────────────────────────────────────

    def leer(self, clave: str) -> tuple[str, bool]:
        """`(valor, legible)`: el valor en claro, y si se pudo descifrar.

        Devolver `("", True)` es "no hay nada guardado", que no es lo mismo que
        `("", False)` — "hay algo guardado y la clave de hoy no lo abre". Quien
        necesite distinguirlos usa esto; quien no, usa `get()`.
        """
        with self.session_factory() as session:
            fila = session.get(SecretoInstancia, clave)
            blob = fila.valor_cifrado if fila is not None else ""
        if not blob:
            return "", True
        try:
            return descifrar_al_dia(blob)[0], True
        except SecretoIndescifrable:
            return "", False

    def get(self, clave: str) -> str:
        """El valor en claro, o vacio si no hay ninguno **o no se puede leer**.

        🔴 **No lanza cuando el valor es indescifrable, a proposito.** Esto lo
        llama el codigo que esta por cobrar, facturar o mandar un correo, y una
        instancia con el `SECRET_KEY` rotado tiene que seguir levantando y
        comportarse como "sin credencial configurada" —que es la verdad— en vez
        de reventar con un 500. Es exactamente lo que hace
        `SmtpSettingsRepository.get()` con la contrasena.

        La contrapartida es que degrada **en silencio**, que es el defecto que
        la pagina del wiki sobre secretos en reposo señala como el problema de
        verdad. Quien tiene que verlo es la sonda, y para eso esta `estado()`.
        """
        return self.leer(clave)[0]

    def estado(self) -> dict[str, dict]:
        """Lo que se le puede mostrar a un humano **sin filtrar ningun secreto**.

        Por cada clave guardada: si hay algo cargado, si se puede descifrar, si
        se descifro con la clave **vigente** o con una anterior, y cuando se
        guardo. El valor no se devuelve nunca, ni enmascarado ni con su largo
        —eso ya seria decir cuantos caracteres tiene—.

        `al_dia=False` no es un error: el valor se leyo bien, con una clave
        declarada en `LIBRAAUTH_CLAVES_ANTERIORES`. Significa que **falta
        recifrarlo**, y por lo tanto que la variable de transicion todavia no se
        puede sacar. Es la señal que hace auditable el cierre de una rotacion, y
        es lo que la sonda tiene que mirar.
        """
        salida: dict[str, dict] = {}
        with self.session_factory() as session:
            filas = session.execute(select(SecretoInstancia)).scalars().all()
            for fila in filas:
                info = {
                    "cargado": bool(fila.valor_cifrado),
                    "legible": True,
                    "al_dia": True,
                    "actualizado_at": (
                        fila.actualizado_at.isoformat(sep=" ", timespec="seconds")
                        if fila.actualizado_at else ""
                    ),
                }
                if fila.valor_cifrado:
                    try:
                        info["al_dia"] = descifrar_al_dia(fila.valor_cifrado)[1]
                    except SecretoIndescifrable:
                        info["legible"] = False
                        info["al_dia"] = False
                salida[fila.clave] = info
        return salida

    def claves_cargadas(self) -> list[str]:
        """Las claves que tienen algo guardado, ordenadas. No dice si se pueden
        leer — para eso esta `estado()`."""
        return sorted(k for k, v in self.estado().items() if v["cargado"])

    # ── Escritura ───────────────────────────────────────────────────────────

    def set(self, clave: str, valor: str) -> None:
        """Guarda `valor` cifrado bajo `clave`. Un valor vacio **borra la fila**.

        Borrar y no guardar un blob vacio: una fila con `valor_cifrado` vacio
        contaria como "existe el secreto" en cualquier barrido que mire la
        tabla, y "sin credencial" tiene que verse igual que "nunca hubo una".

        `cifrar()` lanza `ClaveDeCifradoAusente` si la instancia no tiene ni
        `SECRET_KEY` ni `LIBRAAUTH_ENCRYPTION_KEY`. Se deja propagar a
        proposito: guardar el secreto en claro "porque no habia clave" seria
        justo lo que este modulo existe para impedir.
        """
        clave = (clave or "").strip()
        if not clave:
            raise ValueError("La clave del secreto no puede estar vacia.")
        if len(clave) > 100:
            raise ValueError(f"Clave demasiado larga ({len(clave)} > 100).")
        valor = "" if valor is None else str(valor)

        with self.session_factory() as session:
            fila = session.get(SecretoInstancia, clave)
            if not valor:
                if fila is not None:
                    session.delete(fila)
                    session.commit()
                return
            # Se cifra ANTES de tocar la fila: si falta la clave del entorno,
            # `cifrar` lanza y la fila vieja queda como estaba. Al reves, un
            # `set` que falla dejaria el secreto anterior borrado y el nuevo sin
            # guardar.
            blob = cifrar(valor)
            if fila is None:
                fila = SecretoInstancia(clave=clave)
                session.add(fila)
            fila.valor_cifrado = blob
            fila.actualizado_at = datetime.now()
            session.commit()

    def delete(self, clave: str) -> bool:
        """Borra el secreto y devuelve si habia algo que borrar."""
        with self.session_factory() as session:
            fila = session.get(SecretoInstancia, clave)
            if fila is None:
                return False
            session.delete(fila)
            session.commit()
            return True

    def recifrar(self) -> dict[str, list[str]]:
        """Deja todo lo guardado bajo la clave VIGENTE. Cierra una rotacion.

        Devuelve las tres listas `recifradas`, `al_dia` e `indescifrables`.

        🔑 **No lanza ante una fila ilegible, y por eso devuelve un informe en
        vez de un booleano.** `SmtpSettingsRepository.recifrar()` si lanza, y
        ahi esta bien: hay una sola fila, asi que la excepcion *es* el
        resultado. Aca hay N, y cortar en la primera que no se puede leer
        dejaria sin recifrar a todas las que vienen despues — o sea que una
        credencial rota impediria cerrar la rotacion de las sanas. Quien llama
        ve las tres listas y decide.

        Lo que **no** cambia es la garantia de `crypto.recifrar`: una fila que
        no se puede leer con ninguna clave conocida **no se toca**. Pisarla con
        algo cifrado con la clave nueva destruiria el unico rastro de lo que
        habia.
        """
        informe: dict[str, list[str]] = {
            "recifradas": [], "al_dia": [], "indescifrables": [],
        }
        with self.session_factory() as session:
            filas = session.execute(select(SecretoInstancia)).scalars().all()
            for fila in filas:
                if not fila.valor_cifrado:
                    informe["al_dia"].append(fila.clave)
                    continue
                try:
                    texto, al_dia = descifrar_al_dia(fila.valor_cifrado)
                except SecretoIndescifrable:
                    informe["indescifrables"].append(fila.clave)
                    continue
                if al_dia:
                    informe["al_dia"].append(fila.clave)
                    continue
                fila.valor_cifrado = cifrar(texto)
                fila.actualizado_at = datetime.now()
                informe["recifradas"].append(fila.clave)
            if informe["recifradas"]:
                session.commit()
        for lista in informe.values():
            lista.sort()
        return informe
