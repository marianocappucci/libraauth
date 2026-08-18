"""
Modelo SQLAlchemy de `usuarios`, mismas columnas que la tabla equivalente
de `libracore.db.usuarios` (schema sqlite3 crudo) por continuidad
conceptual, pero pensado para convivir en la misma base que el dominio
propio del producto consumidor — el producto llama
`Base.metadata.create_all(engine)` con el mismo engine que usa para sus
propias tablas.
"""
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, func,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql.functions import FunctionElement


class Base(DeclarativeBase):
    pass


class ahora_local(FunctionElement):
    """La hora **local** como DEFAULT de tabla, en el dialecto que sea.

    Existe por una sola columna, `auth_log.ts`, pero el motivo es fuerte: esa
    tabla la escriben DOS lados —el ORM de este paquete y un `INSERT` crudo sin
    `ts` de `libracore.db.logs`, que se apoya en el DEFAULT—, y las dos mitades
    tienen que quedar en la misma zona horaria o el log de accesos sale con
    parte de los eventos corridos tres horas y mal ordenados entre si. Ver el
    comentario largo en `AuthLog.ts`.

    Estaba escrito como `text("(datetime('now','localtime'))")`, que es SQLite
    puro: contra PostgreSQL el `CREATE TABLE` falla con *"function
    datetime(unknown, unknown) does not exist"* y la instancia no arranca. Lo
    encontro el gate PostgreSQL del piloto LibraDesk el 2026-08-08.

    Como funcion compilada por dialecto, cada motor recibe su forma:

    - **SQLite** — `(datetime('now','localtime'))`, byte por byte lo que se
      emitia antes. Las bases que ya existen no ven ninguna diferencia.
    - **PostgreSQL** — `LOCALTIMESTAMP`, el equivalente directo: timestamp sin
      zona, en hora local.

    > ⚠️ En PostgreSQL "local" es la zona **de la sesion del servidor**
    > (`TimeZone`), no la del contenedor de la aplicacion. Con un sidecar por
    > instancia son el mismo host y coinciden si el contenedor de la base tiene
    > su `TZ` puesto; si algun dia no lo tuviera, los DEFAULT saldrian en UTC y
    > los `default=datetime.now` de Python en local — que es exactamente la
    > mezcla que esta clase existe para evitar. **Verificarlo al armar el
    > sidecar**, no asumirlo.
    """

    type = DateTime()
    inherit_cache = True


@compiles(ahora_local, "sqlite")
def _ahora_local_sqlite(element, compiler, **kw) -> str:
    return "(datetime('now','localtime'))"


@compiles(ahora_local, "postgresql")
def _ahora_local_postgresql(element, compiler, **kw) -> str:
    return "LOCALTIMESTAMP"


@compiles(ahora_local)
def _ahora_local_default(element, compiler, **kw) -> str:
    # Cualquier otro motor: el estandar SQL. Ningun producto de la familia usa
    # uno hoy, y fallar aca por no tener rama seria peor que emitir esto.
    return "LOCALTIMESTAMP"


class Usuario(Base):
    __tablename__ = "usuarios"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    nombre: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="operador")
    activo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class PasswordResetToken(Base):
    """Token de recuperacion de contrasena por correo (v0.5.0).

    **Se guarda solo el hash del token, nunca el token en si** — mismo
    criterio que las contrasenas: quien lea la base (un backup, un dump, el
    `.db` de un cliente) no puede usar los tokens que encuentre ahi para
    entrar como otro usuario. El valor original existe una sola vez, en el
    mail que se manda.

    Vive en el mismo `Base` que `Usuario` a proposito: los consumidores
    corren `Base.metadata.create_all(engine)` contra el engine donde esta
    `usuarios` —que en Gestiolibra/MedLibra/VentaLibra es la base de
    LibraCore, no la del dominio—, asi que la FK resuelve contra la tabla
    correcta. Una tabla con FK a una `usuarios` que no esta en el mismo
    archivo rompe todos los inserts, no solo los que usan la FK.
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # sha256 hex del token: 64 caracteres, unico para que dos tokens no puedan
    # colisionar en silencio.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Sello de un solo uso. `None` = todavia no se uso.
    used_at: Mapped[datetime | None] = mapped_column(DateTime)


class AuthEvent(Base):
    """Un evento de autenticacion: login, logout o intento fallido (v0.8.0).

    **La tabla se llama `auth_log` y no `auth_events` a proposito.** Es la
    misma tabla, con las mismas columnas, que `libracore.db.schema` ya crea en
    Contalibra y Restolibra desde el sqlite3 crudo. Un nombre nuevo habria
    dejado dos tablas con el mismo contenido en la misma base de esos dos
    productos el dia que adopten este repositorio, y ninguna forma obvia de
    saber cual mirar. Con este nombre, `create_all()` encuentra la tabla ya
    creada, no la toca, y las filas viejas siguen siendo legibles.

    **`ts` se calcula en Python (`datetime.now`) y no con `func.now()`**, que
    es lo que usa el resto de este modulo. No es una inconsistencia por
    descuido: `func.now()` en SQLite es `CURRENT_TIMESTAMP`, que devuelve
    **UTC**, mientras la fila que escribe LibraCore usa
    `datetime('now','localtime')`. Con `func.now()`, una base que recibiera
    escrituras de los dos lados quedaria con la mitad de los eventos tres
    horas corridos y ordenados mal entre si — y un log de accesos con la hora
    mal es peor que no tenerlo, porque se lee justo cuando alguien esta
    buscando quien entro y cuando. `datetime.now` da la hora local del
    proceso, que es lo mismo que hace `localtime` en el mismo contenedor.

    No declara FK a `usuarios`: un intento **fallido** trae un username que
    puede no existir, y esa es justamente la fila que mas interesa guardar.
    Por eso se guarda el texto del username y no un id.
    """

    __tablename__ = "auth_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # 🔴 `server_default` ADEMAS del default de Python, y no en su lugar.
    #
    # El default de Python solo aplica a las escrituras del ORM. Pero en
    # Contalibra y Restolibra el otro escritor es `libracore.db.logs`, que hace
    # un `INSERT INTO auth_log (evento, username, ip, detalle)` **crudo, sin
    # `ts`**, contando con el DEFAULT de la tabla. Sin esta clausula, una tabla
    # creada por `create_all()` sale sin DEFAULT y ese INSERT explota con
    # `NOT NULL constraint failed: auth_log.ts`.
    #
    # No se nota en las instancias que ya existen —ahi la tabla la creo
    # LibraCore, con su DEFAULT, y `create_all` no altera lo que ya esta—: se
    # nota **solo en bases nuevas**, o sea en cada instancia que se cree de
    # ahora en adelante, y recien cuando alguien intenta entrar. Lo encontro el
    # bump de Contalibra el 2026-08-06: 148 tests verdes pasaron a 101 errores.
    #
    # El literal es identico al de `libracore.db.schema` a proposito, incluido
    # el `localtime`: con `func.now()` (que en SQLite es UTC) una base escrita
    # desde los dos lados quedaria con la mitad de los eventos tres horas
    # corridos.
    #
    # Se emite via `ahora_local()` y no como `text(...)` para que el mismo
    # DEFAULT exista tambien en PostgreSQL — en SQLite el DDL resultante no
    # cambia. Ver el docstring de esa clase, arriba.
    ts: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.now,
        server_default=ahora_local(),
    )
    evento: Mapped[str] = mapped_column(String(50), nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    # Nulables, como la tabla de LibraCore: las filas de esos dos productos
    # vienen de ahi y una constraint mas estricta del lado del modelo haria que
    # `create_all` cree una tabla incompatible con el mismo INSERT crudo.
    ip: Mapped[str] = mapped_column(String(64), nullable=True, default="")
    detalle: Mapped[str] = mapped_column(String(500), nullable=True, default="")


class SmtpSettings(Base):
    """Configuracion SMTP de la instancia, editable por backoffice (v0.6.0).

    **Una sola fila**, con `id` fijo en 1 (ver `FILA_UNICA` en
    `smtp_settings.py`). No es una tabla clave/valor generica a proposito:
    son seis campos con tipo y semantica propia, y una tabla de pares los
    volveria strings sueltos sin validacion.

    **`password_cifrada` NO guarda la contrasena en claro** — guarda el blob
    de `crypto.cifrar()`, cuya clave vive en el entorno de la instancia. El
    nombre de la columna lo dice a proposito: quien abra un backup con un
    visor de SQLite tiene que ver de inmediato que ese valor no sirve tal
    cual. Ver `crypto.py` para por que este cifrado es la mitigacion que la
    decision de guardar el SMTP en base vuelve necesaria.

    Vive en el mismo `Base` que `Usuario` por la misma razon que
    `PasswordResetToken`: los consumidores corren
    `Base.metadata.create_all(engine)` una sola vez, contra el engine donde
    esta `usuarios`. Esta tabla no declara FK, asi que **podria** vivir en
    otra base — pero separarla obligaria al producto a manejar dos engines
    para este motor sin ninguna ganancia que lo justifique.
    """

    __tablename__ = "smtp_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=587)
    user: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # Texto y no String(n): el blob crece con el largo de la contrasena y no
    # hay motivo para ponerle un techo arbitrario.
    password_cifrada: Mapped[str] = mapped_column(Text, nullable=False, default="")
    from_email: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    from_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class DemoCodigo(Base):
    """Un codigo de acceso a la demo publica (v0.26.0).

    **Se guarda solo el sha256 del codigo**, mismo criterio que
    `PasswordResetToken`: quien lea la base no puede entrar con lo que
    encuentre ahi. El `prefijo` si va en claro, y es a proposito — cuatro de
    doce caracteres no acortan una fuerza bruta a nada util, y sin ellos la
    lista del backoffice seria una grilla de filas indistinguibles.

    Vive en el mismo `Base` que `Usuario` por la razon de siempre: los
    consumidores corren `Base.metadata.create_all(engine)` una sola vez, contra
    el engine donde esta `usuarios`.

    > 🔑 **Y de eso sale que la tabla no necesita migracion.** En los seis
    > productos las tablas de este paquete las crea `create_all()`, no la
    > cadena de Alembic del producto (ver `migrations/env.py` de LibraDesk):
    > al subir el pin, la tabla aparece sola en el proximo arranque. Lo que
    > **si** cambia de comportamiento es que la demo deja de abrirse sin
    > codigo — ver `session_auth`, seccion demo.

    No declara FK a `usuarios`: el codigo autoriza a entrar *como el visitante
    de la demo*, que es uno solo y sale de `DEMO_USERNAME`. Atarlo a un id de
    usuario sugeriria que se pueden emitir codigos para entrar como cualquiera,
    que es justo lo que no tiene que poder hacerse.
    """

    __tablename__ = "demo_codigos"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # sha256 hex: 64 caracteres. Unico e indexado — es la columna por la que se
    # busca en cada intento de ingreso.
    codigo_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    # Los primeros 4 caracteres en claro, para reconocerlo en la lista.
    prefijo: Mapped[str] = mapped_column(String(8), nullable=False, default="")
    # A quien se le dio. Libre y opcional: no lo mira ninguna validacion.
    etiqueta: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # Quien lo emitio. Lo llena el router con el usuario del backoffice.
    emitido_por: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    creado_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Tope de ingresos y cuantos van. El tope es una columna y no una constante
    # porque no es lo mismo un codigo para una reunion con un cliente que uno
    # para una feria.
    usos_max: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    usos: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ultimo_uso: Mapped[datetime | None] = mapped_column(DateTime)
    # Baja logica. La fila no se borra: interesa saber que ese codigo existio y
    # cuantas veces se uso antes de cortarlo.
    revocado: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
