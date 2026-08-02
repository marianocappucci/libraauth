"""
Modelo SQLAlchemy de `usuarios`, mismas columnas que la tabla equivalente
de `libracore.db.usuarios` (schema sqlite3 crudo) por continuidad
conceptual, pero pensado para convivir en la misma base que el dominio
propio del producto consumidor — el producto llama
`Base.metadata.create_all(engine)` con el mismo engine que usa para sus
propias tablas.
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


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
