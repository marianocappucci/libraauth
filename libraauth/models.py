"""
Modelo SQLAlchemy de `usuarios`, mismas columnas que la tabla equivalente
de `libracore.db.usuarios` (schema sqlite3 crudo) por continuidad
conceptual, pero pensado para convivir en la misma base que el dominio
propio del producto consumidor — el producto llama
`Base.metadata.create_all(engine)` con el mismo engine que usa para sus
propias tablas.
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
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
