"""
`UserRepository`, adaptador SQLAlchemy sobre el modelo `Usuario` que expone
el contrato id/username/name/role/active esperado por
`libraauth.session_auth` (distinto del esquema real de la tabla —
id/username/nombre/email/role/activo) — mismo contrato que
`libracore.db.usuarios.UserRepository`, para que el patron de consumo sea
igual al del resto de la familia si se migra mas adelante.
"""
from contextlib import AbstractContextManager
from typing import Callable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .hashing import DUMMY_PASSWORD_HASH, hash_password, verify_password
from .models import Usuario


class UsernameTaken(Exception):
    """El username ya existe.

    Existe para que los consumidores no tengan que capturar la excepcion del
    motor de storage. Antes de esto, los routers de la familia hacian
    `except sqlite3.IntegrityError` — la excepcion cruda que filtraba la
    implementacion sqlite3 de `libracore.db.usuarios`—, asi que al migrar a
    este paquete (SQLAlchemy) el `except` dejaba de matchear y un username
    duplicado devolvia 500 en vez de 409. Se encontro migrando Gestiolibra el
    2026-07-30, con un test de ese repo en rojo; LibraDesk tenia el mismo bug
    latente, sin test que lo cubriera.
    """


def _to_json_dict(u: Usuario) -> dict:
    # `email` se agrego en v0.3.0. Es aditivo: los consumidores que no lo
    # esperaban lo ignoran. Se sumo porque Restolibra/Contalibra lo crean, lo
    # editan y lo DEVUELVEN en la API que consume su SPA — migrarlos sin esto
    # les borraba el campo de la pantalla de usuarios.
    return {
        "id": str(u.id),
        "username": u.username,
        "name": u.nombre,
        "email": u.email or "",
        "role": u.role,
        "active": bool(u.activo),
    }


class UserRepository:
    """`session_factory` es cualquier callable que devuelva un
    `Session` de SQLAlchemy usable como context manager (ej. el
    `sessionmaker(bind=engine)` del producto consumidor)."""

    def __init__(
        self,
        session_factory: Callable[[], AbstractContextManager[Session]],
        roles: tuple[str, ...] = ("admin", "staff"),
    ):
        self.session_factory = session_factory
        self.roles = roles

    def create(self, username: str, name: str, password: str, role: str,
               email: str = "") -> dict:
        if role not in self.roles:
            raise ValueError(f"invalid role: {role!r} (expected one of {self.roles})")
        with self.session_factory() as session:
            u = Usuario(
                username=username.strip(),
                nombre=name.strip(),
                email=(email or "").strip(),
                password_hash=hash_password(password),
                role=role,
                activo=True,
            )
            session.add(u)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                # `username` es la unica constraint UNIQUE de la tabla, pero se
                # chequea el mensaje para no convertir en UsernameTaken una
                # violacion futura de otra constraint.
                if "username" in str(exc.orig).lower():
                    raise UsernameTaken(username.strip()) from exc
                raise
            session.refresh(u)
            return _to_json_dict(u)

    def get_by_id(self, user_id: str) -> dict | None:
        try:
            uid = int(user_id)
        except ValueError:
            return None
        with self.session_factory() as session:
            u = session.get(Usuario, uid)
            return _to_json_dict(u) if u else None

    def get_by_username(self, username: str) -> dict | None:
        with self.session_factory() as session:
            u = session.execute(
                select(Usuario).where(Usuario.username == username)
            ).scalar_one_or_none()
            return _to_json_dict(u) if u else None

    def list(self) -> list[dict]:
        with self.session_factory() as session:
            rows = session.execute(
                select(Usuario).order_by(Usuario.role.desc(), Usuario.username)
            ).scalars()
            return [_to_json_dict(u) for u in rows]

    def update(self, user_id: str, name: str, role: str, active: bool,
               email: str | None = None) -> dict:
        """`email=None` **deja el valor como esta**, no lo borra.

        El default es None y no "" a proposito: los consumidores que ya existian
        llaman `update(id, name, role, active)` sin email, y con un default vacio
        cada edicion de nombre o rol les habria borrado el email en silencio.
        Para vaciarlo hay que pedirlo explicitamente con `email=""`.
        """
        if role not in self.roles:
            raise ValueError(f"invalid role: {role!r} (expected one of {self.roles})")
        uid = self._require_uid(user_id)
        with self.session_factory() as session:
            u = session.get(Usuario, uid)
            u.nombre = name.strip()
            u.role = role
            u.activo = active
            if email is not None:
                u.email = email.strip()
            session.commit()
            session.refresh(u)
            return _to_json_dict(u)

    def update_password(self, user_id: str, new_password: str) -> None:
        uid = self._require_uid(user_id)
        with self.session_factory() as session:
            u = session.get(Usuario, uid)
            u.password_hash = hash_password(new_password)
            session.commit()

    def delete(self, user_id: str) -> None:
        uid = self._require_uid(user_id)
        with self.session_factory() as session:
            u = session.get(Usuario, uid)
            session.delete(u)
            session.commit()

    def _require_uid(self, user_id: str) -> int:
        """Convierte el id de la URL a int y confirma que exista — un id
        no numerico es indistinguible de "no encontrado" para quien
        llama."""
        try:
            uid = int(user_id)
        except ValueError:
            raise KeyError(user_id)
        with self.session_factory() as session:
            if session.get(Usuario, uid) is None:
                raise KeyError(user_id)
        return uid

    def check_credentials(self, username: str, password: str) -> dict | None:
        """Siempre corre `verify_password` (contra un hash señuelo del
        mismo costo si el username no existe o esta inactivo), para que
        el tiempo de respuesta no delate si un username existe."""
        with self.session_factory() as session:
            u = session.execute(
                select(Usuario).where(
                    Usuario.username == username, Usuario.activo == True  # noqa: E712
                )
            ).scalar_one_or_none()
        stored_hash = u.password_hash if u else DUMMY_PASSWORD_HASH
        password_ok = verify_password(stored_hash, password)
        return _to_json_dict(u) if (u and password_ok) else None
