# LibraAuth

Motor transversal de autenticacion para la familia de productos Libra:
sesion por cookie firmada, hashing de contrasenas (PBKDF2) y tabla de
usuarios, sobre SQLAlchemy.

Extraido de `libracore.auth` / `libracore.db.usuarios` (sqlite3 crudo) para
que un producto que ya usa SQLAlchemy para su propio dominio no necesite
mantener una segunda base de datos separada solo para `usuarios`, ni
arrastrar las 28 tablas de facturacion/ARCA de `libracore.db` que no le
aplican.

**Primer consumidor: [LibraDesk](https://github.com/marianocappucci/libradesk)**
(sistema de tickets IT). Migrar el resto de la familia
(Contalibra/Restolibra/Gestiolibra/MedLibra/VentaLibra) desde
`libracore.db.usuarios` a este paquete queda pendiente, evaluado producto
por producto en otra sesion — no se tocan hoy.

Paquete interno privado, instalado por cada producto como dependencia via
tag de Git:

```
libraauth @ git+https://github.com/marianocappucci/libraauth.git@v0.1.0
```

## Uso

```python
from sqlalchemy.orm import sessionmaker
from libraauth.models import Base as AuthBase
from libraauth.repository import UserRepository
from libraauth.session_auth import SessionAuth, build_json_api_auth_router
from libraauth.bootstrap import ensure_default_admin

# 1. Crear las tablas de libraauth contra el mismo engine que el dominio propio
AuthBase.metadata.create_all(engine)

# 2. Repositorio de usuarios (misma sesion/engine que el resto del producto)
session_factory = sessionmaker(bind=engine)
users = UserRepository(session_factory)
ensure_default_admin(users, env_prefix="LIBRADESK")

# 3. SessionAuth + router /auth
session_auth = SessionAuth(
    dev_secret_fallback="dev-secret",
    get_user_by_username=users.get_by_username,
    check_credentials=users.check_credentials,
    cookie_name="libradesk_session",
)
app.state.users = users
app.state.session_auth = session_auth
app.include_router(build_json_api_auth_router())
```

## Desarrollo

```
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Versionado

Semver via tags de Git (`vX.Y.Z`), version derivada automaticamente del tag
via `hatch-vcs`. Cada producto pinea una version exacta (`==`), nunca un
rango abierto.
