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

## Recuperacion de contrasena por correo (v0.5.0)

Opt-in: son dos endpoints mas en el router y un servicio propio, y **no se
prenden solos** porque necesitan SMTP y una pantalla del producto donde
aterrice el link.

```python
from libraauth.password_reset import PasswordResetService

app.state.password_reset = PasswordResetService(
    session_factory,                      # el mismo del UserRepository
    product_name="Gestiolibra",           # sale en el asunto y el cuerpo
    reset_url_base="https://dev.gestiolibra.com.ar/reset-password",
    ttl_minutes=60,                       # default
)
app.include_router(build_json_api_auth_router(incluir_password_reset=True))
```

SMTP **propio del motor**, por variables de entorno (no reusa el de
LibraCore: libraauth existe para que un producto que no factura no tenga que
arrastrarlo):

```
LIBRAAUTH_SMTP_HOST=smtp.empresa.com
LIBRAAUTH_SMTP_PORT=587              # default
LIBRAAUTH_SMTP_USER=cuenta           # opcional (relays internos sin auth)
LIBRAAUTH_SMTP_PASSWORD=...
LIBRAAUTH_SMTP_FROM_EMAIL=...        # si falta, usa LIBRAAUTH_SMTP_USER
LIBRAAUTH_SMTP_FROM_NAME=Soporte     # opcional
```

Sin SMTP configurado la app **levanta igual**; el que avisa es el endpoint,
con un `503`, recien cuando alguien pide un reset.

Endpoints:

| Endpoint | Que hace |
|---|---|
| `POST /auth/forgot-password` `{identificador}` | Acepta username **o** email. Responde **siempre** `{"ok": true}` |
| `POST /auth/reset-password` `{token, new_password}` | Cambia la contrasena. `400` si el enlace no sirve, `422` si la contrasena es corta |

Lo que hay que saber antes de tocarlo:

- **`forgot-password` responde igual exista o no el usuario.** Es a proposito:
  es publico y sin sesion, y una respuesta distinta lo convertiria en un
  buscador de usuarios y correos dados de alta. Hay un test que lo fija
  comparando status y cuerpo de los dos casos.
- **De la base no sale ningun token usable**: se guarda solo su `sha256`.
- **Un solo uso y con vencimiento** (60 min por defecto), y un reset exitoso
  quema tambien los demas tokens pendientes de ese usuario.
- **`reset-password` no crea sesion**: quien cambio la contrasena entra con
  ella, lo que ademas confirma que quedo bien.
- El reloj se inyecta (`now=`) para poder probar el vencimiento sin depender
  de la hora real.

Queda **afuera a proposito**: limitar la cantidad de pedidos por usuario/IP
(rate limiting). Hoy nada impide pedir muchos mails seguidos para la misma
cuenta; si se vuelve un problema, el lugar natural es el proxy, no el motor.

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
