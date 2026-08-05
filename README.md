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

## Log de accesos (v0.8.0)

Quien entro, cuando, desde donde, y quien lo intento sin lograrlo. **Opt-in por
ausencia**: alcanza con setear `app.state.auth_events` y el router empieza a
anotar `login`, `logout` y `login_fallido`. Un consumidor que actualice el
motor y no lo setee no cambia de comportamiento en nada.

```python
from libraauth.auth_events import AuthEventRepository

app.state.auth_events = AuthEventRepository(session_factory)  # el mismo de siempre
```

La tabla es **`auth_log`**, con las mismas columnas que la que ya crea
`libracore.db.schema` en Contalibra y Restolibra — no es una tabla nueva para
esos dos, es la que ya tienen. La crea `AuthBase.metadata.create_all(engine)`
junto al resto.

Para leerlo desde el producto (una pantalla de logs, admin-only):

```python
repo = app.state.auth_events
repo.listar(limit=100, offset=0)      # mas reciente primero
repo.contar()
repo.contar_fallidos_recientes(ip)    # ventana de 15 minutos
```

Dos cosas que conviene saber antes de apoyarse en esto:

- **La IP sale de `X-Forwarded-For`**, porque los seis productos corren detras
  de Nginx Proxy Manager y `request.client.host` seria siempre el proxy. Ese
  header lo puede falsificar el cliente, asi que la IP **sirve para leer un
  log, no para decidir un bloqueo**.
- **Un error al registrar nunca tumba el login.** Se traga a proposito: la
  alternativa es que nadie pueda entrar al sistema porque falla el que anota
  que entraron.

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

## Config SMTP por backoffice, cifrada en reposo (v0.6.0)

Hasta la v0.5.0 el SMTP salia **solo** del entorno, asi que cambiarle el
remitente a una instancia obligaba a editar su compose en el VPS y recrear el
contenedor. Desde la v0.6.0 se puede guardar en la base y editar por pantalla.

**Adoptarla no cambia nada por si sola.** Sin fila guardada, la config se
sigue leyendo del entorno exactamente igual que antes.

```python
from libraauth.models import Base
from libraauth.session_auth import build_smtp_settings_router
from libraauth.smtp_settings import SmtpSettingsRepository, resolver_smtp_config

Base.metadata.create_all(engine)          # crea tambien `smtp_settings`

app.state.smtp_settings = SmtpSettingsRepository(session_factory)
app.include_router(build_smtp_settings_router())        # prefijo configurable

app.state.password_reset = PasswordResetService(
    session_factory,
    product_name="Gestiolibra",
    reset_url_base="...",
    # CALLABLE, no un valor: se resuelve en cada envio. Si se resolviera al
    # arrancar, guardar el SMTP por pantalla no tendria efecto hasta recrear
    # el contenedor — o sea, el problema que esta version viene a resolver.
    smtp_config=lambda: resolver_smtp_config(session_factory),
)
```

| Endpoint | Que hace |
|---|---|
| `GET /admin/smtp` | Estado actual. **Nunca devuelve la contrasena**, solo `password_definida` |
| `PUT /admin/smtp` | Guarda. Omitir `password` la conserva; mandarla en `null` o vacia la borra |
| `DELETE /admin/smtp` | Borra la config y vuelve a leer del entorno |

Los tres exigen **rol admin**: quien pueda escribir aca puede redirigir a
donde salen los enlaces de recuperacion de contrasena de todos los usuarios.

### La contrasena se guarda cifrada

Es la mitigacion que vuelve aceptable tener la credencial en la base del
cliente: sin cifrar, el backup de esa instancia alcanzaria para mandar correo
en su nombre.

- **AES-GCM**, con la clave **derivada por HKDF** del `SECRET_KEY` que la
  instancia ya tiene. Derivada y no reusada: la clave que cifra es distinta de
  la que firma la cookie de sesion.
- Se deriva del `SECRET_KEY` en vez de pedir una variable nueva **a
  proposito** — las instancias ya lo tienen, mientras que una variable nueva
  habria que agregarla a cada compose del VPS antes de que nada funcionara.
  `LIBRAAUTH_ENCRYPTION_KEY` tiene prioridad si se quiere separar.
- **Fail-closed**: sin ningun secreto en el entorno, guardar **falla** en vez
  de persistir la contrasena en claro.
- **Rotar el `SECRET_KEY`** deja lo guardado sin poder descifrarse. No
  revienta: la config queda marcada `password_indescifrable` y `configurado`
  da `False`, asi que el endpoint publico responde `503` ("no configurado",
  que es la verdad) en vez de un 500 al intentar el login SMTP. Se vuelve a
  cargar por pantalla.

Lo que **no** hace: no hay un endpoint de "mandar un mail de prueba". Hoy la
unica forma de comprobar que la config anda es pedir un reset de verdad.

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
