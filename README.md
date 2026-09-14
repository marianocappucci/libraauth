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

- **La IP sale de `X-Forwarded-For`, leido desde la derecha** (v0.39.0),
  porque los productos corren detras de Nginx Proxy Manager y
  `request.client.host` seria siempre el proxy. NPM no reemplaza el header: le
  agrega el par TCP al final, y lo de la izquierda lo escribe el cliente. Se
  saltean los proxies de confianza (`REDES_DE_CONFIANZA`: redes privadas y
  loopback) y el primero que no lo es es el cliente; y el header se ignora si
  el par directo no es un proxy. Hasta v0.38.0 se tomaba el **primer**
  elemento, y cambiarlo en cada intento esquivaba el bloqueo por IP. Un salto
  mas (un CDN delante de NPM) se declara con `LIBRAAUTH_PROXIES_DE_CONFIANZA`,
  redes separadas por coma que **se suman** a las privadas.
- **Un error al registrar nunca tumba el login.** Se traga a proposito: la
  alternativa es que nadie pueda entrar al sistema porque falla el que anota
  que entraron.

## Captcha «No soy un robot» (v0.40.0)

`build_json_api_auth_router(captcha=True)` agrega `GET /auth/captcha` y exige
el campo `captcha` en `POST /auth/login` y `POST /auth/forgot-password`. Es
[ALTCHA](https://altcha.org): una prueba de trabajo que el navegador resuelve
en alrededor de un segundo, emitida y verificada en el propio servidor —sin
proveedor externo, sin cookies y sin tocar la CSP—. El widget va en
`createLogin({ captchaPath })` de libra-ui. ADR-014.

- Las claves se derivan del `SECRET_KEY` por HKDF: no hay variable nueva, y
  rotar el secreto solo invalida los desafios en curso.
- Cada desafio sirve **una vez** y vence a los diez minutos.
- El bloqueo por IP corta antes; un captcha que falta o no vale es un 400 y
  **no** suma intentos fallidos.
- Fuera del router (el backoffice): `Captcha(secret_key)`, con `emitir()` y
  `verificar(payload)`. Tiene que ser **uno por proceso**: la lista de
  desafios usados vive adentro.

## Log de actividad (v0.9.0)

Quien creo, edito o borro que, y que cambio. **No se siembran llamadas en los
repositorios**: el registro cuelga del `flush` de SQLAlchemy, asi que una
escritura que no pase por ahi no existe y un metodo de escritura nuevo queda
auditado sin que nadie se acuerde.

```python
from libraauth.auditoria import (
    AuditoriaBase, AuditoriaRepository, agregar_middleware_de_usuario,
    configurar_auditoria,
)

# La tabla va en la base del DOMINIO, no en la de `usuarios` -- ver abajo.
AuditoriaBase.metadata.create_all(engine_del_dominio)

configurar_auditoria(sessions, {
    "Cliente": "cliente",          # {clase del modelo: nombre logico}
    "Appointment": "turno",
})
app.state.auditoria = AuditoriaRepository(sessions)
agregar_middleware_de_usuario(app)   # sella el usuario de la cookie
```

**`AuditoriaBase` es un `Base` propio, separado del de `models.py`.** La tabla
tiene que quedar donde ocurren las escrituras que audita, y eso **no** siempre
es donde vive `usuarios`: en Gestiolibra, MedLibra y VentaLibra `usuarios` esta
en la base de LibraCore y el dominio en la de LibraGenda/LibraCommerce.

**La lista es blanca, no negra.** Una tabla nueva no entra sola. Las que YA son
historial de algo (los movimientos de un equipo, la linea de tiempo de un
ticket) tienen que quedar afuera: su ficha ya las muestra, y auditarlas pondria
el mismo hecho dos veces en la misma pantalla.

Tres cosas mas que conviene saber:

- **Un `UPDATE` que no cambia nada no deja fila.** Un log lleno de "editado"
  vacios es un log que nadie lee.
- **Las columnas secretas no entran al diff** (`password*`, `token*`, `secret*`,
  `api_key`). El producto suma las suyas con `columnas_ocultas={...}`.
- **Se puede apagar por sesion** con `session.info["auditoria"] = False`, para un
  seed o una migracion de datos, que no son actividad de nadie.

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

## Segundo factor y lockout persistido del backoffice (v0.36.0)

`AdminAuth` acepta dos variables de entorno nuevas, las dos opcionales:

| Variable | Efecto |
|---|---|
| `ADMIN_PANEL_TOTP_SECRET` | Secreto base32 del autenticador. Con esto seteado, `check_credentials(username, password, codigo=...)` exige ademas el codigo TOTP de 6 digitos; cada codigo sirve una sola vez. |
| `ADMIN_PANEL_ESTADO_PATH` | Archivo JSON donde viven los intentos fallidos por IP y el ultimo codigo usado. Con esto, el bloqueo por 5 intentos en 15 minutos **sobrevive al reinicio del contenedor**. |

Enrolar al superadmin:

```
python -m libraauth.totp <producto>
```

Imprime `ADMIN_PANEL_TOTP_SECRET=...` y la URI `otpauth://` para el
autenticador (Google Authenticator, Authy, 1Password, Bitwarden). El secreto se
muestra una sola vez. Un secreto mal cargado frena el arranque con
`RuntimeError`, a proposito: un segundo factor que nunca valida parece que esta.

Un archivo de estado ilegible o no escribible **no apaga** el rate limiting:
sigue en memoria y lo avisa por log. Ver ADR-009 en `DECISIONS.md`.

## TOTP enrolable en runtime, con QR (v0.41.0)

Ademas de `ADMIN_PANEL_TOTP_SECRET` (arriba), el segundo factor se puede
**enrolar desde la app**, sin tocar el `.env` ni recrear el contenedor — el
interruptor "habilitar doble factor" del backoffice:

| Variable | Efecto |
|---|---|
| `ADMIN_PANEL_TOTP_PATH` | Archivo JSON donde vive el secreto enrolado en runtime. Si no esta seteada y **si** `ADMIN_PANEL_ESTADO_PATH` lo esta, se usa el hermano `totp.json` del mismo directorio. Sin ninguna de las dos, no es enrolable. |

API de `AdminAuth`:

```python
a.totp_origen       # "entorno" | "archivo" | None
a.totp_habilitado    # True con secreto activo (entorno o archivo) o con el archivo roto
a.totp_enrolable     # hay ruta de archivo y el origen no es "entorno"

datos = a.iniciar_totp("superadmin")      # {"secreto": "...", "uri": "otpauth://..."}
# mostrar datos["uri"] como QR (o el secreto a mano) y pedir el codigo del autenticador
a.confirmar_totp(codigo)                  # True: activa el secreto pendiente
a.desactivar_totp(codigo)                 # True: apaga el segundo factor por archivo
```

- **Con `ADMIN_PANEL_TOTP_SECRET` seteado, el entorno manda**: `totp_origen`
  es `"entorno"` y `iniciar_totp` / `confirmar_totp` / `desactivar_totp`
  levantan `TotpNoEnrolable`.
- **Enrolar son dos pasos a proposito**: `iniciar_totp` genera un secreto
  PENDIENTE (no lo activa) y devuelve el QR; `confirmar_totp` con el primer
  codigo del autenticador recien lo vuelve el secreto activo. El pendiente
  vence a los 10 minutos si no se confirma.
- **El archivo roto falla CERRADO** (al reves que el estado de login, que
  falla abierto): ilegible, JSON invalido o con forma inesperada deja
  `totp_habilitado=True` con el login cerrado hasta borrar el archivo a mano
  desde el host. Ver ADR-015 en `DECISIONS.md`.
- Escritura atomica con permisos `0600`, igual convencion que el estado de
  login.

## Login en dos pasos del backoffice (v0.42.0)

Ademas de `check_credentials(username, password, codigo)` — que sigue igual,
para quien no migro a la pantalla de dos pasos — `AdminAuth` tiene la API
para pedir usuario y contrasena primero, y recien despues un segundo paso
para el codigo del autenticador:

```python
# Paso 1: usuario y contrasena
if not a.verificar_clave(username, password):
    ...  # 401

if a.totp_habilitado:
    desafio = a.emitir_desafio_totp(username)   # mostrarlo al frontend
    # ... el frontend abre el modal del codigo y lo manda de vuelta junto con `desafio`
else:
    a.create_session_cookie(response, username)  # sin 2FA, ya esta

# Paso 2: el codigo, contra el desafio del paso 1
username = a.validar_desafio_totp(desafio)
if username is None:
    ...  # 401: desafio vencido, alterado o de otra firma
if not a.verificar_codigo_totp(codigo):
    ...  # 401: codigo invalido o ya usado
a.create_session_cookie(response, username)
```

- `emitir_desafio_totp` / `validar_desafio_totp`: token firmado
  (`itsdangerous`) con un **salt propio**, distinto del que firma la cookie
  de sesion — el desafio no sirve como cookie ni la cookie como desafio.
  Vence a los `DESAFIO_TOTP_SEGUNDOS` (5 minutos). Sin estado en el
  servidor: el username va en el payload firmado.
- `verificar_codigo_totp` valida contra el TOTP activo ahora mismo (entorno
  o archivo). El contador de "ultimo codigo usado" es **el mismo** que usa
  `check_credentials`: un codigo gastado en un camino no sirve en el otro.
  Sin 2FA activo, siempre `False` — el paso 2 no existe sin segundo factor.
- **Con 2FA encendido, el paso 1 revela que la contrasena es correcta**
  (antes, clave mal y codigo mal daban el mismo 401). Lo mitigan el captcha,
  el bloqueo por IP, y que la sesion en si sigue exigiendo el codigo. Ver
  ADR-016 en `DECISIONS.md`.

## Sesion por inactividad de 8 horas, con renovacion deslizante (v0.43.0)

`SessionAuth` (login del usuario final) y `AdminAuth` (backoffice de
superadmin) cierran la sesion a las **8 horas sin uso**, no a un plazo fijo
desde el login. "Uso" es cualquier pedido al servidor que pase por una de las
dependencias de este paquete (`require_auth`, `require_admin`, `require_role`,
`json_api_get_current_user` y los guards que cuelgan de ella; `require_login`
del lado de `AdminAuth`): cada uno de esos pedidos, si la sesion sigue viva,
re-firma la cookie con timestamp nuevo — misma cookie, mismos atributos, el
reloj de las 8 horas vuelve a arrancar desde ese pedido. Una pantalla que se
refresca sola (el KDS) sigue contando como uso mientras este abierta.

**Llega solo con subir el pin, en casi todos los consumidores.** FastAPI
inyecta un `Response` real en cualquier funcion usada con `Depends(...)` que
lo declare, aunque el endpoint que la usa no lo declare el — asi que la
renovacion viaja adentro de las dependencias de siempre, sin que el producto
tenga que agregar nada. La excepcion es un consumidor que **envuelve**
`SessionAuth.get_current_user` o `AdminAuth.current_user` en su propia
dependencia sin declarar `response` y pasarlo: relevados, la API JSON de
Contalibra y Restolibra (`get_current_user_json`) y el `admin_actual` de
`libra-backoffice`. A esos les hace falta una linea propia (ver ADR-017).
Sin esa linea no se rompe nada: la sesion sigue valida, pero no se renueva.

```python
from libraauth.session_auth import (
    INACTIVIDAD_MAXIMA_SEGUNDOS,  # 8 * 3600 — default de `max_age`
    RENOVACION_MINIMA_SEGUNDOS,   # 5 * 60 — piso entre una renovacion y la siguiente
)
```

- No renueva en `logout` (no resucita la cookie que borra), ni encima de una
  respuesta que ya trae su propio `Set-Cookie` para el mismo nombre.
- La renovacion re-emite la cookie por `create_session_cookie`, la MISMA
  funcion que usa el login: los atributos (`httponly`, `samesite=lax`,
  `secure`, el nombre y el path) nunca se duplican en un segundo lugar.
- 🔴 **Cambio de comportamiento:** antes de esta version `max_age` eran 7 dias
  (`SessionAuth`) o 3 dias (`AdminAuth`) ABSOLUTOS desde el login. Una cookie
  firmada hace 9 horas, que antes seguia siendo valida, ahora se rechaza
  aunque falten dias para cumplir el plazo viejo.
- Ver ADR-017 en `DECISIONS.md` para el detalle completo, la tabla de
  consumidores y los riesgos relevados (peticiones concurrentes, cache
  intermedia, y que un endpoint que devuelve su propio `Response` —un PDF,
  una redireccion— no renueva la sesion).

## Schema: la cadena de Alembic (2026-09-11)

Hasta aca las seis tablas de este motor las creaba solo
`AuthBase.metadata.create_all(engine)` en el arranque del producto, y
`create_all` **no altera** una tabla que ya existe: cambiarle una columna a
`usuarios` exigia un `ALTER` a mano en cada instancia. Ahora hay cadena propia,
adentro del paquete, con tabla de version **`alembic_version_libraauth`** (la
base es compartida con LibraCore, LibraCommerce y el producto):

```
pip install "libraauth[migrations]"              # trae alembic
libraauth-migrar upgrade --prefijo gestiolibra --base core
libraauth-migrar upgrade --prefijo libradesk --base dominio
libraauth-migrar diferencias --prefijo P --base B  # mide, no cambia nada
```

- **`--base` es obligatorio con `--prefijo`**: las tablas de auth viven en la
  base de LibraCore en unos productos y en la del dominio en otros, y no hay
  una regla que lo deduzca. Ver el docstring de `libraauth/migrar.py`.
- **La baseline (`0001_baseline_libraauth`) crea solo lo que falta** y no toca
  ninguna tabla existente, asi que sobre una instancia viva es un `upgrade`, no
  un `stamp`. Tampoco normaliza `usuarios`/`auth_log` donde los creo LibraCore
  con columnas `TEXT`: eso lo mide `diferencias`.
- **Adoptarla es opcional.** Subir el pin sin declararla no cambia nada: el
  arranque sigue con `create_all()` y alembic no se importa.
- **Todo cambio de schema es modelo + revision nueva**, en el mismo commit:
  `alembic revision --autogenerate -m "..."` parado en la raiz, con
  `DATABASE_URL` apuntando a una base en la cabeza. `test_modelo_y_cadena_coinciden`
  pone rojo el CI si los dos no dicen lo mismo.
- `actividad_log` (`AuditoriaBase`) queda **afuera**: vive en la base del
  dominio, que no siempre es la de `usuarios`.

## Router de usuarios unificado (v0.43.0, ADR-018)

Un solo router de usuarios (`libraauth/usuarios.py`) para los ocho productos
de la familia, en vez de que cada uno mantenga su propia copia. Reemplaza:

| Producto | Router de referencia (antes de adoptar) |
|---|---|
| Gestiolibra, MedLibra | `app/routers/users.py`, prefijo `/users` |
| VentaLibra | `app/routers/users.py`, prefijo `/users`, sin `Depends` propio |
| LibraDesk | `app/routers/users.py`, prefijo `/api/usuarios` |
| LibraCargo, LibraClub | `app/routers/usuarios.py`, prefijo `/api/usuarios` |
| Contalibra, Restolibra | `app/web/api/usuarios.py` + `app/db_usuarios.py` (contrato `nombre`/`activo`, traducido por el adaptador) |

### Modelos públicos (`libraauth/usuarios.py`)

`UsuarioAlta`, `UsuarioEdicion`, `UsuarioClaveNueva`, `UsuarioSalida`. Son el
mismo objeto de Python que usa `libraauth.testing` para armar los payloads
del test de contrato, y los que el backoffice (`libra-backoffice`) importa en
vez de redefinir `UsuarioIn`/`UsuarioUpdate` -- ver "Adoptarla" más abajo.

### `build_users_router(...)`

```python
from libraauth.usuarios import build_users_router
from app.auth import require_admin_o_servicio  # el guard que ya arma el producto

app.include_router(build_users_router(
    prefix="/api/usuarios",              # el que ya usa el producto -- no cambiarlo
    roles=("admin", "staff"),            # el mismo roles= del UserRepository
    admin_guard=require_admin_o_servicio,
))
```

Endpoints: `GET`, `POST`, `GET /{id}`, `PUT /{id}`, `PUT /{id}/password`,
`DELETE /{id}`. Protecciones -- unión de las que tenía cada producto, tabla
completa en el docstring de `build_users_router` y en el ADR-018:

| Protección | Código | Quién la tenía antes |
|---|---|---|
| Username duplicado | 409 | los ocho |
| Rol inválido, alta | 422 | los ocho |
| Rol inválido, edición | 422 | LibraDesk, VentaLibra, LibraCargo, LibraClub, Gestiolibra, MedLibra (por `Literal` en el modelo, ya frenaba en Pydantic) (Contalibra dejaba escapar un 500) |
| Contraseña < 6, alta | 422 | sólo Contalibra/Restolibra |
| Contraseña < 6, reset ajeno | 422 | **nuevo** -- ninguno lo exigía |
| No desactivarte/degradarte vos mismo | 409 | LibraCargo, LibraClub |
| No borrarte vos mismo | 409 | LibraCargo, LibraClub, Contalibra, Restolibra |
| No degradar al único admin activo | 422 | Contalibra, Restolibra |
| No desactivar al único admin activo | 422 | **nuevo** -- ninguno lo exigía |
| No eliminar al único admin | 422 | Contalibra, Restolibra |

`DELETE` responde siempre `204` (Contalibra/Restolibra/VentaLibra respondían
`200` con `{"ok": true}`: sus frontends propios -- no `Usuarios` de
`libra-ui`, que no mira el cuerpo del borrado -- tienen que dejar de esperar
ese cuerpo).

Borrar un usuario con historial (una fila de otra tabla con FK a
`usuarios(id)`, como `turnos_caja.usuario_id` en libracore/ventas/movimientos
de caja) responde `409` con un mensaje que pide desactivarlo en vez de
borrarlo -- `UserRepository.delete()` traduce el `IntegrityError` de la FK a
`UsuarioConHistorial` (`libraauth.repository`), con rollback de la sesión
antes de propagarla.

**No incluye** `PUT /api/usuarios/me/password` (autoservicio de "Mi Cuenta"
de Contalibra/Restolibra): es otra funcionalidad, con otro guard (cualquier
usuario logueado) y sin la contraseña actual -- el equivalente de este motor
es `POST /auth/change-password`, que sí la pide.

### Test de contrato (`libraauth.testing`)

```python
from libraauth.testing import verificar_contrato_de_usuarios

def test_contrato_de_usuarios(admin_client):
    verificar_contrato_de_usuarios(admin_client, "/api/usuarios", role="staff")
```

Corre el mismo ciclo que ejerce el backoffice (listar → alta → editar →
releer por `GET /{id}` → borrar) contra la instancia de router de ESE
producto, con los modelos públicos de arriba -- así el backoffice y el test
de cada producto no pueden divergir entre sí.

### Adoptarla en un producto

1. Borrar `app/routers/users.py` (o `usuarios.py`, o el par
   `app/web/api/usuarios.py` + las 12 funciones equivalentes de
   `app/db_usuarios.py` en Contalibra/Restolibra) y su import en `main.py`/
   `web/app.py`.
2. `app.include_router(build_users_router(prefix=..., roles=..., admin_guard=...))`
   con el prefijo, la tupla de roles y el guard que el producto YA usa (ver
   la tabla de arriba) -- no elegir un default nuevo.
3. Sumar `test_contrato_de_usuarios` (arriba) a la suite del producto; borrar
   los tests propios del router viejo que quedan redundantes con los que ya
   corre `libraauth` (los de las protecciones se prueban acá, una sola vez).
4. Contalibra/Restolibra: su frontend propio (`frontend/src/api.ts`,
   `Usuarios.tsx`) espera `nombre`/`activo` y un `DELETE` con cuerpo -- pasar
   a `name`/`active` y a leer `204` sin cuerpo es trabajo de ESE producto, no
   de esta adopción del backend.
5. `libra-backoffice`: importar `UsuarioIn`/`UsuarioUpdate` (o construir los
   suyos a partir de `UsuarioAlta`/`UsuarioEdicion`) de `libraauth.usuarios`
   en vez de redefinirlos en `routers/config_instancia.py`.

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
