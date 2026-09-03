# Arquitectura — LibraAuth

## Propósito y límites

LibraAuth es el **motor transversal de autenticación** de la familia Libra:
sesión por cookie firmada, hashing de contraseñas, tabla de usuarios y las
piezas alrededor de la identidad (reseteo de contraseña, términos y condiciones,
códigos de demo, auditoría de accesos), sobre **SQLAlchemy**.

Nació de extraer `libracore.auth` / `libracore.db.usuarios` —que hablaban
`sqlite3` crudo— para que un producto que ya usa SQLAlchemy para su propio
dominio no tenga que mantener una segunda base sólo para `usuarios`, ni arrastrar
las tablas de facturación/ARCA de `libracore.db` que no le hacen falta. LibraAuth
**no** conoce el dominio de negocio de ningún producto: no sabe de facturas,
turnos ni catálogo. Aporta identidad y sesión; el schema de usuarios lo completa
cada producto por callback, no lo asume el motor.

## Componentes

El puerto real, medido sobre los consumidores, es `session_auth` (79 sitios de
import) — el resto orbita alrededor de él.

- **`session_auth.py`** (`SessionAuth`): el corazón. Sesión por cookie firmada
  (`itsdangerous`), con las dependencias FastAPI y los routers de login/logout/
  verificación, reseteo y flujo de demo. `_resolve_secret_key` resuelve la clave
  de firma. Los modelos Pydantic de request/response (`_LoginRequest`,
  `_UserOut`, `_VerifyRequest`, `_ForgotPasswordRequest`…) viven acá, privados.
- **`models.py`**: los modelos SQLAlchemy (`Base`, `Usuario`,
  `PasswordResetToken`, `AuthEvent`, `SmtpSettings`, `DemoCodigo`) y los helpers
  de hora local en zona Argentina, con ramas por motor
  (`_ahora_local_sqlite`/`_ahora_local_postgresql`). Segundo módulo más
  consumido (50 sitios).
- **`repository.py`** (`UserRepository`, error `UsernameTaken`): CRUD de usuarios.
- **`hashing.py`** (`hash_password`/`verify_password`): PBKDF2. Módulo mínimo y
  estable, aislado a propósito.
- **`crypto.py`** (`cifrar`/`descifrar`, `clave_de_cifrado`): cifrado simétrico de
  secretos en reposo, con errores tipados (`ClaveDeCifradoAusente`,
  `SecretoIndescifrable`).
- **`password_reset.py`** (`PasswordResetService`): tokens de reseteo con
  expiración; errores `InvalidResetToken`/`EmailNotConfigured`.
- **`terminos.py`** (`TerminosRepository`): términos y condiciones versionados
  por hash (`hash_vigente`, `exige_aceptacion`, `hay_terminos_pendientes`) — un
  producto puede exigir la aceptación de la versión vigente antes de operar.
- **`demo_codigos.py`** (`DemoCodigoRepository`): códigos de acceso demo de un
  solo uso, hasheados.
- **`auth_events.py`** (`AuthEventRepository`): registro de accesos e intentos
  fallidos (`registrar_seguro`, `contar_fallidos_seguro`,
  `verificar_registro_de_accesos`) — pensado para no romper el login si el
  registro falla ("seguro" = tolerante a error).
- **`auditoria.py`** (`AuditoriaBase`, `ActividadLog`, `configurar_auditoria`,
  `agregar_middleware_de_usuario`): auditoría genérica de actividad con diff
  legible, montable como middleware.
- **`bootstrap.py`** (`ensure_default_admin`, `ensure_demo_user`,
  `ensure_admin_user`): siembra idempotente del admin y el usuario demo al
  arrancar.
- **`smtp_settings.py`** (`SmtpSettingsRepository`, `resolver_smtp_config`) +
  **`email_sender.py`** (`SmtpConfig`, `enviar_email`): configuración SMTP por
  instancia y envío (reseteo de contraseña, notificaciones).
- **`admin_auth.py`** (`AdminAuth`): variante de autenticación para los
  backoffices de superadmin.

## Diseño: schema propio del producto por callback

La decisión de fondo, heredada de `libracore.auth`: **la tabla de usuarios es del
producto, no del motor.** Cada vertical que reusa `SessionAuth` trae su propia
`Usuario` en su propio stack de persistencia, y LibraAuth se integra por callback
en vez de asumir el schema. Es el mismo principio de **mínima huella** de toda la
familia: adoptar el motor no obliga a reescribir el modelo de datos del producto.

## Motor dual, hora local

Los modelos usan SQLAlchemy, así que el mismo código corre contra SQLite y
PostgreSQL. Los defaults con reloj se resuelven por motor (`_ahora_local_sqlite`
vs `_ahora_local_postgresql`) para estampar en hora Argentina (UTC-3) sin
depender de la zona de la sesión de la base. La regla de familia PostgreSQL-only
la aplica el **producto** en su arranque; el motor sabe hablar los dos.

## Distribución

Paquete `libraauth` (build `hatchling`), versión pineada al tag por cada producto
(`v0.35.0` al 2026-09). Sin console scripts: es una librería que el producto
importa y compone, no una CLI.

## Referencias

- `README.md` — resumen y motivo de la extracción.
- Wiki: entidad `libraauth`, `concepts/estandares-desarrollo`, y la auditoría
  `auditoria-estructural-familia-libra-2026-09`.
