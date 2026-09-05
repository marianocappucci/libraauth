# Decisiones arquitectónicas — LibraAuth

Registro ADR. Las decisiones no se borran; si dejan de aplicar, se marcan como
reemplazadas. Fechas y motivos salen del código y de la historia registrada en el
wiki (entidad `libraauth`).

## ADR-001 — Extraer auth de LibraCore a un motor propio sobre SQLAlchemy

- Estado: aceptada
- Fecha: 2026-07-29
- Contexto: la autenticación vivía en `libracore.auth` / `libracore.db.usuarios`
  sobre `sqlite3` crudo. Un producto que ya usa SQLAlchemy para su dominio tenía
  que mantener una segunda base sólo para `usuarios`, o arrastrar las ~28 tablas
  de facturación/ARCA de `libracore.db` que no le hacen falta.
- Decisión: extraer un motor de auth independiente (`libraauth`) sobre SQLAlchemy:
  sesión, hashing, tabla de usuarios y lo que orbita la identidad.
- Consecuencias: un producto con stack SQLAlchemy consume auth sin una segunda
  base ni el peso de `libracore.db`; LibraCore conserva su propia auth para los
  productos que siguen sobre él.

## ADR-002 — La tabla de usuarios es del producto, integrada por callback

- Estado: aceptada
- Fecha: 2026-07-29
- Contexto: cada vertical tiene su propio modelo de usuarios y su propia
  persistencia; el motor no puede imponer un schema.
- Decisión: `SessionAuth` se integra por callback en vez de asumir la tabla de
  usuarios; el producto trae su `Usuario`.
- Consecuencias: mínima huella (mismo principio que LibraCore); adoptar el motor
  no obliga a migrar el modelo de datos del producto.

## ADR-003 — Sesión por cookie firmada, sin JWT ni tokens de API

- Estado: aceptada
- Fecha: 2026-07-29
- Contexto: los productos son apps con backend propio; no hay todavía consumidores
  de API de terceros que justifiquen tokens.
- Decisión: sesión por cookie firmada (`itsdangerous`) en `session_auth`, con los
  routers de login/logout/verificación/reseteo/demo.
- Consecuencias: despliegue simple y un solo mecanismo; revisar si aparece un
  consumidor que necesite auth por token.

## ADR-004 — Hashing PBKDF2 aislado en su propio módulo

- Estado: aceptada
- Fecha: 2026-07-29
- Contexto: el hashing de contraseñas es la pieza más sensible y la que menos
  debe cambiar; conviene que no arrastre dependencias del resto del motor.
- Decisión: `hashing.py` (`hash_password`/`verify_password`, PBKDF2) como módulo
  mínimo y estable, separado de la sesión y del repositorio.
- Consecuencias: superficie chica y auditable; el algoritmo se cambia en un solo
  lugar.

## ADR-005 — Secretos cifrados en reposo con clave dedicada

- Estado: aceptada
- Fecha: 2026-07-29
- Contexto: el motor guarda secretos (config SMTP, credenciales) que no deben
  quedar en texto plano en la base.
- Decisión: `crypto.py` cifra/descifra con una clave de cifrado dedicada, y falla
  con errores tipados (`ClaveDeCifradoAusente`, `SecretoIndescifrable`) en vez de
  degradar silenciosamente.
- Consecuencias: un secreto ilegible se distingue de una clave ausente; el
  problema se ve, no se traga.

## ADR-006 — El registro de accesos es tolerante a error ("seguro")

- Estado: aceptada
- Fecha: 2026-08
- Contexto: registrar cada acceso e intento fallido no puede tumbar el login si el
  registro falla.
- Decisión: `auth_events` expone las operaciones en variante "segura"
  (`registrar_seguro`, `contar_fallidos_seguro`) que no propagan el error del
  registro al flujo de autenticación, más una verificación explícita de que el
  registro está andando.
- Consecuencias: el login no depende de que la auditoría de accesos esté sana;
  a cambio, un registro roto hay que detectarlo por la verificación, no por una
  caída.

## ADR-007 — Términos y condiciones versionados por hash

- Estado: aceptada
- Fecha: 2026-08
- Contexto: un producto puede necesitar exigir la aceptación de la versión vigente
  de los términos antes de operar.
- Decisión: `terminos` versiona el texto por hash (`hash_vigente`) y expone si hay
  aceptación pendiente (`hay_terminos_pendientes`, `exigir_terminos`).
- Consecuencias: cambiar el texto invalida la aceptación anterior sin migración;
  el producto decide si gatea.

## ADR-008 — Motor dual y hora local por rama de motor

- Estado: aceptada
- Fecha: 2026-08
- Contexto: los modelos SQLAlchemy corren contra SQLite y PostgreSQL, y los
  timestamps deben estamparse en hora Argentina sin depender de la zona de la
  sesión.
- Decisión: resolver los defaults con reloj por motor
  (`_ahora_local_sqlite` / `_ahora_local_postgresql`).
- Consecuencias: la hora AR es correcta en los dos motores; la restricción
  PostgreSQL-only la aplica el producto, no el motor.

## ADR-009 — Segundo factor TOTP y lockout persistido para el backoffice

- Estado: aceptada
- Fecha: 2026-09
- Contexto: `AdminAuth` protege los ocho backoffices de superadmin con una sola
  contraseña por entorno, y su rate limiting vivía en memoria del proceso: un
  reinicio del contenedor lo borraba. Una contraseña filtrada de un `-admin`
  da acceso a todas las instancias del producto (auditoría F2, 2026-09-05).
- Decisión: TOTP (RFC 6238, SHA1/6 dígitos/30 s) implementado con la stdlib
  en `libraauth/totp.py`, activado por `ADMIN_PANEL_TOTP_SECRET`; cada código
  vale una sola vez. Estado del login (intentos por IP y último código usado)
  en un archivo JSON cuando `ADMIN_PANEL_ESTADO_PATH` está seteado, con
  escritura atómica; sin la variable, memoria como antes.
- Consecuencias: sin dependencia nueva; el enrolamiento es un comando
  (`python -m libraauth.totp <producto>`) y una línea en el `.env`. Un secreto
  inválido frena el arranque. El estado ilegible o no escribible falla
  abierto y avisa por log, igual que el resto del rate limiting del paquete.
  Obligar o sólo ofrecer el segundo factor es decisión del humano: con la
  variable ausente el login sigue siendo de un factor.
