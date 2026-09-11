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
  lugar. **Se cobró el 2026-09-07**: pasar a argon2id fue un archivo, y el resto
  del motor no se enteró — ver ADR-010.

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

## ADR-010 — argon2id para contraseñas, con re-hash al login

- Estado: aceptada
- Fecha: 2026-09-07
- Contexto: el hashing era PBKDF2-HMAC-SHA256 con 260.000 iteraciones. PBKDF2 se
  defiende gastándole **tiempo de CPU** al atacante, que es justo lo barato para
  una GPU o un ASIC: el mismo presupuesto compra órdenes de magnitud más intentos
  por segundo que contra un algoritmo que además gasta **memoria**. Sale del
  punto F2.5 del plan de septiembre.
- Decisión: **argon2id** (`argon2-cffi`) con los parámetros del piso recomendado
  por OWASP —19 MiB, 2 pasadas, 1 hilo— y **no** los defaults de la librería
  (64 MiB, 4 hilos): en este parque conviven doce instancias en un VPS chico, y
  64 MiB por login concurrente es memoria que se le saca a PostgreSQL.
  `verify_password` sigue aceptando el formato viejo, y `check_credentials`
  re-hashea cuando `needs_rehash` lo pide.
- Consecuencias: **ninguna contraseña se resetea**. Una contraseña vieja se migra
  sola la próxima vez que su dueño entra; una que nadie usa se queda en PBKDF2 —
  peor que argon2, pero no una puerta abierta. El re-hash está envuelto en un
  `try` que **nunca puede tumbar el login**: quien ya demostró que sabe su
  contraseña no puede quedarse afuera porque falló una escritura de
  almacenamiento.
- Efecto lateral asumido: el hash señuelo pasó a ser argon2, así que mientras
  queden usuarios sin migrar el costo de verificar contra ellos difiere del de un
  usuario inexistente. Es una fuga más débil que la que el señuelo tapa —dice
  "existe y no entró desde el cambio", no "no existe"— y se cierra sola. Igualar
  los costos exigiría dejar el señuelo en PBKDF2, o sea el hueco abierto para
  siempre del otro lado.

## ADR-011 — Rotar `SECRET_KEY` deja de destruir lo cifrado en reposo

- Estado: aceptada
- Fecha: 2026-09-09
- Contexto: la clave con la que este motor cifra secretos en reposo se **deriva**
  de `SECRET_KEY`. Hasta acá, rotarla dejaba lo guardado ilegible para siempre.
  Eso era deliberado —un respaldo por sí solo no alcanza para recuperar la
  credencial— pero convertía cada rotación en una pérdida silenciosa. El
  2026-09-07 se rotaron cinco instancias del VPS como respuesta a un incidente y
  quedaron ilegibles tres credenciales de terceros; aparecieron dos días después
  y dos de las tres sólo porque alguien las fue a buscar. Una medida de seguridad
  que rompe cosas en silencio termina siendo un argumento para no tomarla.
- Decisión: `LIBRAAUTH_CLAVES_ANTERIORES` lista los valores **anteriores** del
  material de clave, separados por coma. `descifrar` prueba la vigente y después
  esas; `cifrar` usa **siempre** la vigente. Se agregan `descifrar_al_dia()`, que
  informa si el valor vino de una clave anterior, y `recifrar()`, que devuelve el
  valor bajo la clave vigente o `None` si ya lo estaba.
- Consecuencias: una rotación pasa a tener un **ciclo con final**: rotar, declarar
  el valor viejo, recifrar, **sacar la variable**. Mientras la variable siga
  puesta la rotación no terminó, y `descifrar_al_dia()` es lo que permite
  auditarlo desde afuera en vez de confiar en que alguien se acuerde —
  `operaciones/auditar_secretos.py` del wiki lo usa para eso.
- Lo que **no** cambia: la propiedad que justifica todo esto. La base sigue sin
  contener ninguna clave; sin el entorno, un respaldo sigue sin servir. Y
  `recifrar()` **no toca** un valor que no puede leer: pisarlo con algo cifrado
  con la clave nueva destruiría el único rastro de lo que había.

## ADR-012 — Cadena de Alembic propia para el schema de auth

- Estado: aceptada
- Fecha: 2026-09-11
- Contexto: las seis tablas de este motor las creaba sólo `create_all()` en el
  arranque de cada producto, que crea lo que falta y no altera lo que existe.
  Cambiar una columna de `usuarios` en producción exigía un `ALTER` a mano por
  instancia. LibraCore (`v1.53.0`) y LibraCommerce (P9-M0) ya tenían cadena en
  el wheel; éste era el último motor con schema sin una. Punto 2 de "Dirección
  de persistencia" de la auditoría de septiembre.
- Decisión: cadena en `libraauth/migrations/`, tabla de versión
  `alembic_version_libraauth`, comando `libraauth-migrar` con alembic en el
  extra `[migrations]`. La baseline es **DDL escrito** (foto de `v0.38.0`) y no
  una llamada a `create_all()`, porque los modelos siguen cambiando y una
  baseline que creara la cabeza chocaría con la `0002`. Crea tabla por tabla
  sólo lo que falta. `--base core|dominio` es obligatorio con `--prefijo`: el
  engine de auth es la base de LibraCore en Gestiolibra, MedLibra y VentaLibra
  y la del dominio en LibraCargo, LibraClub y LibraDesk, aunque los dos
  primeros tengan base de LibraCore aparte.
- Consecuencias: un cambio de schema es modelo + revisión en el mismo commit, y
  `test_modelo_y_cadena_coinciden` lo ata. La baseline **no normaliza** las
  bases donde `usuarios`/`auth_log` los creó el DDL de LibraCore con columnas
  `TEXT`: una revisión que altere esas tablas tiene que medirlas antes
  (`libraauth-migrar diferencias`) y tolerar las dos formas. Mientras un
  producto no adopte la cadena, nada cambia para él: sigue `create_all()`.
- Fuera de alcance: `actividad_log`, que vive en la base del dominio y en tres
  productos no es la de `usuarios`. Una cadena no puede cubrir dos bases.

## ADR-013 — La IP del cliente se lee desde la derecha de `X-Forwarded-For`

- Estado: aceptada
- Fecha: 2026-09-11
- Contexto: `ip_del_request` tomaba el **primer** elemento de `X-Forwarded-For`,
  y es con esa IP con la que el router de login cuenta los fallidos en
  `auth_log`. Nginx Proxy Manager no reemplaza el header: le **agrega** el par
  TCP (`$proxy_add_x_forwarded_for`), así que el primer elemento lo escribe el
  cliente. Rotarlo en cada intento esquivaba el bloqueo por IP en todos los
  productos. El propio docstring lo decía ("sirve para leer un log, no para
  decidir un bloqueo"), y aun así el bloqueo se apoyaba en ella. `terminos._ip_de`
  repetía la misma regla para la fila probatoria de la cláusula 30.3.
  Topología medida en el VPS el 2026-09-11: DNS directo sin CDN, NPM termina TLS
  y reenvía a cada contenedor en un solo salto por la red de Docker.
- Decisión: se recorre `X-Forwarded-For` desde la derecha salteando los proxies de
  confianza (`REDES_DE_CONFIANZA`: `10/8`, `172.16/12`, `192.168/16`, loopback y
  `fc00::/7`, lo mismo que NPM declara para Docker), y el primero que no lo es es
  el cliente. El header **sólo se lee si el par directo es un proxy de
  confianza**: quien llega al contenedor sin NPM no elige su IP. Si toda la
  cadena es de confianza vale el último elemento, el que escribió el proxy.
  `terminos` usa la misma función.
- Por qué una lista y no `ipaddress.is_private`: ese predicado da `True` también
  para los rangos de documentación y otros reservados, y con él esas direcciones
  pasarían por proxy. Lo cuida `test_ip_no_la_elige_el_cliente`.
- Consecuencias: el bloqueo por intentos pasa a contar por una IP que el cliente
  no controla, que es la condición para que el captcha y el bloqueo se sumen en
  vez de esquivarse igual. Detrás de un proxy con un par que no esté en la lista
  (un CDN delante de NPM, por ejemplo), todos los clientes se verían con la IP de
  ese proxy, y el bloqueo por IP pasaría a ser global.
- **Cómo se agrega un salto** (v0.39.0): `LIBRAAUTH_PROXIES_DE_CONFIANZA`, redes
  separadas por coma en el entorno de la instancia. **Se suman** a las de la
  lista, no la reemplazan: reemplazar dejaría sacar por error la red de Docker
  por la que habla NPM. Una entrada mal escrita se ignora con un error en el log,
  en vez de tirar abajo el login.
- Consumidores pendientes, que **no** quedan protegidos por este cambio hasta que
  lo adopten: el `_ip` propio de `libra-backoffice` (usa el header entero) y
  `libra-web-kit/docs_auth.py` (usa el par directo, así que detrás de NPM su
  bloqueo es global: cinco fallos de cualquiera dejan a todos afuera de `/docs`).
  Y los productos, recién cuando suban el pin.

## ADR-014 — Captcha de prueba de trabajo (ALTCHA), siempre y en el propio servidor

- Estado: aceptada
- Fecha: 2026-09-11
- Contexto: el bloqueo por intentos cuenta por IP, y con la IP arreglada (ADR-013)
  sigue sin frenar a quien reparte los intentos entre muchas. Hacía falta un costo
  por intento que no dependa de la IP. El humano eligió ALTCHA, y que vaya
  **siempre**, no recién después de N fallos (2026-09-11).
- Decisión: `libraauth/captcha.py` con `Captcha(secret_key)`. `emitir()` arma un
  desafío PBKDF2/SHA-256 en modo determinista con la clave derivada firmada, y
  `verificar()` lo acepta una sola vez. Dependencia nueva: `altcha` (MIT, sin
  dependencias propias). En el router, `captcha=True` —opt-in— agrega el endpoint
  del desafío y exige la solución en el login y en forgot-password.
- Por qué ALTCHA: de los cuatro evaluados (con Turnstile, hCaptcha y reCAPTCHA) es
  el único que no sale del servidor. Ningún tercero ve la IP del usuario, no hay
  cookies, la CSP no cambia y el login no depende de que otro esté arriba.
- Claves: HKDF del `SECRET_KEY` con `info` propio (`libraauth/captcha/firma/v1` y
  `libraauth/captcha/clave/v1`), la misma receta que `crypto.py`. Rotar el secreto
  sólo invalida los desafíos en curso: **no** es un consumidor más de la rotación.
- Modo determinista con `hmac_key_secret`: verificar cuesta 0,1 ms sin volver a
  derivar. El servidor no paga lo que paga el cliente, y una solución basura no
  sirve para gastarle CPU.
- Anti-replay en memoria del proceso: los productos corren un solo uvicorn por
  contenedor (medido). Un reinicio vacía la lista, y lo peor que habilita es
  reusar un desafío anterior mientras siga vigente.
- Orden en el login: bloqueo por IP → captcha → credenciales. Un captcha que falta
  o no vale es 400 y **no** se anota como fallido: no se llegó a probar ninguna
  contraseña, y contarlo dejaría bloquear gratis una IP compartida.
- Costo provisorio: 1000 iteraciones por contador, con el contador en
  [2000, 4000): 0,70 s en un hilo de Python en una PC. Se ajusta con la medición
  en el navegador.
- Fuera de alcance: el login de la demo, que ya exige un código emitido por el
  backoffice, y el `/docs` de `libra-web-kit`.

