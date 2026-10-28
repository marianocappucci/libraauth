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

## ADR-015 — TOTP enrolable en runtime, guardado en archivo aparte

- Estado: aceptada
- Fecha: 2026-09-13
- Contexto: el TOTP de ADR-009 solo se carga por `ADMIN_PANEL_TOTP_SECRET`
  en el `.env`, así que activarlo exige editar el archivo y recrear el
  contenedor — dos pasos manuales por instancia, y el humano pidió un
  interruptor "habilitar doble factor" con QR en el backoffice, sin tocar
  el `.env` ni reiniciar nada.
- Decisión: el secreto enrolado vive en un archivo JSON aparte del estado de
  login (`ADMIN_PANEL_TOTP_PATH`, o el hermano `totp.json` de
  `ADMIN_PANEL_ESTADO_PATH` si esa es la única variable seteada), con la
  misma escritura atómica que `_EstadoLogin` (tmp + `os.replace`) más
  `chmod 0600`. `AdminAuth` suma `iniciar_totp` / `confirmar_totp` /
  `desactivar_totp`: enrolar dos pasos (generar un secreto PENDIENTE con QR,
  confirmarlo con un código dentro de los 10 minutos) para no activar un
  secreto que el superadmin nunca llegó a cargar en el autenticador.
- El entorno sigue mandando: con `ADMIN_PANEL_TOTP_SECRET` seteado,
  `totp_origen` es `"entorno"` y enrolar o desactivar desde la app se
  rechaza con `TotpNoEnrolable`. Es la variable que ya usan los ocho
  backoffices vía `.env`; el archivo es un camino nuevo, no un reemplazo.
- **Fail CLOSED, al revés que el resto del rate limiting de este paquete**
  (que falla ABIERTO — ver ADR-009): un archivo de TOTP roto (ilegible, JSON
  inválido, forma inesperada, o un `secreto` que no decodifica) deja
  `totp_habilitado=True` con `check_credentials` devolviendo `False`
  siempre. Es un cambio de política deliberado y acotado a este archivo: el
  estado de login cuenta intentos (fallar cerrado ahí bloquearía a todos
  porque se rompió el contador), pero el TOTP **es** el segundo factor —
  apagarlo solo porque el archivo se corrompió deja el backoffice con un
  factor menos sin que nadie lo decidiera. Recuperarse es borrar el archivo
  a mano desde el host, a propósito: un login cerrado que se arregla
  borrando un archivo es preferible a un 2FA que se cae solo y nadie nota.
- Cada escritura de `confirmar_totp` y `desactivar_totp` se **relee** después
  de guardar y compara contra lo esperado; si no coincide, `RuntimeError` —
  nunca se responde `True` (2FA activado/desactivado) si no persistió.
- Sin dependencia nueva: reusa `Totp` y `totp.generar_secreto` /
  `totp.uri_otpauth` tal cual estaban.
- Compatibilidad: sin `ADMIN_PANEL_TOTP_PATH` ni `ADMIN_PANEL_ESTADO_PATH`,
  `AdminAuth` se comporta exactamente igual que antes de este ADR (no
  enrolable, `totp_habilitado` solo por entorno). `tests/test_admin_auth.py`
  y `tests/test_admin_auth_f2.py` no se tocaron.

## ADR-016 — Login del backoffice en dos pasos, con desafio firmado

- Estado: aceptada
- Fecha: 2026-09-13
- Contexto: el humano pidio que la pantalla de login pida usuario,
  contrasena y captcha primero, y recien despues abra un modal para tipear
  el codigo TOTP digito por digito — hoy `check_credentials` exige los tres
  datos (usuario, contrasena, codigo) en una sola llamada, asi que no hay
  forma de mostrar ese segundo paso sin que el backend ya sepa el codigo de
  antemano.
- Decision: cuatro metodos nuevos en `AdminAuth`, sin tocar
  `check_credentials` (que sigue sirviendo al backoffice de un solo paso):
  `verificar_clave(username, password)` valida solo la clave (misma
  comparacion que la primera mitad de `check_credentials`, ahora factorizada
  en un solo lugar); `emitir_desafio_totp(username)` devuelve un token
  firmado con `itsdangerous.URLSafeTimedSerializer` y un **salt propio**
  (`libraauth.admin.totp-desafio`), vida corta (`DESAFIO_TOTP_SEGUNDOS = 300`,
  5 minutos); `validar_desafio_totp(desafio)` lo verifica sin lanzar nunca; y
  `verificar_codigo_totp(codigo)` valida el codigo TOTP contra el secreto
  activo (entorno o archivo, via `_totp_activo`), compartiendo
  `ultimo_paso_totp` del estado de login con `check_credentials` — un codigo
  usado en un camino no sirve en el otro.
- Por que un salt propio y no la cookie de sesion firmando el desafio:
  `itsdangerous` deriva una clave de firma distinta por salt a partir del
  mismo `SECRET_KEY`, asi que un token firmado con un salt no valida contra
  otro. Es lo que impide que el desafio del paso 1 sirva como cookie de
  sesion (saltandose el paso 2 entero) y que una cookie de sesion robada se
  reuse como desafio.
- Sin estado en el servidor: el desafio lleva el username en el payload
  firmado, no en una tabla ni en memoria — nada que limpiar ni que se pierda
  al reiniciar el contenedor.
- Consecuencia asumida: con 2FA encendido, superar el paso 1 (usuario y
  contrasena correctos) le confirma a quien intenta que la contrasena es
  correcta, algo que antes `check_credentials` no distinguia — clave mal o
  codigo mal daban el mismo 401. Se mitiga con lo que ya protege el login: el
  captcha (ADR-014) encarece cada intento de contrasena, el bloqueo por IP
  (ADR-009) sigue cortando antes de llegar a probar, y la sesion en si exige
  ademas el codigo — superar el paso 1 no abre nada por si solo.
- El camino de un paso (`check_credentials`) sigue igual, para el backoffice
  que todavia no migro a la pantalla en dos pasos: nada cambia de
  comportamiento para el.

## ADR-017 — Sesion por inactividad de 8 horas, con renovacion deslizante

- Estado: aceptada
- Fecha: 2026-09-13
- Contexto: el humano pidio que "todas las sesiones tienen que cerrarse
  pasadas 8 horas sin uso", tanto para el login de usuario final
  (`SessionAuth`, los ocho productos) como para el backoffice de superadmin
  (`AdminAuth`). Hasta esta version `max_age` era un plazo ABSOLUTO desde el
  login: 7 dias en `SessionAuth`, 3 en `AdminAuth`. Un plazo absoluto y una
  ventana de inactividad no son la misma cosa: alguien trabajando sin
  interrupcion durante 8 horas seguidas con el plazo absoluto seguia adentro
  (recien cortaba a los 7 dias), y con una ventana de inactividad mal resuelta
  (comparando siempre contra el login original) se lo echaria igual a mitad
  de una jornada normal. Definimos "uso" como cualquier pedido al servidor —
  el humano acepto la excepcion de las pantallas que se refrescan solas (el
  KDS) mientras el navegador siga abierto.
- Decision:
  1. **Una sola constante para las dos clases**, en `session_auth.py`
     (`admin_auth.py` la importa): `INACTIVIDAD_MAXIMA_SEGUNDOS = 8 * 3600`,
     default de `max_age` en `SessionAuth.__init__` y `AdminAuth.__init__`.
     Sin variable de entorno: no hay en el repo un patron de duracion de
     sesion configurable por instancia, y agregar uno para esto solo
     ampliaria una superficie que nadie pidio.
  2. **Renovacion deslizante, no un plazo mas largo.** `max_age` deja de
     medirse desde el login: `get_current_user`/`current_user` leen el
     timestamp de la FIRMA (`URLSafeTimedSerializer.loads(...,
     return_timestamp=True)`) y, si un `response` llega y esa firma ya tiene
     mas de `RENOVACION_MINIMA_SEGUNDOS` (5 minutos, tambien constante unica),
     re-emiten la cookie via `create_session_cookie` — mismos atributos,
     timestamp nuevo. El piso de 5 minutos evita re-firmar y mandar un
     `Set-Cookie` en cada pedido de un usuario activo.
  3. **Es una API del motor que llega con subir el pin, sin tocar el
     producto — para la mayoria.** `response: Response = None` (bare, no
     `Response | None`: FastAPI no reconoce un tipo `Optional` como el
     parametro especial y rompe con `Invalid args for response field`, medido
     armando la suite) se agrego a `get_current_user`, `require_auth`,
     `require_admin`, `require_role`, `json_api_get_current_user` y a los
     guards compuestos que llaman a este ultimo por fuera de `Depends`
     (`json_api_require_admin_o_servicio`, `_o_panel`,
     `json_api_require_panel_o_admin`) — mismo mecanismo del lado de
     `AdminAuth.current_user`/`require_login`. FastAPI inyecta un `Response`
     real en cualquier dependencia que lo declare, aunque el endpoint que la
     usa no lo declare el (verificado con una prueba dedicada antes de
     escribir el resto). Relevados los nueve consumidores contra
     `origin/main` (ver la tabla en el PR): a los ocho productos y a
     `libracore.admin.app` (el backoffice Jinja2 de Contalibra/Restolibra)
     les alcanza con el bump, porque todos gatean via `Depends(...)` sobre
     alguna de estas funciones. La excepcion es `libra-backoffice`: envuelve
     `AdminAuth.current_user` en su propia dependencia
     (`backend/libra_backoffice/deps.py:admin_actual`, que devuelve 401 JSON
     en vez del redirect de `require_login`) y esa envoltura no declara
     `response` — necesita una linea propia en ESE repo para heredar la
     renovacion. Queda anotado, no resuelto aca: esta tarea es sobre
     `libraauth`.
  4. **No renovar en logout, ni encima de una cookie que la misma respuesta
     ya esta emitiendo.** El handler de `logout` sigue llamando a
     `get_current_user(request)` sin pasar `response` — no hay forma de que
     renueve lo que esta por borrar. Como segunda linea de defensa (no hay
     hoy una ruta real que la necesite, pero cierra el caso para cualquier
     cambio futuro), `_ya_tiene_set_cookie` se fija si `response` ya trae un
     `Set-Cookie` para ese nombre antes de renovar.
- Por que el "ahora" de la renovacion sale del propio signer
  (`signer.make_signer().get_timestamp()`) y no de `datetime.now()`: es el
  mismo reloj que usa `itsdangerous` para firmar y para expirar, asi que los
  tests pueden controlarlo completo parcheando un solo punto
  (`TimestampSigner.get_timestamp`). Se probo con `datetime.now(UTC)` primero
  y el test (a) daba falso-negativo indefinidamente: con el reloj de los
  tests adelantado, `datetime.now() - firmado_en` da negativo y la renovacion
  nunca se dispara.
- Cambio de comportamiento (a documentar en el README, seccion nueva): una
  cookie firmada hace mas de 8 horas se rechaza aunque falten dias para
  cumplir el viejo plazo de 7 (`SessionAuth`) o 3 (`AdminAuth`). Un producto
  que sube el pin sin avisar a sus usuarios los va a desloguear mas seguido
  que antes si dejan la pestaña abierta sin usarla.
- Riesgos identificados, no todos resueltos aca:
  - **Peticiones concurrentes** sobre la misma sesion, cerca del piso de
    renovacion: dos pedidos casi simultaneos pueden renovar los dos (dos
    `Set-Cookie` en dos respuestas distintas, cada una valida por separado —
    no hay carrera de escritura porque no hay estado compartido del lado del
    servidor, es solo cookie). El navegador se queda con la ultima que
    proceso; no es un problema de consistencia, como mucho una renovacion de
    mas.
  - **Cache intermedia**: un proxy o CDN que cachee una respuesta con
    `Set-Cookie` la serviria a otro cliente. No es nuevo de este cambio —
    ya era un riesgo con el login— pero la renovacion ahora puede emitir un
    `Set-Cookie` en CUALQUIER pedido GET, no solo en `/login`, lo que amplia
    la superficie si algun proxy cachea rutas de la API por error. Los
    productos ya deberian estar mandando `Cache-Control` apropiado en las
    rutas autenticadas; no se audito aca.
  - **CSP**: sin cambios — la renovacion usa el mismo `set_cookie` con los
    mismos atributos, no agrega scripts ni headers nuevos.
  - **Endpoints que devuelven su propio `Response`** (`FileResponse`,
    `StreamingResponse`, `RedirectResponse`, un `JSONResponse` armado a mano):
    **esos pedidos NO renuevan la sesion.** La dependencia escribe el
    `Set-Cookie` en el `Response` que FastAPI le inyecta, y FastAPI sólo copia
    esos headers a la respuesta final cuando el endpoint devuelve un valor que
    él serializa; si el endpoint devuelve un `Response`, lo manda tal cual y
    los headers de la dependencia se descartan (`fastapi/routing.py`,
    `if isinstance(raw_response, Response): response = raw_response`, y el
    `response.headers.raw.extend(...)` está sólo en la otra rama; medido en la
    versión del venv del 2026-09-13). No rompe nada —la sesión sigue valida y
    la renueva el próximo pedido JSON— y en la práctica las pantallas hacen
    pedidos JSON todo el tiempo. Pero una pantalla que sólo descargara PDFs
    durante 8 horas se quedaria sin sesión. Si algún día importa, el endpoint
    tiene que copiar `response.headers` de la dependencia a mano.

## ADR-018 — Router de usuarios único, con contrato y test de contrato compartidos

- Estado: aceptada
- Fecha: 2026-09-13
- Se escribió como ADR-017 y se renumeró antes de mergear: el 017 lo tomó la
  sesión por inactividad de 8 horas (#92), que entró primero a `develop`. El
  contenido no cambió.
- Contexto: los ocho productos de la familia (Gestiolibra, MedLibra,
  VentaLibra, LibraDesk, LibraCargo, LibraClub, Contalibra, Restolibra)
  tenían cada uno su propia copia del router de usuarios -- cuatro variantes
  de `app/routers/users(.py|usuarios.py)` más el par
  `app/web/api/usuarios.py` + `app/db_usuarios.py` de Contalibra/Restolibra,
  que además habla un contrato distinto puertas adentro (`nombre`/`activo`).
  Copiar en vez de compartir dejó a las ocho divergiendo en silencio: cinco
  de los ocho no protegían al único administrador activo de una edición que
  lo degrada o desactiva; Contalibra dejaba escapar un `ValueError` de rol
  inválido en la EDICIÓN como `500` (vía `db_usuarios.py`, sin `except` en su
  `PUT`) -- Gestiolibra y MedLibra no tenían este bug: su `UserUpdate.role`
  ya era `Literal["admin", "staff"]`, así que Pydantic frenaba un rol
  inválido con `422` antes de llegar al handler; el
  `DELETE` respondía `204` en cinco productos y `200` con cuerpo JSON en los
  otros tres; y el mínimo de contraseña (6 caracteres) sólo se exigía en el
  alta de Contalibra/Restolibra, en ningún reset de contraseña ajena. El
  backoffice (`libra-backoffice/routers/config_instancia.py`) y la pantalla
  compartida (`Usuarios` de `libra-ui`) ya asumían un contrato único -- lo
  que no era único era lo que había del otro lado.
- Decisión: un solo lugar de verdad, en `libraauth`, con tres piezas:
  1. **Modelos públicos del contrato** (`libraauth/usuarios.py`):
     `UsuarioAlta`, `UsuarioEdicion`, `UsuarioClaveNueva`, `UsuarioSalida`.
     `role` es `str` y no un `Literal` fijo -- el vocabulario de roles no es
     el mismo en toda la familia (`("admin","staff")` en seis productos,
     `("admin","operador","cajero")` en Contalibra, con `"mozo"` sumado en
     Restolibra) -- y se valida contra la tupla `roles` que cada producto le
     pasa a la factory, no contra un tipo fijo del modelo.
  2. **La factory `build_users_router(...)`**, en el mismo módulo: recibe
     `prefix`, `roles`, `admin_role`, `admin_guard` (la dependencia de admin
     que ya arma cada producto -- la factory no elige ninguna por default,
     ver su docstring) y opcionalmente `get_repository`. Devuelve el router
     completo: listar, alta, `GET /{id}`, edición, reset de contraseña de
     otro usuario (`PUT /{id}/password`) y borrado.
  3. **`libraauth.testing.verificar_contrato_de_usuarios(client, path, ...)`**:
     el ciclo que ejerce el backoffice (listar → alta → editar → releer por
     GET → borrar), armado con los MISMOS modelos públicos del punto 1 -- no
     una copia con la misma forma. Cada producto lo llama desde su propia
     suite, con su cliente admin.
- Las protecciones son la UNIÓN de las que tenía cada producto, no la
  intersección -- la tabla completa función × producto está en `README.md`.
  Dos quedan estrictamente MÁS estrictas que cualquier original: el mínimo
  de contraseña ahora aplica también al reset de la ajena, y la protección
  del único admin ahora cubre también "desactivar" (antes sólo cubría
  "degradar el rol"). Nadie pierde una protección al adoptar esto.
- El bug de Contalibra (rol inválido en el `PUT` escapando como 500) no se
  arregla parcheando su `db_usuarios.py`: se cierra de raíz porque la
  factory valida el rol ANTES de llamar al repositorio, con su propio
  mensaje en castellano, y además atrapa el `ValueError` del repositorio
  como red de seguridad si algún día `roles=` de la factory y el `roles=`
  del `UserRepository` de la instancia quedaran desalineados.
- `DELETE` unificado a `204 No Content` en los ocho, alineado con la mayoría
  (cinco de ocho). Contalibra, Restolibra y VentaLibra devuelven hoy `200`
  con `{"ok": true}`; sus frontends propios (no la pantalla compartida de
  `libra-ui`, que no lee el cuerpo del borrado) tienen que dejar de esperar
  ese cuerpo al adoptar la factory -- ver el riesgo anotado en el informe de
  la tarea que creó este ADR.
- **No incluye** el autoservicio "Mi Cuenta" (`PUT /api/usuarios/me/password`)
  que tienen Contalibra y Restolibra: cambia la contraseña PROPIA sin pedir
  la actual, con un guard distinto (cualquier usuario logueado, no sólo
  admin) y no lo consume la pantalla compartida de `libra-ui`. Es una
  funcionalidad de cuenta, ortogonal al ABM de usuarios; el equivalente ya
  cubierto por este motor es `POST /auth/change-password`
  (`session_auth.build_json_api_auth_router`), que sí pide la actual.
- Consecuencia asumida: adoptar la factory es un cambio de contrato para
  Contalibra/Restolibra más allá del código -- pasan de `nombre`/`activo` a
  `name`/`active` en el cuerpo JSON que ve su propio frontend (no el de
  `libra-ui`, que ya usaba este nombrado), así que sus `frontend/src/api.ts`
  y `Usuarios.tsx` propios necesitan su propio ajuste, no sólo el backend.
  No se resuelve en este ADR ni en `libraauth`: es trabajo de adopción de
  cada producto, evaluado por separado.
- Adenda (2026-09-14): `eliminar` sólo atrapaba `KeyError` -- borrar un
  usuario con historial (una fila de otra tabla de la familia con FK a
  `usuarios(id)`, como `turnos_caja.usuario_id`) chocaba con la FK y salía
  como `500`. Ahora `UserRepository.delete()` traduce el `IntegrityError` a
  `UsuarioConHistorial`, con `rollback()` de la sesión antes de propagarla
  (en PostgreSQL, sin eso, el PRÓXIMO pedido sobre la misma sesión sale con
  la transacción abortada), y el router responde `409` pidiendo desactivar
  al usuario en vez de borrarlo.

## ADR-019 — Los campos numéricos de entrada rechazan booleanos, con una guarda propia

- Estado: aceptada
- Fecha: 2026-10-04
- Contexto: `PUT /admin/smtp` aceptaba `{"port": true}`: Pydantic, en modo laxo,
  convierte `true` en `1` y `false` en `0` en un campo `int` (un `bool` es un
  `int` para Python), y el puerto `1` se guardaba en la configuración SMTP sin
  que nadie lo validara -- el rango del puerto se mira en
  `SmtpSettingsRepository.save`, ya con el número convertido, y `1` pasa.
  Lo detectó la guardia de booleanos del motor (libracommerce, ADR-028). Medido
  con Pydantic 2.13.5: los tres campos numéricos de entrada de este paquete
  tenían el mismo defecto: `_SmtpSettingsIn.port`, `_DemoCodigoIn.dias` y
  `_DemoCodigoIn.usos_max` (con `true` el alta de un código de demo "andaba" y
  emitía uno de 1 día y 1 uso). Los modelos de `usuarios.py` y `terminos.py`
  no tienen campos numéricos de entrada.
- Decisión: una guarda mínima y PROPIA, `_sin_booleano()` en
  `libraauth/session_auth.py`, enganchada con `@field_validator(..., mode="before")`
  en esos tres campos. Rechaza un `bool` con «<campo> tiene que ser un número,
  no un booleano» y sale por el `422` normal de Pydantic/FastAPI. Un entero, un
  texto numérico (`"587"`) y el campo omitido siguen valiendo como antes; el
  rango del puerto y el mínimo de `dias`/`usos_max` siguen donde estaban.
- Por qué acá y no importando la del motor: `libraauth` es la capa de abajo --
  `libracore` lo declara como dependencia -- y no puede importar de `libracore`
  ni de `libracommerce`. Duplicar cinco líneas es más barato que invertir la
  dependencia. Si el motor llegara a vivir en un paquete que `libraauth` pueda
  consumir, esta guarda se reemplaza por la compartida.
- Consecuencias: un cliente que mandaba `true`/`false` en estos campos (un
  error, no un uso legítimo) ahora recibe `422`. Un modelo nuevo con un campo
  numérico de entrada tiene que usar el mismo patrón; los tests de
  `test_smtp_settings.py` y `test_demo_codigos.py` fijan los tres casos.

## ADR-020 — Términos 1.1 publicados como «próxima versión», todavía no vigentes (2026-10-10)

**Pedido del dueño.** Los precios de la suite son finales con el IVA incluido, como ya decía la landing de VentaLibra. La
cláusula 5.1 de los términos (comunes a los ocho productos) decía «más IVA». Se decidió cambiarla para todos.

**Restricciones del propio contrato.**
- **29.2:** una modificación se publica en el sitio y se notifica con 30 días corridos de anticipación.
- **29.3:** recién al entrar en vigencia el sistema pide la nueva aceptación.
- **29.4:** el precio sólo cambia por acuerdo expreso; el aviso a cada cliente actual lo cubre.

El sistema no tenía versiones con fecha futura: subir `VERSION_VIGENTE` corta en el acto a los ocho productos.

**Decisión.**
- `terminos_v1_1.md`: la 1.0 tal cual, con dos cambios. El encabezado dice «Versión 1.1 — vigente desde el 09-11-2026», más una línea que explica el cambio. La 5.1 pasa a «como precio final con el IVA incluido cuando corresponda, más todo otro tributo que corresponda». Un test fija que no haya otra diferencia.
- `VERSION_PROXIMA`, `PROXIMA_DESDE` y `ARCHIVO_PROXIMA`, con `texto_proximo()`, `texto_html_proximo()` y `hash_proximo()`, que usan la misma normalización a LF y el mismo convertidor que la vigente.
- **No cambia nada adentro del sistema:** el gate y el hash de la prueba siguen siendo los de la 1.0. Sólo los usa `libra_web_kit.legal_gen` para publicar la 1.1 al lado de la vigente, con su hash verificable.
- **El 09-11-2026** se pasa a `VERSION_VIGENTE = "1.1"`, `VIGENTE_DESDE = "09-11-2026"` y `ARCHIVO_TERMINOS = terminos_v1_1.md`, y las tres de la próxima vuelven a `None`. Se corta un tag nuevo, se sube el pin en los ocho productos y se despliega. Ese día el sistema pide la nueva aceptación. La 1.0 queda en el repo: es la prueba de lo que aceptó cada cliente.

**No cubre.** Un aviso adentro del sistema antes de la vigencia; el aviso a los clientes actuales lo manda el dueño.

## ADR-021 — La versión vigente de los términos se decide por fecha: la 1.1 entra sola el 09-11-2026 (2026-10-10)

**Pedido del dueño.** Que la 1.1 (ADR-020) «se active sola el 09-11», sin depender de un deploy ese día y respetando los 30
días de aviso de la cláusula 29.2.

**Problema.** La vigente era una constante leída al importar. Además, `TerminosRepository` fijaba la versión al construirse
y guardaba en memoria «ya aceptó» sin decir de qué versión: un proceso que viniera corriendo desde antes del 09-11 habría
seguido dando por aceptada la 1.0.

**Decisión.**
- `version_vigente(hoy)` y `vigente_desde(hoy)` devuelven la próxima desde `PROXIMA_DESDE` (00:00 de Argentina, `-03:00`
  fijo) y la anterior antes de esa fecha. `texto_vigente`, `hash_vigente`, el gate, el estado y `/aceptar` usan esas
  funciones. `texto_proximo` devuelve `None` una vez que la próxima rige. `VERSION_VIGENTE` queda como la versión base.
- `TerminosRepository(version=None)` resuelve la versión en cada llamada, y la memoria del «ya aceptó» guarda **qué**
  versión: el 09-11 el mismo proceso vuelve a cortar con 403, pide la 1.1 y guarda la fila nueva con su hash.
- Los tests fijan el día (`_hoy_argentina`) antes del cambio y prueban el paso explícitamente. Si no, desde el 09-11 se
  habrían roto solos todos los que aceptan `VERSION_VIGENTE`.

**No cubre.** Las páginas públicas de los sitios son HTML estático: el 09-11 hay que regenerarlas (`generate_legal.py`)
para que `terminos.html` pase a mostrar la 1.1.

## ADR-022 — El formato del log de actividad es uno solo y tiene dos caminos de escritura: el flush del ORM y `registrador_dbapi` (2026-10-12)

**Pedido del dueño.** Que la auditoría de escrituras viva en el motor: que el CRUD de clientes de LibraDesk pueda pasar por
`libracore.db.clients` sin perder el log, que lo usen también VentaLibra, Contalibra y Restolibra, y que el log de
`libracommerce` deje de ser una segunda copia del formato.

**Problema.** El formato de `actividad_log` estaba definido dos veces: acá, colgado del `flush` de SQLAlchemy, y en
`libracommerce.db.auditoria`, para el SQL crudo. La copia ya había divergido: tapaba menos columnas (sin `password_cifrada`,
`token_hash` ni `secret_key`: el valor de una contraseña SMTP cambiada habría quedado copiado en el diff), ignoraba
`created_at` y declaraba `entidad_id INTEGER`. Y `libracore` no tiene SQLAlchemy ni auditoría: sus clientes sólo se auditaban si
el producto los escribía por su propio ORM, que es por lo que LibraDesk no podía adoptar `db/clients.py`.

**Decisión.**
- **Funciones puras que definen el formato**, y el listener del ORM pasa por ellas con salida idéntica a la de antes:
  `fila_de_auditoria` (descripción `«<Entidad> — <etiqueta>»`, usuario del `ContextVar`, `entidad_id` como texto),
  `diff_de_valores` (compara el valor crudo; `[antes, después]` sólo de lo cambiado; ocultas tapadas con `[OCULTO, OCULTO]`;
  ignoradas fuera; gancho `resumir`) y `etiqueta_de_valores` (la regla de `ATRIBUTOS_ETIQUETA` sobre una función
  `atributo -> valor`).
- **`registrador_dbapi(entidades, *, atributos, columnas_ocultas, columnas_ignoradas, etiqueta, resumir)`** devuelve un
  callable `(conn, cambio)`. `cambio` se lee por duck typing (`tabla`, `accion`, `id`, `antes`, `despues`), así que `libracore`
  y `libracommerce` lo usan sin que este paquete importe de ellos ni ellos de este. Inserta con `?`, el `ts` como texto
  `YYYY-MM-DD HH:MM:SS` y **sin commit**: la fila vive y muere con la transacción de la escritura. Una edición que llega
  **sin foto de `antes`** (un repositorio que no sabe leer el estado previo) se registra sin detalle: el hecho queda, el
  diff no se inventa. Una `etiqueta` propia que devuelve `None` cae en el armado por defecto, para resolver sólo las tablas
  que el producto conoce.
- **Las claves del diff son atributos del ORM, no columnas** (el caso `nombre` → `name` de LibraDesk): `atributos` renombra, y
  las ocultas se comparan contra las dos formas del nombre, como en el ORM.
- **Una tabla para el que no tiene `AuditoriaBase`:** `crear_tabla_actividad_log(bind)`, idempotente, con un `Engine` o una
  `Connection`. No hay DDL crudo aparte a propósito: una tercera definición de la tabla es lo que se quiere evitar.
- **Un test de paridad** (`tests/test_registrador_dbapi.py`) hace el mismo alta, edición, desactivación y baja por los dos
  caminos y exige filas iguales salvo `id` y `ts`; el de PostgreSQL entra al gate del CI.

**Lo que no resuelve.**
- La tabla que ya existe no se corrige. Contalibra, Restolibra y VentaLibra la tienen por el DDL de `libracommerce`
  (`entidad_id INTEGER`, `ts TEXT`); el registrador entra igual (el id va como texto y PostgreSQL lo asigna al entero, medido).
  Sólo falla si algún día un id no numérico se audita ahí.
- Un valor se informa como lo devuelve la base: una columna entera que el ORM mapea a `Boolean` da `[1, 0]` por DB-API y
  `[True, False]` por el ORM. La pantalla lo muestra igual; si importara, el producto normaliza antes de pasar el cambio.
- La etiqueta del camino DB-API sólo ve las columnas de la fila, no propiedades ni relaciones del modelo.

## ADR-023 — Varios procesos por producto: el captcha anota en la base y el estado del backoffice se escribe bajo `flock` (2026-10-13)

**Pedido del dueño.** Dejar el código listo para correr un producto con `uvicorn --workers N` (`WEB_CONCURRENCY`) arreglando todo lo que se rompe con N procesos, **sin prender más workers todavía**: todo sigue en 1.

**Qué ya existía (se miró antes de diseñar).** El bloqueo por IP del login de los productos cuenta sobre `auth_log` (`contar_fallidos_seguro`): ya es compartido. `libracore.arca_wsaa._cerrojo` (`flock` sobre `<ticket>.lock`, no bloqueante con `asyncio.sleep`, límite de espera) es el patrón de exclusión entre procesos de la familia, y `libracommerce` ya serializa con `pg_advisory_xact_lock`. Lo que **no** era compartido: el anti-replay del captcha (`Captcha._usados`, un `dict` en el proceso) y el estado de `AdminAuth` (`_EstadoLogin` / `_EstadoTotp`, con `threading.Lock` y un JSON).

**Decisión.**
- **Captcha: costura `usados=`.** `Captcha(secret, usados=...)` delega en un objeto con `usar(firma, vence, ahora) -> bool` (`True` si era la primera vez). `UsadosEnMemoria` es el default y hace exactamente lo de antes. `UsadosEnBase(session_factory, poda=0.02)` hace un `INSERT ... ON CONFLICT DO NOTHING ... RETURNING firma` sobre `libraauth_captcha_usados(firma PK, vence)`: si devuelve la fila, aceptado; si no, replay. Poda probabilística de los vencidos (`DELETE ... WHERE vence < ahora`, 2 % de las veces). Se usa `RETURNING` y no `rowcount` porque con psycopg 3 el `rowcount` de ese INSERT vuelve −1 (medido). Otros dialectos caen en un `INSERT` pelado dentro de un savepoint. **Si la base falla, `usar` levanta** (el login da 500): un captcha que no se puede validar no se da por bueno, al revés del rate limiting, que falla abierto, porque acá lo que cuesta el error es justamente lo que el captcha cobra.
- **Cómo se pasa la sesión:** `build_json_api_auth_router(captcha=True, captcha_usados=UsadosEnBase(SessionLocal))`, o a mano en `app.state.captcha = Captcha(secret, usados=...)` (que manda sobre el parámetro, como siempre).
- **Migración `0003_captcha_usados`**, en la cadena propia (`alembic_version_libraauth`): crea la tabla y el índice sobre `vence` sólo si faltan (el `create_all()` del arranque puede haberla hecho antes, igual que `0001`/`0002`). **Se puede bajar** (a diferencia de `0001`/`0002`): es un cerrojo de vida corta (los desafíos duran 10 minutos) y no guarda nada que haya que conservar. Modelo `CaptchaUsado` y revisión van juntos, como manda `models.py`; `test_modelo_y_cadena_coinciden` lo verifica.
- **Backoffice (`AdminAuth`): `flock` sobre `<estado>.lock`** alrededor de cada leer-modificar-escribir (`registrar_fallido`, `marcar_paso_totp`, `reclamar_paso_totp`, y la escritura del archivo TOTP), además del `threading.Lock`. Es el patrón de `arca_wsaa._cerrojo`: `flock` no bloqueante con reintento y **límite de 5 s**; si vence o el `.lock` no se puede abrir, se avisa y se sigue **sin** cerrojo (falla abierto, como el resto del rate limiting). El temporal de la escritura atómica pasa a ser propio de cada proceso e hilo (`<archivo>.<pid>.<tid>.tmp`): con el nombre fijo `.tmp` dos procesos se lo pisaban.
- **Anti-replay del TOTP atómico:** `reclamar_paso_totp(paso) -> bool` compara y escribe dentro de la misma sección crítica. `check_credentials` y `verificar_codigo_totp` lo usan: `paso_valido` filtra rápido y el que decide es el reclamo, así que dos procesos con el mismo código dan un `True` y un `False`. `confirmar_totp` y `desactivar_totp` siguen con `marcar_paso_totp` (que ahora es atómico) porque su orden «guardar, releer y recién entonces marcar» es parte del contrato.
- **Aviso en el arranque:** `AdminAuth` loguea un warning si `WEB_CONCURRENCY` > 1 y no hay `ADMIN_PANEL_ESTADO_PATH`: sin archivo, cada worker lleva sus propios intentos (N veces más) y su propio último código.
- **El rate limit del login de los productos no se toca** (`auth_log`): un test con dos procesos y PostgreSQL lo fija para que nadie lo pase a memoria sin saberlo.

**Verificación.** Cada arreglo tiene su prueba con procesos de verdad (`multiprocessing`, `spawn`) y se puso roja sin él: 2 procesos × 50 fallidos ⇒ 100 (sin `flock`: 50); el mismo código TOTP, 3 rondas, un solo proceso lo acepta (sin `flock`: 2); el mismo desafío del captcha, 15 rondas, un solo proceso lo acepta (con `UsadosEnMemoria`: 2).

**Lo que no resuelve.**
- `UsadosEnBase` agrega una ida a la base por cada login con captcha.
- El estado de `AdminAuth` sigue en un archivo: dos **contenedores** (no procesos de uno) tendrían que compartir el volumen.
- No hay un helper de `create_engine` en este paquete (cada producto arma el suyo), así que `pool_pre_ping=True` es de cada producto; hoy lo tienen libradesk, libracargo, libraclub y libra-panel, y no contalibra, restolibra, gestiolibra, medlibra ni ventalibra.

**Consecuencias.** MINOR (propuesta v0.50.0), **con migración** (`0003`): la cabeza de la cadena cambia, y `exigir_schema_al_dia` hace que un producto que sube el pin sin correr `libraauth-migrar` no arranque (con el comando en el mensaje), aunque no use `UsadosEnBase`.


## ADR-024 — El responsable acepta por adelantado la próxima versión de los Términos, desde adentro del sistema (2026-10-15)

**Pedido del dueño.** Los Términos 1.1 (ADR-020: el abono pasa a precio final con IVA incluido) entran solos el 09-11-2026 (ADR-021).
La cláusula 29.2 pide 30 días de aviso y la 29.4 un acuerdo expreso para un cambio de precio. Decidió que esa conformidad se dé
**dentro del sistema** y no por correo: que el responsable de cada cliente pueda aceptar la 1.1 al entrar, antes de que rija.

**Problema.** El estado no sabía de la próxima versión (ADR-020 lo dejó fuera a propósito: «no cubre un aviso adentro del
sistema») y `POST /aceptar` rechazaba con 409 cualquier versión que no fuera la vigente. La única aceptación posible de la 1.1
era el 09-11, con la aplicación ya bloqueada.

**Qué ya existía (se miró antes de diseñar).** `version_vigente(hoy)` por fecha, `texto_proximo`/`hash_proximo`/`texto_html_proximo`,
y una tabla de aceptaciones con la **versión y el hash** en cada fila. Con eso, lo que hace falta es una sola cosa: poder escribir
la fila de la 1.1 antes de la fecha. El 09-11 `aceptacion_vigente()` busca **por versión**, así que la encuentra sin tocarla.

**Decisión.**
- **`GET /terminos` suma `proxima`**: `{version, vigente_desde, hash_texto, aceptada, aceptada_por, aceptada_at,
  resumen_del_cambio, texto, texto_html}`, o `null` si no hay próxima anunciada. `texto` y `texto_html` sólo viajan con `?texto=1`
  (igual que los de la vigente: ~30 KB que el gate no necesita en cada carga). **Los campos que ya había no cambian.** El
  `resumen_del_cambio` es `RESUMEN_PROXIMA`, una constante junto a `VERSION_PROXIMA`/`PROXIMA_DESDE`/`ARCHIVO_PROXIMA`.
- **`POST /aceptar` acepta la vigente o la próxima**, con la misma regla de roles (`ROLES_QUE_ACEPTAN`, cláusula 30.5, 403 antes que
  nada), la misma fila (`AceptacionTerminos`: versión, hash del texto, usuario, IP, user-agent, fecha) y el mismo rastro
  (`GET /historial`). Otra versión sigue siendo 409. Es idempotente por versión. `TerminosRepository.registrar_proxima` la
  escribe y **no toca la memoria de `esta_aceptada`**: aceptar la 1.1 no dice nada de la vigente, que sigue pendiente si lo estaba.
- **El 09-11 la instancia que ya aceptó no queda pendiente.** No hay código nuevo para eso: es la propiedad de buscar por versión.
  Un test mueve la fecha y lo fija con el mismo proceso, sin redeploy; su control negativo (sin aceptación adelantada, sigue
  pendiente) evita que el verde se explique por un gate que ya no corta.
- **Una demo no ve el aviso ni acepta la próxima** (`proxima: null`, y `POST` de la 1.1 da 409): en una demo no hay Cliente ni
  contrato (`exige_aceptacion()`), el mismo argumento que para `pendiente`; y el reset nocturno borra la tabla, así que una
  aceptación ahí no probaría nada.
- **Sin cambios de schema ni migración**: ninguna columna nueva. La aceptación adelantada se distingue de una normal porque su
  `aceptado_at` es anterior a la `vigente_desde` de su versión. Un producto que sube el pin no corre `libraauth-migrar`.
- **El texto de la 1.1 queda congelado.** La fila adelantada guarda (versión, hash) y el 09-11 se encuentra por versión; si el
  Markdown de la 1.1 cambiara después de que un cliente la aceptó, esa fila probaría haber aceptado otro texto, sin síntoma. Un
  test fija el sha256 de la 1.1: cambiar el contenido exige una versión nueva (1.2), como ya dice el comentario de
  `VERSION_VIGENTE`. (La aceptación de la vigente tiene el mismo supuesto, pero ahí no hay ventana entre aceptar y regir.)

**Prefijos.** Nada cambia: el bloque `proxima` y `POST /aceptar` cuelgan del mismo router, así que ContaLibra y RestoLibra
(`build_terminos_router(prefix="/api/terminos")`) lo sirven donde ya lo servían; un test lo fija. El frontend ya lo sabe por
`terminosPath` de `createAuthContext`.

**Cuando la próxima rige.** `proxima_anunciada()` devuelve `None` (`texto_proximo` ya lo hacía) y `proxima` vuelve a `null`. La
limpieza de ADR-020 (pasar la 1.1 a `VERSION_VIGENTE` y quitar las constantes de la próxima) suma una a la lista: `RESUMEN_PROXIMA`.
Mientras no se haga, no estorba.

**Lo que no resuelve.**
- No avisa a quien no puede aceptar: el estado se lo cuenta (`puede_aceptar`), pero la decisión de mostrarlo es del frontend.
- Una instancia nueva que acepta la 1.0 después del anuncio ve el aviso igual: son dos aceptaciones, a propósito.
- La conformidad por escrito de la 29.4 sigue siendo del dueño; esto es la forma de darla, no un reemplazo del aviso.

**Consecuencias.** MINOR (propuesta v0.51.0), **sin migración**. Un frontend anterior ignora `proxima` (campo nuevo, aditivo).
Para que el responsable vea el aviso hace falta `libra-ui` 0.153.0 (`GateTerminos`); sin él, el endpoint anda y nadie lo muestra.

**Verificación.** **779 → 793 tests** (1 omitido igual que antes): 14 nuevos en `tests/test_terminos.py` y 1 reescrito
(`test_el_dia_anterior_sigue_rigiendo_la_1_0`, que afirmaba el 409 de la 1.1 y ahora afirma que se registra sin destrabar la 1.0).
**Contra `origin/develop` (el `terminos.py` anterior con los tests nuevos) fallan 13 de 48**: los 11 que ejercen el estado y la
aceptación adelantada, el del prefijo `/api/terminos` y el reescrito; los otros 2 nuevos pasan en los dos árboles a propósito: el
control negativo del 09-11 (sin aceptación adelantada sigue pendiente) y el que congela el hash de la 1.1. Suite completa en
PostgreSQL local con `-n 4` y `ruff` limpios.


## ADR-025 — Token de servicio con rotación sin corte, y credencial de integración aparte (2026-10-18)

**Pedido del dueño (2026-10-18).** El token de servicio pasa de «uno por producto» a «uno por instancia», y lo que llama a una
instancia para meterle datos (integraciones, ingesta de comprobantes) deja de usar ese token y lleva una credencial propia. Este es
el primer paso de la serie y sólo toca libraauth: los productos y el backoffice adoptan después.

**Problema.** `LIBRA_SERVICE_TOKEN` es compartido por las instancias de un producto (medido el 2026-08-20: dos clientes distintos de
LibraDesk tienen el mismo), y una integración que lo tiene abre además usuarios, SMTP y el resto de lo que administra el backoffice.
Para pasar a uno por instancia hay que cambiar el token en la instancia y en el backoffice, y hoy eso es un corte: entre que cambia
uno y cambia el otro, el backoffice recibe 401.

**Qué ya existía (se miró antes de diseñar).** `token_de_servicio_valido()` (`x-internal-auth`, `hmac.compare_digest`, falla cerrado
sin variable) y la credencial del panel por instancia (`LIBRA_PANEL_TOKEN`/`x-panel-auth`, `PANEL_USER`, gates propios aplicados
router por router), que es el precedente que se copia.

**Decisión.**
- **Rotación sin corte**: `LIBRA_SERVICE_TOKEN_ANTERIOR`. Si está definida, `token_de_servicio_valido()` acepta el nuevo **o** el
  anterior. Se rota así: se pone el nuevo en la instancia y el viejo en `_ANTERIOR`; se cambia el backoffice; se borra `_ANTERIOR`.
  Vacía o ausente no vale nada (cada variable por sí sola; un header vacío nunca entra).
- **Siempre las dos comparaciones**, con `hmac.compare_digest` y sin cortocircuito: el tiempo de respuesta no dice cuál coincidió
  ni que hay una rotación en curso. Se comparan bytes, así que un header no ASCII da `False` en vez de un `TypeError`.
- **Aviso de token corto**: si una variable definida tiene menos de 32 caracteres (`LARGO_MINIMO_DE_TOKEN`), un `WARNING` en
  `libraauth.session_auth`, una vez por variable y por proceso, con el nombre y nunca el valor. No se rechaza: no se le corta el
  servicio a una instancia en producción por esto.
- **Credencial de integración**: `LIBRA_INTEGRACION_TOKEN` (+ `LIBRA_INTEGRACION_TOKEN_ANTERIOR`, misma rotación), header
  `x-integracion-auth`, `token_de_integracion_valido()`, identidad `INTEGRACION_USER` (`@integracion`, `id: None`,
  `es_integracion: True`). Su `role` es `"integracion"` y **no** `"admin"`: si por un descuido llega a código que pregunta por admin,
  la respuesta es no.
- **Dos gates nuevos**, aplicados router por router:
  - `json_api_require_admin_o_servicio_o_integracion`: admin de la instancia, servicio o integración. Para `/api/integraciones/*` y
    la ingesta de comprobantes que también se maneja desde la pantalla. Con la sesión hace lo mismo que el de servicio (Términos y
    excepción de lectura de la demo).
  - `json_api_require_integracion_o_servicio`: sólo credenciales de máquina, ninguna sesión (401). Para endpoints sin pantalla.
- 🔴 **La integración no abre ningún gate anterior**: `json_api_require_admin`, `_staff`, `_admin_o_servicio`,
  `_admin_o_servicio_o_panel`, `_panel_o_admin`, ni los routers de SMTP, usuarios y códigos de demo. Por eso son gates nuevos y no
  una ampliación de `json_api_require_admin_o_servicio`, el mismo argumento que con el gate del panel (v0.35.0). Los tests lo fijan.

**Lo que no cambia.** Sin las variables nuevas todo se comporta como antes. La credencial del panel no gana `_ANTERIOR` (no se
pidió; se suma igual si hace falta). El panel sigue sin aceptar el token de servicio.

**Lo que no resuelve.** Generar un token por instancia, cargarlo en el backoffice y mover cada ruta de integración al gate nuevo es
trabajo de los PRs siguientes de la serie, en los productos y el backoffice.

**Consecuencias.** MINOR (propuesta v0.52.0), **sin migración**, aditivo: constantes, funciones y gates nuevos; ninguna firma cambia.

**Verificación.** `tests/test_token_rotacion_e_integracion.py` (nuevo, 31 tests) más `test_service_token.py`, `test_panel_token.py` y
`test_gate_panel.py` sin cambios, en local sin xdist; suite completa en CI.

## ADR-026 — La marca `Secure` de la cookie de sesión de la app se puede apagar por entorno, para el nodo de LibraEdge (2026-10-20)

**Problema (medido en una VM Ubuntu 26.04 con el nodo de ContaLibra, libraedge v0.15.0).** El nodo de LibraEdge sirve el
producto por **http** en la LAN: `http://localhost:8000` en la PC y `http://<IP>:8000` desde las otras cajas. `SessionAuth`
ponía la cookie con `secure=True` fijo. En la app de escritorio (Tauri sobre WebKitGTK) `POST /api/login` daba 200, la cookie
no se guardaba y el pedido siguiente daba 401: WebKit no hace la excepción de `localhost` para cookies `Secure` por http. Desde
las otras cajas, por `http://<IP>:8000`, **ningún** navegador la guardaría (Chrome y Firefox sólo exceptúan `localhost`).

**Qué ya existía (se miró antes de diseñar).**
- Las variables de libraauth se leen con `os.environ.get` en el momento de usarlas (`LIBRAAUTH_PROXIES_DE_CONFIANZA` en
  `auth_events.py`, los tokens de ADR-025), con prefijo `LIBRAAUTH_` para lo propio del paquete.
- Los flags booleanos se leen con `.strip().lower()` contra una lista cerrada (`DEMO_MODE` en `session_auth.py`).
- El aviso en el log una vez por proceso, con el nombre de la variable y nunca el valor (ADR-025, token corto).
- Las únicas cookies que pone libraauth son la de sesión de `SessionAuth` (`create_session_cookie`, también usada por la
  renovación deslizante del ADR-017 y por el login de la demo) y la del backoffice de `AdminAuth`. El captcha (ADR-014) no usa
  cookies, y no hay CSRF ni «recordarme» con cookie propia.
- La **lectura** de la sesión (`get_current_user`, los guards y `/me`) no mira el esquema de la URL: sólo valida la firma.

**Decisión.**
- `LIBRAAUTH_COOKIE_SECURE` (`COOKIE_SECURE_ENV`) y `cookie_secure()` en `session_auth.py`. **Default: `Secure`.** Sólo un
  «falso» explícito la apaga: `0`, `false`, `no`, `off` (sin importar mayúsculas ni espacios). Cualquier otro valor —vacío, `1`,
  `true`, `falso`, `flase`— la deja `Secure`: un error de configuración tiene que dejar la seguridad puesta.
- Se lee en cada `create_session_cookie`, así que el login, el login de la demo y la renovación deslizante salen con la misma
  marca. `HttpOnly` y `SameSite=Lax` no cambian.
- Aviso `WARNING` en `libraauth.session_auth` una vez por proceso si la marca queda apagada, y otro si la variable tiene un valor
  que no se reconoce (se ignora). Sólo el nombre de la variable.
- **`AdminAuth` no la lee**: el backoffice de superadmin no se sirve en nodos y su cookie sigue `Secure` siempre (un test lo fija).

**Quién la apaga.** El instalador de LibraEdge, en el `nodo.env` de cada nodo (libraedge ADR-016). Ninguna instancia de la nube.

**Lo que no cambia.** Sin la variable, todo igual. Un producto con un libraauth anterior a esta versión ignora la variable: en el
nodo queda como hoy (login roto por http) hasta que suba el pin.

**Lo que no resuelve.** La cookie viaja en claro por la LAN del local (sin TLS). Es el mismo riesgo que ya tenía la clave en el
`POST /api/login` por http; servir el nodo por https con un certificado local es otro trabajo. `Strict-Transport-Security` (que
pone `libracore.security_headers`) por http lo ignoran los navegadores (RFC 6797 §8.1) y no aplica a IPs: no hace falta tocarlo.

**Consecuencias.** MINOR (propuesta v0.53.0), **sin migración**, aditivo: una constante y una función nuevas; ninguna firma cambia.

**Verificación.** `tests/test_cookie_secure.py` (nuevo): default `Secure`; los cuatro falsos (con mayúsculas y espacios) la
apagan; vacío, verdaderos y valores raros no; login y `/api/me` de punta a punta por `http://<IP>:8000` con el router JSON real;
sin la variable, por http, el cliente no devuelve la cookie (401, el bug); la lectura no exige https; logout por http; renovación
con la misma marca; avisos del log; `AdminAuth` sin la variable. Más `test_session_auth.py` sin cambios.


## ADR-027 — Los usuarios de un nodo de LibraEdge son los del central: el nodo no los escribe (2026-10-21)

**Decisión del humano (2026-10-21).** Los usuarios del nodo son los del central. Cada cajero entra con su usuario y su clave de
siempre aunque no haya internet; los cambios de usuarios se hacen en el central (la versión web) y bajan al volver la conexión.
`usuarios` es una tabla **espejo** del nodo (LibraEdge la baja del central): el nodo la lee, no la escribe.

**Problema (medido con la base real).** En un nodo recién instalado `ensure_default_admin` / `ensure_admin_user` ven la tabla vacía y
crean un `admin` local con clave aleatoria. Cuando baja el `admin` del central —otro id, mismo `username`— el `INSERT` choca con
`UNIQUE(username)` y **traba la bajada de la tabla entera** (`test_el_choque_que_motivo_el_cambio`). Y por la API, cualquier alta,
edición, cambio de clave o baja hecha en el nodo es una escritura que el espejo pisa en la próxima bajada, o que se queda sin
subir a ningún lado.

**Qué ya existía (se miró antes de diseñar).**
- libraedge reconoce el nodo por `LIBRAEDGE_NODE_ID` (`cli.py`, `_requerido`), pero no exporta un helper, y libraauth no depende de
  libraedge ni de nada de la familia: el helper es propio y lee la misma variable.
- Los 409 con `detail` de código ya tienen precedente en `terminos.py` (`{"code": "terminos_pendientes", "mensaje": ...}`): el
  frontend matchea por el código, no por el texto.
- Las variables se leen con `os.environ.get` en el momento de usarlas (ADR-025, ADR-026).
- Los puntos que escriben `usuarios` (relevados con `grep` de `.create(`, `.update(`, `.update_password(`, `.delete(`,
  `session.add`/`commit` sobre `Usuario`): `bootstrap.py` (tres funciones), `usuarios.py` (alta, edición, clave, baja),
  `session_auth.py` (`/auth/change-password`, `/auth/reset-password`), `password_reset.py` (vía `reset`), `repository.py`
  (`_rehash`). `AdminAuth` (el superadmin del backoffice) no usa `usuarios`.

**Decisión.**
- `libraauth/nodo.py` (nuevo): `es_nodo()` —`LIBRAEDGE_NODE_ID` definida y no vacía, leída en cada llamada—, la guarda
  `exigir_central()` y `exigir_central_si_escribe(request)`, y `error_solo_en_el_central(mensaje)`. Contestan **409** con
  `detail = {"code": "solo_en_el_central", "mensaje": "Los usuarios se administran desde la versión web."}`.
- **Arranque.** `ensure_default_admin`, `ensure_admin_user` y `ensure_demo_user` no crean nada en un nodo y dejan una línea
  `[INFO]` que nombra la variable. `ensure_default_admin` tampoco exige `<PREFIX>_ADMIN_PASSWORD` ahí (el nodo no la tiene y no la
  necesita). Es el mismo cierre para los tres: son los únicos que crean usuarios al arrancar.
- **API de usuarios.** `build_users_router` cuelga `exigir_central_si_escribe` del **router entero**, después del guard de admin
  (quien no es admin sigue recibiendo su 401/403 y no se entera de si es un nodo): alta, edición, clave de otro, **clave propia por
  el ABM** y baja dan 409; las lecturas (`GET`) andan. Cuelga del router y no de cada ruta para que una ruta que se agregue
  mañana nazca cerrada en el nodo. La guarda corre antes de validar el cuerpo: un cuerpo inválido da 409, no 422.
- **Clave propia y recupero por correo** (los otros caminos que escriben `usuarios`): `POST /auth/change-password`,
  `POST /auth/forgot-password` y `POST /auth/reset-password` llaman a `exigir_central()` y dan el mismo 409. El cambio de clave propia
  lo hace después de la identidad y antes de mirar la clave actual, así que ni cuenta como intento fallido.
- **`_rehash`** no escribe en un nodo: el login sigue verificando la clave (sin internet, contra el espejo) y deja el hash como
  está; se migra a argon2 cuando el usuario entra al central y el espejo lo baja.
- **Términos y Condiciones.** *Hoy*, el gate lee `aceptaciones_terminos` de la base local: si el espejo no la trae (inferido, no medido: no se
  verificó qué tablas espeja cada instalación), el nodo arranca con el gate **cortando**: el local entero queda sin vender con un 403 `terminos_pendientes`; y si el `admin` espejado acepta ahí, la
  prueba de la cláusula 30.3 queda escrita en una base que no es la del central. *Decisión*: `exige_aceptacion()` devuelve `False`
  en un nodo —igual que en una demo—, con lo que el gate no corta, `pendiente` es `false` y no hay aviso de próxima versión;
  `puede_aceptar` es `false`; `POST /terminos/aceptar` da 409 `solo_en_el_central` con «Los Términos se aceptan desde la versión
  web.»; y si el espejo trae una aceptación, `GET /terminos` y `/historial` la siguen mostrando. La aceptación se hace una sola vez,
  en el central.
- **Usuario dado de baja.** Un `activo=false` que baja del central ya corta la sesión: `json_api_get_current_user` vuelve a leer el
  usuario en cada pedido y da 401 si `active` es falso, y `check_credentials` no deja volver a entrar. No hizo falta código; el
  test lo fija con la base real (`test_el_usuario_que_baja_inactivo_pierde_la_sesion_del_nodo`).

**Lo que no cambia.** Sin `LIBRAEDGE_NODE_ID`, todo igual: cada caso nuevo lleva su contraprueba en el central. Ninguna firma cambia.

**Lo que no resuelve (abierto).**
- **Baja física en el central.** `UserRepository.delete()` hace `DELETE` físico y convierte la violación de FK en
  `UsuarioConHistorial` (409 «desactivalo»), así que en el central un usuario con historial ya no se puede borrar. El riesgo es
  otro: un `DELETE` de un usuario *sin* historial en el central baja al nodo como borrado, y si el nodo tiene filas propias que lo
  referencian (turnos, ventas aún sin subir) viola la FK y **traba el espejo**. Recomendación, **no implementada** (cambia el
  comportamiento del central: el 204 de la baja pasaría a ser una desactivación y la fila seguiría ocupando el `username`): que la
  baja desde el ABM sea lógica (`activo=false`) y que el borrado físico quede para quien lo pida expresamente. Va a decisión.
- **Guards de las apps server-rendered.** `SessionAuth.require_auth/require_admin/require_role` y `get_current_user_json` de
  Contalibra/Restolibra no miran `active` de la sesión en curso (sólo `json_api_get_current_user` lo hace): un usuario desactivado
  conserva la sesión ya abierta hasta que vence la cookie. Pasa igual en el central; en el nodo no se puede cortar de otra forma.
  Se informa aparte, no se toca acá.
- **`PasswordResetService.reset()` llamado directo** por un producto (sin pasar por el router) no tiene la guarda: es de la capa de
  servicio, y los routers de libraauth, que son su único llamador en la familia, sí.
- El valor de `LIBRAEDGE_NODE_ID` no se valida contra nada: alcanza con que esté definida.

**Consecuencias.** MINOR (propuesta v0.54.0), **sin migración**, aditivo: un módulo nuevo (`libraauth.nodo`) y guardas que sólo actúan
con la variable. El producto con un libraauth anterior a esta versión se comporta como hoy en el nodo (admin local, escrituras
abiertas, gate de Términos cortando) hasta que suba el pin.

**Verificación.** `tests/test_nodo.py` (nuevo, 28 tests), con las contrapruebas del central; puesto sobre el código sin el arreglo, 11
de los 28 se ponen rojos (el resto son las contrapruebas del central y las lecturas, que tienen que pasar en los dos). Más los
archivos vecinos en local sin xdist; suite completa en CI.

## ADR-028 — En un nodo de LibraEdge no se pide captcha (2026-10-21)

**Decisión del humano (2026-10-21).** En un nodo de LibraEdge no se pide captcha: al nodo sólo se llega por la red del local, no
desde internet. Siguen el bloqueo por intentos fallidos y la clave. En la nube (fuera de un nodo) todo sigue igual. Es una
excepción a la decisión del 2026-09-11 de ADR-014 («el captcha va siempre»), que se tomó pensando en un servicio público.

**Problema (medido en una prueba real, 2026-10-21).** Desde un puesto (otra PC del local) se entra a la PC principal por
`http://<IP-LAN>:8000`. El widget ALTCHA muestra «Secure context (HTTPS) required.»: resuelve la prueba de trabajo con WebCrypto
(`crypto.subtle`), que Chromium/WebView2 y WebKitGTK sólo exponen en contextos seguros (https o `localhost`). Sin widget no hay
solución, y sin solución el login da 400. Resultado: nadie podía iniciar sesión desde un puesto, ni en la app de escritorio
(Tauri) ni en un navegador. No se arregla del lado del widget: es una restricción del navegador sobre el origen, y poner https
con certificado propio en cada PC del local es otro proyecto (ver ADR-026, que ya apagó la marca `Secure` de la cookie por lo mismo).

**Qué ya existía (se miró antes de diseñar).**
- `libraauth.nodo.es_nodo()` (ADR-027): `LIBRAEDGE_NODE_ID` definida y no vacía, leída en cada llamada.
- Las rutas que exigen captcha cuando `captcha=True`, relevadas con `grep` de `captcha` en `session_auth.py`: **dos**,
  `POST {prefijo}/login` y `POST {prefijo}/forgot-password`. No hay alta pública ni otra ruta con captcha; `AdminAuth` (backoffice)
  no lo usa. En un nodo `forgot-password` ya daba 409 `solo_en_el_central` antes de mirar el captcha (ADR-027).
- **Cómo lo consume el frontend** (`libra-ui`, `src/captcha.ts`, `useCaptcha`): consulta `GET {captchaPath}` al montar y sólo
  dibuja el widget y deshabilita «Ingresar» si la respuesta tiene la **forma** de un desafío (`parameters` objeto + `signature`
  texto). Cualquier otra cosa —un 404, el `index.html` del catch-all de la SPA, un JSON sin esa forma— deja el captcha apagado y el
  login manda sólo usuario y clave. Es decir: el contrato «sin captcha» ya existía del lado del cliente; faltaba que el servidor
  lo dijera.
- **El bloqueo por intentos fallidos** que sigue protegiendo el login (no se toca): `max_intentos_fallidos` (default **5**) por
  `ventana_fallidos_minutos` (default `VENTANA_FALLIDOS_MINUTOS` = **15**) en `build_json_api_auth_router` (`session_auth.py`, login:
  el corte va antes de mirar la credencial); cuenta los `login_fallido` de la IP del cliente en `auth_log`
  (`AuthEventRepository.contar_fallidos_recientes` y `contar_fallidos_seguro`, `auth_events.py`) y contesta **429**. La IP sale de
  `ip_del_request`. Lo que sigue valiendo: un fallido se anota aunque el usuario no exista, y el 429 corta con la clave buena.

**Decisión.**
1. **Contrato: `GET {prefijo}/captcha` contesta `200 {"requerido": false}` en un nodo.** Con `Cache-Control: no-store`, igual que
   el desafío. Fuera de un nodo no cambia ni un byte: el desafío de siempre (`parameters` + `signature`), sin campo `requerido`.
   La regla para el cliente es la que ya aplica libra-ui: *hay captcha si y sólo si la respuesta es un desafío*; `requerido: false`
   es la forma explícita de decir que no. Se descartaron: un **204** (el cliente de libra-ui parsea JSON y un cuerpo vacío es un
   error que hoy se traga igual, pero «no hace falta» se confunde con «falló»), un **404** (indistinguible de un producto sin
   captcha y rompe el monitoreo de rutas) y un **campo en otro endpoint** (el login no consulta otro antes: sería una consulta
   más para el mismo dato).
2. **El login y `forgot-password` no exigen ni validan el captcha en un nodo.** Un helper local, `_exige_captcha()`
   (`captcha and not es_nodo()`), se lee **en cada pedido**, no al armar el router. El flag `captcha=` sigue siendo del producto: en
   un nodo sólo deja de exigir donde el producto lo había prendido; un router con `captcha=False` no gana el endpoint.
3. **Un frontend viejo contra un nodo nuevo no queda peor que hoy.** Si manda `captcha` (bueno o basura) el campo se ignora, sin
   tocar el desafío (un desafío resuelto no se gasta). Y uno viejo que no sabe de `requerido` ya trata la respuesta como «sin
   captcha», porque no es un desafío: no dibuja el widget y entra. Por eso no hace falta coordinar el orden de los bumps.
4. **El central no cambia.** Sin `LIBRAEDGE_NODE_ID`, todo igual; cada caso nuevo lleva su contraprueba.

**Lo que no resuelve (abierto).**
- ✅ **El bloqueo por IP se esquivaba en la LAN (medido el 2026-10-21) y se cierra acá.** `ip_del_request` leía `X-Forwarded-For`
  cuando el par directo era de una red de confianza, y `REDES_DE_CONFIANZA` incluye las del local: un puesto en `192.168.1.51` que
  rotaba la cabecera hizo doce intentos con 401 sin bloquearse. En un nodo **no hay proxy adelante** (el producto corre con uvicorn en
  la PC del local, servicio de systemd o de Windows, y los puestos le hablan directo a `<IP>:8000`), así que en un nodo
  `ip_del_request` toma siempre el par directo y no lee la cabecera. Test en `tests/test_auth_events.py`.
- El bloqueo es **por IP**, no por usuario: quien reparte los intentos entre varias IPs (varios puestos) no lo dispara. Es el mismo
  límite que motivó el captcha en ADR-014; no hay bloqueo por cuenta en libraauth.
- `forgot-password` sigue cerrado en el nodo (409, ADR-027); no hay recupero de clave ahí.

**Consecuencias.** MINOR (propuesta v0.55.0), **sin migración**, aditivo: un helper y dos condiciones. El contrato del endpoint en
un nodo cambia de «un desafío» a `{"requerido": false}`; ningún cliente de la familia depende de que ahí haya un desafío (el único
consumidor es `useCaptcha` de libra-ui, que ya lo descarta por la forma). Se sube en libra-ui 0.177.0 (ADR-091) la prueba que lo
fija y la documentación del contrato.

**Verificación.** `tests/test_captcha.py`, 8 tests nuevos: en un nodo el desafío dice `{"requerido": false}` y no se cachea; el login
entra sin captcha; con un captcha basura o resuelto entra igual y el desafío no se gasta; la clave mala da 401; cinco fallidos y el
sexto es 429 aun con la clave buena; con `captcha=False` no hay endpoint; `forgot-password` da 409. Contraprueba fuera de un
nodo: el desafío conserva su forma y sin captcha el login da 400. Puesto sobre el código sin el arreglo, 5 de los 8 se ponen
rojos (los otros tres son contrapruebas que tienen que pasar en los dos lados).

## ADR-029 — `verificar_captcha`: la verificación pública para las rutas propias de un producto (2026-10-28)

**Problema.** El portal de jugadores de LibraClub pide captcha en su propio login (`/api/portal/login`) y, para no partir el
anti-replay en dos, verifica con el mismo `Captcha` de proceso que el router de `/auth`. libraauth no exponía cómo obtenerlo:
el producto llamaba a la función privada `_captcha_de` por atributo de módulo y documentaba que «el arreglo de fondo sería que
libraauth exporte una versión pública de esto» (pendientes de la familia, Motores).

**Qué ya existía.** `_captcha_de(request, usados)` (un `Captcha` por proceso, creado con el `SECRET_KEY` de la instancia si el
producto no inyectó uno) y `captcha_usados=` (ADR-023). Las suites de los nueve productos y del panel parchean
`libraauth.session_auth._captcha_de` para no resolver un desafío real en cada login.

**Decisión.** `libraauth.session_auth.verificar_captcha(request, respuesta, usados=None) -> bool`, que delega en `_captcha_de`
buscándola en el módulo en cada llamada: el parche de las suites sigue valiendo, sin tocar ningún `conftest.py`. No mira si es
un nodo (ADR-028): la ruta del producto decide si exige captcha, como el router con `_exige_captcha()`. `_captcha_de` sigue
existiendo con el mismo nombre y la misma firma, porque es el punto que parchean los tests.
