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
  lo degrada o desactiva; tres dejaban escapar un `ValueError` de rol
  inválido en la EDICIÓN como `500` (Contalibra vía `db_usuarios.py`,
  Gestiolibra y MedLibra vía el `except` que faltaba en su `PUT`); el
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

