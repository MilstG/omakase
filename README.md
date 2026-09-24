# Kanjō 勘定 — deployment en Railway

Tablero financiero y operativo del omakase, con persistencia en **PostgreSQL**,
sesiones firmadas y **control de acceso por roles (RBAC) aplicado por el servidor**:
cada persona entra con su usuario, y su rol define qué módulos ve y cuáles edita.

## Qué hay acá

```
server.js          Express: estáticos + /api/storage + login, usuarios y roles
lib/rbac.js        LA POLÍTICA: módulos, qué clave pertenece a cuál, roles de fábrica
lib/auth.js        Contraseñas (scrypt), caché de sesiones, siembra del primer admin
lib/db.js          Clave-valor versionado + tablas users/roles: Postgres o data.json
public/index.html  El tablero completo (kanjo v4, 11 tabs) con el shim inyectado
public/shim.js     window.storage contra la API: login, versiones, conflictos 409
public/login.html  Página de acceso (el tablero solo se sirve con sesión)
```

## Paso a paso (una sola vez, ~10 minutos)

1. **Repo.** Subí esta carpeta al repo (por ej. `github.com/MilstG/omakase`, carpeta `railway/`,
   o un repo propio). Incluí todo menos `node_modules/` y `data.json` (ya está en `.gitignore`).

2. **Proyecto en Railway.** railway.app → *New Project* → *Deploy from GitHub repo* → elegí el repo.
   Si el código está en una subcarpeta: *Settings → Root Directory* = `railway`.

3. **PostgreSQL.** En el proyecto: *+ New → Database → PostgreSQL*.
   Railway inyecta `DATABASE_URL` automáticamente en el servicio — no hay que copiar nada,
   pero verificá en *Variables* del servicio web que `DATABASE_URL` aparezca (si no:
   *Variables → Add Reference → Postgres.DATABASE_URL*).

4. **Variables** (en el servicio web, *Variables*):
   | Variable | Valor |
   |---|---|
   | `APP_PASSWORD_ADMIN` | contraseña inicial del usuario `admin`. **Solo se usa la primera vez**, para sembrarlo; después la contraseña vive hasheada en la base y esta variable no hace nada. |
   | `APP_PASSWORD_STAFF` | opcional: si está, siembra un usuario `staff` con rol *Encargado* para no cortarle el acceso al equipo el día del deploy. Misma regla: solo cuenta en el primer arranque. |
   | `LEGACY_LOGIN` | opcional: `off` desactiva el login sin usuario (solo contraseña). Ponelo cuando cada persona tenga la suya. |
   | `SESSION_SECRET` | **recomendada**: 64 caracteres al azar (`openssl rand -hex 32`). Si falta, se genera una efímera por proceso y las sesiones caen en cada deploy/restart. Nunca se deriva de las contraseñas. |
   | `OPENAI_API_KEY` | opcional: habilita ✦ Puntuar con IA en Maridaje 相性 (solo admin) |
   | `OPENAI_MODEL` | opcional, default `gpt-5.5`. El endpoint dispara pocas veces por mes: usá un modelo grande, cuesta centavos. Si el modelo rechaza `temperature` (razonadores), el servidor reintenta solo sin el parámetro. |
   | `OPENAI_BASE_URL` | opcional: para proxies o endpoints compatibles (default `https://api.openai.com`) |

5. **Dominio.** *Settings → Networking → Generate Domain* → queda `algo.up.railway.app`.
   (Dominio propio: agregá el CNAME que Railway indica.)

6. **Verificar.** `https://tu-dominio/healthz` debe responder `{"ok":true,"db":"postgres"}`.
   Entrá al dominio: aparece el login. Usuario `admin` + `APP_PASSWORD_ADMIN`.
   Si no definiste esa variable, el server imprime **una vez** en los logs de Railway
   una contraseña de un solo uso — buscá la línea `[auth] usuarios iniciales creados`.

## Migrar los datos actuales

En la versión que venías usando: **Resumen 週報 → Administración → ⬇ Backup total**
(baja un JSON). En la versión deployada, con sesión **admin**: **⬆ Restaurar** y elegí
ese archivo. Listo — todo el historial pasa a Postgres.

## Cómo funcionan los roles (RBAC)

**Una persona = un usuario.** El audit log dice quién hizo cada cosa, y dar de baja a
alguien no obliga a cambiarle la contraseña a todo el equipo.

**Un rol = una matriz módulo × acción.** Cada uno de los 20 tabs, más tres candados sin
tab propio (*Cierre de mes 締*, *Sueldos y tarifas 給*, *Usuarios y backup 管*), tiene
uno de tres estados:

| | qué significa |
|---|---|
| `— no lo ve` | el tab no aparece y el servidor no entrega el dato |
| `lo ve` | el tab aparece sin los controles de edición |
| `lo edita` | acceso completo a ese módulo |

Roles de fábrica: **Admin** (todo, y no se edita: es la salida de emergencia para que el
tablero nunca quede sin quien lo administre), **Encargado**, **Cocina · itamae**,
**Sala · sommelier** y **Contador · solo lectura**. Todos menos Admin se ajustan desde
*Resumen 週報 → Administración → Permisos por rol*, y el cambio aplica sin que nadie
vuelva a loguearse.

**El servidor es la autoridad.** La política vive en `lib/rbac.js`, que mapea cada clave
`kanjo:*` a su módulo. Esconder un tab no alcanza si la API igual entrega el dato, así que
las claves sensibles están cerradas **también en lectura**: `kanjo:caja`, `kanjo:cierres`,
`kanjo:hitopay` (sueldos) y `kanjo:crm` (datos personales de clientes). El resto se lee
libremente porque la app las necesita para calcular, pero **escribir** siempre pide
permiso sobre el módulo dueño de la clave. Aunque alguien manipule el navegador, el
servidor devuelve 403.

### Administrar el equipo

*Resumen 週報 → Administración*:

- **Usuarios** — alta, baja, cambio de rol y reseteo de contraseña. Cada usuario puede
  ligarse a una persona del plantel de *Equipo 人*, para que el legajo y la llave sean
  la misma cosa. La contraseña la genera el servidor y **se muestra una sola vez**: se
  pasa a mano y la persona elige la suya al entrar. Nadie —ni el admin— puede volver a
  verla; si se pierde, se genera otra.
- **Permisos por rol** — la matriz de arriba.
- **Actividad** — el audit log, ahora con la columna *Quién*.

Dar de baja a alguien o cambiarle el rol **corta al instante sus sesiones abiertas**;
no hay que esperar a que venza la cookie.

### Migrar desde las contraseñas compartidas

En el primer arranque con esta versión el server siembra los usuarios `admin` y `staff`
con las contraseñas que ya tenías en las variables de entorno, así que **nadie queda
afuera el día del deploy**. Después:

1. Entrá como `admin` y creá un usuario por persona, con su rol.
2. Cambiá tu propia contraseña (*Tu cuenta → Cambiar mi contraseña*).
3. Borrá o dá de baja el usuario `staff`.
4. Poné `LEGACY_LOGIN=off` en Railway y reiniciá, para cerrar el login sin usuario.

(El login heredado también se apaga solo: deja de funcionar en cuanto esas dos cuentas
cambian de contraseña.)

## Concurrencia

Cada clave tiene versión. Si dos personas editan lo mismo, la segunda escritura recibe
un aviso: *pisar con tu versión* o *recargar y traer lo último*. Sin pérdidas silenciosas.

## Desarrollo local

```bash
npm install
APP_PASSWORD_ADMIN=admin123 APP_PASSWORD_STAFF=staff123 node server.js
# → http://localhost:3000  (sin DATABASE_URL usa data.json)
# Entrás con usuario `admin` y contraseña `admin123`.
# Para empezar de cero: borrá data.json (ahí viven también usuarios y roles).
```

## Novedades v6 — impuestos más finos, features nuevas y UI

**Impuestos** (validá los parámetros con tu contador; el modelo sigue siendo de planificación):

- **IVA**: el crédito sobre CMV sale de las compras reales de los últimos 90 días (alícuota
  de cada factura) o del % manual si no hay historial; cada línea de ③ Ocupación y ④ Operación
  lleva su alícuota (0 / 10,5 / 21 / 27) y de ahí sale su crédito. La caja paga la **posición
  mensual** a los días de diferimiento (PyME), en vez de un golpe trimestral. El diferimiento
  se valúa por devaluación esperada.
- **Débitos y créditos**: 0,6 % sobre cada movimiento bancario (cobros con tarjeta, QR, apps y
  link; pagos por banco según el % que cargues). El efectivo no lo paga. La parte computable es
  pago a cuenta de Ganancias y se descuenta ahí.
- **Ganancias**: alícuota plana o **escala de sociedades** con tramos anuales en ARS editables
  (anualiza el resultado mensual al TC de Genka). Anticipos mensuales en la caja.
- **Retenciones de tarjeta y QR**: bajan el cobro de la semana y se descuentan de IVA, IIBB y
  anticipos cuando vencen; si quedan sin aplicar, la caja avisa.
- **Cargas sociales por rol**: manual, relación de dependencia (calculado desde contribuciones
  patronales, ART, SAC y otros) o monotributista (×1).

**Features**:

- **Elasticidad medida** en Precios dinámicos: cuando el historial tiene cambios de precio, el
  modelo mide cuánto reaccionó la ocupación y te deja usar ese número en vez de un preset;
  historial de precio implícito por mes y turno.
- **Dotación desde el pronóstico**: cada turno de la semana que viene marcado flojo / normal /
  pico según sillas, con el costo laboral plan y el ahorro posible en los flojos.
- **Shock cambiario** en Escenarios: devaluación, inflación de insumos, ajuste salarial e
  insumos dolarizados; dice cuánto tiene que subir la carta para sostener el margen y lo guarda
  como escenario.
- **Alertas locales** de la PWA (caja negativa, precios de insumos viejos, días sin cargar): se
  activan desde *Tu cuenta* y se avisan al abrir o volver a la app, una vez por día.
- **Importar CSV** de servicios, delivery y reservas desde el POS, Meitre o una planilla:
  separador automático, columnas por sinónimos, fechas ISO o DD/MM/AAAA.
- **Presupuesto vs real por centro de costo** (Resumen 予実): plan del esquema contra lo cargado
  en servicios, delivery, compras y fichajes, mes a mes, con desvíos y lecturas; el mes en curso
  se prorratea por días transcurridos. El cierre de mes guarda el cuadro.
- **Comparativa de meses cerrados**: sparklines de margen, food cost, ticket, ocupación y
  delivery cuando hay dos o más cierres.
- **Excel para el contador**: un solo archivo `.xls` con nueve hojas (P&L plan, servicios,
  delivery, resumen mensual, compras, mermas, liquidaciones, cierres, presupuesto vs real).
  Sin dependencias externas (formato SpreadsheetML; Excel avisa por la extensión y abre igual).

**UI**: navegación compacta y fija en el teléfono; sin scroll horizontal en ningún tab; KPIs del
encabezado en grilla; tarjetas colapsadas que se recuerdan y «colapsar todo»; paneles avanzados
del pronóstico plegados; el foco no se pierde al editar en Genka ni en el esquema; diálogos
propios en vez de `prompt`/`confirm`; toasts apilados a la derecha; semáforo de food cost sin
falsos verdes; números en formato es-AR; `#tab` en la URL; listas largas con «ver más»;
etiquetas de accesibilidad, foco visible y más contraste; estado de carga; hoja de impresión
y botón imprimir en el esquema.

## Novedades v5.1 — conciliación de apps, precio por canal y capacidad

- **Liquidaciones de apps** (Caja 現金, clave `kanjo:liquidaciones`, escriben *caja* y *turnos*):
  cada liquidación de Rappi/PedidosYa con ventas según la app, comisión, promos financiadas,
  cancelaciones, retenciones y neto acreditado. Se cruza con los días registrados en 番付:
  comisión efectiva real vs la del esquema, diferencia entre lo que la app dice y lo
  registrado, retenciones a cuenta para el contador, rezago real de pago (con un botón para
  usarlo en la proyección de caja) y neto que no cierra con los descuentos declarados.
- **Precio por canal** en Precios dinámicos 平価 · delivery: recargo del precio en la app para
  absorber la comisión, con la misma sensibilidad de demanda aplicada solo a los pedidos de app.
- **Tope de pedidos por día** (esquema ⑧): capacidad de cocina. Frena el simulador de promos,
  marca en el pronóstico los días cuya banda alta lo supera y avisa en el analista cuando hubo
  días por encima.
- **Fijos comunes**: por defecto el delivery se evalúa por **contribución** (0 % de fijos
  comunes; el salón los carga todos, como antes de v5). Dejando el campo vacío se prorratea en
  proporción a la facturación.

## Novedades v5 — delivery 配 y menús múltiples

- **Delivery como canal en el esquema 勘定**: tarjeta ⑧ *Delivery · canal* con su propia
  dinámica (días × pedidos × ticket, no sillas × ocupación) y sus propios costos: envase por
  pedido, comisión de apps sobre el bruto c/IVA, envío propio para el canal directo, dotación
  extra y pauta. Aparece como centro propio en la anatomía del peso, el desglose, la cascada,
  el tornado (pedidos y comisión como drivers), el P&L CSV y los escenarios. El equilibrio sigue
  midiéndose en ocupación de salón: el delivery entra como ingreso constante y su contribución
  reduce los fijos a cubrir. Con el canal apagado el modelo es exactamente el anterior; una
  baseline guardada sin delivery se migra **apagada** (no se inventa facturación).
- **Registro diario de delivery** (`kanjo:delivery`, mismo permiso que los servicios) en el
  analista 番付: un registro por día con pedidos, comida, bebida, cuánto entró por apps y por
  canal propio, efectivo y cancelados. Cada día se costea con los parámetros del canal y carga la
  parte de fijos comunes que el delivery absorbe (*Fijos comunes que absorbe*, por defecto
  proporcional a su facturación). Panel propio: contribución por pedido, resultado por día,
  mix apps, a dónde va cada peso de un pedido, perfil por día de semana. Botón en ⚡ carga rápida.
- **Pronóstico 予想**: pronóstico del delivery por día de semana (últimas 8 semanas, con
  tendencia amortiguada; sin historial usa el plan). El resultado proyectado del mes ahora es
  salón + delivery.
- **Precios dinámicos 平価**: modo *Delivery · promo y canal*: promo sobre el ticket con
  elasticidad en pedidos (no en ocupación), pedidos necesarios para empatar, y la palanca
  apps vs canal propio (comisión contra cadete) a pedidos constantes.
- **Caja 現金**: liquidación de apps neta de comisión y con rezago propio (*Liquidación de apps*,
  días), canal propio en la semana, CMV del delivery, envases + cadete semanales, pauta el día 1
  y dotación extra con los sueldos. IIBB e IVA incluyen la facturación del canal.
- **Costeo de menú 原価 · varios menús**: `kanjo:genka` pasa de un menú a `menus[]` (migración
  automática al abrir). Cada menú tiene tipo *salón* (precio del turno del esquema, o propio) o
  *delivery* (precio del box, envase, food cost también sobre el neto después de la comisión de
  la app). Todos comparten insumos y TC. El ★ **principal** es el que siguen leyendo Carta QR,
  Maridaje, Servicio y el food cost teórico del Resumen. Duplicar, renombrar, borrar; *Enviar al
  esquema* actualiza el food cost del salón o los parámetros del canal delivery según el menú.
- **Resumen y cierre de mes**: fila *Delivery (4 sem)* con semáforo contra el plan, lecturas
  cuando el pedido no deja contribución o el volumen no cubre los fijos, y el cierre congela
  pedidos, neto, contribución y resultado del canal.

## Novedades v4

- **Wa 輪 (Rueda)**: dos ruedas de maridaje de carta **propia e independiente**
  (no toca Genka ni Aishō) — la cava (37 platos × 24 bebidas por nivel, toggle
  común/premium) y la despensa (28 pescados × 28 sabores de la cocina). Click en
  un producto abre su perfil con foto y alternativa conseguible en Argentina
  (bebidas); click en un hilo, la ficha del maridaje con el porqué. El admin
  agrega/quita productos y `POST /api/ai/wa` (solo admin, auditado, rate-limited)
  puntúa lo nuevo, redacta perfil y notas — todo queda ✦ sin revisar hasta el
  visto bueno. Incluye **generador de maridajes**: pasos + ingredientes +
  categorías + calidad + presupuesto → flight con plan A y plan B por pour.
  Persiste en `kanjo:wa` (escritura admin-only; staff lee).
- **Fotos de Wa**: `node tools/fetch-wa-photos.mjs` baja ~100 fotos de licencia
  libre de Wikimedia Commons a `public/img/wa/` (créditos en `credits.json`).
  Correrlo una vez en local y commitear la carpeta — la CSP solo permite
  imágenes propias, no hay dependencias externas en producción.

## Novedades v3

- **Maridaje 相性 (Aishō)**: matriz de afinidad menú × bebidas (sake, té, vino común/premium),
  bebidas 100% editables con disponibilidad, flights costeados al TC global, optimizador
  exacto por precio, mapa de arcos, guía de compra con el porqué gastronómico, y
  puntuación por IA vía `POST /api/ai/pair` (proxy: la key vive en el servidor, solo admin,
  rate-limited). Persiste en `kanjo:aisho` (escribible por staff — marcar "no se consigue"
  es tarea del salón).

## Novedades v2

- **Cierre de mes 締め** (Resumen): congela el P&L del mes en `kanjo:cierres` —
  clave que solo un admin puede escribir (el servidor lo aplica).
- **Audit log**: cada login, escritura y borrado queda registrado (rol, clave,
  versión anterior → nueva). Se consulta desde *Resumen → Administración →
  Ver actividad*, o por API: `GET /api/audit?limit=80` (solo admin).
- **Scorecard de proveedores** (Compras): gasto y share por proveedor, y brechas
  de precio del mismo insumo entre proveedores en los últimos 90 días.
- **PWA / modo servicio**: en el teléfono, "Agregar a pantalla de inicio" instala
  el tablero con ícono propio. El botón **⚡ carga rápida** de la barra abre los
  formularios del día (servicio, reservas, compra, merma) con un toque.
  El service worker cachea solo el shell estático; la API va siempre por red.

## Novedades v4 — hardening

- **Baseline al arranque**: el esquema guardado se carga automáticamente al abrir la app
  (antes había que apretar «Cargar baseline»: todos los tabs calculaban sobre defaults).
- **Persistencia segura**: una clave que no cargó bien del servidor (error de red, 500)
  queda en solo lectura hasta recargar — nunca más pisar datos reales con un estado
  vacío. Los guardados que fallan avisan con un flash en vez de fingir éxito.
- **Tablero solo con sesión**: `index.html` (que embebe el modelo del negocio) se sirve
  únicamente con cookie válida; sin sesión aparece `login.html`.
- **Sesiones**: secreto nunca derivado de contraseñas; sin `APP_PASSWORD_ADMIN` en
  producción (con `DATABASE_URL`) el servidor no arranca. `trust proxy` + `req.ip` para
  que el rate limit de login no sea burlable con `X-Forwarded-For`.
- **Headers**: CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store` en el HTML.
- **Logout** en la barra (⎋ salir) — clave en tablets compartidas con sesiones de 14 días.
- **Service worker v2**: `/` y `/shim.js` van red-primero — los deploys llegan a las
  PWAs instaladas sin tener que reinstalar.
- **Modelo**: el efectivo cargado (post-descuento) ya no se descuenta dos veces al
  calcular la mezcla de pagos; las mermas congelan su costo unitario al registrarse
  (los cambios de precio posteriores no reescriben la historia).
- **CRM**: el buscador ya no pierde el foco en cada tecla.
- **Google Sheets eliminado**: con Postgres como base, el sync con la sheet era un
  vestigio — y el peor tipo de vestigio: un endpoint GAS que recibía la facturación
  (incluido el flag de efectivo) fuera de tu control. Para el contador: **Turnos →
  Exportar servicios / Resumen mensual** baja CSVs que se abren directo en Excel o
  Sheets. Importante: **borrá la implementación vieja del Apps Script** (script.google.com
  → tu proyecto → Implementaciones → archivar) — la URL sigue viva aunque la app ya no la use.
- **`kanjo:cierres` admin-only también en lectura**: el P&L histórico congelado no
  viaja a sesiones staff (el panel se oculta solo en Resumen).
- **Higiene**: `data.json` local con escritura atómica (tmp+rename), poda automática
  del audit log en Postgres (últimas ~4000 entradas) y de los mapas de rate limit.

## Notas honestas
- `express.json` acepta hasta 8 MB por escritura y el servidor limita cada valor a 4 MB —
  de sobra para años de servicios.
- Si algún día el contador quiere una sheet "viva" en vez de CSVs, lo correcto es un
  job del lado del servidor que empuje a la API de Sheets con credenciales propias —
  no un endpoint GAS público. Hasta que exista esa necesidad real, menos es más.
