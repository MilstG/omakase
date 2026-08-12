# Kanjō 勘定 — deployment en Railway

Tablero financiero y operativo del omakase, con persistencia en **PostgreSQL**,
sesiones firmadas y **dos roles aplicados por el servidor** (admin / staff).

## Qué hay acá

```
server.js          Express: estáticos + /api/storage + login por roles
lib/db.js          Clave-valor versionado: Postgres (Railway) o data.json (local)
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
   | `APP_PASSWORD_ADMIN` | contraseña del dueño (fuerte) |
   | `APP_PASSWORD_STAFF` | contraseña del equipo (distinta) |
   | `SESSION_SECRET` | **recomendada**: 64 caracteres al azar (`openssl rand -hex 32`). Si falta, se genera una efímera por proceso y las sesiones caen en cada deploy/restart. Nunca se deriva de las contraseñas. |
   | `OPENAI_API_KEY` | opcional: habilita ✦ Puntuar con IA en Maridaje 相性 (solo admin) |
   | `OPENAI_MODEL` | opcional, default `gpt-5.5`. El endpoint dispara pocas veces por mes: usá un modelo grande, cuesta centavos. Si el modelo rechaza `temperature` (razonadores), el servidor reintenta solo sin el parámetro. |
   | `OPENAI_BASE_URL` | opcional: para proxies o endpoints compatibles (default `https://api.openai.com`) |

5. **Dominio.** *Settings → Networking → Generate Domain* → queda `algo.up.railway.app`.
   (Dominio propio: agregá el CNAME que Railway indica.)

6. **Verificar.** `https://tu-dominio/healthz` debe responder `{"ok":true,"db":"postgres"}`.
   Entrá al dominio: aparece el login de Kanjō. Con la contraseña admin ves todo;
   con la de staff, solo los tabs habilitados.

## Migrar los datos actuales

En la versión que venías usando: **Resumen 週報 → Administración → ⬇ Backup total**
(baja un JSON). En la versión deployada, con sesión **admin**: **⬆ Restaurar** y elegí
ese archivo. Listo — todo el historial pasa a Postgres.

## Cómo funcionan los roles

- La **contraseña define el rol** (el botón de roles del tablero queda informativo).
- Staff puede **leer** todo lo que la app necesita para renderizar — con una excepción:
  `kanjo:caja` (saldos y proyección de caja) es **admin-only también en lectura** —
  y **escribir** las claves operativas: servicios, compras, mermas, TC, reservas,
  clientes, stock, genka.
- Staff **no puede escribir** (el servidor devuelve 403, aunque manipulen el navegador):
  `kanjo:baseline` (esquema), `kanjo:scenarios`, `kanjo:caja`, `kanjo:auth` (permisos),
  `kanjo:cierres`. Tampoco puede borrar claves ni listar.
- La visibilidad de tabs se sigue configurando en *Resumen → Administración* y viaja
  en `kanjo:auth` — que solo un admin puede modificar.

## Concurrencia

Cada clave tiene versión. Si dos personas editan lo mismo, la segunda escritura recibe
un aviso: *pisar con tu versión* o *recargar y traer lo último*. Sin pérdidas silenciosas.

## Desarrollo local

```bash
npm install
APP_PASSWORD_ADMIN=admin123 APP_PASSWORD_STAFF=staff123 node server.js
# → http://localhost:3000  (sin DATABASE_URL usa data.json)
```

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
