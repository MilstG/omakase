# Kanjō 勘定 — Esquema de costos del omakase

A single-file cost-modeling and analytics tool for an omakase restaurant in Buenos Aires. Everything is modeled in **USD, net of IVA**, and every input is editable so the entire analysis recalculates instantly as you change assumptions.

`kanjo-esquema-costos.html` is a self-contained web app — HTML, CSS, and vanilla JavaScript in one file, no build step and no framework. Open it in a browser and it runs.

---

## What it does

The app is organized into four tabs, each labeled with a kanji that names its role.

### 1. Esquema de costos (勘定) — the cost model

The core P&L model. You edit a base set of assumptions and watch the outputs recompute:

- **Revenue** — seats and target occupancy
- **Turnos** (shifts) — Mediodía, 1° noche, 2° noche, each with its own days/month, price, beverage spend, and labor weight
- **CMV** — food and beverage cost percentages
- **Labor** — a roster of roles with gross pay and a burden multiplier
- **Ocupación** — rent, expensas, utilities, connectivity
- **Operación** — software/POS, accountant, insurance, marketing, cleaning, maintenance, laundry
- **Pagos** — card/QR/cash mix and processing rates
- **Impuestos** — IIBB, débitos/créditos, ganancias
- **Capex** — investment amount and amortization horizon
- **IVA** — sales/CMV rates, deductible shares, deferral days, annual yield on deferred cash

Outputs include a KPI header, a cost cascade, break-even and profit-vs-occupancy charts, a tornado sensitivity analysis, a payback curve, a full P&L, and an IVA cash-flow view. You can also save named **scenarios**, set and restore a **baseline**, and export the P&L or raw data to CSV.

### 2. Analista de turnos (番付) — per-service analysis

Loads actual end-of-shift data. Each service (one shift on one night) carries its **prorated fixed cost** from the main model plus its real variable costs, so you see the net result of each shift rather than just its billing. Prices are entered **IVA-included**, matching how they're rung up. Includes filtering, ranking, monthly aggregation, automatic insights and alerts, a service list, and a heatmap.

### 3. Precios dinámicos (平価) — pricing simulator

Simulate a discount on a slow day and see the **occupancy-lift threshold** you'd need for it to pay off. Supports discount presets and combination scenarios, all evaluated against the current price and cost structure.

### 4. Pronóstico (予想) — forecasting

A deliberately simple, transparent forecasting model with **confidence bands** and a **walk-forward backtest**. It fits a baseline per (day-of-week × turno), layers on a damped trend plus holiday and payday multipliers (shrunk toward 1 to avoid overfitting), detects model degradation, and renders a forecast calendar and day-of-week profile. Argentine holidays are built in.

---

## Running it

No install, no server, no dependencies to fetch beyond fonts.

1. Open `kanjo-esquema-costos.html` in any modern browser.
2. Start editing values — the model recalculates live.

The only external requests are to Google Fonts (Zilla Slab, Inter, JetBrains Mono). If you're offline, the app still works; it just falls back to system fonts.

---

## Data & persistence

State is saved locally through an async `window.storage` wrapper under these keys:

| Key | Contents |
|-----|----------|
| `kanjo:baseline` | Saved baseline of the cost model |
| `kanjo:scenarios` | Named what-if scenarios |
| `kanjo:services` | Loaded per-service records (Turnos tab) |
| `kanjo:sheeturl` | Google Sheets sync endpoint |
| `kanjo:fchealth` | Forecast-accuracy history (Pronóstico tab) |

---

## Google Sheets sync (optional)

The Turnos tab can push and pull service records to a Google Sheet via a **Google Apps Script web app**. This is optional — everything works locally without it.

To connect:

1. Deploy the companion Apps Script (`kanjo-apps-script.gs`) as a web app, with access set to *anyone*.
2. Paste the deployment URL (it ends in `/exec`) into the sync bar and test the connection.
3. Use **Traer de la sheet** to pull cloud records into the app, or **Subir locales** to push local records up.

Under the hood the client POSTs JSON actions (`list`, `replaceAll`, and per-record changes) to the script, which reads and writes rows. If a sync fails, changes are still saved locally and the status bar flags that it didn't reach the cloud.

The Sheet is treated as an **export/sync target**, not the source of truth — useful for handing read-only data to an accountant without coupling the app to a spreadsheet.

---

## Architecture notes

- **Single file, vanilla JS.** ~50+ top-level functions; no framework, no bundler.
- **Charts are hand-rolled** as inline SVG/HTML rather than a charting library.
- `defaultState()` defines the full data model; `ensureShape()` migrates older saved state forward so existing scenarios and baselines keep loading after schema changes.
- `compute()` is the single source of derived numbers that the whole cost tab renders from.
- UI language is Spanish; domain terms (turnos, CMV, IIBB, IVA) are kept as-is throughout.

---

## Status

This HTML file is the original monolithic build of Kanjō. A phased migration to a modern stack (Vite + Preact + TypeScript, with Supabase as the backend) is underway; this file remains the reference implementation and the source of truth for the cost logic being ported.
