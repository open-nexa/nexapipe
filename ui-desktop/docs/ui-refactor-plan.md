# nexapipe Desktop — UI Refactor Plan

Status: draft for review (rev 3 — rev 2 deepened i18n/CJK §5.5 and added the platform & architecture matrix §5.11; rev 3 specifies the clash-verge-style TUN gating model §5.12 and refreshes the backend contract facts)
Scope owner: UI layer (`src/**`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/**`)
Layout reference: [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) (Tauri 2, frameless shell, collapsible nav, per-page header)

---

## 1. Goals and non-goals

### Goals

1. Replace the ad-hoc shell with a clash-verge-rev-style app shell: a frameless window with a
   custom title bar, a collapsible icon+label sidebar, and a per-page header with an action slot
   above exactly one scroll container.
2. Introduce a design-token layer (`styles/tokens.css` + `styles/themes.css`) with complete
   light and dark themes, and delete the current partially-defined token soup.
3. Build a self-hosted base component library under `components/base/`. No third-party UI kit is
   added; the only new runtime dependency is `vue-i18n`.
4. Add i18n with English as the default locale and `zh-CN` as the secondary locale, with
   CJK-aware typography and layout rules baked into the base components (§5.5).
5. Wire up the global feedback layer (toast + confirm) that currently exists but is unreachable,
   and route every backend failure path through it.
6. Keep the Tauri command surface byte-compatible — with exactly one sanctioned, additive
   exception: the `use_tun` parameter on `start_proxy` required by the explicit proxy-mode model
   (§5.12, see §9.1).
7. Keep the shipped 3-OS × 2-arch matrix (Windows/macOS/Linux × amd64/aarch64) intact: the UI
   layer stays architecture-agnostic and OS-aware (§5.11).
8. Make proxy mode explicit and clash-verge-consistent: without the service installed the app can
   only run in local proxy mode; once the service is installed (which itself requires
   sudo/administrator), the TUN toggle becomes available (§5.12).

### Non-goals (this phase)

- Changing Rust command signatures beyond the additive `use_tun: Option<bool>` parameter on
  `start_proxy` (§5.12).
- New proxy functionality beyond the mode model in §5.12 (relay behaviour, 2FA behaviour, new
  TUN capabilities). §5.12 only *selects* between the two existing forwarding modes; it does not
  change what either mode does.
- Traffic graph / live throughput. The sidebar footer will show status, not bandwidth: no backend
  command exposes byte counters today, so a traffic widget would need a new Rust command first.
- Tray menu, global shortcut, deep link.
- Traditional Chinese (`zh-Hant`/`zh-TW`/`zh-HK`). Only `zh-CN` ships; see locale mapping (§5.5).
- A universal (fat) macOS binary — per-arch builds already ship via CI (§5.11).

---

## 2. Current state audit

### 2.1 Inventory

| File | Lines | Role | Fate |
| --- | --- | --- | --- |
| `src/App.vue` | 513 | Shell + global CSS tokens + nav + toast/confirm host | Split into `app/shell/*`, `styles/*` |
| `src/pages/DashboardPage.vue` | 409 | Connect page | Migrate |
| `src/pages/ConfigPage.vue` | 718 | Proxy + network + load-balancing config | Migrate |
| `src/pages/SettingsPage.vue` | 705 | Service / mode / TUN / relay / 2FA / app / about | Migrate |
| `src/pages/LogsPage.vue` | 453 | Log tail viewer | Migrate |
| `src/components/ProxyStatusControl.vue` | 661 | Status ring + start/stop/refresh + node id | Split |
| `src/components/ProxyConfigForm.vue` | 696 | Unused | **Delete** (see D1) |
| `src/components/ServiceManager.vue` | 415 | Service install/uninstall | Migrate |
| `src/components/Toast.vue` | 213 | Toast renderer, never fed | Replace |
| `src/components/ConfirmDialog.vue` | 214 | Dialog, never opened | Generalise |
| `src/composables/useConfigStore.ts` | 193 | Module-singleton reactive config + localStorage | Split |
| `src/types/index.ts` | 48 | Types | Prune |
| `src/router/index.ts` | 28 | 4 routes | Keep, harden |
| `src/main.ts` | 7 | App bootstrap | Extend |

Total ≈ 5,200 lines of `.vue` + `.ts`, of which ~700 are dead.

### 2.2 Defects that the refactor must resolve

**D1 — Dead component.** `src/components/ProxyConfigForm.vue` (696 lines) is not imported by any
file. It is a stale duplicate of the Config page. Delete it.

**D2 — The feedback layer is inert.** `App.vue` declares `toasts` and `confirmDialog` and renders
both components, but nothing ever pushes to `toasts` and `confirmDialog.visible` is never set to
`true`. Consequently every failing `invoke()` ends in `console.error` and the user sees nothing.
The only visible error path in the whole app is `ProxyStatusControl`'s local `errorMessage`, which
covers start/stop only. Installing a service, toggling auto-start, reading logs, and reading the
node ID all fail silently.

**D3 — Four undefined CSS custom properties.** These are referenced but never declared, so the
declarations silently drop:

| Token | Referenced at |
| --- | --- |
| `--success-400` | `App.vue:306` |
| `--success-200` | `ServiceManager.vue:244` |
| `--error-300` | `ServiceManager.vue:355` |
| `--error-400` | `ConfigPage.vue:706`, `LogsPage.vue:316` |

**D4 — Hard-coded viewport math.** `LogsPage.vue` root is `height: calc(100vh - 180px)`. The 180px
is the sum of the current shell's paddings and header. Any shell change breaks the Logs page, so
this must be replaced by a `min-height: 0` flex chain (§5.3) as a hard prerequisite.

**D5 — Hand-rolled nav tooltip.** `App.vue` renders the tooltips as `div` siblings inside `nav`
and positions them at `left: calc(100% + 8px)`, outside the 60px sidebar, with no clipping
container. Long labels paint over the content area with no z-index contract.

**D6 — Icons have no single source.** `App.vue#getNavIcon` and `Toast.vue#getIcon` build SVG
strings passed through `v-html`; the same paths are re-typed inline in every page, and the
`settings` gear path alone is duplicated in three files.

**D7 — Decoration for decoration's sake.** `--gradient-primary` is used both as the background of
primary CTAs and as a 2px/3px "card header decoration" rule in four places at two different
heights. clash-verge-rev has no equivalent; hierarchy there comes from typography and spacing.

**D8 — No dark theme.** The sidebar is hard-coded dark (`--surface-sidebar: #0f172a`) against a
light `--gradient-surface` body. There is no theme switch and no `prefers-color-scheme` handling.

**D9 — No i18n.** Every string is an English literal inside a template.

**D10 — Two Settings controls are decorative.** `minimizeOnClose` and `logLevel` are plain local
`ref`s: not persisted, not applied to anything. They must either be implemented or removed.

**D11 — Config persistence is unversioned.** One localStorage key `nexa-config` holds a flat
object written by a `deep: true` watcher. `migrateOldConfig` exists but there is no version field,
so future migrations cannot be sequenced.

**D12 — Split-brain status ownership.** `ProxyStatusControl.vue` performs the `invoke()`
orchestration (start / stop / status / node id) while `useConfigStore` owns the `proxyStatus` ref.
The component can only call `setProxyStatus` after the fact.

**D13 — Unused types.** `ServiceStatus` and `NodeInfo` in `types/index.ts` are never referenced.

**D14 — Template leftover document title.** `index.html` still ships the Vite template
`<title>Tauri + Vue + Typescript App</title>`. The window title comes from `tauri.conf.json`,
but the document title leaks into devtools, the webview's accessibility tree, and any
history/bookmark surface.

**D15 — Font stacks have no CJK fallback.** The sans stack (`-apple-system, …, Arial, sans-serif`,
`App.vue:222`) and the mono stack (`'SF Mono', Monaco, 'Courier New', monospace`, three files)
contain no Chinese family. Each WebView then picks its own fallback — on Windows, CJK inside the
mono stack renders through a *serif* face (SimSun via font-linking) in the middle of monospace
log lines; on Linux it is whatever fontconfig resolves first. The same zh-CN string gets
different faces, weights, and metrics on each of the three OSes.

**D16 — Proxy mode is implicit and conflated with the execution backend.** The Settings "Proxy
Mode" card (Normal Mode / Service Mode) actually selects the *execution backend* (in-process vs
system service) — it has nothing to do with the forwarding mode. The actual forwarding mode
(TUN vs local proxy) is decided by the backend at start time: `ProxyManager::start()` probes
`TunProxy::is_available()` (admin privileges) and silently starts TUN, or silently falls back to
local proxy (`manager.rs:225-286`). There is no TUN switch anywhere in the UI, and the user only
learns which mode they got *after* starting, from the status line. This refactor replaces the
implicit probe with an explicit, gated TUN toggle (§5.12).

### 2.3 What must not break

- The 9 Tauri commands: `start_proxy`, `stop_proxy`, `get_proxy_status`, `get_node_id`,
  `install_service`, `uninstall_service`, `is_service_running`, `get_startup_error`, `get_logs`
  (`greet` has since been removed).
- `get_proxy_status` returns the structured `{ running: boolean, mode: "tun" | "local_proxy" |
  "starting" | "stopped" }` (the old packed string `"true:tun"` is gone — see `src-tauri/src/status.rs`).
- Failures reject with a structured `AppError` carrying a **stable error code**
  (`proxy.no_nodes`, `service.elevation_denied`, `logs.read_failed`, … — see
  `src-tauri/src/error.rs`). The frontend translates by code; the `detail` field is for the log.
- The argument names and shapes of `start_proxy` (snake_case on the Rust side, camelCase from JS).
- Config persistence. Existing users must not lose their nodes / domains / 2FA settings.
- Both runtime backends (in-process and system service) plus the service→process fallback.
- The six-target release pipeline: all of Windows/macOS/Linux × amd64/aarch64 must keep building
  and bundling (§5.11).

---

## 3. Target architecture

### 3.1 Layout wireframe

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ ●●● (macOS only)      nexa                            ─   □   ✕              │ 38px
│ <────────────────── data-tauri-drag-region ──────────────────>            │ title bar
├────────────────────┬───────────────────────────────────────────────────────┤
│  [logo] nexa       │  Connect                    [Refresh]  [Start Proxy]  │      page
│  ───────────────   │───────────────────────────────────────────────────────│    header
│  ▸ Connect         │                                                       │
│  ▸ Config          │                                                       │
│  ▸ Settings        │        <router-view> — the ONLY scroll container      │
│  ▸ Logs            │                                                       │
│                    │                                                       │
│  ───────────────   │                                                       │
│  ● Running · TUN   │                                                       │
│  node 8f2c…        │                                                       │
│  v0.1.0            │                                                       │
└────────────────────┴───────────────────────────────────────────────────────┘
  200px expanded               flex: 1; min-width: 0; min-height: 0
   60px collapsed
```

Key properties:

- The shell is a CSS grid: `grid-template-columns: auto 1fr;
  grid-template-rows: auto 1fr;` with the title bar spanning both columns.
- Exactly one element in the whole app scrolls: the page content region. The sidebar has its own
  internal scroll only when its nav list overflows.
- The title bar and the page header are both drag regions, matching clash-verge's `BasePage`
  (`<header data-tauri-drag-region="true">`), so the user can drag the window by the header strip
  too.

### 3.2 Directory layout

```text
src/
  main.ts                          # createApp + plugin install only
  App.vue                          # composes providers + AppShell, nothing else
  app/
    providers/
      AppProviders.vue             # Theme > I18n > Toast > Confirm > Router
    shell/
      AppShell.vue                 # grid skeleton, owns sidebar collapse + scroll chain
      TitleBar.vue                 # drag region, app name, window controls
      WindowControls.vue           # minimize / maximize / close, per-platform placement
      SideBar.vue                  # nav list + footer
      SideBarItem.vue              # icon + label + active state + collapsed tooltip
      SideBarFooter.vue            # status dot, mode, node id, version
      PageShell.vue                # BasePage equivalent: title/header slots + scroll body
  components/
    base/                          # self-built primitives, zero business logic
      AppButton.vue
      AppIconButton.vue
      AppCard.vue                  # section container: title + optional actions + body
      AppInput.vue
      AppTextarea.vue
      AppSelect.vue
      AppToggle.vue
      AppRadioGroup.vue
      AppBadge.vue                 # status pill: dot + text + tone
      AppTag.vue
      AppIcon.vue                  # <AppIcon name="wifi" /> over the icon registry
      AppEmpty.vue
      AppSpinner.vue
      AppTooltip.vue
      AppDialog.vue                # generic, driven by useConfirm
      ToastHost.vue                # generic, driven by useToast
      SettingRow.vue               # left: label + hint, right: control
      PageHeader.vue               # title + right slot, drag region
    domain/                        # business components, i18n-aware, token-styled
      ProxyStatusPanel.vue
      ProxyToggleButton.vue
      StatTile.vue
      NodeListRow.vue
      NodeEditorCard.vue
      DomainTagCloud.vue
      ServicePanel.vue
      LogToolbar.vue
      LogList.vue
  composables/
    useToast.ts
    useConfirm.ts
    useTheme.ts
    useLocale.ts
    useSidebar.ts
    useWindowControls.ts           # window API + per-OS capability flags
                                   # (isMacos / isWindows / isLinux / frameless, modifier key)
  stores/
    config.ts                      # persisted user config + migration
    proxy.ts                       # runtime status + start/stop/refresh actions
    prefs.ts                       # theme, locale, sidebarCollapsed
  styles/
    tokens.css                     # raw palette + scale + font stacks, theme-agnostic
    themes.css                     # :root[data-theme="light"|"dark"] semantic mapping
    base.css                       # reset, focus ring, scrollbar, selection
    utilities.css                  # a deliberately tiny set of helpers
  icons/
    registry.ts                    # name -> path data, single source of truth
  i18n/
    index.ts
    locales/en.json
    locales/zh-CN.json
  router/index.ts
  types/index.ts
  utils/connection.ts
  pages/
    ConnectPage.vue
    ConfigPage.vue
    SettingsPage.vue
    LogsPage.vue
    _DevComponentsPage.vue         # dev-only gallery for base components
```

### 3.3 Component ownership

| Layer | May contain | Must not contain |
| --- | --- | --- |
| `components/base/*` | Presentational props, `v-model`, sizes/tones | `invoke()`, store access, i18n keys as literals |
| `components/domain/*` | Store access, `invoke()` via stores, i18n text | Raw hex colours, raw px magic numbers |
| `pages/*` | `PageShell` usage, layout composition | Own scroll containers, own card styling |
| `app/shell/*` | Window API, layout, nav model | Business logic |

---

## 4. Design tokens

`tokens.css` declares raw values; `themes.css` maps them to semantic names per theme. Components
only ever read semantic names.

### 4.1 Raw scale

```text
Palette     neutral 0,25,50,100,200,300,400,500,600,700,800,900,950
            primary / success / warning / error / info — each 50,100,200,300,400,500,600,700,800
Radius      xs 4 · sm 6 · md 8 · lg 12 · xl 16 · full 9999
Space       0 4 8 12 16 20 24 32 40 48        (4px base; no arbitrary values)
Font size   11 12 13 14 16 18 20 24 28
Line height 1.4 tight · 1.6 normal · 1.5 mono
Weight      400 · 500 · 600 · 700
Duration    fast 120ms · normal 200ms · slow 320ms
Easing      standard cubic-bezier(.2,0,0,1) · out cubic-bezier(0,0,.2,1)
Font family sans  --font-sans  per-OS UI stack with CJK fallbacks (§5.11, fixes D15)
            mono  --font-mono  per-OS mono stack with CJK fallbacks (§5.11, fixes D15)
```

Layout constants are also tokens, because the shell depends on them:

```text
--layout-titlebar-h: 38px
--layout-sidebar-w: 200px
--layout-sidebar-w-collapsed: 60px
--layout-page-pad-x: 24px
--layout-page-pad-y: 20px
--layout-content-max-w: 1080px     # content column, keeps long forms readable
```

### 4.2 Semantic tokens (both themes must define all of them)

| Group | Tokens |
| --- | --- |
| Surface | `--bg-app`, `--bg-sidebar`, `--bg-sidebar-hover`, `--bg-sidebar-active`, `--bg-card`, `--bg-elevated`, `--bg-input`, `--bg-hover`, `--bg-active`, `--bg-overlay` |
| Text | `--text-primary`, `--text-secondary`, `--text-muted`, `--text-inverse`, `--text-link`, `--text-on-accent` |
| Border | `--border-subtle`, `--border-default`, `--border-strong`, `--border-focus` |
| Accent | `--accent`, `--accent-hover`, `--accent-active`, `--accent-subtle`, `--accent-text` |
| Status | `--success`, `--success-subtle`, `--success-text`, and the same triple for `warning`, `error`, `info` |
| Shadow | `--shadow-sm`, `--shadow-md`, `--shadow-lg`, `--shadow-popup` |
| Focus | `--focus-ring` (a full box-shadow value, not a colour) |

Reference values leaning on clash-verge-rev: dark content surface `#1e1f27`, white content surface
in light mode, nav selected state `alpha(accent, 0.15)` in light and `alpha(accent, 0.35)` in dark.

### 4.3 Rules

- A component that needs a colour it cannot name from the semantic table is a signal that the token
  table is incomplete — extend the table, do not inline a hex value.
- No gradient backgrounds. In particular `--gradient-primary` and the four
  `card-header-decoration` rules (D7) are deleted.
- Shadows are neutral black with alpha; the current `--shadow-card` tints the shadow blue, which
  looks wrong in dark mode.
- Font stacks are declared exactly once in `tokens.css` as `--font-sans` / `--font-mono`
  (§5.11). No component re-declares `font-family` — today three files carry their own mono stack.
- Every token in §4.2 must exist in both themes, and a check script enforces it (§5.9).

---

## 5. Cross-cutting technical decisions

### 5.1 Frameless window

`src-tauri/tauri.conf.json`:

```jsonc
"app": {
  "windows": [{
    "title": "nexa",
    "width": 1000, "height": 680,
    "minWidth": 760, "minHeight": 520,
    "decorations": false,
    "transparent": false,
    "titleBarStyle": "Overlay",   // macOS: keep traffic lights, hide title
    "hiddenTitle": true
  }]
}
```

Platform notes and the fallback:

- **macOS** — `titleBarStyle: "Overlay"` + `hiddenTitle: true` keeps the native traffic lights
  over our title bar. The title bar must therefore reserve ~78px of leading space. Identical on
  Intel and Apple Silicon; nothing in this refactor is arch-sensitive (§5.11).
- **Windows** — with `decorations: false` we lose the native drop shadow and rounded corners.
  Recover with `windowEffects` (Mica/Acrylic) where supported; if that proves visually unstable,
  ship a plain opaque surface with a 1px border. `transparent: true` is deliberately **not** used
  on Windows: it interacts badly with the resize handles and with WebView2 background painting.
- **Linux** — `decorations: false` requires us to implement our own resize handles on all eight
  edges (clash-verge-rev ships `window-resize-handles` for exactly this). That is out of scope for
  v1 of the refactor: on Linux keep `decorations: true` and hide `TitleBar.vue`'s window controls,
  driven by a single `isFrameless` capability flag from `useWindowControls`.
- A CSP/behaviour escape hatch: `useWindowControls` exposes `frameless` (platform-derived). If the
  window chrome misbehaves in a specific environment, flipping `decorations: true` in the config
  must degrade gracefully rather than produce a title bar inside a title bar.

`src-tauri/capabilities/default.json` gains:

```json
"core:window:allow-start-dragging",
"core:window:allow-minimize",
"core:window:allow-toggle-maximize",
"core:window:allow-maximize",
"core:window:allow-unmaximize",
"core:window:allow-is-maximized",
"core:window:allow-close",
"core:window:allow-set-theme"
```

`allow-set-theme` is needed so the OS-level window chrome follows the in-app theme.

### 5.2 Drag regions

- Every element that should drag the window carries `data-tauri-drag-region`.
- Interactive children (`button`, `input`, `select`, `a`) inside a drag region must not inherit the
  behaviour. Tauri's implementation matches the attribute on the exact target element, so a plain
  `<button>` inside the header is already safe; the invisible full-height flex spacer above the
  controls is the reliable drag surface.
- Double-click-to-maximize is not provided by `data-tauri-drag-region` on all platforms; implement
  it explicitly in `useWindowControls` via a `dblclick` handler on the drag surface.
- `-webkit-app-region` is not used anywhere. It is an Electron API and is ignored by WebView2/WKWebView.

### 5.3 The scroll chain (fixes D4)

The rule, applied top to bottom:

```text
html, body, #app        { height: 100%; overflow: hidden; }
.AppShell               { display: grid; height: 100vh; overflow: hidden; }
  .main-column          { display: flex; flex-direction: column; min-width: 0; min-height: 0; }
    .PageShell          { display: flex; flex-direction: column; flex: 1; min-height: 0; }
      .PageShell__header{ flex: 0 0 auto; }
      .PageShell__body  { flex: 1 1 auto; min-height: 0; overflow-y: auto; }
```

`min-height: 0` at every level is the load-bearing part; without it a flex child refuses to shrink
below its content and the page grows instead of scrolling. `LogsPage` then becomes `height: 100%`
inside `.PageShell__body` with an internal `min-height: 0` flex column, and the `calc(100vh - 180px)`
disappears.

### 5.4 Theme

- Three preferences: `system` | `light` | `dark`, stored in `prefs.ts`, default `system`.
- Resolution order: stored preference → `matchMedia('(prefers-color-scheme: dark)')`.
- The resolved theme is written to `<html data-theme="dark">`. All theme CSS keys off that.
- A `matchMedia` listener keeps `system` live while the app is open.
- On change, also call `getCurrentWindow().setTheme(theme)` so the OS chrome and native context
  menus follow.
- `useTheme` is initialised in `AppProviders` **before** first paint to avoid a flash of the wrong
  theme: read the preference from localStorage synchronously in `main.ts` and set the attribute
  before `app.mount()`.

### 5.5 i18n (en / zh-CN)

**Setup.**

- `vue-i18n` v9+, `legacy: false`, `globalInjection: true`, `fallbackLocale: 'en'`.
- `vue-i18n` is pure JS with no platform-specific optional dependencies, so adding it cannot
  break the six-target CI install (§5.11, rule 9).
- `missingWarn` / `fallbackWarn` on in dev, off in production builds.

**Locale resolution.** stored preference → `navigator.language` → `en`. Any `zh-*` tag
(`zh`, `zh-Hans`, `zh-CN`, `zh-SG`, …) resolves to `zh-CN`: this project ships Simplified Chinese
only, and mapping the whole family avoids falling back to English on `zh-Hans` systems — the tag
Linux distributions most commonly report. Traditional Chinese (`zh-Hant`, `zh-TW`, `zh-HK`) is a
future locale file, not a mapping change (non-goal, §1).

**Runtime behaviour.**

- Switching languages is live (reactive `locale` ref) — no reload, no remount.
- The resolved locale is written to `<html lang="…">` so screen readers, `Intl`, and the WebView's
  font selection follow it. `document.title` stays the untranslated product name "nexa"
  (fixes D14).
- Numbers, counts, and any future dates go through vue-i18n `n()` / `d()` (i.e. `Intl`) — never
  manual concatenation. Log timestamps are exempt: they are a technical artifact and keep their
  raw backend format.

Key namespaces:

```text
app.*        window title, product name
nav.*        sidebar labels
common.*     save, cancel, confirm, retry, copy, copied, close, loading, empty, …
connect.*    status, mode, connection method, node list, start/stop, node id, tun toggle
config.*     nodes, node editor, domains, network, load balancing
settings.*   service, mode, tun, relay, twoFactor, app, about, appearance
logs.*       filters, levels, actions, counts, empty
error.*      one key per backend error code (error.proxy.no_nodes, …) plus generic fallbacks
```

**CJK typography and layout rules.** Binding on the base components and page specs, because
Chinese text has different metrics than English and the current CSS assumes English:

- Line height ≥ 1.5 wherever a localized string can appear (CJK glyphs fill the em box; the 1.4
  "tight" step from §4.1 is reserved for known-Latin contexts such as node IDs and counters).
- No `letter-spacing` on localized text — tracking is a Latin typographic device; it splays CJK.
- No `text-transform: uppercase` / `capitalize` on localized text — Chinese has no case; the
  transform silently does nothing in zh-CN while changing en metrics.
- Buttons and pills take `min-width` + horizontal padding, never a fixed `width`: "Start Proxy"
  and "启动代理" differ in length by ~2× in either direction.
- `SettingRow` labels and hints must wrap (`white-space: normal`): a long zh-CN label wraps rather
  than pushing its control off the card.
- Where ellipsis truncation is used (node id, log lines), the full value is exposed via a `title`
  attribute and, where interactive, a copy action.
- Counts and plurals use vue-i18n pluralisation (`t('connect.nodeCount', { n }, n)`) — zh-CN has
  no plural form, en does.

**IME composition.** Any input submitted with Enter (domain chips, node search) must ignore the
Enter key while an IME composition is active — check `event.isComposing` (or track
`compositionstart` / `compositionend`). Without this, confirming a Chinese candidate with Enter
submits the form with the raw composition string. No current input hits this, but §6.2 adds the
first one.

**Message authoring.**

- `en` is the source of truth; `zh-CN` mirrors it. Key sets must match exactly — `lint:i18n`
  (§5.9) fails the build otherwise, so unknown-key leakage cannot ship.
- Messages contain text and placeholders only: no HTML, no nested `t()` calls inside a message.
  Interpolation, never concatenation.
- The project convention remains "English source": code comments, logs, and default strings stay
  English. i18n does not relax that — it only adds a translation layer over the UI.

### 5.6 Feedback layer (fixes D2)

```ts
// useToast.ts — module-level singleton array, callable from anywhere including stores
const toast = useToast()
toast.success(t('connect.started'))
toast.error(err)                       // normalises string | Error | unknown
```

- `ToastHost.vue` renders at the app root, stacking bottom-right, max 4 visible, auto-dismiss 4s
  for success/info and 8s for warning/error, click-to-dismiss, and de-duplication so a polling loop
  cannot stack 50 identical errors.
- `useConfirm.ts` returns a promise:

```ts
const ok = await confirm({
  title: t('settings.uninstallService'),
  message: t('settings.uninstallServiceConfirm'),
  tone: 'danger',
  confirmText: t('common.uninstall'),
})
if (!ok) return
```

- Destructive actions that must be routed through `confirm` in this refactor: stop proxy, uninstall
  service, clear logs, overwrite/clear config, enable service mode (privilege escalation).
- Error normalisation: backend failures reject with a structured `AppError` carrying a stable
  code (`proxy.no_nodes`, `service.elevation_denied`, …). `toErrorMessage(e, fallbackKey)`
  resolves `error.<code>` from the locale file, logs the raw `detail` to the console, and falls
  back to a translated generic message for unknown codes or non-`AppError` rejections. The
  i18n sweep (Phase 4) must cover every code constant in `src-tauri/src/error.rs`.
- `console.error` is retained alongside the toast for diagnostics; it is no longer the only signal.

### 5.7 State

Keep the module-singleton composable pattern (no Pinia — consistent with the "self-built" decision).
Split by concern:

| Store | Owns | Persistence |
| --- | --- | --- |
| `stores/config.ts` | `nodes`, `domains`, `localAddr`, `dnsAddr`, `upstreamDns`, `loadBalancing`, `tunName`, `useTun`, `useService`, `relay*`, `twoFactor*` | `localStorage['nexapipe.config']`, debounced 300ms |
| `stores/proxy.ts` | `status`, `nodeId`, `busy`, `startupError`, `serviceRunning` (polled via `is_service_running`); actions `start()`, `stop()`, `refresh()`, `refreshNodeId()`, `refreshServiceRunning()` | none |
| `stores/prefs.ts` | `theme`, `locale`, `sidebarCollapsed` | `localStorage['nexapipe.prefs']` |

`proxy.ts` absorbs the orchestration currently in `ProxyStatusControl.vue` (D12). The 1s/2s sleeps
around start become a bounded poll with a timeout instead of a fixed `setTimeout`, so a slow start
no longer reports a false failure.

`useTun` defaults to `false` in the v1 config shape; the migration (below) adds it explicitly so
existing payloads stay valid. `useService` keeps meaning "execution backend", and `useTun` means
"forwarding mode" — the two are now orthogonal but linked by the gating rule in §5.12.

Config migration (D11):

```ts
// read order, first hit wins
'nexapipe.config'  -> current shape, has { version, ... }
'nexa-config'      -> legacy, passed through the existing migrateOldConfig()
                     then written out as version 1 and the legacy key removed
```

`version: 1` is written from the first launch after this refactor. Each future migration is a
`from -> to` function in an ordered list.

### 5.8 Icons

`icons/registry.ts` maps a name to SVG path data. `AppIcon.vue` renders it. `v-html` is removed from
the codebase entirely (D6), which also removes a class of escaping bugs and makes icons styleable
through one `stroke`/`fill` contract.

### 5.9 Quality gates

New dev scripts in `package.json` (no new runtime deps):

| Script | What it does |
| --- | --- |
| `lint:i18n` | Fails if `en.json` and `zh-CN.json` key sets differ, or if a `t('x.y')` literal has no key |
| `lint:tokens` | Fails if a `var(--x)` reference has no definition in `themes.css`, and if any component file contains a raw hex colour or a local `font-family` declaration |
| `dev:components` | Dev-only route rendering the base component gallery |

### 5.10 Router hardening

`createWebHistory()` works in dev but is fragile under the packaged `tauri://` / custom-protocol
origin on reload. Switch to `createWebHashHistory()` and add a catch-all route redirecting to `/`.
Low risk, removes a whole class of "white screen after reload" reports.

### 5.11 Platform and architecture matrix

The app already ships on six platform/arch combinations, built by `.github/workflows/release.yml`
on native runners (no cross-compilation). This refactor must not narrow that matrix. The UI
layer's obligations on each axis:

| OS | Arch | WebView runtime | Window chrome | Verified by |
| --- | --- | --- | --- | --- |
| Windows | amd64 | WebView2 (Evergreen) | frameless + custom controls, Mica where available | local dev + CI bundle |
| Windows | aarch64 | WebView2 (Evergreen, ARM64) | same as amd64 — no arch difference in the WebView | CI bundle (windows-11-arm runner) |
| macOS | amd64 | WKWebView | `titleBarStyle: Overlay`, traffic lights | CI bundle (macos-15-intel) |
| macOS | aarch64 | WKWebView | same as amd64 | CI bundle (macos-14) |
| Linux | amd64 | webkit2gtk-4.1 | native decorations (§5.1), custom controls hidden | CI bundle + release dry-run |
| Linux | aarch64 | webkit2gtk-4.1 | same as amd64 | CI bundle (ubuntu-22.04-arm runner) |

**Rules.**

1. **The frontend never branches on architecture.** Arch differences are build-time concerns —
   per-target wintun.dll selection and native runners are already handled by release CI's
   `ci-config.mjs` config override. The webview code's only platform signal is the OS, consumed
   via capability flags on `useWindowControls` (`isMacos` / `isWindows` / `isLinux` /
   `frameless`), derived from `@tauri-apps/api` — never `navigator.userAgent` sniffing.
2. **Config merge discipline.** Release CI generates `ci-override.json`, which overrides
   `bundle.resources` (per-arch wintun.dll), `bundle.createUpdaterArtifacts`, and
   `build.beforeBuildCommand`. This refactor edits the `app.windows` block and capabilities only;
   it must not move or restructure `bundle.*` keys or the override stops merging cleanly. Every
   `tauri.conf.json` change is validated by a six-triple prerelease dry-run before the next real
   release (Phase 5).
3. **Font stacks are per-OS and CJK-complete** (fixes D15). Declared once in `tokens.css`:

   ```css
   --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                "PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC",
                "WenQuanYi Micro Hei", sans-serif;
   --font-mono: "Cascadia Code", "SF Mono", Menlo, Consolas, "Liberation Mono",
                "Noto Sans Mono CJK SC", monospace;
   ```

   Latin UI fonts come first so Latin glyphs render with the native UI face and CJK falls through
   to the platform's CJK family on all three OSes ("Microsoft YaHei" on Windows incl. ARM64,
   "PingFang SC" on macOS, Noto/WenQuanYi on Linux). CJK glyphs inside mono contexts (log lines)
   render through the CJK fallback at full width — expected and acceptable. No webfont is bundled:
   system fonts keep the native feel, the bundle stays small on all six targets, and there is no
   font-license payload. A Linux install without any CJK font falls back to whatever fontconfig
   offers — a distro concern, not an app one.
4. **CSS baseline = WebKitGTK as shipped on Ubuntu 22.04**, which lags WebView2 and WKWebView.
   No `:has()`, no container queries, no `subgrid` in the token or component CSS. The <860px
   sidebar auto-collapse (R7) is a `ResizeObserver` on the shell root toggling a class — not a
   media or container query — so the behaviour is identical in all three WebViews.
5. **Scrollbars**: thin custom `::-webkit-scrollbar` styles are kept; all three runtimes accept
   them (WebView2 is Chromium). macOS overlay scrollbars stay native and are not styled.
6. **Keyboard modifiers** derive from `isMacos` (`⌘` vs `Ctrl` in tooltips and shortcuts, e.g.
   the Logs search focus shortcut). `Esc` behaves identically everywhere.
7. **Display scaling.** Sizes are px tokens; all three WebViews follow the OS scale factor
   automatically. Verified at 125% and 150% on Windows — 150% is the default on many ARM64
   laptops — and at 2× on a retina Mac.
8. **No universal macOS binary.** dmg/app are built per-arch and the updater serves per-target
   entries assembled from the six CI jobs; a fat binary would change the release pipeline for no
   user-visible gain.
9. **Lockfile discipline.** The committed `package-lock.json` must keep the full set of
   platform-specific optional native packages (`@tauri-apps/cli-*`, `@esbuild/*`,
   `@rollup/rollup-*`) for all six CI jobs — a lockfile generated next to an existing
   `node_modules` records only the generating platform's packages and starves the other five
   (npm/cli#4828; release.yml already self-heals with `npm install`, but the lockfile should be
   complete anyway). Adding `vue-i18n` is safe (pure JS). If any future dependency ships native
   optional packages, regenerate the lockfile in a **clean directory** containing only
   `package.json` (`npm install --package-lock-only`) and copy the result back. Also: the repo
   currently carries both `yarn.lock` and `package-lock.json` while CI forces npm — delete
   `yarn.lock` and switch `beforeBuildCommand` to `npm run build` during Phase 1 so there is
   exactly one lockfile and one package manager.

### 5.12 Proxy mode model and TUN gating (fixes D16)

Semantics, matching clash-verge-rev: **TUN is an explicit user choice, gated on the service.**

```text
service not installed ──►  only Local Proxy is possible.
                            The TUN toggle renders disabled with a hint
                            ("requires the system service"); clicking it offers
                            an inline install (confirm dialog → install_service,
                            which elevates via UAC / sudo / polkit).

service installed ──────►  TUN toggle is enabled. Default stays off (Local Proxy).
                            Turning it on is applied on the next start (or triggers
                            a restart of a running proxy, after confirm).
```

Rules:

1. **The toggle, not the probe, decides.** Today `ProxyManager::start()` probes
   `TunProxy::is_available()` and silently picks TUN or falls back to local proxy (D16). The
   backend grows an additive `use_tun: Option<bool>` parameter on `start_proxy` (the one
   sanctioned Rust change, §1 / §9.1): `Some(true)` requests TUN, anything else requests local
   proxy. The privilege probe remains as a *guard*, not as the selector: when TUN is requested but
   privileges are unavailable, the backend returns a new error code (`proxy.tun_unavailable`)
   instead of silently downgrading the mode. The parameter is threaded through the service IPC
   channel as well, so service mode honours the same flag.
2. **Service install is the gate, elevation is implied by it.** `install_service` already
   elevates (the `service.elevation_*` error codes exist for exactly that flow). The UI never
   promises TUN from an ad-hoc elevated app run: even when the process happens to have admin
   rights, the TUN toggle stays locked until the service is installed — one gate, one mental
   model, same as clash-verge.
3. **Gating state is polled, not assumed.** `stores/proxy.ts` owns `serviceRunning`
   (`is_service_running`), refreshed on app focus, after install/uninstall, and alongside the
   status poll. The TUN toggle's `disabled` state derives from it reactively. Uninstalling the
   service while `useTun` is `true` flips the toggle back off with an explanatory toast.
4. **The status line reports what actually runs.** After `start()`, the proxy store verifies the
   reported mode against the requested one; a mismatch (e.g. service died between toggle and
   start, or the service→process fallback kicked in) surfaces as a warning toast, never silence.
   The Connect stat row shows the *actual* mode from `get_proxy_status`, not the requested one.
5. **TUN settings stay where they are.** The TUN group in Settings keeps only the device-name
   field (rarely touched); the on/off decision lives on Connect next to Start, where the mode
   is visible while it takes effect. This mirrors clash-verge: the toggle sits with the
   connection controls, advanced TUN details sit in settings.
6. **i18n keys** (namespace `connect.*`): `tunMode` (toggle label), `tunRequiresService` (disabled
   hint), `tunInstallPrompt` / `tunInstallTitle` (inline-install confirm), `tunUnavailable`
   (start refused), `modeMismatch` (warning), plus `error.proxy.tun_unavailable` and the existing
   `service.elevation_*` codes in `error.*`.

---

## 6. Page-by-page migration spec

### 6.1 Connect (from `DashboardPage.vue`)

Layout: `PageShell` titled "Connect", header actions = `Refresh` + `Start/Stop`.

1. **Status panel** — the status ring and the start/stop/refresh buttons, split out of
   `ProxyStatusControl.vue` into `ProxyStatusPanel.vue` + `ProxyToggleButton.vue`. The store owns
   the actions; the panel only renders. The **TUN toggle** (§5.12) sits here next to Start:
   disabled with a hint while the service is not installed, offering inline install on click.
   Node ID row moves into the panel with a copy affordance that toasts on success.
2. **Stat row** — four `StatTile`s (connection method, proxy mode, domain count, node count).
   The proxy-mode tile shows the *actual* mode from `get_proxy_status`, and flags a mismatch
   against the requested mode (§5.12 rule 4). Drops the per-tile `translateY(-2px)` hover lift,
   which draws attention to four non-interactive elements.
3. **Node list** — `NodeListRow.vue`. Replaces the current per-node green dot (which only mirrors
   the global running state and therefore tells the user nothing) with an honest per-row summary:
   connection type badge, domain count, and a masked connection string with a reveal/copy action.
4. Empty state uses `AppEmpty` with a CTA that navigates to Config.

### 6.2 Config (from `ConfigPage.vue`)

Layout: `PageShell` titled "Config", header actions = `Add Node`.

1. **Two-column master–detail**, following clash-verge's Profiles page: left rail lists nodes
   (label, type badge, domain count, active marker), right pane edits the selected node
   (connection string, proxied domains). Below ~900px window width it collapses to a single column
   with a back affordance.
   Rationale: the current stacked design re-renders every node's full editor at once, and the
   per-node `<textarea>` binding through a `Map` (`nodeDomainsText`) leaks state for removed nodes.
2. **Domains editor** gets explicit chips per domain with add/remove, plus a bulk "one per line"
   textarea behind a toggle. The chip input submits on Enter — with the IME composition guard
   (§5.5), the first Enter-submitted input in the app. The current free-text textarea silently
   accepts junk and cannot be reordered.
3. **Network** (local addr, DNS listen, upstream DNS) → collapsed "Advanced" `AppCard`, since most
   users never touch it.
4. **Load balancing** → `AppRadioGroup` inside the Advanced card.
5. **Domain overview** card is dropped: it duplicates the union of the per-node lists, which the
   left rail already shows. If kept for search, it becomes a filter over the node list rather than
   a separate card.
6. `Load Example` / `Clear Config` move into the page header overflow menu; `Clear Config` is
   destructive and must confirm.

### 6.3 Settings (from `SettingsPage.vue`)

Layout: `PageShell` titled "Settings". Groups, in order: Appearance, Service, Proxy Mode, TUN,
Relay, 2FA, Application, About.

1. **Appearance** (new): theme (system/light/dark) and language. The language selector lists
   locales under their native names — `English` / `简体中文` — so the setting is findable even when
   the UI is in the wrong language for the user.
2. **Proxy Mode** (the old Normal/Service card) is dissolved (D16). The execution backend
   (service vs in-process) merges into the **Service** panel below — it is a property of the
   service, not a "mode". The forwarding mode (Local Proxy vs TUN) becomes the gated TUN toggle
   on Connect (§5.12); only the TUN device-name field stays in Settings under the TUN group.
3. **Service** is `ServicePanel.vue`. It absorbs the execution-backend switch (in-process vs
   service) from the dissolved Proxy Mode card (§5.12): install/uninstall plus a
   "route through the service" toggle, whose failures toast via the `service.*` error codes.
   The three static "hints" become inline copy attached to the relevant control instead of a
   floating list, and the duplicated inner `card-header` is removed (the panel already sits in an
   `AppCard` that renders a title — currently the words "Service Management" render twice, once
   from the card and once from the component).
4. **2FA**: the revealed fields belong in a nested group with a warning that the secret is stored
   in plaintext localStorage. TOTP secret gets a reveal toggle.
5. **Application**: `launchAtStartup` is wired (`is_auto_start_enabled` / `set_auto_start`) and must
   surface failures through a toast (it currently swallows them). `minimizeOnClose` and `logLevel`
   are **removed** unless a backend command lands for them (D10) — decorative switches are worse
   than absent ones.

### 6.4 Logs (from `LogsPage.vue`)

Layout: `PageShell` titled "Logs", `full` mode (no content padding so the list can bleed to the
edges), header actions = copy + clear.

1. `LogToolbar.vue`: level filter, **new** free-text search, auto-scroll toggle, entry count,
   copy, clear (destructive → confirm).
2. `LogList.vue`: keeps the 2s incremental poll and 300-entry cap, renders inside the shell's scroll
   container. Level is currently both a coloured label and a left border on `error`/`warn` rows;
   collapse to one signal.
3. Add a "paused" state that suspends polling while the user scrolls up, and a "jump to latest"
   affordance — currently `autoScroll` fights the user the moment they scroll to read.
4. `MAX_LOGS` and the poll interval move to named constants in one place.
5. Log content stays verbatim (backend text, raw timestamps) — it is a technical artifact and is
   not localized (§5.5). Only the toolbar chrome around it is.

---

## 7. Phased execution

Each phase ends in a shippable state. Phases 3.1–3.4 are independent of each other and can be
reviewed one at a time.

### Phase 0 — Baseline and safety net

- Record the current behaviour: screenshots of all four pages in the current build, plus a written
  functional checklist (§10) that passes before any edit.
- Delete `ProxyConfigForm.vue` (D1) and the unused types (D13) as a standalone commit.
- Backend delta as its own commit: add the additive `use_tun: Option<bool>` parameter to
  `start_proxy` (threaded through the service IPC), add the `proxy.tun_unavailable` error code,
  and keep the implicit privilege probe as the guard behind an explicit `use_tun=true` (§5.12
  rule 1). `cargo check --all-targets` plus the CI matrix must stay green; the frontend still
  omits the parameter at this point, so behaviour is unchanged until Phase 3.1.
- Add `lint:i18n` / `lint:tokens` scripts in no-op form so later phases fill them in.

Exit: build is green, `git log` shows the deletion commit in isolation.

### Phase 1 — Shell and infrastructure

- `styles/tokens.css`, `styles/themes.css`, `styles/base.css` with both themes fully populated
  (this alone fixes D3 and D8), including the `--font-sans` / `--font-mono` stacks with per-OS
  CJK fallbacks (fixes D15, §5.11 rule 3).
- `AppProviders`, `AppShell`, `TitleBar`, `WindowControls`, `SideBar`, `SideBarItem`,
  `SideBarFooter`, `PageShell`.
- `tauri.conf.json` window block + `capabilities/default.json` permissions (§5.1). `bundle.*`
  keys are left untouched (§5.11 rule 2).
- Stores split into `config` / `proxy` / `prefs`; legacy localStorage key migrated (§5.7).
- `useTheme`, `useLocale`, `useSidebar`, `useWindowControls`, `useToast`, `useConfirm`, with the
  per-OS capability flags from §5.11 rule 1.
- i18n wired with `en` and `zh-CN` containing the *shell and nav* keys only; locale resolution
  incl. the `zh-*` mapping and `<html lang>` sync (§5.5).
- Router switched to hash history + catch-all (§5.10).
- `index.html`: title fixed to "nexa", `lang` attribute driven by the resolved locale (D14).
- Package-manager consolidation: delete `yarn.lock`, switch `beforeBuildCommand` to
  `npm run build` (§5.11 rule 9).
- Pages temporarily render inside `PageShell` with their existing markup untouched.

Exit: window drags/minimises/maximises/closes; sidebar collapses and remembers; theme switches
without flicker; language switches live and `<html lang>` follows; nav highlights correctly; all
four existing pages still work and no page double-scrolls; document title reads "nexa".

#### Phase 1 — implementation notes

A few decisions made while executing Phase 1 that are not in the original checklist:

- `src/styles/legacy.css` was added as a temporary token bridge. The old `:root` block lived inside
  the pre-refactor `App.vue`, so removing `App.vue` also removed the palette the four un-migrated
  pages and three legacy components still use. The bridge maps those old names onto the new
  semantic layer so the pages render correctly in both themes until they are rewritten (Phase 3)
  and then the bridge is deleted with them (Phase 4).
- Linux keeps `decorations: true` via `src-tauri/tauri.linux.conf.json` platform-specific config.
  The base config keeps `decorations: false` for Windows and macOS; macOS uses
  `titleBarStyle: Overlay` so its native traffic lights stay visible.
- Legacy `nexa-config` key deletion is gated by `dropLegacyKey()` returning `false` in
  `src/stores/config.ts` until the old `src/composables/useConfigStore.ts` is deleted in Phase 3/4.
  Removing the key earlier would have silently reset the Config page to an empty node list because
  the un-migrated pages still read from and write to the old key.
- `src/components/ProxyStatusControl.vue` was updated to read the structured `ProxyStatus` object
  now returned by `get_proxy_status`; the previous string-split implementation predated that
  backend change and left the panel permanently showing "Stopped".
- The `lint:i18n` / `lint:tokens` scripts were strengthened: they strip comments before scanning,
  treat `font-family: var(--font-*)` as the correct pattern, and quarantine known violations in the
  Phase 3/4 deletion set while still failing on any new code.

### Phase 2 — Base component layer

- The 16 components under `components/base/` (§3.2), built to the CJK typography rules (§5.5).
- `icons/registry.ts`; `v-html` removed from the codebase (D6).
- `_DevComponentsPage.vue` gallery on a dev-only route.

Exit: gallery renders every component in both themes, both locales, and at both sidebar widths;
`lint:tokens` passes.

### Phase 3 — Page migration (four independent sub-phases)

3.1 Connect → 3.2 Config → 3.3 Settings → 3.4 Logs, each following its spec in §6 and each ending
with the §10 checklist for that page plus screenshots in both themes **and both locales**.
3.1 includes the TUN toggle wiring (§5.12): gating on `serviceRunning`, inline-install flow,
mode-mismatch surfacing, and `useTun` in the persisted config. 3.3 dissolves the old Proxy Mode
card into the Service panel and the Connect toggle.

### Phase 4 — Cleanup and hardening

- Remove the four `card-header-decoration` rules and every gradient surface (D7).
- Wire the remaining feedback paths: every `invoke()` failure in the app reaches a toast, every
  destructive action reaches `confirm`.
- Delete `Toast.vue` / `ConfirmDialog.vue` once `ToastHost` / `AppDialog` fully replace them.
- Full i18n sweep: zero hard-coded user-visible strings; `lint:i18n` passes; `aria-label`s and
  `title` attributes included.
- a11y pass: visible focus ring on every interactive element, `Esc` closes dialogs and returns
  focus to the trigger, tab order follows visual order, `aria-current="page"` on the active nav
  item, form controls all labelled.
- Keyboard nav for the sidebar when collapsed (tooltip must also appear on focus, not hover only).

### Phase 5 — Packaging and cross-platform verification

- `npm run build` (vue-tsc must pass).
- `tauri build` on Windows locally, at 100% and 150% display scaling (§5.11 rule 7).
- One prerelease-tag dry-run through `.github/workflows/release.yml`: all six triples
  (windows amd64/arm64, macos amd64/arm64, linux amd64/arm64) must produce bundles, the
  `ci-config.mjs` override must still merge with the edited `tauri.conf.json` (§5.11 rule 2), and
  the merged `latest.json` must contain six platform entries. The UI refactor does not touch Rust,
  but `tauri.conf.json` affects bundling, so this dry-run gates the next real release.
- Linux and macOS UI verification (CJK fonts, frameless chrome, scrollbars, Overlay title bar) via
  screenshots from the dry-run artifacts or community testers — there is no local Linux/macOS
  machine to smoke-test on.
- Verify on a machine with no prior config: fresh `localStorage` path and legacy-migration path.

---

## 8. Risk register

| # | Risk | Impact | Mitigation |
| --- | --- | --- | --- |
| R1 | Frameless window breaks dragging or edge-resize on Windows/Linux | High — app feels broken | Platform-split strategy (§5.1); `decorations: true` fallback is a one-line config change; Linux keeps native chrome in this phase |
| R2 | macOS traffic lights overlap the title bar content | Medium | Reserve 78px leading space when `platform === 'macos'`; verify in both themes |
| R3 | Lost user config during the localStorage key migration | High | Migration reads the legacy key and writes the new one before deleting; test with a seeded legacy payload; never overwrite an existing new-format key |
| R4 | i18n sweep misses strings | Low | `lint:i18n` + a manual pass over every `.vue` diff; visual check in zh-CN for overflow, since Chinese strings are shorter but buttons with fixed widths are not |
| R5 | Flex `min-height: 0` missed somewhere → double scrollbar or clipped list | Medium | The scroll chain is specified once (§5.3) and reviewed per page; Logs is the canary |
| R6 | Refactor scope creeps into Rust (e.g. `get_proxy_status` string protocol) | Medium | Explicitly a non-goal; listed in §9 as a follow-up item instead |
| R7 | Window became too small for a 200px sidebar | Medium | Raise the default window size and set `minWidth: 760`; auto-collapse the sidebar below a 860px breakpoint via `ResizeObserver` (§5.11 rule 4) |
| R8 | Toast storms from the 2s log poll | Low | Toast de-duplication by message hash + max stack of 4 (§5.6) |
| R9 | Dark theme looks wrong because shadows/tokens were light-only | Medium | `--shadow-*` redefined per theme; gallery page reviewed in both themes before page migration starts |
| R10 | Losing the existing hand-tuned error surfacing on Connect (the only working one today) | Low | `ProxyStatusPanel` keeps the inline error block; the toast is additive, not a replacement |
| R11 | zh-CN layout breaks: clipped line-height, fixed-width buttons, unwrappable labels, serif fallback inside mono text | Medium | CJK typography rules are binding on base components (§5.5); CJK-complete font stacks (§5.11 rule 3); gallery and acceptance checklist run in zh-CN at the 760px minimum width |
| R12 | CSS works in WebView2/WKWebView but not on the older WebKitGTK baseline | Medium | §5.11 rule 4 fixes the baseline (no `:has()`, no container queries); `ResizeObserver` instead of container queries; Linux checked in the release dry-run |
| R13 | A new npm dependency drops optional native packages from the lockfile and breaks the six-target CI | Medium | `vue-i18n` is pure JS; lockfile regeneration rule (§5.11 rule 9); the prerelease dry-run catches it before a real release |
| R14 | Enter-submitting during IME composition corrupts domain/node input for Chinese users | Medium | IME composition guard is specified with the first Enter-submitted input (§5.5, §6.2) and covered in the acceptance checklist |
| R15 | TUN toggle enabled but the service died / privileges were lost between toggle and start → silent downgrade or confusing failure | Medium | `proxy.tun_unavailable` error code instead of silent fallback (§5.12 rule 1); store verifies reported mode vs requested after start (rule 4); `serviceRunning` re-polled on focus and after install/uninstall (rule 3) |
| R16 | `use_tun` parameter change breaks the installed-service IPC protocol (old service binary, new app) | Medium | Parameter is additive and optional; the IPC payload gains an optional field — an old service answers without it (defaults to the old probe behaviour) and only the mode-verification toast (§5.12 rule 4) tells the user the truth; service reinstall is prompted when the mismatch persists |

---

## 9. Open questions

### 9.1 Backend contract — needs a decision

Two items from earlier drafts are already done on the Rust side and are removed from the open
list: `get_proxy_status` now returns the structured `ProxyStatus` (no more `"true:tun"`
splitting), and `start_proxy` / `stop_proxy` return `Result<(), AppError>` with stable error
codes instead of discarded English prose. `greet` has been deleted.

Still open:

- **`use_tun` parameter (sanctioned by this plan, §5.12).** Additive `Option<bool>` on
  `start_proxy`, threaded through the service IPC; new error code `proxy.tun_unavailable`;
  privilege probe demoted from selector to guard. This is the only backend change in scope.
- **The service→process silent fallback** (`lib.rs`: "Failed to start proxy via service, falling
  back to process mode"). **Decided (2026-09-16): refuse the fallback when `use_tun=true`** —
  the command fails loudly with `proxy.tun_unavailable` instead of starting a process-mode local
  proxy the user did not ask for. The fallback stays as-is for `use_tun=false` (process-mode
  local proxy is an acceptable degradation there).

### 9.2 Brand

The current accent is Tailwind blue-500 `#3b82f6`. clash-verge-rev's default is a teal/green. Pick
one before Phase 1, since the whole token table depends on it: keep the blue, or adopt an accent
that reads better against the `#1e1f27` dark surface.

### 9.3 Linting

ESLint dependencies (`eslint`, `eslint-plugin-vue`, `typescript-eslint`, `vue-eslint-parser`)
are already installed in `package.json`, but there is **no config file yet**. Add a flat
`eslint.config.js` in Phase 1 (before page migration), because a 5-page migration is exactly when
dead bindings and unused refs accumulate.

---

## 10. Acceptance checklist

Per page, in both themes, at 1000x680 and at the 760px minimum width, with English and Chinese:

- [ ] No page creates a second scrollbar; the header and toolbar stay pinned.
- [ ] Every interactive control is reachable by keyboard and shows a visible focus ring.
- [ ] No user-visible string is a raw literal.
- [ ] No raw hex colour in any component.
- [ ] zh-CN at the 760px minimum width: labels wrap, nothing clips, buttons do not truncate
      ("Start Proxy" ↔ "启动代理" both fit).
- [ ] Switching language takes effect live; `<html lang>` follows; no reload or remount.
- [ ] Enter-submitting an input during IME composition does not submit (domain chips).
- [ ] zh-CN text renders with the platform CJK UI font on Windows (no serif glyphs inside
      monospace log lines).

Functional regression (must hold before and after):

- [ ] Start proxy → status flips to running, mode and node ID appear; the ID copies and toasts.
- [ ] Stop proxy → confirms, then status returns to stopped.
- [ ] Start with no nodes configured → the button is disabled.
- [ ] A node with an empty connection string is rejected with a visible message.
- [ ] Backend startup failure (`get_startup_error`) is surfaced to the user.
- [ ] Service install → status shows running; uninstall → confirms, then shows stopped.
- [ ] Launch-at-startup toggle survives an app restart.
- [ ] Config survives an app restart (nodes, per-node domains, network, relay, 2FA).
- [ ] A pre-refactor `nexa-config` payload migrates intact.
- [ ] Logs poll incrementally, filter by level, copy, and clear (clear confirms).
- [ ] Collapsed sidebar state and theme/locale choices survive an app restart.

Proxy mode gating (§5.12, clash-verge parity):

- [ ] With no service installed, the TUN toggle is disabled with a hint; the proxy starts and
      runs in local proxy mode.
- [ ] Clicking the disabled toggle offers the inline install; declining changes nothing;
      accepting walks the elevation flow (`service.elevation_*` failures toast their code).
- [ ] After the service is installed, the TUN toggle unlocks; enabling it and starting flips the
      status line to TUN (`mode: "tun"`).
- [ ] Requesting TUN when privileges are unavailable fails with the `proxy.tun_unavailable`
      message — never a silent downgrade to local proxy.
- [ ] Uninstalling the service while TUN is enabled flips the toggle off with an explanatory
      toast.
- [ ] A mode mismatch (requested vs reported) after start always surfaces a warning.

Cross-platform and packaging (Phase 5):

- [ ] Windows local build at 100% and 150% display scaling: no clipped or overlapping controls.
- [ ] A prerelease-tag dry-run builds all six platform/arch bundles and a six-entry `latest.json`.
- [ ] The `ci-config.mjs` override still merges with the edited `tauri.conf.json` (wintun.dll
      per-arch selection intact on windows arm64).
- [ ] Linux/macOS screenshots from the dry-run artifacts reviewed: native chrome on Linux, traffic
      lights on macOS, CJK fonts resolved on each OS.
