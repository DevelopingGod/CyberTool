# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

NetGuard: a Tauri 2 + React/TypeScript + Rust Windows desktop app that diagnoses network safety and system security posture (Wi-Fi security, DNS/hosts tampering, ARP anomalies, open ports, suspicious processes/persistence, firewall/Defender status, driver anomalies). It is explicitly **not** an antivirus — a rule-based diagnostic/triage tool, not a scanner/remover. The full original product spec is `CYBERTOOL_BUILD_PROMPT.md`; non-obvious implementation decisions made against that spec are logged in `DECISIONS.md` — read both before making architectural changes.

## Commands

Run from the repo root (`D:\Claude-Projects\CyberTool`). Rust/Cargo must be on `PATH` — in Bash: `export PATH="$HOME/.cargo/bin:$PATH"` first.

- `npm run build` — `tsc && vite build`; the frontend typecheck + build. Run this after any frontend change.
- `cargo check` (run inside `src-tauri`) — fast Rust compile check.
- `cargo test` (run inside `src-tauri`) — runs all check-agent unit tests. Run a single test with `cargo test <name>` (e.g. `cargo test wifi::` to scope to one check module).
- `npm run tauri build` — full release build, produces the NSIS Windows installer under `src-tauri/target/release/bundle/nsis/`. Long-running (first Rust release compile is slow); run in the background.
- **Never run `npm run tauri dev` or `tauri dev`** in an agent session — it opens a blocking native GUI window that never returns control.

## Architecture

### Backend / frontend split
All OS interaction (registry, process table, network config, firewall/Defender status) lives in Rust in `src-tauri/src/`. The React frontend never talks to the OS directly — it only calls Tauri commands (`src-tauri/src/commands.rs`) and listens for scan events. Keep it this way: new diagnostics belong in Rust, not in JS shelling out.

### Check-agent pattern (`src-tauri/src/checks/`)
Every diagnostic is an independent module implementing the `SecurityCheck` trait (`checks/mod.rs`): `id`, `name`, `category`, `required_permission`, `permission_description`, `run(&self, ctx: &ScanContext) -> CheckResult`. `all_checks()` in `checks/mod.rs` is the single registration point — a new check-agent must be added there or it won't run or appear anywhere.

Each check module separates **pure parsing/evaluation functions** from the **OS-interaction shell** (the `run()` method, which shells out via `sysutil::run_command`). Unit tests exercise only the pure functions against hand-written sample command output (`netsh`, `arp -a`, `netstat -ano`, `driverquery` CSV, etc.) — there is no mocked command-runner trait. Follow this split for any new check so it stays testable without mocking OS calls.

`sysutil::run_command` is the one place that shells out (fixed argv, no string-built commands, `CREATE_NO_WINDOW`). Any new subprocess call should go through it, not `std::process::Command` directly.

### Scan orchestration (`src-tauri/src/scan.rs`)
`run_scan(app, approved_once, categories: Option<&[CheckCategory]>)` optionally filters `all_checks()` down to the requested categories (`None`/empty = full catalog — this is the only thing category filtering changes; the permission state machine, events, rollup, and history recording all run identically for a category-scoped scan) before applying the permission state machine per check, running allowed ones against a single shared `ScanContext` (captures the process table once per scan), and emitting three Tauri events as it goes rather than blocking until done: `netguard://scan-progress`, `netguard://scan-result`, `netguard://scan-complete`. The overall rollup severity is the **max severity among executed checks only** — `PermissionDenied`/`Error` outcomes never count as `Ok`, and if nothing executed the rollup is `Caution`, never `Ok`. Preserve this "never silently report safe" rule in any rollup changes. The `run_scan` Tauri command takes the same `categories` param; the frontend's category-scan selector on the Dashboard passes it through, `None`/`null` for a full scan.

`ScanContext` also carries `previous_raw_keys: HashMap<String, Vec<String>>` — the previous scan's `CheckResult.raw_keys` per check id, seeded in `run_scan` from `history::latest()` *before* the context is built (so `checks` never depends on `history`, avoiding a cycle). `persistence.rs` and `process_baseline.rs` use this to flag entries that are new since the last scan (escalated severity, "new since last scan" in the finding). `raw_keys` is a check's own stable per-entry identifiers for this purpose only — empty for checks that don't diff.

Background scans (`src-tauri/src/background.rs`, spawned from `tauri::Builder::setup`) call `scan::run_scan(app, &[])` — the exact same function as a manual scan, with an empty `approved_once`. This means a background run only ever executes checks currently set to `Allowed`; `Denied` and `AskEveryTime` are both skipped (no UI is available to prompt during a background run). Never add a second/parallel permission-check path for background scans — always route through `run_scan`.

### Permission & consent state machine (`src-tauri/src/permissions.rs`) — the part most likely to be broken by a careless change
Three states per check-agent: `Allowed` / `Denied` / `AskEveryTime` (default), persisted in `permissions.json` via `tauri-plugin-store`. Critical invariant: **the backend never caches a "user already said yes" decision across scans.** `run_scan` takes an `approvedOnce: Vec<String>` argument — the set of check IDs the *frontend* obtained one-time approval for via `ConsentDialog` *before* calling `run_scan` for this specific run. An `AskEveryTime` check not present in `approvedOnce` is skipped and shown as permission-needed, every time, with no exceptions. Toggling a permission in Settings takes effect on the very next scan because every lookup re-reads the store (`permissions::get_one`) — there is no in-memory cache to invalidate. When touching this code path, preserve: (1) no state where `AskEveryTime` silently behaves like `Allowed`, (2) toggling `Denied`→anything or anything→`Denied` is reflected immediately on the next scan.

### Frontend structure (`src/`)
- `theme/tokens.css` — the single source of truth for all colors/gradients/spacing/severity tokens (light-green cybersecurity gradient palette, red/orange/green severity, light+dark variants). Components reference `var(--ng-*)` only — do not hardcode colors in component CSS. `theme/global.css` also themes the WebView2 (Chromium) scrollbar globally via `::-webkit-scrollbar`.
- `types.ts` — hand-mirrors the Rust `serde`-tagged types (`CheckOutcome`'s `{state, result}` tagging, `Finding.action`'s `RemediationAction` tagging in particular). If a Rust type in `checks/mod.rs`, `scan.rs`, or `history.rs` changes shape, update `types.ts` to match — there is no codegen keeping these in sync (a deliberate v1 tradeoff, see `DECISIONS.md`).
- `lib/api.ts` — typed wrappers around `invoke`/`listen` calls; the only place that should call raw Tauri APIs (the Developer page's `openUrl` call, via `@tauri-apps/plugin-opener` directly, is the one deliberate exception — it needs no typed response).
- `pages/` (`Dashboard`, `Settings`, `HistoryDetail`, `CheckDetail`, `Developer`, `Terms`, `PrivacyPolicy`) vs `components/` (presentational pieces: `CheckCard`, `StatusBanner`, `ScanButton`, `ConsentDialog`, `RemediationDialog`, `Sidebar`, `CheckGrid`). No router — view switching is `useState` in `App.tsx` (`View` = `dashboard | settings | history-detail | check-detail | developer | terms | privacy`).
- **Check-detail navigation**: `CheckCard` no longer expands inline — clicking a card (or its "View details" button) calls `onOpenDetail(outcome)`, which `App.tsx` stores as `selectedOutcome` and switches to the `check-detail` view rendering `CheckDetail`. `App.tsx` tracks a `detailOrigin` (`dashboard` vs a specific history scan id) so "Back" returns to wherever the card was opened from. The full `CheckOutcome` object is passed through React state, not re-fetched by id — both `Dashboard` and `HistoryDetail` already hold it in memory.
- **Remediation action surface**: a `Finding` can carry an optional `action: RemediationAction` (`{kind:"directFix", actionId, label, params}` or `{kind:"deepLink", uri, label}`). `CheckDetail` renders an action button per finding that has one; clicking it opens `RemediationDialog` (styled like `ConsentDialog`) for an explicit per-action confirmation before calling `api.runDirectFix`/`api.openSettingsDeepLink`. See `DECISIONS.md` for the safety model and per-check classification.
- No emoji anywhere in UI copy or code — icons come from `lucide-react` via `lib/icons.ts`.

### Persistence
Local JSON documents under the Tauri app data dir via `tauri-plugin-store`, no SQLite, no network sync ever: `permissions.json` (`{checkId: PermissionState}`), `history.json` (`{scans: ScanRecord[]}`, capped at 100 entries, managed in `history.rs`), `background.json` (`{enabled, frequency}`, the opt-in background-scan preference, managed in `background.rs`).

### Remediation actions (`src-tauri/src/remediation.rs`)
Two Tauri commands, both requiring an explicit per-action confirmation on the frontend before they're called (never invoked automatically): `run_direct_fix(action_id, params)` changes system state itself, but only for a small hard-coded allowlist of safe/reversible/non-destructive actions (`firewall_enable_profile`, `persistence_delete_run_value`, `rdp_disable`); `open_settings_deep_link(uri)` just opens a Windows Settings/Control Panel URI via the opener plugin and touches nothing. Both return a `RemediationOutcome { success, message }` so failure (e.g. insufficient privileges) is always reported back, never silent. See `DECISIONS.md` for the full safety model and the per-check direct-fix/deep-link/informational-only classification.

### Report export (`src-tauri/src/export.rs` + `src-tauri/src/pdf.rs`)
`export::prepare_report_data(record)` is the single shared, pure data-prep step (category-grouped, executive-summary counts) both exporters build on — never duplicate report-content logic between them. `render_report_html` produces the printable HTML report (temp file + `opener::open_path`, browser "Print to PDF" still available); `pdf::render_report_pdf` produces real PDF bytes via `printpdf` (built-in Helvetica fonts, no bundled font asset — see that module's doc comment for why `printpdf` was chosen over `genpdf`), written directly to a user-chosen path via `tauri-plugin-dialog`, same pattern as JSON export.

## Adding a new check-agent

1. New file in `src-tauri/src/checks/`, implementing `SecurityCheck`, with pure parse/eval functions separate from `run()`.
2. Register it in `all_checks()` in `checks/mod.rs`.
3. If it needs a new `PermissionKind` variant, add it in `checks/mod.rs` and give it a clear `permission_description()`.
4. Add unit tests against sample command output for the pure functions.
5. No frontend change needed for a new check to appear — the catalog and permission list are driven dynamically from `commands::get_checks_catalog`.
