# DECISIONS.md

Non-obvious judgment calls made while building NetGuard, per the build prompt's
instruction to document anything underspecified and keep going rather than
stopping to ask.

## Architecture

- **Styling approach**: CSS Modules + a single `src/theme/tokens.css` custom-property
  file, not Tailwind. All colors/gradients/spacing/radii/severity tokens live in
  `tokens.css`; components only ever reference `var(--ng-*)`. Chosen over Tailwind
  because it keeps the token system in one obviously-inspectable file rather than a
  Tailwind config plus utility classes scattered through JSX.
- **No routing library**: navigation is plain `useState` in `App.tsx` (`dashboard` /
  `settings` / `history-detail`). Three views with no deep-linking need didn't
  justify pulling in `react-router`.
- **Frontend/Rust type mirroring**: `src/types.ts` hand-mirrors the Rust
  `serde`-tagged types (`CheckOutcome`, `CheckResult`, etc.) rather than generating
  TS bindings from Rust. A codegen step (e.g. `ts-rs`/`specta`) would be the more
  robust long-term choice; deferred for v1 to avoid an extra build dependency. The
  serde attributes (`rename_all = "camelCase"`, `tag`/`content`) were chosen
  specifically to make this hand-mirroring straightforward and stable.
- **Persistence**: `tauri-plugin-store` (JSON files under the app data dir) rather
  than `tauri-plugin-sql`/SQLite, per the build prompt's explicit "or a small local
  SQLite file" alternative. Three JSON documents: `permissions.json`
  (`{ checkId: PermissionState }`), `history.json` (`{ scans: ScanRecord[] }`,
  capped at 100 entries). All local, no network sync.

## Permission & consent state machine (the part most likely to be gotten wrong)

- The backend `run_scan` command takes `approvedOnce: string[]` - the set of check
  IDs the **frontend** already obtained a one-time approval for, via the
  `ConsentDialog`, before calling `run_scan`. The backend never prompts on its own
  and never persists a "the user said yes once" flag. Concretely:
  - `Allowed` -> runs, no prompt.
  - `Denied` -> skipped, `PermissionDenied` outcome, always.
  - `AskEveryTime` -> skipped **unless** its id is in `approvedOnce` for this
    specific call. There is no code path where `AskEveryTime` behaves like
    `Allowed` on a later scan; every scan re-derives the check's state from the
    store and re-requires an explicit approval in `approvedOnce`.
- This means toggling a permission in Settings takes effect immediately: the very
  next `run_scan` call reads the store fresh (`permissions::get_one`), no
  in-memory cache anywhere in the Rust process holds a stale decision.
- The dashboard's "Grant & run" button on a permission-needed card is implemented
  as: set the permission to `Allowed`, then re-run the *entire* scan (not just
  the one check). NetGuard has no per-check partial-rescan command; re-running the
  full catalog is simpler and still satisfies "grant and re-run" from the user's
  perspective, at the cost of also re-running checks that already succeeded.

## Rollup rule

- Overall severity = `max` over the severities of **executed** checks only.
  `PermissionDenied`/`Error` outcomes contribute no severity. If *no* checks
  executed at all (e.g. everything denied), the rollup is `Caution`, never `Ok`
  - "unknown" must not present as "safe" (see `scan::rollup`).
- The UI always states "based on N of M checks" in the status banner so a partial
  scan is never presented as if it were complete.

## Check-agent specifics

- **Wi-Fi**: SSID "looks public" heuristic is a fixed substring list (`free`,
  `guest`, `public`, default vendor names, etc.) - intentionally conservative and
  documented as a heuristic, not a definitive signal.
- **DNS/gateway/hosts**: "unexpected DNS server" = a public IP that is neither the
  default gateway nor on a short known-resolver allowlist (Google/Cloudflare/
  Quad9/OpenDNS). Hosts-file check only flags entries mapping a small curated list
  of high-value domains (search/OS-update/major banks/identity providers) to a
  non-loopback address - not exhaustive by design (v1 scope).
- **ARP anomaly**: two heuristics only, both cheap OS-cache reads: (1) the default
  gateway IP resolving to >1 MAC = `AtRisk`; (2) one MAC claiming an unusually
  large number of distinct IPs (threshold: 8) = `Caution`. No packet capture, per
  spec.
- **Firewall status**: Windows doesn't expose a simple single-command "your
  *currently active* profile" without extra network-category correlation, so this
  check reads all three profiles (Domain/Private/Public) via
  `netsh advfirewall show allprofiles state` and flags any disabled profile
  (`Caution` if some are off, `AtRisk` if all are off) rather than trying to infer
  which profile is "active."
- **Defender status**: read-only via PowerShell `Get-MpComputerStatus`. If the
  command fails to report `RealTimeProtectionEnabled` at all (e.g. because a
  third-party AV has taken over Defender's status API), the result is `Caution`
  ("could not determine"), not `Ok` - absence of a clear "protected" signal is
  never treated as safe.
- **Driver/certificate anomalies**: scoped down from full Authenticode signature
  verification (would require `WinVerifyTrust`/crypto API integration, a
  meaningfully larger v1 addition) to a lighter heuristic: flag drivers loaded
  from outside `System32\drivers`/`SysWOW64\drivers`/`System32`, via
  `driverquery /fo csv /v`. This limitation is stated in the check's own
  `permission_description()` and surfaced in the About section's spirit (this is
  a diagnostic tool, not exhaustive verification).
- **Process baseline / persistence**: "unfamiliar" is judged by two independent,
  narrow signals - executable path under a Temp directory, and a random-hex-looking
  filename (`^[0-9a-f]{8,}$` on the basename) - rather than a broad allow/deny
  list of "known good" software, which would either be far too large to maintain
  or produce constant false positives for ordinary third-party apps. Both signals
  present together = `AtRisk`; Temp path alone = `Caution`.
- **RAT signatures**: presence is always at most `Caution`, per the spec's explicit
  "presence isn't proof of compromise."

## Testing

- Every check module is unit-tested by separating **pure parsing/evaluation
  functions** (e.g. `parse_wifi_interfaces`, `evaluate`) from the **OS-interaction
  shell** (`run()`, which calls `sysutil::run_command`). Tests feed the parse/eval
  functions hand-written sample command output (`netsh`, `ipconfig`, `arp -a`,
  `netstat -ano`, `driverquery` CSV, etc.) rather than mocking a command-runner
  trait. This was chosen over a full `CommandRunner` trait + mock because the
  actual parsing/decision logic - the part with real bugs to catch - is what's
  under test either way, and it avoids adding a trait-object layer to every check
  purely for testability. 37 unit tests total across the 11 check modules.
- `ScanContext` (which wraps `sysinfo::System`) is used as-is (not mocked) in the
  handful of tests that call `evaluate()` with a real context, since those tests
  only exercise the pure evaluation logic against hand-built `ProcessInfo`/
  `NetstatEntry` fixtures, not the live process table.

## Packaging

- Bundle target restricted to `["nsis"]` (not `"all"`) since NSIS is the
  build prompt's suggested simpler default and this is a Windows-only app.
  `installMode: "currentUser"` avoids requiring admin elevation to install.
- Code signing intentionally left unconfigured (no `certificateThumbprint`), per
  the build prompt's explicit "don't block on obtaining one now."
- `identifier: "com.netguard.app"` and `productName: "NetGuard"` were already
  correct/set by the scaffold and build prompt respectively; verified rather than
  changed.

## Known limitations / not implemented in v1

- Scheduled-task and service enumeration for persistence is best-effort: scheduled
  tasks are included (`schtasks /query /fo CSV /v`), but Windows services are not
  separately enumerated - the registry Run/RunOnce keys plus scheduled tasks were
  judged sufficient signal for v1 without adding a third parsing surface
  (`sc query`) of comparable complexity.
- No automated `tauri build` (NSIS bundle) run was performed as part of this
  build - see the final report for why and what was verified instead.

## Round 2 additions (17 new checks/features: Parts A-E)

### Part A - six new check-agents

- **BitLocker**: uses `manage-bde -status`, not `Get-BitLockerVolume` (the spec's
  first suggestion). Live-tested on the dev machine: `Get-BitLockerVolume` threw
  `Access denied` (`HRESULT 0x80041003`) even though the session wasn't obviously
  unprivileged, while `manage-bde -status` at least produces a clear "administrator
  rights required" error that the check can surface honestly. If `manage-bde`
  itself can't read status (no admin rights), the result is `Caution`
  ("could not determine, likely needs admin") - never silently `Ok`.
- **Memory integrity (HVCI)**: `SecurityServicesConfigured`/`Running` service code
  `2` = HVCI, confirmed live on the dev machine (`{2}`/`{2}`). "Configured but not
  running" and "not configured at all" are both `Caution` - the spec only asked for
  the former, but "not available at all" is at least as concerning and treating it
  as `Ok` would violate the project's "unknown/absent is never safe" rule.
- **RDP exposure**: `netsh advfirewall firewall show rule name="Remote Desktop*"`
  (the spec's suggested exact-name wildcard) returned zero matches in live testing
  even with rules present under other query forms - `netsh`'s `name=` doesn't do
  substring wildcarding. Switched to `name=all` plus a client-side substring match
  on "Remote Desktop" in each rule's name, mirroring the existing firewall-profile
  check's own documented heuristic style.
- **Proxy tampering**: scoped to `HKCU\...\Internet Settings` (`ProxyEnable`,
  `ProxyServer`, `AutoConfigURL`) only - no per-browser extension or Chrome/Edge
  policy auditing. Matches the driver check's existing precedent of documenting a
  narrowed v1 scope rather than silently under-covering it. A loopback proxy
  (127.0.0.1/localhost, e.g. a local dev proxy or ad-blocker) is treated as `Ok`;
  any other proxy host is `AtRisk`; a PAC/auto-config URL is `Caution` (weaker
  signal - legitimate corporate networks commonly use PAC).
- **Credential/LSASS protection**: `RunAsPPL` and Credential Guard are queried
  independently (two separate reads, including a second small PowerShell call
  duplicating part of the memory-integrity check's query) rather than sharing
  state through `ScanContext` - each check-agent stays self-contained per the
  existing architecture, and the extra process spawn is cheap next to the value of
  not coupling two otherwise-independent checks.
- **Windows Update currency**: uses `Get-HotFix | Sort-Object InstalledOn
  -Descending | Select -First 1`, not the `LastSuccessTime` registry path the spec
  offered as the primary option. Live-verified: `Get-HotFix` reliably returned a
  real, recent date on the dev machine, while the registry path's presence/shape
  varies by Update Agent version and isn't guaranteed. Thresholds: `Caution` at
  >30 days since the last hotfix, `AtRisk` at >90 days *or* if the date can't be
  parsed at all (undeterminable is treated as the worse outcome, not `Ok`).

### Part B - driver signature verification & baseline diffing

- **Driver signatures (`WinVerifyTrust`)**: any non-zero return code is treated
  uniformly as "invalid/unsigned" (`SignatureStatus::Untrusted`) rather than
  decoded into the full `TRUST_E_*`/`CERT_E_*` taxonomy (dozens of codes,
  including several that mean "policy provider unavailable" rather than "bad
  signature"). This is a deliberate v1 scoping choice matching the spec's literal
  ask ("flag unsigned/invalid-signature drivers") - a diagnostic tool, not an
  exhaustive PKI validator. Verification is skipped (`Unknown`, not flagged either
  way) for driver paths `driverquery` reports as a bare filename with no
  directory, since there's nothing to hand `WinVerifyTrust`. Revocation checking
  is explicitly turned off (`WTD_REVOKE_NONE`) so a scan's result doesn't depend
  on live network/CRL reachability. `AtRisk` (bad signature) now outranks the
  original `Caution` (unusual location) heuristic, which is kept as-is as a
  secondary signal per the spec.
- **Baseline diffing shape**: `CheckResult` gained a `rawKeys: string[]` field
  (`#[serde(default)]` for backward-compat with older `history.json` entries) -
  a flat list of stable per-entry identifiers, *not* the full previous findings.
  `ScanContext` gained `previous_raw_keys: HashMap<String, Vec<String>>` (id ->
  that check's previous `raw_keys`), built in `scan.rs` from `history::latest()`
  *before* constructing `ScanContext`, specifically so `checks::mod` never has to
  depend on `history` (which itself depends on `checks::CheckOutcome` - a cycle).
  Persistence's key is `source|name|command`; process baseline's is
  `name|exe_path` (deliberately excluding PID, which is reused constantly across
  process lifetimes and would make everything look "new" every scan). A first-ever
  scan has an empty `previous_raw_keys` map, so both checks behave exactly as
  before - no regression. A flagged entry whose key wasn't present last scan
  escalates one severity step (persistence: Caution -> AtRisk; process baseline:
  the same) and is labeled "new since last scan" in its finding.

### Part C - background scanning, tray, notifications

- **Consent safety mechanism**: a background scan calls the *exact same*
  `scan::run_scan(app, &[])` used by manual scans, with an empty `approved_once`.
  No new/parallel permission-checking code was written. This was a deliberate
  choice specifically because it's the highest-risk feature in this round -
  reusing the already-tested function means there is only one place in the
  codebase that decides whether a check runs, and it's unmodified by this work.
  `Allowed` runs; `Denied` and `AskEveryTime` (the latter because its id is never
  in an empty list) are both skipped with the existing `PermissionDenied` outcome.
- **Preference storage**: a fourth `tauri-plugin-store` file, `background.json`
  (`{ enabled: bool, frequency: ScanFrequency }`), mirroring
  `permissions.json`/`history.json`'s pattern rather than folding it into either
  existing file - it's a distinct, small piece of state with its own read/write
  pattern (polled by the background task) and keeping it separate avoids growing
  either existing store's schema.
- **Scheduling mechanism**: a single long-lived `tauri::async_runtime::spawn`ed
  loop that wakes every 15 minutes, re-reads the preference from disk fresh each
  tick (never cached, matching the permissions module's "no stale in-memory
  decision" philosophy), and runs a scan once `frequency.to_duration()` has
  elapsed since the last run. Chosen over one `tokio::interval` sized to the
  configured frequency because that would require tearing down and rebuilding the
  interval task whenever the user changes the frequency in Settings; the 15-minute
  poll is cheap and reacts to preference/frequency changes without any such
  bookkeeping.
- **Close-to-tray, reverted**: the main window's close ("X") button originally
  hid the window instead of exiting (`on_window_event` + `prevent_close`), so
  background scanning could keep running after close. This was explicitly
  reversed on user request: the "X" button now calls `app_handle.exit(0)` and
  fully terminates the process, including the tray icon and background scan
  task. Trust that closing the window means the app is completely gone was
  judged more important than background scanning surviving a close - the
  background-scan preference and tray icon are now only meaningful while the
  app is actually open; there is no longer a way to scan while fully closed.
- **Tray + notifications**: `tauri::tray` (`tray-icon` Cargo feature) with an
  Open/Run scan now/Quit menu, and `tauri-plugin-notification` for the
  scan-complete toast (severity + "N of M checks" in the body, matching the
  in-app status banner's own language). A frontend event
  (`netguard://background-scan-complete`) is emitted alongside the OS toast so an
  already-open window shows an in-app toast too, without waiting on an OS
  notification click.

### Part D - report export

- **JSON export**: the full `ScanRecord` is serialized as-is (it's already fully
  `Serialize`) to a path obtained via `tauri-plugin-dialog`'s save dialog on the
  frontend; the backend command just takes the already-chosen path and writes to
  it, keeping file-picker UI entirely out of Rust.
- **Printable HTML report over a bundled PDF crate**: the report is rendered as a
  self-contained HTML string (inline CSS, reusing the same severity colors as
  `tokens.css`), written to a temp file, and opened via the already-present
  `tauri-plugin-opener`. Chosen over adding a PDF-generation crate (e.g.
  `printpdf`/`wkhtmltopdf` bindings) specifically to keep the dependency
  footprint - and attack surface - small; the browser's native "Print to PDF" is a
  reliable, zero-extra-dependency path to a shareable PDF and needs no NetGuard
  code to generate PDF bytes at all.

### Part E - UX polish (partial - see final report for what was cut and why)

- Added: a local toast/snackbar system (`state/ToastContext.tsx`, no external
  library), used for scan-complete, background-scan-complete (including the
  cross-window handoff from Part C), and export success/failure; an animated
  toggle switch for the new background-scan enable control (thumb slide + color
  transition, `--ng-duration-mid`/`--ng-ease` tokens only); hover/press
  micro-interactions on the new export/run-now buttons. All new animations are
  guarded by `prefers-reduced-motion: reduce`, matching the existing pattern.
- Not done in this round (deprioritized per the task's explicit cut-from-the-
  bottom ordering, since Parts A-D were higher priority): a skeleton loading
  state for not-yet-run cards during a scan, a smoother height-animated
  card expand/collapse if the existing one wasn't already fluid, and a dedicated
  pass on narrow-width (~800px/~500px) grid breakpoints. The existing permission
  toggle in Settings (Allowed/Ask/Denied) was left as its existing segmented
  control rather than converted to a switch, since it's a three-state control, not
  a boolean.

## Round 3 additions (items 1-11: check-detail page, category scans, real PDF,
## report quality, dev/legal pages, scrollbar, greeting, direct remediation)

### 1 - Dedicated check-detail page

- `CheckCard` no longer expands inline. It's now a compact, clickable card
  (whole card + an explicit "View details" affordance) that calls
  `onOpenDetail(outcome)`. `App.tsx` holds the selected `CheckOutcome` in
  state and renders a new `check-detail` view (`pages/CheckDetail.tsx`)
  instead of adding a router - matching the existing "no routing library"
  decision. The full `CheckOutcome` is passed through React state rather
  than re-fetched by id from the backend, since both `Dashboard` and
  `HistoryDetail` already hold the outcomes they render in memory - adding a
  `get_check_result(scanId, checkId)` command would be pure duplication.
- "Back" needs to return to wherever the card was opened from (the live
  dashboard scan, or a specific history record), so `App.tsx` tracks a small
  `detailOrigin` discriminated union (`{kind:"dashboard"}` vs
  `{kind:"history", scanId}`) rather than always returning to the dashboard.

### 8 - Category-scoped scanning

- Backend: `run_scan` gained `categories: Option<&[CheckCategory]>`
  (`None`/empty = full scan, matching the existing "empty means default"
  convention already used for `approved_once`). Category filtering is
  applied once, before the permission loop - everything after that
  (permission state machine, events, rollup, history) is byte-for-byte the
  same code path as a full scan, so category scoping cannot accidentally
  change consent behavior. `total_count`/`executed_count` in the resulting
  `ScanRecord` reflect the filtered set's size, not the full catalog's - "N
  of M checks" in the UI still means what it says for a category-scoped run.
- Frontend: the Dashboard's category pills feed a plain `CheckCategory[]`
  into `startScan(categories)`; `Full Scan` calls `startScan()` with no
  argument (empty array), reusing the same function rather than two
  separate scan-kick-off code paths. The permission-consent-queue logic is
  unchanged except that it's now computed against the category-filtered
  catalog subset, so a category scan never prompts for a check outside the
  selected categories.

### 9 - Direct in-app remediation: the safety model

This is the highest-stakes addition in this round, so the model is spelled
out explicitly:

- A `Finding` (not the whole `CheckResult`) can carry an optional
  `action: RemediationAction`. Per-finding rather than per-check because a
  check like Persistence can have several findings, each pointing at a
  different fixable target (one startup entry vs. another) - a check-level
  action couldn't express "fix this specific one."
- `RemediationAction` is one of exactly two kinds, both requiring an
  explicit confirmation dialog (`RemediationDialog`, styled like
  `ConsentDialog`) on every single invocation - there is no "apply all" /
  silent-apply path anywhere in the frontend or backend:
  - `DirectFix { actionId, label, params }` - NetGuard performs the change
    itself, via `remediation::run_direct_fix`. Only three actions are
    whitelisted, hard-coded by `action_id` in `remediation.rs` (not driven
    by arbitrary frontend-supplied commands):
    - `firewall_enable_profile` (`netsh advfirewall set <profile>profile
      state on`) - reversible, no more privilege than the Firewall Status
      check itself already needed to read profile state.
    - `persistence_delete_run_value` - deletes exactly one named registry
      value from exactly one of the two paths `persistence.rs` itself reads
      (`ALLOWED_RUN_KEY_PATHS`, checked against an allowlist before any
      registry write) - never the whole key, never an arbitrary path.
      Scheduled-task entries are deliberately left informational-only in
      this round (no `schtasks /delete` action) to keep the allowlist small
      and auditable; see "not done" below.
    - `rdp_disable` (`fDenyTSConnections = 1` under
      `HKLM\...\Terminal Server`) - reversible (Settings > System > Remote
      Desktop re-enables it), requires admin since it's an HKLM write; a
      non-elevated NetGuard fails this cleanly rather than silently no-op-ing.
  - `DeepLink { uri, label }` - NetGuard touches nothing; it opens a Windows
    Settings page (`ms-settings:...`) or the `windowsdefender:` protocol via
    `remediation::open_settings_deep_link` (`tauri-plugin-opener`). Used for
    BitLocker, Defender, Memory Integrity/Core Isolation, Windows Update,
    System Proxy, and Credential/LSASS Protection - all either require
    elevation/GUI interaction NetGuard shouldn't attempt to script, or are
    too consequential (BitLocker, Windows Update) to automate.
  - Both command handlers return `RemediationOutcome { success, message }`,
    surfaced as a toast - a failed direct fix (e.g. "insufficient
    privileges") is always reported, never swallowed.
- **Per-check classification** (the "document per-check" requirement):
  - **Direct-fix**: Windows Firewall Status (per disabled profile), Startup
    & Persistence Entries (per registry Run/RunOnce finding only, not
    scheduled tasks), Remote Desktop Exposure (disable RDP).
  - **Deep-link**: Disk Encryption/BitLocker, Windows Defender Status,
    Memory Integrity (HVCI), Credential & LSASS Protection, System Proxy
    Configuration, Windows Update Currency.
  - **Informational-only** (no action attached - remediation text only, per
    the check's existing `remediation` string): Wi-Fi Security, DNS/Gateway,
    ARP Anomaly, Open Ports, Outbound Connections, Process Baseline, RAT
    Signatures, Driver Anomalies. These either have no single safe automated
    fix (killing a flagged process/connection is not reversible or safe to
    automate blindly), or the "fix" is inherently a manual investigation
    step (recognize/don't recognize this driver or connection).
- **Not done in this round**: a direct-fix action for scheduled-task
  persistence entries (`schtasks /delete`) - deferred to keep the v1
  allowlist small; a "kill process" direct-fix for RAT-signature/process
  findings - deliberately *not* added, since killing a process is a much
  higher-blast-radius action than removing a startup entry or toggling a
  setting, and the spec's own examples (firewall, startup entry, RDP) didn't
  include it.

### 4 - Real PDF export

- `printpdf` was chosen over `genpdf` (the higher-level layout crate the
  task suggested as the easier option) specifically because `genpdf`
  requires embedding an actual `.ttf` font file, and this project ships no
  font assets - it would mean either bundling a font (extra binary size,
  license considerations) or reaching for one on disk at runtime (fragile,
  Windows-Fonts-folder-dependent). `printpdf` ships the 14 standard PDF
  fonts (Helvetica/Helvetica-Bold used here) with no font file needed at
  all, at the cost of doing text wrapping/pagination by hand
  (`pdf::wrap_text`, a pure function, unit-tested) instead of via a layout
  engine. `printpdf` resolved to `0.7.0` from the `"0.7"` version constraint.
- Both `export::render_report_html` and `pdf::render_report_pdf` are built
  on the same `export::prepare_report_data(record)` - a pure, no-I/O
  function that groups outcomes by category (Network/Process/Persistence/
  System, in that fixed order) and computes the executive-summary severity
  counts once. This was the explicit ask ("reuse a shared data-preparation
  step... rather than duplicating report-content logic") and also means the
  two report formats can never say different things about the same scan.

### 2/3 - Remediation text and report content review

- Auditing all ~17 checks' `remediation` strings found them already fairly
  specific (exact Settings paths, exact `netsh`/PowerShell commands, e.g.
  "Open Windows Security > Virus & threat protection...", "Open Control
  Panel > BitLocker Drive Encryption...") from earlier rounds - this round's
  changes were smaller than a full rewrite: tightened a couple of
  command-failure fallback messages, and (more substantively) made
  Persistence's remediation genuinely per-finding by attaching a specific
  `DirectFix` action to each flagged registry entry rather than only a
  single generic "review and remove" string for the whole check.
- The HTML report (`export.rs`) was restructured per the ask: an executive
  summary (overall result, N of M checks, OK/Caution/At Risk/Skipped
  counts, a plain-language explanation of what the overall severity means)
  now sits above category-grouped sections, each check rendered as a
  focused card with verdict, findings, a visually prominent remediation
  callout, and its data source - versus the previous flat list of all
  checks in scan order with no grouping or summary.

### 5/6/7/10/11 - Developer page, scrollbar, greeting, legal pages

- **Developer page**: a new `developer` view (`pages/Developer.tsx`),
  reachable from the sidebar under a "Legal & About" group, replacing
  nothing in Settings - the existing Settings > About section was kept (it
  explains what the *app* is) and gained one button linking to the new page
  (which is about who *built* it - name, LinkedIn, GitHub). Links open via
  `openUrl` from `@tauri-apps/plugin-opener` called directly in the
  frontend (the one place `lib/api.ts`'s "only place that calls raw Tauri
  APIs" convention is deliberately broken, since it's a one-line fire-and-
  forget call with no typed response worth wrapping) - this required adding
  `opener:allow-open-url` to `capabilities/default.json` alongside the
  existing `opener:default`, since frontend-initiated plugin calls (unlike
  the backend's own `app.opener()` calls for report-opening) go through the
  ACL permission system.
- lucide-react (pinned at `^1.34.0` in this project) has no `Linkedin`/
  `Github` icons in its set; the Developer page uses `Globe` and `CodeXml`
  instead rather than pulling in a second icon library for two glyphs.
- **Scrollbar**: themed globally in `theme/global.css` via
  `::-webkit-scrollbar` (WebView2 is Chromium-based) plus the Firefox-style
  `scrollbar-color`/`scrollbar-width` properties for completeness, using
  `--ng-border-strong` (thumb) / `--ng-brand-400` (hover) - no per-component
  overrides needed since it's applied to `*`.
- **Greeting**: `commands::get_current_username` reads the `USERNAME`
  environment variable rather than shelling out to `whoami` via
  `sysutil::run_command` - Windows always sets `USERNAME` for an
  interactive session, so this avoids a process spawn and its associated
  failure modes for something this simple; falls back to the string
  "there" if unset/empty so the greeting degrades to "Good morning, there."
  rather than showing an error or blank.
- **Category scan selector button hierarchy**: "Full Scan" (the existing
  `ScanButton`, now parameterized with a `label` prop) sits next to a new
  plain "Run selected (N)" button that's disabled until at least one
  category pill is toggled on - deliberately *not* replacing "Start
  Diagnose" outright, since a full scan is still almost certainly the more
  common action and shouldn't be demoted to a secondary control.
- **Terms & Privacy Policy**: written to describe exactly what this round's
  code actually does (local-only JSON storage under the Tauri app data dir,
  no telemetry, the DNS check's DNS resolution as the sole network
  exception, explicit per-action confirmation for every remediation action)
  rather than generic boilerplate, and explicitly framed in their own
  subtitles as informal indie-tool disclosure, not reviewed legal counsel
  text, per the task's explicit instruction.

### Verification

- `cargo check`/`cargo test` inside `src-tauri`: 93 tests passing (90
  pre-existing + 3 new for category filtering in `scan.rs`, plus the new
  `pdf::wrap_text`/PDF-header and `remediation::` allowlist-rejection tests
  already counted in the 93). `npm run build` (`tsc && vite build`): zero
  TypeScript errors.
- Not independently verified: an actual `npm run tauri build` / running the
  packaged app (per the task's own instruction not to run slow/blocking
  build or dev commands in this session) - in particular, the `ms-settings:`
  deep links, the three direct-fix registry/netsh actions, and the PDF's
  visual layout have not been eyeballed in the real running app, only
  compiled and unit-tested. The `printpdf`-generated PDF's byte output was
  verified to start with a valid `%PDF` header and to render without error
  against a multi-finding sample record, but not opened in an actual PDF
  viewer.
