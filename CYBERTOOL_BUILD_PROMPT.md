# Build Prompt: NetGuard — Windows Network & System Security Diagnostic Tool

Paste everything below into a fresh Claude Code session, in an empty project directory, to build this app end-to-end.

---

## 1. What you are building

Build **NetGuard**, a desktop Windows application (the user can rename it later) that helps a non-expert user answer three questions in plain language, backed by real checks:

1. Is the network I'm currently connected to safe?
2. Has my laptop been hijacked or tampered with?
3. Are there security vulnerabilities / misconfigurations on my laptop I should fix?

**This is explicitly NOT an antivirus.** It does not scan files for malware signatures and does not claim to replace Windows Defender or any AV product. It is a diagnostic and triage tool: it inspects network configuration, running processes, persistence mechanisms, and system security posture, and reports findings with clear severity and remediation guidance. Frame all copy in the app around "diagnose / detect indicators / recommend action," never "we removed/cleaned a threat."

You are building this from scratch in an empty directory. Design the full architecture, UI, animations, and app icon yourself. If you hit a decision this document doesn't specify (exact registry keys, exact IPC message shape, exact severity thresholds, exact spacing values), make a reasonable, documented decision and keep going — do not stop to ask. Leave a short comment or a `DECISIONS.md` note for any non-obvious judgment call so it's easy to revisit later.

Treat this as a real product: no placeholder screens, no `TODO` stubs left in the final result, no dead scaffolding code.

---

## 2. Tech stack (mandatory)

- **Shell / packaging**: Tauri 2.x. It produces a small, fast, native-feeling Windows app and bundles to an installable `.exe`/`.msi` via its built-in NSIS/WiX bundler — no separate installer framework needed.
- **Backend (system & network checks)**: Rust, inside the Tauri backend. Rust is the right fit here because these checks talk to OS APIs, parse command output, and read the registry/process table — this should be memory-safe, typed, and fast, and it keeps all sensitive logic out of the webview.
- **Frontend**: React + TypeScript + Vite.
- **Styling**: Your choice of Tailwind CSS or CSS Modules — pick one and use it consistently. Either way, centralize the theme (colors, gradients, spacing, radii, severity tokens) in a single design-tokens source (e.g. `theme.css` custom properties or a `tokens.ts` file) that both the light and dark themes and the severity color system pull from. Do not scatter hex codes through components.
- **Icons**: Use a proper icon component library (Lucide React or Phosphor Icons are good fits — pick one). **No emoji anywhere in the UI**, including in copy, empty states, or notifications. Every visual indicator (status, severity, nav, settings) is an icon component or a custom SVG, never a Unicode emoji glyph.
- **State/persistence**: Tauri's `store` plugin (or a small local SQLite file via `tauri-plugin-sql`) for settings, permission preferences, and scan history. Everything stays local — this app must never phone home or transmit scan data anywhere.

---

## 3. Information architecture

Three primary views, reachable from a persistent left sidebar or top nav (your call on layout, but keep navigation always visible — no dead-end screens):

### 3.1 Dashboard (default view)
- Prominent **"Start Diagnose"** primary button. While a scan runs, replace/augment it with a live progress state showing which check-agent is currently running and a running count (e.g. "6 / 10 checks complete").
- An overall status banner at the top showing the aggregate result: **Safe (green) / Caution (orange) / At Risk (red)**, driven by the worst severity found among all check-agents (see §5.2 for the rollup rule).
- Below the banner, a **card grid** — one card per check-agent, populated as each check completes (don't make the user wait for the whole scan to see the first results). Each card shows:
  - Icon representing the check category (network, process, persistence, firewall, etc.)
  - Check name and one-line verdict
  - Severity color treatment (border/accent/badge — pick a consistent treatment and use it everywhere)
  - Expand/collapse for full detail: what was checked, what was found, and a concrete remediation suggestion when severity is orange or red
  - If the check was skipped because a required permission wasn't granted, show a distinct neutral "Permission needed" card state with a button to grant and re-run just that check.
- A "last scan" timestamp and a way to view scan history (can be a simple list/table view reachable from the dashboard, showing past scans with their overall rollup status and timestamp).

### 3.2 Settings & Preferences
This tab is a first-class part of the app, not an afterthought. It contains:
- **Appearance**: Light / Dark / System theme toggle.
- **Permissions & Privacy** (the core of this tab — see §4 for the full behavior spec): one row per check-agent, showing its name, a short description of what OS-level access it needs (e.g. "reads Wi-Fi profile security settings," "reads the process list," "reads Windows Firewall status"), and a toggle for whether the user has authorized it. Include a clear explanation of the "ask every time" behavior near the top of this section so the user understands why they keep seeing prompts.
- **Scan history management**: view/clear stored scan history.
- **About**: app version, and a plain-language reminder that this tool is a diagnostic aid, not an antivirus, and does not replace professional incident response for a confirmed compromise.

### 3.3 Scan result / history detail (secondary view)
A detail view for a single past scan, reusing the same card layout as the dashboard, so results are consistent whether live or historical.

---

## 4. Permission & consent system (mandatory behavior — implement exactly this)

Every check-agent declares the OS-level capability it needs (e.g. "read Wi-Fi profiles," "read process list," "read registry Run keys," "read firewall/Defender status," "read scheduled tasks," "resolve DNS / read hosts file," "list network connections"). None of these require full admin elevation for the Standard check set in §5 — confirm this as you implement each check, and if one genuinely needs elevation, surface that clearly in its permission description rather than silently requesting it.

Behavior, per check-agent, per scan run:
1. Look up the user's stored preference for that check-agent's permission. Valid states: `Allowed`, `Denied`, or `AskEveryTime` (this is the **default** for every permission on first install — nothing runs without an explicit decision the first time).
2. If `AskEveryTime`: show a consent dialog before running that specific check, every single scan, with the check's name, what it inspects, and why. The user can approve just this once, or open Settings to change the persisted preference.
3. If `Allowed`: run without prompting.
4. If `Denied`: skip the check and show the "Permission needed" card state described in §3.1 — never silently omit the card.
5. **Critical rule**: if the user changes a permission from `Allowed` back to `AskEveryTime` or `Denied` in Settings, the very next attempted run of that check must re-prompt (if `AskEveryTime`) or skip-with-visible-state (if `Denied`) — there is no cached "already answered" bypass. Toggling off must visibly take effect immediately, and toggling to `AskEveryTime` must never quietly behave like `Allowed`.
6. Persist preferences locally only, keyed by a stable check-agent ID, so preferences survive app restarts.

---

## 5. Check-agent architecture ("agentic, not LLM")

The user explicitly wants this to feel "smart"/agentic through **independent, rule-based logic modules**, not by wiring in an LLM. Do not add an LLM dependency for v1.

### 5.1 Shared interface
Define a shared Rust trait, something like:

```rust
trait SecurityCheck {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn category(&self) -> CheckCategory; // Network, Process, Persistence, System
    fn required_permission(&self) -> PermissionKind;
    fn run(&self, ctx: &ScanContext) -> CheckResult;
}
```

`CheckResult` should carry: severity (`Ok` / `Caution` / `AtRisk`), a short verdict string, structured findings (so the UI can render detail without re-parsing prose), and a remediation string when severity is above `Ok`. Each check-agent is its own module/file, independently unit-testable with mocked system input — do not let checks share hidden global state.

### 5.2 Overall rollup
Overall scan status = the single worst severity among all *executed* (non-skipped) checks. Skipped/permission-needed checks should influence the UI (visibly flagged) but should not silently count as "Ok" — make this explicit in how you compute and label the rollup, and be honest in the UI if the overall status is "based on N of M checks" when some were skipped.

### 5.3 Standard check-agent catalog (build all of these for v1)

**Network**
- Wi-Fi security posture — read the current connection's security type (Open / WEP / WPA/WPA2 / WPA3) and flag Open or WEP as `AtRisk`, WPA2 on an unfamiliar/public-sounding SSID as `Caution`.
- Default gateway & DNS integrity — check DNS servers in use aren't unexpected/suspicious, and that the hosts file has no unauthorized entries redirecting known domains.
- ARP table anomaly heuristic — look for duplicate/conflicting MAC-to-IP mappings for the gateway address as a lightweight MITM/ARP-spoofing indicator (no packet capture required — read the OS ARP cache).
- Open listening ports — enumerate locally listening ports/processes and flag ones that are unusual for a typical laptop (e.g. unexpected remote-access services).
- Unusual outbound connections — look at active outbound connections for endpoints associated with known remote-access tooling ports/patterns.

**Process & persistence**
- Running-process baseline diff — compare the current process list against a small built-in baseline/allowlist heuristic and flag unfamiliar processes with suspicious names/paths (e.g. running from Temp, unsigned).
- Known remote-access-tool signatures — check running processes and installed services against a small curated list of common legitimate-but-often-abused RAT/remote-access tool names, flagged as `Caution` (presence isn't proof of compromise, just worth reviewing).
- Startup/persistence entries — enumerate registry `Run`/`RunOnce` keys, scheduled tasks, and services, flagging entries pointing to unusual paths (Temp, AppData with random names, unsigned binaries).

**System posture**
- Firewall status — is Windows Firewall enabled for the active profile.
- Defender status — is real-time protection enabled (read-only status check, not a virus scan).
- Driver/certificate anomalies — flag unsigned or unusually-located drivers if this is feasible via available OS APIs; otherwise scope this down to a documented lighter check and note the limitation.

For each check, be explicit in code and in the UI copy about *what data source* it reads (a specific Windows API / command / registry path) so results are explainable, not a black box.

---

## 6. Visual design direction

- **Theme**: light-green, cybersecurity-toolkit feel — think shield/network/scan aesthetics, not generic SaaS blue/purple. Use layered green gradients (e.g. deep teal-green to a brighter accent green) for primary surfaces like the dashboard header/banner and primary button, with a clean neutral (off-white in light mode, deep charcoal in dark mode) as the base background so the green accents pop without overwhelming the card content.
- **Severity system**: define exactly three semantic colors — green (safe/ok), orange (caution), red (at risk) — as design tokens, each with light and dark variants that meet accessible contrast against their surfaces. Use them consistently for card borders/accents, the overall status banner, badges, and icons. Never rely on color alone — pair every severity indicator with an icon and a text label for accessibility.
- **Dark theme**: full parity with light theme, not an afterthought — same gradient language, adjusted for dark surfaces (darker greens, glow-style accents work well here).
- **Cards**: subtle elevation (shadow or soft border), rounded corners, a left accent bar or top accent in the severity color, generous spacing so the grid reads as calm and organized even when several checks flag issues at once.
- **Motion**: purposeful, not decorative. Card entrance animation as each check completes during a scan (stagger-in), a subtle pulsing/scanning animation on the "Start Diagnose" button or a progress indicator while a scan is running, and a smooth color/height transition when a card expands. Respect `prefers-reduced-motion`.
- **App icon**: design and generate an app icon (produce the actual asset — e.g. an SVG you render to the required `.ico`/`.png` sizes for Tauri's bundler) built around a shield-plus-network-node motif in the same green gradient language, legible at small taskbar sizes (test how it reads at 16x16/32x32 conceptually — keep the silhouette simple).
- **In-app iconography**: use the chosen icon library consistently for nav items, check categories, and states (success/caution/risk/permission-needed) — no mixing of styles/weights.

---

## 7. Packaging

- Configure `tauri.conf.json` with real app metadata: product name, version (start at `0.1.0`), identifier, and a placeholder publisher/author field.
- Configure the Windows bundle target (NSIS is the simpler default) so `npm run tauri build` (or equivalent) produces an installable `.exe`. Verify this actually builds and that the resulting installer installs and launches the app.
- Don't worry about code-signing infrastructure for v1 — leave the config ready for a signing certificate to be added later, but don't block on obtaining one now.

---

## 8. Code principles

- Idiomatic, typed Rust and TypeScript throughout — no `any` escape hatches in TS without a documented reason, no `unwrap()`-on-anything-that-can-fail in Rust (handle errors and surface them as a `CheckResult` failure state, don't crash the app because one check failed).
- One responsibility per module: each check-agent is its own file; UI components are small and composed, not monolithic screens.
- No dead code, no leftover scaffolding, no commented-out experiments in the final result.
- Secure-by-default implementation practices, since this is itself a security tool: no building shell commands via string concatenation from untrusted input, validate/parse all external command output defensively rather than assuming a fixed format, principle of least privilege (only request what each check actually needs), and no network calls of any kind from the app itself beyond what's strictly required for a check (e.g. DNS resolution as part of the DNS integrity check) — absolutely no telemetry or remote logging.
- Add unit tests for check-agent logic where the OS interaction can reasonably be mocked/abstracted behind a trait — don't skip tests just because "it talks to the OS."

---

## 9. Definition of done

- App builds and runs in dev mode (`tauri dev`) and packages to an installable Windows `.exe` (`tauri build`).
- All check-agents in §5.3 are implemented behind the shared trait and appear as cards on the dashboard.
- Settings tab has working theme toggle and per-check permission controls with the exact re-prompt/re-block behavior from §4 (this is the part most likely to be gotten wrong — double-check it before calling this done).
- Light and dark themes both fully styled, no unstyled/default-browser-looking elements.
- No emoji anywhere in the shipped UI.
- App icon asset generated and wired into the Tauri bundle.
- No `TODO`/placeholder screens remain.
