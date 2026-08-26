<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2e1d,50:1a5c3a,100:3ddc84&height=220&section=header&text=NetGuard&fontSize=70&fontColor=e8fff0&animation=fadeIn&fontAlignY=38&desc=Diagnose%20your%20network.%20Diagnose%20your%20laptop.%20Not%20an%20antivirus.&descAlignY=58&descSize=18" width="100%" alt="NetGuard banner" />

<a href="https://github.com/DevelopingGod/CyberTool">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&duration=2600&pause=900&color=3DDC84&center=true&vCenter=true&width=680&lines=Is+the+network+I'm+on+safe%3F;Has+my+laptop+been+tampered+with%3F;What+should+I+fix+-+and+can+you+fix+it+for+me%3F;Rule-based.+Local-only.+No+telemetry.+No+LLM." alt="Typing SVG" />
</a>

<br/>

<img src="https://img.shields.io/badge/platform-Windows-3DDC84?style=for-the-badge&logo=windows11&logoColor=white" />
<img src="https://img.shields.io/badge/Tauri-2.x-1a5c3a?style=for-the-badge&logo=tauri&logoColor=3DDC84" />
<img src="https://img.shields.io/badge/Rust-backend-0f2e1d?style=for-the-badge&logo=rust&logoColor=3DDC84" />
<img src="https://img.shields.io/badge/React-TypeScript-1a5c3a?style=for-the-badge&logo=react&logoColor=3DDC84" />
<img src="https://img.shields.io/badge/license-MIT-3DDC84?style=for-the-badge" />

</div>

<br/>

## What is this

**NetGuard** is a Windows desktop app that answers three questions with real, local, explainable checks — not guesses and not a network call to some vendor's cloud:

1. **Is the network I'm connected to safe?**
2. **Has my laptop been hijacked or tampered with?**
3. **Are there security misconfigurations I should fix?**

> **This is explicitly not an antivirus.** NetGuard doesn't scan files for malware signatures and doesn't claim to replace Windows Defender. It's a diagnostic and triage tool — it inspects network configuration, running processes, persistence mechanisms, and system security posture, then tells you exactly what it found, exactly where it looked, and exactly how to fix it.

Every check is a small, independent, rule-based Rust module — "agentic" in the sense of many focused specialists working together, deliberately **without** an LLM in the loop. Nothing here is a black box: every result names the precise registry key, command, or API it read.

<br/>

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=transparent&color=3DDC84&height=2&section=header" width="100%" />
</div>

## Table of contents

<details>
<summary><strong>Click to expand</strong></summary>

- [What is this](#what-is-this)
- [Feature tour](#feature-tour)
- [The 17 check-agents](#the-17-check-agents)
- [The permission model](#the-permission-model-the-part-we-care-about-most)
- [Getting started](#getting-started)
- [Architecture at a glance](#architecture-at-a-glance)
- [Tech stack](#tech-stack)
- [Roadmap](#roadmap)
- [Developer](#developer)
- [Disclaimer](#disclaimer)
- [License](#license)

</details>

<br/>

## Feature tour

<table>
<tr>
<td width="50%" valign="top">

### Dashboard
- Time-of-day greeting, your Windows username
- **Full scan** or pick specific categories (Network / Process / Persistence / System)
- Live per-check progress as the scan runs — cards populate as each check finishes, not after a long wait
- Overall **Safe / Caution / At Risk** banner, honestly labeled "based on N of M checks" if anything was skipped

### Consent, every time
- Every privileged check asks before it reads anything, if you've set it to "ask every time"
- Turn a permission off and the very next scan re-blocks it — no cached "already said yes"

</td>
<td width="50%" valign="top">

### Fix it, don't just flag it
- Safe, reversible fixes (enable a disabled firewall profile, remove one flagged startup entry, disable RDP) apply in one click behind an explicit confirmation
- Anything riskier deep-links straight to the right Windows settings page instead of touching it for you

### Reports that explain themselves
- One-click **PDF** and JSON export, plus a print-ready HTML report
- Executive summary, grouped by category, plain-language remediation next to every finding

</td>
</tr>
</table>

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=transparent&color=3DDC84&height=2&section=header" width="100%" />
</div>

## The 17 check-agents

Each one is its own file, its own unit tests, and names the exact data source it reads.

<table>
<tr><th align="left">Category</th><th align="left">Check</th><th align="left">Data source</th></tr>

<tr><td rowspan="5"><strong>Network</strong></td><td>Wi-Fi security posture</td><td><code>netsh wlan show interfaces</code></td></tr>
<tr><td>DNS / gateway / hosts integrity</td><td><code>ipconfig</code>, hosts file, resolver allowlist</td></tr>
<tr><td>ARP anomaly heuristic</td><td><code>arp -a</code></td></tr>
<tr><td>Open listening ports</td><td><code>netstat -ano</code></td></tr>
<tr><td>Unusual outbound connections</td><td><code>netstat -ano</code></td></tr>

<tr><td rowspan="3"><strong>Process</strong></td><td>Process baseline diff <em>(new-since-last-scan aware)</em></td><td><code>sysinfo</code> process table</td></tr>
<tr><td>Known remote-access-tool signatures</td><td>Process &amp; service name matching</td></tr>
<tr><td>Browser proxy tampering</td><td><code>HKCU\...\Internet Settings</code></td></tr>

<tr><td rowspan="2"><strong>Persistence</strong></td><td>Startup entries <em>(new-since-last-scan aware)</em></td><td><code>HKCU</code>/<code>HKLM Run(Once)</code></td></tr>
<tr><td>Scheduled tasks</td><td><code>schtasks /query /fo CSV /v</code></td></tr>

<tr><td rowspan="7"><strong>System</strong></td><td>Firewall status</td><td><code>netsh advfirewall</code></td></tr>
<tr><td>Defender status</td><td>PowerShell <code>Get-MpComputerStatus</code></td></tr>
<tr><td>Driver anomalies</td><td><code>driverquery</code> + real <code>WinVerifyTrust</code> signature check</td></tr>
<tr><td>BitLocker / disk encryption</td><td><code>manage-bde -status</code></td></tr>
<tr><td>Memory integrity (HVCI)</td><td><code>Win32_DeviceGuard</code> (WMI/CIM)</td></tr>
<tr><td>RDP exposure</td><td>Registry + firewall rule state</td></tr>
<tr><td>LSASS / Credential Guard</td><td>Registry + <code>Win32_DeviceGuard</code></td></tr>
<tr><td colspan="2" align="center"><em>...and Windows Update currency, in Process/System depending on how you slice it.</em></td></tr>
</table>

<br/>

## The permission model (the part we care about most)

Three states, per check, persisted locally: **Allowed**, **Denied**, **Ask every time** *(default)*.

```
AskEveryTime  ──▶  prompt shown, every single scan, no exceptions
Denied        ──▶  check skipped, always shown as "permission needed" — never silently omitted
Allowed       ──▶  runs without prompting
```

Flip a permission off in Settings and the **very next scan** re-blocks that check — there is no in-memory cache anywhere that can go stale. Background scans (opt-in, off by default) reuse the exact same code path with zero pre-approved checks, so they can *only* ever run checks already set to `Allowed` — there is no second permission path for them to slip through.

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=transparent&color=3DDC84&height=2&section=header" width="100%" />
</div>

## Getting started

### Prerequisites
- Windows 10/11
- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) (stable, MSVC toolchain)
- Visual Studio Build Tools — "Desktop development with C++" workload
- Windows 11's **Smart App Control**, if enabled, will block freshly-compiled build-script binaries. Disable it if you hit a linker error mentioning "Application Control policy" (Settings → Privacy & security → Windows Security → App & browser control).

### Run it

```bash
git clone https://github.com/DevelopingGod/CyberTool.git
cd CyberTool
npm install
npm run build          # frontend typecheck + build
cd src-tauri && cargo check && cargo test && cd ..
npm run tauri build    # produces the installer under src-tauri/target/release/bundle/nsis/
```

> Don't run `npm run tauri dev` in a headless/agent context — it opens a blocking native window.

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=transparent&color=3DDC84&height=2&section=header" width="100%" />
</div>

## Architecture at a glance

```
                      React / TypeScript (src/)
                             │  Tauri invoke() / listen()
                             ▼
                    Rust backend (src-tauri/src/)
        ┌──────────────┬──────────────┬───────────────┐
        │  checks/*.rs │ permissions  │  scan.rs       │
        │  17 agents,  │ .rs          │  orchestrator, │
        │  one trait   │ Allowed/     │  events,       │
        │              │ Denied/Ask   │  rollup        │
        └──────────────┴──────────────┴───────────────┘
                             │
                 local JSON only (no SQLite, no network sync)
                 permissions.json · history.json · background.json
```

Every check implements one shared `SecurityCheck` trait; pure parsing/evaluation logic is unit-tested separately from the OS-interaction shell. Full details of every non-obvious judgment call, with the *why*, live in [`DECISIONS.md`](./DECISIONS.md).

## Tech stack

| Layer | Choice |
|---|---|
| Shell / packaging | Tauri 2 → NSIS Windows installer |
| Backend | Rust — `sysinfo`, `winreg`, `windows`, `printpdf`, `tokio` |
| Frontend | React 19 + TypeScript + Vite |
| Styling | CSS Modules + a single design-token file (light/dark, green-gradient theme) |
| Icons | `lucide-react` — zero emoji, anywhere |
| Persistence | Local JSON via `tauri-plugin-store` |

## Roadmap

- [x] 17 rule-based check-agents across Network / Process / Persistence / System
- [x] Consent-first permission model with re-prompt-on-toggle
- [x] Scan-to-scan baseline diffing (new-since-last-scan escalation)
- [x] Real Authenticode driver signature verification
- [x] Opt-in background scanning + tray icon, consent-safe by construction
- [x] JSON, HTML, and native PDF report export
- [x] One-click safe remediation + deep-links for everything else
- [ ] Full service enumeration (`sc query`) as a persistence signal
- [ ] Code-signed installer
- [ ] Scan result diffing UI across more than the last snapshot

## Developer

**Sankalp Sandeep Indish**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-sankalp--indish-1a5c3a?style=for-the-badge&logo=linkedin&logoColor=3DDC84)](https://www.linkedin.com/in/sankalp-indish/)
[![GitHub](https://img.shields.io/badge/GitHub-DevelopingGod-0f2e1d?style=for-the-badge&logo=github&logoColor=3DDC84)](https://github.com/DevelopingGod/)

## Disclaimer

NetGuard is a diagnostic aid, not an antivirus and not a substitute for professional incident response. Every check runs entirely locally; the only outbound network activity is DNS resolution as part of the DNS/gateway integrity check itself. See the in-app **Privacy Policy** and **Terms** pages for the full, plain-language version.

## License

MIT — see [`LICENSE`](./LICENSE).

<br/>

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:3ddc84,100:0f2e1d&height=100&section=footer" width="100%" />
</div>
