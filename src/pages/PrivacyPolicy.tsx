import { Lock } from "lucide-react";
import styles from "./LegalPage.module.css";

export function PrivacyPolicy() {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <span className={styles.headerIcon}>
          <Lock size={20} aria-hidden="true" />
        </span>
        <div>
          <h1 className={styles.title}>Privacy Policy</h1>
          <p className={styles.subtitle}>Plain-language disclosure for an indie tool - not reviewed legal counsel text.</p>
        </div>
      </header>

      <section className={styles.section}>
        <h2>Everything is local-only</h2>
        <p>
          NetGuard runs entirely on your device. There is no account, no sign-in, and no server this app talks to.
          Scan results, permission preferences, and settings are stored only in local JSON files under your Windows
          user profile's app data directory (managed by <code>tauri-plugin-store</code>), and are never uploaded,
          synced, or transmitted anywhere.
        </p>
      </section>

      <section className={styles.section}>
        <h2>No telemetry</h2>
        <p>
          NetGuard does not collect analytics, does not phone home, and does not report usage statistics, crash
          reports, or diagnostics to the developer or any third party.
        </p>
      </section>

      <section className={styles.section}>
        <h2>The only network activity NetGuard performs</h2>
        <p>
          NetGuard's checks read local OS state (registry, process list, firewall/Defender status, network
          configuration) via built-in Windows tools and APIs. The one exception involving the network is the DNS/
          gateway check, which resolves DNS as part of verifying your configured DNS servers and default gateway
          behave as expected. NetGuard does not otherwise make outbound network requests, does not download anything,
          and does not check for updates automatically.
        </p>
      </section>

      <section className={styles.section}>
        <h2>What's stored, and where</h2>
        <ul>
          <li>
            <strong>permissions.json</strong> - which checks you've allowed, denied, or set to "ask every time."
          </li>
          <li>
            <strong>history.json</strong> - your last 100 scan results (findings, severities, verdicts), stored
            locally, capped automatically.
          </li>
          <li>
            <strong>background.json</strong> - your background-scan enable/frequency preference, if you use that
            feature.
          </li>
        </ul>
        <p>
          All three live under the Tauri app data directory for this app on your device. Clearing scan history from
          Settings deletes the stored records immediately; uninstalling the app removes these files entirely.
        </p>
      </section>

      <section className={styles.section}>
        <h2>Exported reports</h2>
        <p>
          When you export a scan as JSON, PDF, or an HTML report, that file is written only to the location you
          choose via the save dialog. NetGuard does not upload exported reports anywhere - what you do with the file
          afterward (e.g. sharing it) is up to you.
        </p>
      </section>

      <section className={styles.section}>
        <h2>Not a substitute for professional judgment</h2>
        <p>
          NetGuard is a diagnostic aid, not an antivirus and not a replacement for professional incident response. If
          you believe your device is actively compromised, disconnect it from the network and seek professional
          help.
        </p>
      </section>
    </div>
  );
}
