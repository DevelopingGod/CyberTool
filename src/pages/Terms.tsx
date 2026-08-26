import { FileText } from "lucide-react";
import styles from "./LegalPage.module.css";

export function Terms() {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <span className={styles.headerIcon}>
          <FileText size={20} aria-hidden="true" />
        </span>
        <div>
          <h1 className={styles.title}>Terms &amp; Conditions</h1>
          <p className={styles.subtitle}>Informal terms for an indie tool - not reviewed legal counsel text.</p>
        </div>
      </header>

      <section className={styles.section}>
        <h2>What NetGuard is</h2>
        <p>
          NetGuard is a rule-based network and system security diagnostic and triage tool for Windows. It inspects
          your network configuration, running processes, startup entries, firewall/Defender status, and related
          system settings, and reports findings with a severity rating and remediation guidance.
        </p>
      </section>

      <section className={styles.section}>
        <h2>What NetGuard is not</h2>
        <p>
          NetGuard is <strong>not an antivirus</strong> and does not claim to be one. It does not scan files for
          malware signatures, does not quarantine or remove anything on its own initiative, and is not a substitute
          for a dedicated security product or for professional incident response. It is also not a guarantee of
          security: a clean scan result means the checks that ran found nothing concerning, not that your device is
          free of every possible threat.
        </p>
      </section>

      <section className={styles.section}>
        <h2>Use at your own judgment</h2>
        <p>
          NetGuard is provided "as is," without warranty of any kind. Every finding is meant to be reviewed by a
          human before acting on it. Any in-app "Fix this" action requires your explicit, per-action confirmation
          before it changes anything on your device - NetGuard never applies a fix silently or automatically. Deep
          links open the relevant Windows settings page for you to review and act on yourself. You are responsible
          for the decisions you make based on NetGuard's output, including any remediation actions you confirm.
        </p>
      </section>

      <section className={styles.section}>
        <h2>No warranty, no liability</h2>
        <p>
          The developer makes no guarantee that NetGuard is free of bugs, that its checks are exhaustive, or that its
          heuristics won't produce false positives or false negatives. To the fullest extent permitted by law, the
          developer is not liable for any damage, data loss, or other harm arising from your use of NetGuard,
          including from a remediation action you confirmed.
        </p>
      </section>

      <section className={styles.section}>
        <h2>If you believe you're actively compromised</h2>
        <p>
          Disconnect the device from the network and seek professional incident response. NetGuard is a diagnostic
          aid, not an emergency response tool.
        </p>
      </section>

      <section className={styles.section}>
        <h2>Changes</h2>
        <p>
          These terms may change as NetGuard changes. There is no tracked "acceptance" mechanism - continuing to use
          the app means you accept the current terms shown here.
        </p>
      </section>
    </div>
  );
}
