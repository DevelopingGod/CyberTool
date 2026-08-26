import type { Severity } from "../types";
import { severityIcon, severityLabel } from "../lib/icons";
import styles from "./StatusBanner.module.css";

interface StatusBannerProps {
  severity: Severity | null;
  executedCount: number;
  totalCount: number;
  lastScanAt: string | null;
  scanning: boolean;
}

const verdictCopy: Record<Severity, string> = {
  ok: "No significant issues found in the checks that ran.",
  caution: "A few things are worth a closer look.",
  atRisk: "One or more checks found something that needs attention.",
};

export function StatusBanner({ severity, executedCount, totalCount, lastScanAt, scanning }: StatusBannerProps) {
  if (scanning) {
    return (
      <div className={styles.banner} data-tone="scanning">
        <div className={styles.iconWrap} data-pulse="true">
          <span className={styles.pulseRing} aria-hidden="true" />
          <span className={styles.pulseRing} data-delay="true" aria-hidden="true" />
        </div>
        <div>
          <h2 className={styles.title}>Scanning your system&hellip;</h2>
          <p className={styles.subtitle}>Results will appear below as each check finishes.</p>
        </div>
      </div>
    );
  }

  if (!severity) {
    return (
      <div className={styles.banner} data-tone="idle">
        <div>
          <h2 className={styles.title}>No scan run yet</h2>
          <p className={styles.subtitle}>Start a diagnostic scan to see your network and system security posture.</p>
        </div>
      </div>
    );
  }

  const Icon = severityIcon[severity];
  const skipped = totalCount - executedCount;

  return (
    <div className={styles.banner} data-tone={severity}>
      <div className={styles.iconWrap}>
        <Icon size={30} aria-hidden="true" />
      </div>
      <div>
        <h2 className={styles.title}>
          {severityLabel[severity]}
          <span className={styles.basedOn}>
            {" "}
            &middot; based on {executedCount} of {totalCount} checks
          </span>
        </h2>
        <p className={styles.subtitle}>
          {verdictCopy[severity]}
          {skipped > 0 && ` ${skipped} check${skipped === 1 ? "" : "s"} were skipped due to permissions.`}
        </p>
        {lastScanAt && <p className={styles.timestamp}>Last scan: {new Date(lastScanAt).toLocaleString()}</p>}
      </div>
    </div>
  );
}
