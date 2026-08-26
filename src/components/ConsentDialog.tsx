import { ShieldQuestion } from "lucide-react";
import type { CheckMeta } from "../types";
import styles from "./ConsentDialog.module.css";

interface ConsentDialogProps {
  check: CheckMeta;
  remaining: number;
  onApproveOnce: () => void;
  onDeny: () => void;
  onOpenSettings: () => void;
}

export function ConsentDialog({ check, remaining, onApproveOnce, onDeny, onOpenSettings }: ConsentDialogProps) {
  return (
    <div className={styles.overlay} role="presentation">
      <div className={styles.dialog} role="dialog" aria-modal="true" aria-labelledby="consent-title">
        <div className={styles.iconWrap}>
          <ShieldQuestion size={22} aria-hidden="true" />
        </div>
        <h2 id="consent-title" className={styles.title}>
          Allow &ldquo;{check.name}&rdquo; to run?
        </h2>
        <p className={styles.description}>{check.permissionDescription}</p>
        <p className={styles.note}>
          This permission is set to &ldquo;ask every time,&rdquo; so you'll see this prompt before every scan until
          you change it in Settings.
        </p>
        <div className={styles.actions}>
          <button type="button" className={styles.secondaryButton} onClick={onDeny}>
            Skip this check
          </button>
          <button type="button" className={styles.linkButton} onClick={onOpenSettings}>
            Open Settings
          </button>
          <button type="button" className={styles.primaryButton} onClick={onApproveOnce}>
            Allow once
          </button>
        </div>
        {remaining > 0 && <p className={styles.queueNote}>{remaining} more permission prompt(s) after this one.</p>}
      </div>
    </div>
  );
}
