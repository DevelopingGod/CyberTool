import { ShieldAlert, ExternalLink } from "lucide-react";
import type { RemediationAction } from "../types";
import styles from "./ConsentDialog.module.css";

interface RemediationDialogProps {
  action: RemediationAction;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** Explicit, per-action confirmation shown every time before NetGuard either
 * changes system state itself (a "direct fix") or opens a Windows settings
 * page ("deep link") on the user's behalf. Reuses `ConsentDialog`'s visual
 * language and styling (same modal, same button hierarchy) since both are
 * "confirm before NetGuard does something" moments - there is no silent
 * auto-apply path for either kind of action. See `DECISIONS.md`.
 */
export function RemediationDialog({ action, busy, onConfirm, onCancel }: RemediationDialogProps) {
  const isDirectFix = action.kind === "directFix";

  return (
    <div className={styles.overlay} role="presentation">
      <div className={styles.dialog} role="dialog" aria-modal="true" aria-labelledby="remediation-title">
        <div className={styles.iconWrap}>
          {isDirectFix ? <ShieldAlert size={22} aria-hidden="true" /> : <ExternalLink size={22} aria-hidden="true" />}
        </div>
        <h2 id="remediation-title" className={styles.title}>
          {isDirectFix ? `Apply fix: ${action.label}?` : `Open: ${action.label}?`}
        </h2>
        <p className={styles.description}>
          {isDirectFix
            ? "NetGuard will make this specific change on your device right now. Nothing else is touched."
            : "NetGuard will open the relevant Windows settings page in a separate window. You make the change yourself - NetGuard does not modify anything."}
        </p>
        {isDirectFix && (
          <p className={styles.note}>
            This action is reversible and limited to exactly what's described above. If NetGuard isn't running with
            enough privilege to make this change, you'll see a clear failure message rather than a silent no-op.
          </p>
        )}
        <div className={styles.actions}>
          <button type="button" className={styles.secondaryButton} onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="button" className={styles.primaryButton} onClick={onConfirm} disabled={busy}>
            {busy ? "Working..." : isDirectFix ? "Apply fix" : "Open settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
