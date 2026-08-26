import { useState } from "react";
import { ArrowLeft, CircleAlert, Wrench, ExternalLink } from "lucide-react";
import type { CheckOutcome, Finding, RemediationAction } from "../types";
import { categoryIcon, severityIcon, severityLabel } from "../lib/icons";
import { RemediationDialog } from "../components/RemediationDialog";
import { useToast } from "../state/ToastContext";
import * as api from "../lib/api";
import styles from "./CheckDetail.module.css";

interface CheckDetailProps {
  outcome: CheckOutcome;
  onBack: () => void;
}

export function CheckDetail({ outcome, onBack }: CheckDetailProps) {
  const [pendingAction, setPendingAction] = useState<RemediationAction | null>(null);
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  if (outcome.state !== "completed") {
    // Only completed checks are ever opened into this page (CheckCard only
    // makes permission-denied/error cards non-clickable), but keep this
    // defensive rather than assuming.
    return (
      <div className={styles.page}>
        <BackButton onBack={onBack} />
        <p className={styles.empty}>This check has no detail to show.</p>
      </div>
    );
  }

  const result = outcome.result;
  const CategoryIcon = categoryIcon[result.category];
  const SeverityIcon = severityIcon[result.severity];

  const runAction = async (action: RemediationAction) => {
    setBusy(true);
    try {
      const remediationOutcome =
        action.kind === "directFix"
          ? await api.runDirectFix(action.actionId, action.params)
          : await api.openSettingsDeepLink(action.uri);
      showToast(remediationOutcome.message, remediationOutcome.success ? "ok" : "atRisk");
    } catch (err) {
      console.error("Remediation action failed", err);
      showToast("The action failed unexpectedly.", "atRisk");
    } finally {
      setBusy(false);
      setPendingAction(null);
    }
  };

  return (
    <div className={styles.page}>
      <BackButton onBack={onBack} />

      <div className={styles.banner} data-tone={result.severity}>
        <div className={styles.bannerIcon}>
          <SeverityIcon size={30} aria-hidden="true" />
        </div>
        <div>
          <p className={styles.bannerEyebrow}>
            <CategoryIcon size={14} aria-hidden="true" />
            {categoryLabel[result.category]}
          </p>
          <h1 className={styles.bannerTitle}>{result.name}</h1>
          <p className={styles.bannerSeverity}>{severityLabel[result.severity]}</p>
        </div>
      </div>

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Verdict</h2>
        <p className={styles.verdict}>{result.verdict}</p>
      </section>

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Findings</h2>
        <div className={styles.findingsList}>
          {result.findings.map((f, i) => (
            <FindingRow key={i} finding={f} onRunAction={setPendingAction} />
          ))}
          {result.findings.length === 0 && <p className={styles.empty}>No individual findings were recorded.</p>}
        </div>
      </section>

      {result.remediation && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Remediation</h2>
          <div className={styles.remediationBox}>
            <CircleAlert size={18} aria-hidden="true" />
            <p>{result.remediation}</p>
          </div>
        </section>
      )}

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Data source</h2>
        <p className={styles.dataSource}>{result.dataSource}</p>
      </section>

      {pendingAction && (
        <RemediationDialog
          action={pendingAction}
          busy={busy}
          onConfirm={() => runAction(pendingAction)}
          onCancel={() => setPendingAction(null)}
        />
      )}
    </div>
  );
}

function FindingRow({ finding, onRunAction }: { finding: Finding; onRunAction: (action: RemediationAction) => void }) {
  return (
    <div className={styles.finding}>
      <div>
        <p className={styles.findingLabel}>{finding.label}</p>
        <p className={styles.findingDetail}>{finding.detail}</p>
      </div>
      {finding.action && (
        <button type="button" className={styles.actionButton} onClick={() => onRunAction(finding.action!)}>
          {finding.action.kind === "directFix" ? <Wrench size={15} aria-hidden="true" /> : <ExternalLink size={15} aria-hidden="true" />}
          {finding.action.label}
        </button>
      )}
    </div>
  );
}

function BackButton({ onBack }: { onBack: () => void }) {
  return (
    <button type="button" className={styles.backButton} onClick={onBack}>
      <ArrowLeft size={16} aria-hidden="true" />
      Back
    </button>
  );
}

const categoryLabel: Record<string, string> = {
  network: "Network",
  process: "Processes & Programs",
  persistence: "Startup & Persistence",
  system: "System Security",
};
