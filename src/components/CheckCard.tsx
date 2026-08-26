import { ChevronRight, ShieldQuestion, CircleAlert } from "lucide-react";
import type { CheckOutcome, Severity } from "../types";
import { categoryIcon, severityIcon, severityLabel } from "../lib/icons";
import styles from "./CheckCard.module.css";

interface CheckCardProps {
  outcome: CheckOutcome;
  index: number;
  onGrantAndRerun?: (checkId: string) => void;
  onOpenDetail: (outcome: CheckOutcome) => void;
}

function toneFor(outcome: CheckOutcome): Severity | "neutral" {
  if (outcome.state === "completed") return outcome.result.severity;
  if (outcome.state === "error") return "caution";
  return "neutral";
}

/** Compact, at-a-glance card for the dashboard grid - clicking it (or its
 * "View details" action) navigates to the dedicated check-detail page
 * rather than expanding inline, per user feedback that inline expansion
 * felt cramped for findings/remediation/data-source. */
export function CheckCard({ outcome, index, onGrantAndRerun, onOpenDetail }: CheckCardProps) {
  const tone = toneFor(outcome);
  const CategoryIcon = categoryIcon[outcome.result.category];
  const canOpen = outcome.state === "completed";

  return (
    <article
      className={styles.card}
      data-tone={tone}
      data-clickable={canOpen}
      style={{ animationDelay: `${Math.min(index, 12) * 45}ms` }}
      onClick={canOpen ? () => onOpenDetail(outcome) : undefined}
      role={canOpen ? "button" : undefined}
      tabIndex={canOpen ? 0 : undefined}
      onKeyDown={
        canOpen
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onOpenDetail(outcome);
              }
            }
          : undefined
      }
    >
      <div className={styles.header}>
        <span className={styles.categoryIcon}>
          <CategoryIcon size={18} aria-hidden="true" />
        </span>
        <div className={styles.titleBlock}>
          <h3 className={styles.name}>{outcome.result.name}</h3>
          {outcome.state === "completed" && <p className={styles.verdict}>{outcome.result.verdict}</p>}
          {outcome.state === "permissionDenied" && (
            <p className={styles.verdict}>Permission needed to run this check.</p>
          )}
          {outcome.state === "error" && <p className={styles.verdict}>{outcome.result.message}</p>}
        </div>
        <SeverityBadge outcome={outcome} />
      </div>

      {outcome.state === "permissionDenied" && (
        <div className={styles.permissionRow}>
          <ShieldQuestion size={16} aria-hidden="true" />
          <span>This check was skipped because it isn't allowed yet.</span>
          {onGrantAndRerun && (
            <button
              type="button"
              className={styles.grantButton}
              onClick={(e) => {
                e.stopPropagation();
                onGrantAndRerun(outcome.result.id);
              }}
            >
              Grant &amp; run
            </button>
          )}
        </div>
      )}

      {canOpen && (
        <button
          type="button"
          className={styles.detailButton}
          onClick={(e) => {
            e.stopPropagation();
            onOpenDetail(outcome);
          }}
        >
          <span>View details</span>
          <ChevronRight size={16} aria-hidden="true" />
        </button>
      )}
    </article>
  );
}

function SeverityBadge({ outcome }: { outcome: CheckOutcome }) {
  if (outcome.state === "permissionDenied") {
    return (
      <span className={styles.badge} data-tone="neutral">
        <ShieldQuestion size={14} aria-hidden="true" />
        Permission needed
      </span>
    );
  }
  if (outcome.state === "error") {
    return (
      <span className={styles.badge} data-tone="caution">
        <CircleAlert size={14} aria-hidden="true" />
        Check failed
      </span>
    );
  }
  const Icon = severityIcon[outcome.result.severity];
  return (
    <span className={styles.badge} data-tone={outcome.result.severity}>
      <Icon size={14} aria-hidden="true" />
      {severityLabel[outcome.result.severity]}
    </span>
  );
}
