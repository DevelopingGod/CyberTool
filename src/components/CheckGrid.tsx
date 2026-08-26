import type { CheckOutcome } from "../types";
import { CheckCard } from "./CheckCard";
import styles from "./CheckGrid.module.css";

interface CheckGridProps {
  outcomes: CheckOutcome[];
  onGrantAndRerun?: (checkId: string) => void;
  onOpenDetail: (outcome: CheckOutcome) => void;
}

export function CheckGrid({ outcomes, onGrantAndRerun, onOpenDetail }: CheckGridProps) {
  if (outcomes.length === 0) {
    return null;
  }
  return (
    <div className={styles.grid}>
      {outcomes.map((outcome, i) => (
        <CheckCard key={outcome.result.id} outcome={outcome} index={i} onGrantAndRerun={onGrantAndRerun} onOpenDetail={onOpenDetail} />
      ))}
    </div>
  );
}
