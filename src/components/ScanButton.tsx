import { ScanSearch, Loader2 } from "lucide-react";
import styles from "./ScanButton.module.css";

interface ScanButtonProps {
  scanning: boolean;
  completed: number;
  total: number;
  onStart: () => void;
  label?: string;
}

export function ScanButton({ scanning, completed, total, onStart, label = "Start Diagnose" }: ScanButtonProps) {
  return (
    <button type="button" className={styles.button} data-scanning={scanning} onClick={onStart} disabled={scanning}>
      <span className={styles.ring} aria-hidden="true" />
      {scanning ? (
        <>
          <Loader2 size={18} className={styles.spinner} aria-hidden="true" />
          <span>
            Scanning&hellip; {completed}/{total} checks complete
          </span>
        </>
      ) : (
        <>
          <ScanSearch size={18} aria-hidden="true" />
          <span>{label}</span>
        </>
      )}
    </button>
  );
}
