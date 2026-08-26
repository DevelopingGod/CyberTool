import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import * as api from "../lib/api";
import type { CheckOutcome, ScanRecord } from "../types";
import { StatusBanner } from "../components/StatusBanner";
import { CheckGrid } from "../components/CheckGrid";
import { ExportButtons } from "../components/ExportButtons";
import styles from "./HistoryDetail.module.css";

interface HistoryDetailProps {
  scanId: string;
  onBack: () => void;
  onOpenCheckDetail: (outcome: CheckOutcome) => void;
}

export function HistoryDetail({ scanId, onBack, onOpenCheckDetail }: HistoryDetailProps) {
  const [record, setRecord] = useState<ScanRecord | null>(null);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setRecord(null);
    setNotFound(false);
    api.getScanDetail(scanId).then((r) => {
      if (cancelled) return;
      if (r) setRecord(r);
      else setNotFound(true);
    });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  return (
    <div className={styles.page}>
      <button type="button" className={styles.backButton} onClick={onBack}>
        <ArrowLeft size={16} aria-hidden="true" />
        Back to dashboard
      </button>

      {notFound && <p className={styles.empty}>This scan is no longer available (it may have been cleared from history).</p>}

      {record && (
        <>
          <StatusBanner
            severity={record.overallSeverity}
            executedCount={record.executedCount}
            totalCount={record.totalCount}
            lastScanAt={record.timestamp}
            scanning={false}
          />
          <ExportButtons getRecord={() => Promise.resolve(record)} />
          <CheckGrid outcomes={record.outcomes} onOpenDetail={onOpenCheckDetail} />
        </>
      )}
    </div>
  );
}
