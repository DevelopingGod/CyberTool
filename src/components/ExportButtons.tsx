import { useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { FileJson, FileText, FileDown } from "lucide-react";
import * as api from "../lib/api";
import { useToast } from "../state/ToastContext";
import styles from "./ExportButtons.module.css";

interface ExportButtonsProps {
  /** Fetches the full ScanRecord to export, on demand (not held in state
   * elsewhere) - keeps this component usable from both the Dashboard's
   * current-scan view and History Detail without either page having to
   * carry a full record around just for exporting. */
  getRecord: () => Promise<import("../types").ScanRecord | null>;
  disabled?: boolean;
}

export function ExportButtons({ getRecord, disabled }: ExportButtonsProps) {
  const [busy, setBusy] = useState<"json" | "report" | "pdf" | null>(null);
  const { showToast } = useToast();

  const handleExportJson = async () => {
    setBusy("json");
    try {
      const record = await getRecord();
      if (!record) return;
      const path = await save({
        defaultPath: `netguard-scan-${record.id}.json`,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!path) return;
      await api.exportScanJson(record, path);
      showToast("Scan exported as JSON.", "ok");
    } catch (err) {
      console.error("JSON export failed", err);
      showToast("JSON export failed.", "atRisk");
    } finally {
      setBusy(null);
    }
  };

  const handleExportReport = async () => {
    setBusy("report");
    try {
      const record = await getRecord();
      if (!record) return;
      await api.exportScanReport(record);
      showToast("Report opened in your browser - use Print to save as PDF.", "ok");
    } catch (err) {
      console.error("Report export failed", err);
      showToast("Report export failed.", "atRisk");
    } finally {
      setBusy(null);
    }
  };

  const handleExportPdf = async () => {
    setBusy("pdf");
    try {
      const record = await getRecord();
      if (!record) return;
      const path = await save({
        defaultPath: `netguard-report-${record.id}.pdf`,
        filters: [{ name: "PDF", extensions: ["pdf"] }],
      });
      if (!path) return;
      await api.exportScanPdf(record, path);
      showToast("Report exported as PDF.", "ok");
    } catch (err) {
      console.error("PDF export failed", err);
      showToast("PDF export failed.", "atRisk");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={styles.row}>
      <button type="button" className={styles.button} disabled={disabled || busy !== null} onClick={handleExportJson}>
        <FileJson size={15} aria-hidden="true" />
        Export JSON
      </button>
      <button type="button" className={styles.button} disabled={disabled || busy !== null} onClick={handleExportPdf}>
        <FileDown size={15} aria-hidden="true" />
        Export PDF
      </button>
      <button type="button" className={styles.button} disabled={disabled || busy !== null} onClick={handleExportReport}>
        <FileText size={15} aria-hidden="true" />
        Printable report
      </button>
    </div>
  );
}
