import { useEffect, useState } from "react";
import { Sidebar, type View, type PrimaryView } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { Settings } from "./pages/Settings";
import { HistoryDetail } from "./pages/HistoryDetail";
import { CheckDetail } from "./pages/CheckDetail";
import { Developer } from "./pages/Developer";
import { Terms } from "./pages/Terms";
import { PrivacyPolicy } from "./pages/PrivacyPolicy";
import { ToastProvider, useToast } from "./state/ToastContext";
import { severityLabel } from "./lib/icons";
import * as api from "./lib/api";
import type { CheckOutcome } from "./types";
import styles from "./App.module.css";

/** Where to return to when the user backs out of the check-detail page -
 * either the dashboard's live scan or a specific history record. */
type DetailOrigin = { kind: "dashboard" } | { kind: "history"; scanId: string };

function AppShell() {
  const [view, setView] = useState<View>("dashboard");
  const [historyScanId, setHistoryScanId] = useState<string | null>(null);
  const [selectedOutcome, setSelectedOutcome] = useState<CheckOutcome | null>(null);
  const [detailOrigin, setDetailOrigin] = useState<DetailOrigin>({ kind: "dashboard" });
  const { showToast } = useToast();

  const navigate = (v: PrimaryView) => {
    setHistoryScanId(null);
    setSelectedOutcome(null);
    setView(v);
  };

  const openHistoryDetail = (id: string) => {
    setHistoryScanId(id);
    setSelectedOutcome(null);
    setView("history-detail");
  };

  const openCheckDetailFromDashboard = (outcome: CheckOutcome) => {
    setSelectedOutcome(outcome);
    setDetailOrigin({ kind: "dashboard" });
    setView("check-detail");
  };

  const openCheckDetailFromHistory = (outcome: CheckOutcome) => {
    setSelectedOutcome(outcome);
    setDetailOrigin({ kind: "history", scanId: historyScanId ?? "" });
    setView("check-detail");
  };

  const backFromCheckDetail = () => {
    setSelectedOutcome(null);
    if (detailOrigin.kind === "history" && detailOrigin.scanId) {
      setHistoryScanId(detailOrigin.scanId);
      setView("history-detail");
    } else {
      setView("dashboard");
    }
  };

  // A background scan can complete while the window is open; surface it as
  // a toast rather than silently updating history underneath the user.
  useEffect(() => {
    const unlisten = api.onBackgroundScanComplete((e) => {
      showToast(`Background scan complete: ${severityLabel[e.overallSeverity]} (${e.executedCount}/${e.totalCount} checks)`, e.overallSeverity);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [showToast]);

  return (
    <div className={styles.shell}>
      <Sidebar active={view} onNavigate={navigate} />
      <main className={styles.content}>
        {view === "dashboard" && (
          <Dashboard
            onOpenSettings={() => setView("settings")}
            onOpenHistoryDetail={openHistoryDetail}
            onOpenCheckDetail={openCheckDetailFromDashboard}
          />
        )}
        {view === "settings" && <Settings onOpenDeveloper={() => navigate("developer")} />}
        {view === "history-detail" && historyScanId && (
          <HistoryDetail scanId={historyScanId} onBack={() => navigate("dashboard")} onOpenCheckDetail={openCheckDetailFromHistory} />
        )}
        {view === "check-detail" && selectedOutcome && <CheckDetail outcome={selectedOutcome} onBack={backFromCheckDetail} />}
        {view === "developer" && <Developer />}
        {view === "terms" && <Terms />}
        {view === "privacy" && <PrivacyPolicy />}
      </main>
    </div>
  );
}

function App() {
  return (
    <ToastProvider>
      <AppShell />
    </ToastProvider>
  );
}

export default App;
