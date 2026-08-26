import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { History } from "lucide-react";
import { StatusBanner } from "../components/StatusBanner";
import { ScanButton } from "../components/ScanButton";
import { CheckGrid } from "../components/CheckGrid";
import { ConsentDialog } from "../components/ConsentDialog";
import { ExportButtons } from "../components/ExportButtons";
import { useToast } from "../state/ToastContext";
import { severityLabel, categoryIcon } from "../lib/icons";
import * as api from "../lib/api";
import type { CheckCategory, CheckMeta, CheckOutcome, PermissionState, ScanSummary } from "../types";
import styles from "./Dashboard.module.css";

interface DashboardProps {
  onOpenSettings: () => void;
  onOpenHistoryDetail: (id: string) => void;
  onOpenCheckDetail: (outcome: CheckOutcome) => void;
}

const ALL_CATEGORIES: CheckCategory[] = ["network", "process", "persistence", "system"];
const CATEGORY_LABEL: Record<CheckCategory, string> = {
  network: "Network",
  process: "Processes",
  persistence: "Persistence",
  system: "System",
};

function greetingForHour(hour: number): string {
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

export function Dashboard({ onOpenSettings, onOpenHistoryDetail, onOpenCheckDetail }: DashboardProps) {
  const [catalog, setCatalog] = useState<CheckMeta[]>([]);
  const [outcomes, setOutcomes] = useState<CheckOutcome[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ completed: 0, total: 0 });
  const [overallSeverity, setOverallSeverity] = useState<ScanSummary["overallSeverity"] | null>(null);
  const [executedCount, setExecutedCount] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const [lastScanAt, setLastScanAt] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [consentQueue, setConsentQueue] = useState<CheckMeta[]>([]);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [selectedCategories, setSelectedCategories] = useState<CheckCategory[]>([]);
  const approvedOnceRef = useRef<string[]>([]);
  const consentResolveRef = useRef<((approvedIds: string[]) => void) | null>(null);
  const { showToast } = useToast();

  const greeting = useMemo(() => greetingForHour(new Date().getHours()), []);

  const loadCatalogAndHistory = useCallback(async () => {
    const [c, h, name] = await Promise.all([api.getChecksCatalog(), api.getScanHistory(), api.getCurrentUsername()]);
    setCatalog(c);
    setHistory(h);
    setUsername(name);
    if (h.length > 0) {
      const latest = h[0];
      const detail = await api.getScanDetail(latest.id);
      if (detail) {
        setOutcomes(detail.outcomes);
        setOverallSeverity(detail.overallSeverity);
        setExecutedCount(detail.executedCount);
        setTotalCount(detail.totalCount);
        setLastScanAt(detail.timestamp);
        setCurrentScanId(detail.id);
      }
    }
  }, []);

  useEffect(() => {
    loadCatalogAndHistory();
  }, [loadCatalogAndHistory]);

  useEffect(() => {
    const unlisten: Array<Promise<() => void>> = [
      api.onScanProgress((e) => setProgress({ completed: e.completed, total: e.total })),
      api.onScanResult((outcome) => {
        setOutcomes((prev) => {
          const idx = prev.findIndex((o) => o.result.id === outcome.result.id);
          if (idx === -1) return [...prev, outcome];
          const next = [...prev];
          next[idx] = outcome;
          return next;
        });
      }),
      api.onScanComplete((e) => {
        setScanning(false);
        setOverallSeverity(e.overallSeverity);
        setExecutedCount(e.executedCount);
        setTotalCount(e.totalCount);
        setLastScanAt(e.timestamp);
        setCurrentScanId(e.id);
        api.getScanHistory().then(setHistory);
        showToast(`Scan complete: ${severityLabel[e.overallSeverity]} (${e.executedCount}/${e.totalCount} checks)`, e.overallSeverity);
      }),
    ];
    return () => {
      unlisten.forEach((p) => p.then((fn) => fn()));
    };
  }, [showToast]);

  /** Resolves every `AskEveryTime` permission by prompting the user one
   * check at a time, then kicks off the actual scan. This is the only path
   * by which an `AskEveryTime` check can run - the backend refuses to run
   * one unless its id is explicitly included as a one-time approval, and
   * that approval is never persisted or reused on a later scan.
   *
   * `categories` mirrors the backend's own contract: an empty array (or
   * omitted) means "run everything," matching `run_scan`'s
   * `Option<Vec<CheckCategory>>` where `None`/empty is a full scan. */
  const startScan = useCallback(async (categories: CheckCategory[] = []) => {
    const [perms, freshCatalog] = await Promise.all([api.getPermissions(), api.getChecksCatalog()]);
    setCatalog(freshCatalog);

    const relevantCatalog =
      categories.length === 0 ? freshCatalog : freshCatalog.filter((c) => categories.includes(c.category));

    const needsPrompt = relevantCatalog.filter((c: CheckMeta) => {
      const state: PermissionState | undefined = perms[c.id];
      return state === "askEveryTime" || state === undefined;
    });

    approvedOnceRef.current = [];

    if (needsPrompt.length > 0) {
      setConsentQueue(needsPrompt);
      await new Promise<void>((resolve) => {
        consentResolveRef.current = (approvedIds) => {
          approvedOnceRef.current = approvedIds;
          resolve();
        };
      });
      setConsentQueue([]);
    }

    setScanning(true);
    setOutcomes([]);
    setProgress({ completed: 0, total: relevantCatalog.length });
    try {
      await api.runScan(approvedOnceRef.current, categories.length > 0 ? categories : null);
    } catch (err) {
      setScanning(false);
      console.error("Scan failed", err);
    }
  }, []);

  /** Advances the consent queue by one, optionally recording an approval
   * for the check currently at the front. When the queue empties, resolves
   * the promise `startScan` is awaiting with the full set of approvals
   * gathered this run. */
  const advanceConsentQueue = useCallback((approve: boolean) => {
    setConsentQueue((prev) => {
      const [current, ...rest] = prev;
      if (approve && current) {
        approvedOnceRef.current = [...approvedOnceRef.current, current.id];
      }
      if (rest.length === 0 && consentResolveRef.current) {
        consentResolveRef.current(approvedOnceRef.current);
        consentResolveRef.current = null;
      }
      return rest;
    });
  }, []);

  const handleGrantAndRerun = useCallback(
    async (checkId: string) => {
      await api.setPermission(checkId, "allowed");
      await startScan();
    },
    [startScan],
  );

  const toggleCategory = (cat: CheckCategory) => {
    setSelectedCategories((prev) => (prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]));
  };

  const currentConsent = consentQueue[0];

  return (
    <div className={styles.page}>
      <div className={styles.greetingRow}>
        <h1 className={styles.greeting}>
          {greeting}
          {username ? `, ${username}` : ""}.
        </h1>
        <p className={styles.greetingSubtitle}>Choose a full diagnostic scan, or run just the categories you care about right now.</p>
      </div>

      <div className={styles.scanSelector}>
        <div className={styles.categoryPills}>
          {ALL_CATEGORIES.map((cat) => {
            const CatIcon = categoryIcon[cat];
            const active = selectedCategories.includes(cat);
            return (
              <button
                key={cat}
                type="button"
                className={styles.categoryPill}
                data-active={active}
                onClick={() => toggleCategory(cat)}
                disabled={scanning}
              >
                <CatIcon size={15} aria-hidden="true" />
                {CATEGORY_LABEL[cat]}
              </button>
            );
          })}
        </div>
        <div className={styles.scanActions}>
          <ScanButton
            scanning={scanning}
            completed={progress.completed}
            total={progress.total || catalog.length}
            onStart={() => startScan()}
            label="Full Scan"
          />
          <button
            type="button"
            className={styles.selectedScanButton}
            disabled={scanning || selectedCategories.length === 0}
            onClick={() => startScan(selectedCategories)}
          >
            Run selected ({selectedCategories.length})
          </button>
        </div>
      </div>

      <div className={styles.topRow}>
        <button type="button" className={styles.historyLink} onClick={() => history[0] && onOpenHistoryDetail(history[0].id)} disabled={history.length === 0}>
          <History size={16} aria-hidden="true" />
          Scan history ({history.length})
        </button>
      </div>

      <StatusBanner
        severity={overallSeverity}
        executedCount={executedCount}
        totalCount={totalCount || catalog.length}
        lastScanAt={lastScanAt}
        scanning={scanning}
      />

      {currentScanId && (
        <ExportButtons disabled={scanning} getRecord={() => (currentScanId ? api.getScanDetail(currentScanId) : Promise.resolve(null))} />
      )}

      <CheckGrid outcomes={outcomes} onGrantAndRerun={handleGrantAndRerun} onOpenDetail={onOpenCheckDetail} />

      {history.length > 0 && (
        <section className={styles.historySection}>
          <h3 className={styles.historyTitle}>Recent scans</h3>
          <ul className={styles.historyList}>
            {history.slice(0, 6).map((h) => (
              <li key={h.id}>
                <button type="button" className={styles.historyItem} onClick={() => onOpenHistoryDetail(h.id)}>
                  <span data-tone={h.overallSeverity} className={styles.historyDot} aria-hidden="true" />
                  <span>{new Date(h.timestamp).toLocaleString()}</span>
                  <span className={styles.historyMeta}>
                    {h.executedCount}/{h.totalCount} checks
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {currentConsent && (
        <ConsentDialog
          check={currentConsent}
          remaining={consentQueue.length - 1}
          onApproveOnce={() => advanceConsentQueue(true)}
          onDeny={() => advanceConsentQueue(false)}
          onOpenSettings={() => {
            if (consentResolveRef.current) {
              consentResolveRef.current(approvedOnceRef.current);
              consentResolveRef.current = null;
            }
            setConsentQueue([]);
            onOpenSettings();
          }}
        />
      )}
    </div>
  );
}
