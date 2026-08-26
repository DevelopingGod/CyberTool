import { useCallback, useEffect, useState } from "react";
import { Sun, Moon, MonitorCog, Trash2, Info, Bell, PlayCircle, UserCircle2 } from "lucide-react";
import * as api from "../lib/api";
import { useTheme, type ThemePreference } from "../state/ThemeContext";
import { useToast } from "../state/ToastContext";
import type { BackgroundScanPreference, CheckMeta, PermissionState, ScanFrequency, ScanSummary } from "../types";
import { categoryIcon } from "../lib/icons";
import styles from "./Settings.module.css";

const APP_VERSION = "0.1.0";

const PERMISSION_LABEL: Record<PermissionState, string> = {
  allowed: "Allowed",
  denied: "Denied",
  askEveryTime: "Ask every time",
};

const FREQUENCY_LABEL: Record<ScanFrequency, string> = {
  every6Hours: "Every 6 hours",
  daily: "Daily",
  weekly: "Weekly",
};

interface SettingsProps {
  onOpenDeveloper: () => void;
}

export function Settings({ onOpenDeveloper }: SettingsProps) {
  const { preference, setPreference } = useTheme();
  const [catalog, setCatalog] = useState<CheckMeta[]>([]);
  const [permissions, setPermissions] = useState<Record<string, PermissionState>>({});
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [clearing, setClearing] = useState(false);
  const [background, setBackground] = useState<BackgroundScanPreference | null>(null);
  const [runningNow, setRunningNow] = useState(false);
  const { showToast } = useToast();

  const load = useCallback(async () => {
    const [c, p, h, b] = await Promise.all([
      api.getChecksCatalog(),
      api.getPermissions(),
      api.getScanHistory(),
      api.getBackgroundSettings(),
    ]);
    setCatalog(c);
    setPermissions(p);
    setHistory(h);
    setBackground(b);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const updatePermission = async (checkId: string, state: PermissionState) => {
    // Optimistic UI update; the backend write is the source of truth the
    // very next scan reads from, so there is no stale-cache window.
    setPermissions((prev) => ({ ...prev, [checkId]: state }));
    await api.setPermission(checkId, state);
  };

  const handleClearHistory = async () => {
    setClearing(true);
    await api.clearScanHistory();
    setHistory([]);
    setClearing(false);
  };

  const updateBackground = async (next: BackgroundScanPreference) => {
    setBackground(next);
    await api.setBackgroundSettings(next);
  };

  const handleRunBackgroundNow = async () => {
    setRunningNow(true);
    try {
      await api.runBackgroundScanNow();
      showToast("Background scan started - it only runs checks set to Allowed.", "neutral");
    } finally {
      setRunningNow(false);
    }
  };

  return (
    <div className={styles.page}>
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Appearance</h2>
        <div className={styles.themeRow}>
          <ThemeOption icon={Sun} label="Light" value="light" current={preference} onSelect={setPreference} />
          <ThemeOption icon={Moon} label="Dark" value="dark" current={preference} onSelect={setPreference} />
          <ThemeOption icon={MonitorCog} label="System" value="system" current={preference} onSelect={setPreference} />
        </div>
      </section>

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Permissions &amp; Privacy</h2>
        <p className={styles.sectionIntro}>
          Every check below needs a specific, narrow piece of OS-level access to run - listed next to its name. New
          checks default to <strong>Ask every time</strong>, which prompts you before every scan so nothing runs
          without your say-so. Switch a check to <strong>Allowed</strong> to stop being asked, or to{" "}
          <strong>Denied</strong> to skip it entirely - both take effect starting with your very next scan, with no
          delay and no cached bypass.
        </p>
        <ul className={styles.permissionList}>
          {catalog.map((check) => {
            const state = permissions[check.id] ?? "askEveryTime";
            const CategoryIcon = categoryIcon[check.category];
            return (
              <li key={check.id} className={styles.permissionRow}>
                <span className={styles.permissionIcon}>
                  <CategoryIcon size={17} aria-hidden="true" />
                </span>
                <div className={styles.permissionInfo}>
                  <p className={styles.permissionName}>{check.name}</p>
                  <p className={styles.permissionDescription}>{check.permissionDescription}</p>
                </div>
                <div className={styles.permissionControl} role="radiogroup" aria-label={`${check.name} permission`}>
                  {(["allowed", "askEveryTime", "denied"] as PermissionState[]).map((option) => (
                    <button
                      key={option}
                      type="button"
                      role="radio"
                      aria-checked={state === option}
                      data-active={state === option}
                      className={styles.permissionOption}
                      onClick={() => updatePermission(check.id, option)}
                    >
                      {PERMISSION_LABEL[option]}
                    </button>
                  ))}
                </div>
              </li>
            );
          })}
        </ul>
      </section>

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Background Scans</h2>
        <p className={styles.sectionIntro}>
          Optionally run scans automatically in the background, in addition to scans you start yourself. Background
          scans <strong>only ever run checks currently set to Allowed</strong> above - a check set to Ask every time
          or Denied is always skipped in the background, since there's no window to prompt you in. Turning this off
          takes effect immediately.
        </p>
        {background && (
          <div className={styles.backgroundRow}>
            <button
              type="button"
              role="switch"
              aria-checked={background.enabled}
              data-active={background.enabled}
              className={styles.toggleSwitch}
              onClick={() => updateBackground({ ...background, enabled: !background.enabled })}
            >
              <span className={styles.toggleThumb} />
            </button>
            <div className={styles.backgroundInfo}>
              <p className={styles.permissionName}>
                <Bell size={15} aria-hidden="true" style={{ verticalAlign: "-2px", marginRight: 6 }} />
                Enable background scans
              </p>
              <p className={styles.permissionDescription}>
                {background.enabled ? "Background scans are on." : "Background scans are off (default)."}
              </p>
            </div>
            <select
              className={styles.frequencySelect}
              value={background.frequency}
              disabled={!background.enabled}
              onChange={(e) => updateBackground({ ...background, frequency: e.target.value as ScanFrequency })}
            >
              {(Object.keys(FREQUENCY_LABEL) as ScanFrequency[]).map((f) => (
                <option key={f} value={f}>
                  {FREQUENCY_LABEL[f]}
                </option>
              ))}
            </select>
            <button type="button" className={styles.dangerButton} data-tone="neutral" onClick={handleRunBackgroundNow} disabled={runningNow}>
              <PlayCircle size={16} aria-hidden="true" />
              Run scan now
            </button>
          </div>
        )}
      </section>

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Scan History</h2>
        <p className={styles.sectionIntro}>
          {history.length === 0
            ? "No scans stored yet."
            : `${history.length} scan${history.length === 1 ? "" : "s"} stored locally on this device.`}
        </p>
        <button type="button" className={styles.dangerButton} onClick={handleClearHistory} disabled={clearing || history.length === 0}>
          <Trash2 size={16} aria-hidden="true" />
          Clear scan history
        </button>
      </section>

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>About</h2>
        <div className={styles.aboutBox}>
          <Info size={18} aria-hidden="true" className={styles.aboutIcon} />
          <div>
            <p className={styles.aboutVersion}>NetGuard v{APP_VERSION}</p>
            <p className={styles.aboutCopy}>
              NetGuard is a diagnostic and triage tool. It inspects your network configuration, running processes,
              startup entries, and system security posture, and reports findings with severity and remediation
              guidance. It is <strong>not an antivirus</strong> - it does not scan files for malware signatures and
              does not remove or clean anything. If you believe your device is actively compromised, disconnect it
              from the network and seek professional incident response.
            </p>
            <p className={styles.aboutCopy}>All scan data stays on this device. NetGuard never transmits results anywhere.</p>
            <button type="button" className={styles.dangerButton} data-tone="neutral" onClick={onOpenDeveloper}>
              <UserCircle2 size={16} aria-hidden="true" />
              Developer &amp; credits
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

function ThemeOption({
  icon: Icon,
  label,
  value,
  current,
  onSelect,
}: {
  icon: typeof Sun;
  label: string;
  value: ThemePreference;
  current: ThemePreference;
  onSelect: (v: ThemePreference) => void;
}) {
  return (
    <button type="button" className={styles.themeOption} data-active={current === value} onClick={() => onSelect(value)}>
      <Icon size={18} aria-hidden="true" />
      <span>{label}</span>
    </button>
  );
}
