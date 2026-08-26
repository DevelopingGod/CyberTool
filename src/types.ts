// Mirrors the Rust types in src-tauri/src/checks/mod.rs, history.rs,
// permissions.rs, and scan.rs. Kept hand-in-sync deliberately (see
// DECISIONS.md) rather than adding a schema-generation build step for v1.

export type CheckCategory = "network" | "process" | "persistence" | "system";

export type Severity = "ok" | "caution" | "atRisk";

export type RemediationAction =
  | { kind: "directFix"; actionId: string; label: string; params: Record<string, string> }
  | { kind: "deepLink"; uri: string; label: string };

export interface Finding {
  label: string;
  detail: string;
  action?: RemediationAction | null;
}

export interface CheckResult {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  verdict: string;
  findings: Finding[];
  remediation: string | null;
  dataSource: string;
}

export interface RemediationOutcome {
  success: boolean;
  message: string;
}

export type CheckOutcome =
  | { state: "completed"; result: CheckResult }
  | { state: "permissionDenied"; result: { id: string; name: string; category: CheckCategory } }
  | { state: "error"; result: { id: string; name: string; category: CheckCategory; message: string } };

export type PermissionState = "allowed" | "denied" | "askEveryTime";

export interface CheckMeta {
  id: string;
  name: string;
  category: CheckCategory;
  permissionDescription: string;
}

export interface ScanSummary {
  id: string;
  timestamp: string;
  overallSeverity: Severity;
  executedCount: number;
  totalCount: number;
}

export interface ScanRecord extends ScanSummary {
  outcomes: CheckOutcome[];
}

export interface ScanProgressEvent {
  completed: number;
  total: number;
  runningId: string;
  runningName: string;
}

export interface ScanCompleteEvent extends ScanSummary {}

export type ScanFrequency = "every6Hours" | "daily" | "weekly";

export interface BackgroundScanPreference {
  enabled: boolean;
  frequency: ScanFrequency;
}
