import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  BackgroundScanPreference,
  CheckCategory,
  CheckMeta,
  PermissionState,
  RemediationOutcome,
  ScanCompleteEvent,
  ScanProgressEvent,
  CheckOutcome,
  ScanRecord,
  ScanSummary,
} from "../types";

export const EVENT_PROGRESS = "netguard://scan-progress";
export const EVENT_RESULT = "netguard://scan-result";
export const EVENT_COMPLETE = "netguard://scan-complete";
export const EVENT_BACKGROUND_SCAN_COMPLETE = "netguard://background-scan-complete";

export function getChecksCatalog(): Promise<CheckMeta[]> {
  return invoke("get_checks_catalog");
}

export function getPermissions(): Promise<Record<string, PermissionState>> {
  return invoke("get_permissions");
}

export function setPermission(checkId: string, state: PermissionState): Promise<void> {
  return invoke("set_permission", { checkId, state });
}

export function runScan(approvedOnce: string[], categories?: CheckCategory[] | null): Promise<ScanCompleteEvent> {
  return invoke("run_scan", { approvedOnce, categories: categories && categories.length > 0 ? categories : null });
}

export function getCurrentUsername(): Promise<string> {
  return invoke("get_current_username");
}

export function runDirectFix(actionId: string, params: Record<string, string>): Promise<RemediationOutcome> {
  return invoke("run_direct_fix", { actionId, params });
}

export function openSettingsDeepLink(uri: string): Promise<RemediationOutcome> {
  return invoke("open_settings_deep_link", { uri });
}

export function getScanHistory(): Promise<ScanSummary[]> {
  return invoke("get_scan_history");
}

export function getScanDetail(id: string): Promise<ScanRecord | null> {
  return invoke("get_scan_detail", { id });
}

export function clearScanHistory(): Promise<void> {
  return invoke("clear_scan_history");
}

export function onScanProgress(cb: (e: ScanProgressEvent) => void): Promise<UnlistenFn> {
  return listen<ScanProgressEvent>(EVENT_PROGRESS, (event) => cb(event.payload));
}

export function onScanResult(cb: (e: CheckOutcome) => void): Promise<UnlistenFn> {
  return listen<CheckOutcome>(EVENT_RESULT, (event) => cb(event.payload));
}

export function onScanComplete(cb: (e: ScanCompleteEvent) => void): Promise<UnlistenFn> {
  return listen<ScanCompleteEvent>(EVENT_COMPLETE, (event) => cb(event.payload));
}

export function onBackgroundScanComplete(cb: (e: ScanCompleteEvent) => void): Promise<UnlistenFn> {
  return listen<ScanCompleteEvent>(EVENT_BACKGROUND_SCAN_COMPLETE, (event) => cb(event.payload));
}

export function getBackgroundSettings(): Promise<BackgroundScanPreference> {
  return invoke("get_background_settings");
}

export function setBackgroundSettings(preference: BackgroundScanPreference): Promise<void> {
  return invoke("set_background_settings", { preference });
}

export function runBackgroundScanNow(): Promise<void> {
  return invoke("run_background_scan_now");
}

export function exportScanJson(record: ScanRecord, path: string): Promise<void> {
  return invoke("export_scan_json", { record, path });
}

export function exportScanReport(record: ScanRecord): Promise<void> {
  return invoke("export_scan_report", { record });
}

export function exportScanPdf(record: ScanRecord, path: string): Promise<void> {
  return invoke("export_scan_pdf", { record, path });
}
