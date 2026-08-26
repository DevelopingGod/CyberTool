//! Tauri command surface exposed to the frontend.

use crate::background::{self, BackgroundScanPreference};
use crate::checks::CheckCategory;
use crate::history::{ScanRecord, ScanSummary};
use crate::permissions::{self, PermissionState};
use crate::scan::{self, CheckMeta, ScanCompleteEvent};
use std::collections::HashMap;
use tauri::AppHandle;
use tauri_plugin_opener::OpenerExt;

#[tauri::command]
pub fn get_checks_catalog() -> Vec<CheckMeta> {
    scan::catalog()
}

#[tauri::command]
pub fn get_permissions(app: AppHandle) -> Result<HashMap<String, PermissionState>, String> {
    let all = crate::checks::all_checks();
    let id_list: Vec<&str> = all.iter().map(|c| c.id()).collect();
    permissions::get_all(&app, &id_list)
}

#[tauri::command]
pub fn set_permission(app: AppHandle, check_id: String, state: PermissionState) -> Result<(), String> {
    permissions::set_one(&app, &check_id, state)
}

#[tauri::command]
pub async fn run_scan(
    app: AppHandle,
    approved_once: Vec<String>,
    categories: Option<Vec<CheckCategory>>,
) -> Result<ScanCompleteEvent, String> {
    scan::run_scan(&app, &approved_once, categories.as_deref()).await
}

/// Reads the current Windows username via the `USERNAME` environment
/// variable. Chosen over shelling out to `whoami` (through `sysutil`) since
/// it's the simplest reliable option - Windows always sets `USERNAME` for
/// every interactive session, and reading an env var has no process-spawn
/// cost or failure mode beyond "unset," which is handled with a plain
/// fallback greeting.
#[tauri::command]
pub fn get_current_username() -> String {
    std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "there".to_string())
}

#[tauri::command]
pub fn get_scan_history(app: AppHandle) -> Result<Vec<ScanSummary>, String> {
    crate::history::list_summaries(&app)
}

#[tauri::command]
pub fn get_scan_detail(app: AppHandle, id: String) -> Result<Option<ScanRecord>, String> {
    crate::history::get(&app, &id)
}

#[tauri::command]
pub fn clear_scan_history(app: AppHandle) -> Result<(), String> {
    crate::history::clear(&app)
}

#[tauri::command]
pub fn get_background_settings(app: AppHandle) -> BackgroundScanPreference {
    background::get_preference(&app)
}

#[tauri::command]
pub fn set_background_settings(app: AppHandle, preference: BackgroundScanPreference) -> Result<(), String> {
    background::set_preference(&app, preference)
}

/// Triggers an immediate background-semantics scan (same "Allowed checks
/// only" rule as the scheduled task - see `background.rs`), used by the
/// Settings "Run scan now" affordance and the tray menu.
#[tauri::command]
pub async fn run_background_scan_now(app: AppHandle) {
    background::run_background_scan(&app).await;
}

/// Writes the full `ScanRecord` as JSON to a path the user already chose via
/// the frontend's `tauri-plugin-dialog` save dialog.
#[tauri::command]
pub fn export_scan_json(record: ScanRecord, path: String) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write {path}: {e}"))
}

/// Renders the scan as a printable HTML report, writes it to a temp file,
/// and opens it in the default browser so the user can use its native
/// "Print to PDF."
#[tauri::command]
pub fn export_scan_report(app: AppHandle, record: ScanRecord) -> Result<(), String> {
    let html = crate::export::render_report_html(&record);
    let file_name = format!("netguard-report-{}.html", record.id);
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, html).map_err(|e| format!("failed to write report: {e}"))?;
    app.opener()
        .open_path(path.to_string_lossy().to_string(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Renders the scan as a real PDF file (via `printpdf`, see `pdf.rs`) and
/// writes it to a path the frontend already chose via `tauri-plugin-dialog`'s
/// save dialog - a direct one-click download, no manual "print to PDF" step.
#[tauri::command]
pub fn export_scan_pdf(record: ScanRecord, path: String) -> Result<(), String> {
    let bytes = crate::pdf::render_report_pdf(&record)?;
    std::fs::write(&path, bytes).map_err(|e| format!("failed to write {path}: {e}"))
}
