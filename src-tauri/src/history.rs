//! Scan history persistence.
//!
//! Stored locally via `tauri-plugin-store` in `history.json`. Never
//! transmitted anywhere - this app performs no network calls beyond what an
//! individual check needs (e.g. DNS resolution for the DNS check).

use crate::checks::{CheckOutcome, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "history.json";
const LIST_KEY: &str = "scans";
/// Keep history bounded so the store file doesn't grow unbounded.
const MAX_HISTORY: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub overall_severity: Severity,
    pub executed_count: usize,
    pub total_count: usize,
    pub outcomes: Vec<CheckOutcome>,
}

/// Lightweight row for the history list view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub overall_severity: Severity,
    pub executed_count: usize,
    pub total_count: usize,
}

impl From<&ScanRecord> for ScanSummary {
    fn from(r: &ScanRecord) -> Self {
        Self {
            id: r.id.clone(),
            timestamp: r.timestamp,
            overall_severity: r.overall_severity,
            executed_count: r.executed_count,
            total_count: r.total_count,
        }
    }
}

fn read_all(app: &AppHandle) -> Result<Vec<ScanRecord>, String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    match store.get(LIST_KEY) {
        Some(value) => serde_json::from_value(value.clone()).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

fn write_all(app: &AppHandle, records: &[ScanRecord]) -> Result<(), String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    let value = serde_json::to_value(records).map_err(|e| e.to_string())?;
    store.set(LIST_KEY, value);
    store.save().map_err(|e| e.to_string())
}

pub fn save(app: &AppHandle, record: ScanRecord) -> Result<(), String> {
    let mut records = read_all(app)?;
    records.insert(0, record);
    if records.len() > MAX_HISTORY {
        records.truncate(MAX_HISTORY);
    }
    write_all(app, &records)
}

pub fn list_summaries(app: &AppHandle) -> Result<Vec<ScanSummary>, String> {
    Ok(read_all(app)?.iter().map(ScanSummary::from).collect())
}

pub fn get(app: &AppHandle, id: &str) -> Result<Option<ScanRecord>, String> {
    Ok(read_all(app)?.into_iter().find(|r| r.id == id))
}

/// Returns the most recently saved scan (records are stored newest-first),
/// or `None` if no scan has ever completed. Used to seed `ScanContext` with
/// the previous scan's raw entries for baseline diffing.
pub fn latest(app: &AppHandle) -> Result<Option<ScanRecord>, String> {
    Ok(read_all(app)?.into_iter().next())
}

pub fn clear(app: &AppHandle) -> Result<(), String> {
    write_all(app, &[])
}
