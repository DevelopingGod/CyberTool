//! Background scheduled scanning.
//!
//! Persists a user preference (`background.json`, via `tauri-plugin-store`,
//! the same mechanism used for `permissions.json`/`history.json`) and, when
//! enabled, spawns a `tokio` interval task from `tauri::Builder::setup` that
//! periodically triggers a scan.
//!
//! **Consent safety is the entire point of this module.** A background scan
//! calls `scan::run_scan(app, &[])` - the exact same function and code path
//! as a manual scan, with an *empty* `approved_once` list. Per
//! `scan::run_scan`'s existing (untouched) permission state machine:
//!   - `Allowed` checks run.
//!   - `Denied` checks are skipped (`PermissionDenied` outcome).
//!   - `AskEveryTime` checks are skipped too, because their id is never in
//!     an empty `approved_once` list - there is no UI available to prompt
//!     during a background run, so they are simply not run for that scan,
//!     the same as if the user had declined a prompt.
//! No new/parallel permission logic was written for background scans - this
//! module deliberately reuses `run_scan` unmodified specifically so there is
//! only one place that decides "does this check get to run," and it's the
//! one that already has tests and scrutiny. See `DECISIONS.md`.

use crate::scan;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "background.json";
const PREFERENCE_KEY: &str = "preference";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanFrequency {
    Every6Hours,
    Daily,
    Weekly,
}

impl ScanFrequency {
    pub fn to_duration(self) -> std::time::Duration {
        let hours = match self {
            ScanFrequency::Every6Hours => 6,
            ScanFrequency::Daily => 24,
            ScanFrequency::Weekly => 24 * 7,
        };
        std::time::Duration::from_secs(hours * 3600)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundScanPreference {
    pub enabled: bool,
    pub frequency: ScanFrequency,
}

impl Default for BackgroundScanPreference {
    fn default() -> Self {
        // Off by default - this is an opt-in feature.
        Self { enabled: false, frequency: ScanFrequency::Daily }
    }
}

pub fn get_preference(app: &AppHandle) -> BackgroundScanPreference {
    let Ok(store) = app.store(STORE_FILE) else { return BackgroundScanPreference::default() };
    match store.get(PREFERENCE_KEY) {
        Some(value) => serde_json::from_value(value.clone()).unwrap_or_default(),
        None => BackgroundScanPreference::default(),
    }
}

pub fn set_preference(app: &AppHandle, preference: BackgroundScanPreference) -> Result<(), String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    let value = serde_json::to_value(preference).map_err(|e| e.to_string())?;
    store.set(PREFERENCE_KEY, value);
    store.save().map_err(|e| e.to_string())
}

/// Runs one background scan and shows a completion notification. Preference
/// is re-read from disk right before running (never cached), so a user
/// disabling background scans in Settings takes effect on the very next
/// tick without restarting the app.
pub async fn run_background_scan_if_enabled(app: &AppHandle) {
    let preference = get_preference(app);
    if !preference.enabled {
        return;
    }
    run_background_scan(app).await;
}

pub async fn run_background_scan(app: &AppHandle) {
    // Empty approved_once: see module doc - this is what guarantees an
    // AskEveryTime check is never silently treated as approved here.
    match scan::run_scan(app, &[], None).await {
        Ok(complete) => {
            crate::notifications::notify_scan_complete(app, &complete);
        }
        Err(e) => {
            eprintln!("background scan failed: {e}");
        }
    }
}

/// Spawns the recurring background-scan task. Called once from
/// `tauri::Builder::setup`. The interval is re-read from the persisted
/// preference on every tick (not captured once at startup), so a frequency
/// change in Settings is picked up without restarting the timer.
pub fn spawn_background_scan_task(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // Poll on the shortest supported frequency's cadence so a change to
        // a shorter frequency is noticed reasonably promptly, rather than
        // capturing one interval for the lifetime of the app.
        let poll_interval = std::time::Duration::from_secs(60 * 15);
        let mut last_run = std::time::Instant::now();
        loop {
            tokio::time::sleep(poll_interval).await;
            let preference = get_preference(&app);
            if !preference.enabled {
                continue;
            }
            if last_run.elapsed() >= preference.frequency.to_duration() {
                run_background_scan(&app).await;
                last_run = std::time::Instant::now();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let pref = BackgroundScanPreference::default();
        assert!(!pref.enabled);
    }

    #[test]
    fn frequency_durations_are_ordered() {
        assert!(ScanFrequency::Every6Hours.to_duration() < ScanFrequency::Daily.to_duration());
        assert!(ScanFrequency::Daily.to_duration() < ScanFrequency::Weekly.to_duration());
    }
}
