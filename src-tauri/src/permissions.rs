//! Permission & consent state machine.
//!
//! Every check-agent has a persisted preference, one of [`PermissionState`].
//! `AskEveryTime` is the default for every check on first install - nothing
//! runs without an explicit decision.
//!
//! Persistence uses `tauri-plugin-store` (a local JSON file under the app's
//! data directory, `permissions.json`). Critically, this module never
//! caches an "already answered" bypass in memory: every read goes back to
//! the store, so flipping a preference in Settings takes effect on the very
//! next scan.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "permissions.json";
const MAP_KEY: &str = "permissions";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionState {
    Allowed,
    Denied,
    AskEveryTime,
}

impl Default for PermissionState {
    fn default() -> Self {
        PermissionState::AskEveryTime
    }
}

fn read_map(app: &AppHandle) -> Result<HashMap<String, PermissionState>, String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    match store.get(MAP_KEY) {
        Some(value) => serde_json::from_value(value.clone()).map_err(|e| e.to_string()),
        None => Ok(HashMap::new()),
    }
}

fn write_map(app: &AppHandle, map: &HashMap<String, PermissionState>) -> Result<(), String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    let value = serde_json::to_value(map).map_err(|e| e.to_string())?;
    store.set(MAP_KEY, value);
    store.save().map_err(|e| e.to_string())
}

/// Returns the preference for every check-agent, defaulting missing entries
/// to `AskEveryTime` in the returned map (without persisting the default -
/// it's written the first time the user makes an explicit choice).
pub fn get_all(app: &AppHandle, check_ids: &[&str]) -> Result<HashMap<String, PermissionState>, String> {
    let stored = read_map(app)?;
    let mut result = HashMap::new();
    for id in check_ids {
        result.insert((*id).to_string(), stored.get(*id).copied().unwrap_or_default());
    }
    Ok(result)
}

/// Looks up a single check-agent's stored preference, defaulting to
/// `AskEveryTime` if none has ever been set.
pub fn get_one(app: &AppHandle, check_id: &str) -> PermissionState {
    read_map(app)
        .ok()
        .and_then(|m| m.get(check_id).copied())
        .unwrap_or_default()
}

pub fn set_one(app: &AppHandle, check_id: &str, state: PermissionState) -> Result<(), String> {
    let mut map = read_map(app)?;
    map.insert(check_id.to_string(), state);
    write_map(app, &map)
}
