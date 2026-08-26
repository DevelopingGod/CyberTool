//! Direct in-app remediation actions.
//!
//! Every action here is either:
//! - a **direct fix** (`run_direct_fix`): NetGuard changes system state
//!   itself, but only for a small, explicitly whitelisted set of safe,
//!   reversible, non-destructive actions that require no more privilege than
//!   the check that flagged the problem already needed. The frontend always
//!   shows an explicit confirmation dialog before calling this - there is no
//!   "fix everything" / silent-apply path anywhere in this module.
//! - a **deep link** (`open_settings_deep_link`): NetGuard does not touch
//!   system state at all; it just opens the correct Windows Settings page or
//!   Control Panel applet via `tauri-plugin-opener` so the user makes the
//!   change themselves, for anything that needs elevation, GUI interaction,
//!   or is too consequential to automate (BitLocker, Windows Update, Core
//!   Isolation/Memory Integrity).
//!
//! See `DECISIONS.md` for the per-check classification (direct-fix /
//! deep-link / informational-only) and why each one was placed there.

use crate::sysutil::run_command;
use serde::Serialize;
use std::collections::HashMap;
use tauri::AppHandle;
use tauri_plugin_opener::OpenerExt;
use winreg::enums::*;
use winreg::RegKey;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationOutcome {
    pub success: bool,
    pub message: String,
}

impl RemediationOutcome {
    fn ok(message: impl Into<String>) -> Self {
        Self { success: true, message: message.into() }
    }
    fn fail(message: impl Into<String>) -> Self {
        Self { success: false, message: message.into() }
    }
}

/// The registry Run/RunOnce paths persistence.rs actually reads - the only
/// paths `persistence_delete_run_value` is ever allowed to touch, so this
/// action can never be pointed at an arbitrary registry value.
const ALLOWED_RUN_KEY_PATHS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

#[tauri::command]
pub fn run_direct_fix(action_id: String, params: HashMap<String, String>) -> RemediationOutcome {
    match action_id.as_str() {
        "firewall_enable_profile" => enable_firewall_profile(&params),
        "persistence_delete_run_value" => delete_run_value(&params),
        "rdp_disable" => disable_rdp(),
        other => RemediationOutcome::fail(format!("Unknown remediation action '{other}'.")),
    }
}

#[tauri::command]
pub fn open_settings_deep_link(app: AppHandle, uri: String) -> RemediationOutcome {
    match app.opener().open_url(uri.clone(), None::<&str>) {
        Ok(()) => RemediationOutcome::ok(format!("Opened {uri}.")),
        Err(e) => RemediationOutcome::fail(format!("Could not open {uri}: {e}")),
    }
}

/// `netsh advfirewall set <profile>profile state on`. Reversible (the same
/// profile can be turned back off in Settings) and requires no more than the
/// Firewall Status check itself already needed to read profile state.
fn enable_firewall_profile(params: &HashMap<String, String>) -> RemediationOutcome {
    let Some(profile) = params.get("profile").map(|s| s.to_ascii_lowercase()) else {
        return RemediationOutcome::fail("Missing 'profile' parameter.");
    };
    if !["domain", "private", "public"].contains(&profile.as_str()) {
        return RemediationOutcome::fail(format!("Unknown firewall profile '{profile}'."));
    }
    let arg = format!("{profile}profile");
    match run_command("netsh", &["advfirewall", "set", &arg, "state", "on"]) {
        Ok(_) => RemediationOutcome::ok(format!("Turned on the {profile} firewall profile.")),
        Err(e) => RemediationOutcome::fail(format!(
            "Could not enable the {profile} firewall profile (insufficient privileges or netsh unavailable): {e}"
        )),
    }
}

/// Deletes exactly one named value from exactly one of the two Run/RunOnce
/// keys persistence.rs reads - never the whole key, never an arbitrary
/// registry path. Reversible in the sense that removing a startup entry
/// doesn't delete the underlying program; the user can always re-add it.
fn delete_run_value(params: &HashMap<String, String>) -> RemediationOutcome {
    let (Some(hive), Some(path), Some(value_name)) =
        (params.get("hive"), params.get("path"), params.get("valueName"))
    else {
        return RemediationOutcome::fail("Missing 'hive', 'path', or 'valueName' parameter.");
    };
    if !ALLOWED_RUN_KEY_PATHS.contains(&path.as_str()) {
        return RemediationOutcome::fail("Refusing to modify a registry path outside the known Run/RunOnce keys.");
    }
    let root = match hive.as_str() {
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
        "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
        other => return RemediationOutcome::fail(format!("Unknown registry hive '{other}'.")),
    };
    match root.open_subkey_with_flags(path, KEY_SET_VALUE) {
        Ok(key) => match key.delete_value(value_name) {
            Ok(()) => RemediationOutcome::ok(format!("Removed startup entry '{value_name}' from {hive}\\{path}.")),
            Err(e) => RemediationOutcome::fail(format!(
                "Could not remove '{value_name}' (insufficient privileges, or it was already removed): {e}"
            )),
        },
        Err(e) => RemediationOutcome::fail(format!("Could not open {hive}\\{path} (insufficient privileges): {e}")),
    }
}

/// Sets `fDenyTSConnections = 1` under
/// `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, disabling Remote
/// Desktop. Reversible (re-enable in Settings > System > Remote Desktop).
/// Requires admin, since it's an HKLM write - if NetGuard isn't elevated
/// this fails and reports "insufficient privileges" rather than silently
/// doing nothing.
fn disable_rdp() -> RemediationOutcome {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\Terminal Server", KEY_SET_VALUE) {
        Ok(key) => match key.set_value("fDenyTSConnections", &1u32) {
            Ok(()) => RemediationOutcome::ok("Remote Desktop has been disabled."),
            Err(e) => RemediationOutcome::fail(format!(
                "Could not disable Remote Desktop (insufficient privileges - try running NetGuard as an administrator): {e}"
            )),
        },
        Err(e) => RemediationOutcome::fail(format!(
            "Could not open the Terminal Server registry key (insufficient privileges - try running NetGuard as an administrator): {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_action_id() {
        let outcome = run_direct_fix("nonsense".to_string(), HashMap::new());
        assert!(!outcome.success);
    }

    #[test]
    fn rejects_unknown_firewall_profile() {
        let mut params = HashMap::new();
        params.insert("profile".to_string(), "evil".to_string());
        let outcome = enable_firewall_profile(&params);
        assert!(!outcome.success);
    }

    #[test]
    fn rejects_registry_path_outside_allowlist() {
        let mut params = HashMap::new();
        params.insert("hive".to_string(), "HKCU".to_string());
        params.insert("path".to_string(), r"Software\Some\Other\Key".to_string());
        params.insert("valueName".to_string(), "Evil".to_string());
        let outcome = delete_run_value(&params);
        assert!(!outcome.success);
        assert!(outcome.message.contains("Refusing"));
    }

    #[test]
    fn rejects_missing_params() {
        let outcome = delete_run_value(&HashMap::new());
        assert!(!outcome.success);
    }
}
