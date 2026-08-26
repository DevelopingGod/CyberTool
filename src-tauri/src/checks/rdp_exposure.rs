//! Remote Desktop (RDP) exposure check.
//!
//! Data sources: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
//! (`fDenyTSConnections`, 0 = RDP enabled), `...\WinStations\RDP-Tcp`
//! (`UserAuthentication`, 1 = Network Level Authentication required), and
//! `netsh advfirewall firewall show rule name=all` filtered to rules whose
//! name contains "Remote Desktop" (the standard built-in RDP rule group's
//! English display names - a documented v1 heuristic, same style as the
//! firewall-profile check; see `DECISIONS.md`).

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use winreg::enums::*;
use winreg::RegKey;

fn disable_rdp_action() -> RemediationAction {
    RemediationAction::DirectFix {
        action_id: "rdp_disable".to_string(),
        label: "Disable Remote Desktop".to_string(),
        params: std::collections::HashMap::new(),
    }
}

pub struct RdpExposureCheck;

const DATA_SOURCE: &str =
    "HKLM\\SYSTEM\\...\\Terminal Server (fDenyTSConnections, UserAuthentication); netsh advfirewall firewall show rule name=all";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdpState {
    /// `None` means the value couldn't be read (key/value missing).
    pub deny_connections: Option<u32>,
    pub nla_required: Option<u32>,
    pub firewall_rule_enabled: bool,
}

pub fn read_rdp_registry_state() -> (Option<u32>, Option<u32>) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let deny = hklm
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("fDenyTSConnections").ok());
    let nla = hklm
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("UserAuthentication").ok());
    (deny, nla)
}

/// Parses `netsh advfirewall firewall show rule name=all` output, returning
/// true if any rule whose name mentions Remote Desktop has `Enabled: Yes`.
pub fn parse_rdp_firewall_enabled(output: &str) -> bool {
    let mut in_rdp_rule = false;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if let Some(name) = line.strip_prefix("Rule Name:") {
            in_rdp_rule = name.to_ascii_lowercase().contains("remote desktop");
            continue;
        }
        if in_rdp_rule {
            if let Some(enabled) = line.strip_prefix("Enabled:") {
                if enabled.trim().eq_ignore_ascii_case("yes") {
                    return true;
                }
            }
        }
    }
    false
}

pub fn evaluate(state: &RdpState) -> (Severity, Vec<Finding>, String) {
    let rdp_enabled = state.deny_connections == Some(0);
    let nla_required = state.nla_required == Some(1);

    let mut findings = vec![
        Finding::new("RDP enabled", if rdp_enabled { "Yes" } else { "No" }),
        Finding::new("Network Level Authentication required", if nla_required { "Yes" } else { "No" }),
        Finding::new("Reachable via firewall", if state.firewall_rule_enabled { "Yes" } else { "No" }),
    ];

    if !rdp_enabled {
        return (Severity::Ok, findings, "Remote Desktop is disabled.".to_string());
    }

    if !nla_required && state.firewall_rule_enabled {
        findings.push(Finding::with_action(
            "Risk",
            "RDP is enabled, reachable through the firewall, and does not require Network Level Authentication.",
            disable_rdp_action(),
        ));
        return (
            Severity::AtRisk,
            findings,
            "Remote Desktop is enabled and reachable without Network Level Authentication.".to_string(),
        );
    }

    if nla_required {
        findings.push(Finding::with_action(
            "Turn off Remote Desktop",
            "RDP is enabled with NLA required. If you don't use it, disabling it removes the exposure entirely.",
            disable_rdp_action(),
        ));
        return (
            Severity::Caution,
            findings,
            "Remote Desktop is enabled with Network Level Authentication required.".to_string(),
        );
    }

    findings.push(Finding::with_action(
        "Turn off Remote Desktop",
        "RDP is enabled without NLA. If you don't use it, disabling it removes the exposure entirely.",
        disable_rdp_action(),
    ));
    (
        Severity::Caution,
        findings,
        "Remote Desktop is enabled without Network Level Authentication (not currently reachable via firewall).".to_string(),
    )
}

impl SecurityCheck for RdpExposureCheck {
    fn id(&self) -> &'static str {
        "rdp_exposure"
    }

    fn name(&self) -> &'static str {
        "Remote Desktop Exposure"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::RdpExposure
    }

    fn permission_description(&self) -> &'static str {
        "Reads whether Remote Desktop is enabled, whether Network Level Authentication is required, and whether a firewall rule allows it through, via the registry and `netsh advfirewall`."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let (deny_connections, nla_required) = read_rdp_registry_state();
        let firewall_rule_enabled = match run_command("netsh", &["advfirewall", "firewall", "show", "rule", "name=all"]) {
            Ok(output) => parse_rdp_firewall_enabled(&output),
            Err(_) => false,
        };

        let state = RdpState { deny_connections, nla_required, firewall_rule_enabled };
        let (severity, findings, verdict) = evaluate(&state);
        let remediation = match severity {
            Severity::Ok => None,
            Severity::AtRisk => Some(
                "Disable Remote Desktop if you don't need it (Settings > System > Remote Desktop), or require Network Level Authentication under System Properties > Remote."
                    .to_string(),
            ),
            Severity::Caution => Some(
                "If you don't use Remote Desktop, turn it off under Settings > System > Remote Desktop. If you do, make sure Network Level Authentication is required."
                    .to_string(),
            ),
        };

        CheckResult {
            id: self.id().to_string(),
            name: self.name().to_string(),
            category: self.category(),
            severity,
            verdict,
            findings,
            remediation,
            data_source: DATA_SOURCE.to_string(),
            raw_keys: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RDP_RULE_ENABLED: &str = r#"
Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In

Rule Name:                            Some Other App
----------------------------------------------------------------------
Enabled:                              Yes
"#;

    const SAMPLE_RDP_RULE_DISABLED: &str = r#"
Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              No
"#;

    #[test]
    fn detects_enabled_rdp_rule() {
        assert!(parse_rdp_firewall_enabled(SAMPLE_RDP_RULE_ENABLED));
    }

    #[test]
    fn ignores_disabled_rdp_rule() {
        assert!(!parse_rdp_firewall_enabled(SAMPLE_RDP_RULE_DISABLED));
    }

    #[test]
    fn disabled_rdp_is_ok() {
        let state = RdpState { deny_connections: Some(1), nla_required: None, firewall_rule_enabled: false };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn enabled_no_nla_reachable_is_at_risk() {
        let state = RdpState { deny_connections: Some(0), nla_required: Some(0), firewall_rule_enabled: true };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::AtRisk);
    }

    #[test]
    fn enabled_with_nla_is_caution() {
        let state = RdpState { deny_connections: Some(0), nla_required: Some(1), firewall_rule_enabled: true };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Caution);
    }
}
