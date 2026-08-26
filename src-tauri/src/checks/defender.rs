//! Windows Defender real-time protection status check.
//!
//! Data source: PowerShell `Get-MpComputerStatus` (a read-only status
//! query - this is not a virus scan, and does not download/execute any
//! definitions).

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;

fn open_defender_action() -> Finding {
    Finding::with_action(
        "Fix this",
        "Open Windows Security to review or re-enable real-time protection.",
        RemediationAction::DeepLink {
            uri: "windowsdefender:".to_string(),
            label: "Open Windows Security".to_string(),
        },
    )
}

pub struct DefenderStatusCheck;

const DATA_SOURCE: &str = "PowerShell Get-MpComputerStatus";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefenderState {
    pub real_time_protection: Option<bool>,
    pub antivirus_enabled: Option<bool>,
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Parses the `Key : Value` lines PowerShell's default list formatter
/// produces for a single-object `Format-List` output.
pub fn parse_defender_status(output: &str) -> DefenderState {
    let mut state = DefenderState::default();
    for line in output.lines() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_ascii_lowercase();
            let value = line[idx + 1..].trim();
            match key.as_str() {
                "realtimeprotectionenabled" => state.real_time_protection = parse_bool(value),
                "antivirusenabled" => state.antivirus_enabled = parse_bool(value),
                _ => {}
            }
        }
    }
    state
}

pub fn evaluate(state: &DefenderState) -> (Severity, Vec<Finding>, String) {
    let mut findings = Vec::new();
    if let Some(rtp) = state.real_time_protection {
        findings.push(Finding::new("Real-time protection", if rtp { "Enabled" } else { "Disabled" }));
    }
    if let Some(av) = state.antivirus_enabled {
        findings.push(Finding::new("Antivirus enabled", if av { "Enabled" } else { "Disabled" }));
    }

    match state.real_time_protection {
        Some(true) => (Severity::Ok, findings, "Real-time protection is enabled.".to_string()),
        Some(false) => (Severity::AtRisk, findings, "Real-time protection is turned off.".to_string()),
        None => {
            findings.push(Finding::new(
                "Note",
                "Could not determine status - a third-party antivirus may be managing protection instead of Defender.",
            ));
            (Severity::Caution, findings, "Could not determine Defender real-time protection status.".to_string())
        }
    }
}

impl SecurityCheck for DefenderStatusCheck {
    fn id(&self) -> &'static str {
        "defender_status"
    }

    fn name(&self) -> &'static str {
        "Windows Defender Status"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::DefenderStatus
    }

    fn permission_description(&self) -> &'static str {
        "Reads whether Windows Defender real-time protection is enabled via PowerShell's Get-MpComputerStatus. This is a status read only - not a virus scan."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let command = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled | Format-List";
        match run_command("powershell", &["-NoProfile", "-NonInteractive", "-Command", command]) {
            Ok(output) => {
                let state = parse_defender_status(&output);
                let (severity, mut findings, verdict) = evaluate(&state);
                let remediation = if severity == Severity::AtRisk {
                    findings.push(open_defender_action());
                    Some("Open Windows Security > Virus & threat protection and turn Real-time protection back on.".to_string())
                } else if severity == Severity::Caution {
                    findings.push(open_defender_action());
                    Some("If you use a different antivirus product, confirm it's active and up to date. Otherwise open Windows Security to check Defender's status directly.".to_string())
                } else {
                    None
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
            Err(e) => CheckResult {
                id: self.id().to_string(),
                name: self.name().to_string(),
                category: self.category(),
                severity: Severity::Caution,
                verdict: "Could not query Windows Defender status.".to_string(),
                findings: vec![Finding::new("PowerShell error", e)],
                remediation: Some("Ensure PowerShell is available and Windows Defender is installed.".to_string()),
                data_source: DATA_SOURCE.to_string(),
                raw_keys: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enabled_status() {
        let out = "\nRealTimeProtectionEnabled : True\nAntivirusEnabled          : True\n\n";
        let state = parse_defender_status(out);
        assert_eq!(state.real_time_protection, Some(true));
        assert_eq!(state.antivirus_enabled, Some(true));
    }

    #[test]
    fn disabled_is_at_risk() {
        let state = DefenderState { real_time_protection: Some(false), antivirus_enabled: Some(true) };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::AtRisk);
    }

    #[test]
    fn unknown_is_caution_not_ok() {
        let state = DefenderState::default();
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Caution);
    }
}
