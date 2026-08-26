//! Memory integrity (HVCI) / exploit protection posture check.
//!
//! Data source: `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard
//! -ClassName Win32_DeviceGuard`, read via PowerShell. `SecurityServicesRunning`
//! / `SecurityServicesConfigured` are arrays of small integer codes; `2` is
//! Hypervisor-protected Code Integrity (memory integrity / HVCI). This CIM
//! class was confirmed queryable (unauthenticated, no elevation needed) during
//! this project's earlier diagnosis - verified again live: on this dev
//! machine it returns `SecurityServicesConfigured : {2}` /
//! `SecurityServicesRunning : {2}`.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;

fn open_core_isolation_action() -> Finding {
    Finding::with_action(
        "Fix this",
        "Open Core isolation settings to turn on Memory integrity (requires a restart).",
        RemediationAction::DeepLink {
            uri: "ms-settings:windowsdefender-core-isolation".to_string(),
            label: "Open Core isolation settings".to_string(),
        },
    )
}

pub struct MemoryIntegrityCheck;

const DATA_SOURCE: &str = "PowerShell Get-CimInstance root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard";

/// The `SecurityServicesRunning`/`Configured` code for Hypervisor-protected
/// Code Integrity (memory integrity).
const HVCI_SERVICE_CODE: u32 = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceGuardState {
    pub configured: Vec<u32>,
    pub running: Vec<u32>,
}

/// Parses a PowerShell array rendered by `Format-List`, e.g. `{1, 2}` or a
/// bare `2`, or an empty `{}`.
fn parse_int_array(value: &str) -> Vec<u32> {
    value
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .collect()
}

pub fn parse_device_guard_status(output: &str) -> DeviceGuardState {
    let mut state = DeviceGuardState::default();
    for line in output.lines() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_ascii_lowercase();
            let value = line[idx + 1..].trim();
            match key.as_str() {
                "securityservicesconfigured" => state.configured = parse_int_array(value),
                "securityservicesrunning" => state.running = parse_int_array(value),
                _ => {}
            }
        }
    }
    state
}

pub fn evaluate(state: &DeviceGuardState) -> (Severity, Vec<Finding>, String) {
    let findings = vec![
        Finding::new("Security services configured", format!("{:?}", state.configured)),
        Finding::new("Security services running", format!("{:?}", state.running)),
    ];

    if state.running.contains(&HVCI_SERVICE_CODE) {
        (Severity::Ok, findings, "Memory integrity (HVCI) is enabled and running.".to_string())
    } else if state.configured.contains(&HVCI_SERVICE_CODE) {
        (
            Severity::Caution,
            findings,
            "Memory integrity (HVCI) is configured but not currently running.".to_string(),
        )
    } else {
        (
            Severity::Caution,
            findings,
            "Memory integrity (HVCI) is not enabled on this device.".to_string(),
        )
    }
}

impl SecurityCheck for MemoryIntegrityCheck {
    fn id(&self) -> &'static str {
        "memory_integrity"
    }

    fn name(&self) -> &'static str {
        "Memory Integrity (HVCI)"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::MemoryIntegrity
    }

    fn permission_description(&self) -> &'static str {
        "Reads whether Hypervisor-protected Code Integrity (memory integrity) is configured and running, via the read-only Win32_DeviceGuard CIM class."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let command = "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard | Select-Object SecurityServicesConfigured,SecurityServicesRunning | Format-List";
        match run_command("powershell", &["-NoProfile", "-NonInteractive", "-Command", command]) {
            Ok(output) => {
                let state = parse_device_guard_status(&output);
                let (severity, mut findings, verdict) = evaluate(&state);
                let remediation = if severity != Severity::Ok {
                    findings.push(open_core_isolation_action());
                    Some("Open Windows Security > Device security > Core isolation and turn on Memory integrity. A restart is required.".to_string())
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
                verdict: "Could not query memory integrity status.".to_string(),
                findings: vec![Finding::new("PowerShell error", e)],
                remediation: Some("Ensure PowerShell is available and try again.".to_string()),
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
    fn parses_running_hvci() {
        let out = "\nSecurityServicesConfigured : {2}\nSecurityServicesRunning    : {2}\n\n";
        let state = parse_device_guard_status(out);
        assert_eq!(state.configured, vec![2]);
        assert_eq!(state.running, vec![2]);
    }

    #[test]
    fn running_is_ok() {
        let state = DeviceGuardState { configured: vec![2], running: vec![2] };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn configured_but_not_running_is_caution() {
        let state = DeviceGuardState { configured: vec![2], running: vec![] };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Caution);
    }

    #[test]
    fn not_configured_is_caution_not_ok() {
        let state = DeviceGuardState::default();
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Caution);
    }

    #[test]
    fn parses_empty_array() {
        assert_eq!(parse_int_array("{}"), Vec::<u32>::new());
    }
}
