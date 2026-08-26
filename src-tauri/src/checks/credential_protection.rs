//! Credential / LSASS protection check.
//!
//! Data sources: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`
//! (LSASS protected-process-light; 1 or 2 = enabled) and Credential Guard
//! status via the same `Win32_DeviceGuard` CIM query used by the memory
//! integrity check (`SecurityServicesRunning` containing service code `1` =
//! Credential Guard). Queried independently of the memory integrity check
//! since each check-agent is self-contained and does not share state beyond
//! `ScanContext` (see `checks/mod.rs`); the extra PowerShell call is cheap.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use winreg::enums::*;
use winreg::RegKey;

fn open_core_isolation_action() -> Finding {
    Finding::with_action(
        "Fix this",
        "Open Core isolation settings to turn on Local Security Authority protection.",
        RemediationAction::DeepLink {
            uri: "ms-settings:windowsdefender-core-isolation".to_string(),
            label: "Open Core isolation settings".to_string(),
        },
    )
}

pub struct CredentialProtectionCheck;

const DATA_SOURCE: &str =
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (RunAsPPL); PowerShell Get-CimInstance root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard";

/// The `SecurityServicesRunning`/`Configured` code for Credential Guard.
const CREDENTIAL_GUARD_SERVICE_CODE: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialProtectionState {
    pub run_as_ppl: Option<u32>,
    pub credential_guard_running: bool,
}

pub fn read_run_as_ppl() -> Option<u32> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\Lsa")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("RunAsPPL").ok())
}

/// Parses the same `SecurityServicesRunning : {...}` line format as the
/// memory integrity check, returning whether Credential Guard is running.
pub fn parse_credential_guard_running(output: &str) -> bool {
    for line in output.lines() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_ascii_lowercase();
            if key == "securityservicesrunning" {
                let value = line[idx + 1..].trim();
                let running: Vec<u32> = value
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .collect();
                return running.contains(&CREDENTIAL_GUARD_SERVICE_CODE);
            }
        }
    }
    false
}

fn lsass_protected(run_as_ppl: Option<u32>) -> bool {
    matches!(run_as_ppl, Some(1) | Some(2))
}

pub fn evaluate(state: &CredentialProtectionState) -> (Severity, Vec<Finding>, String) {
    let lsa_protected = lsass_protected(state.run_as_ppl);
    let findings = vec![
        Finding::new("LSASS protected-process-light (RunAsPPL)", if lsa_protected { "Enabled" } else { "Disabled" }),
        Finding::new("Credential Guard running", if state.credential_guard_running { "Yes" } else { "No" }),
    ];

    if lsa_protected || state.credential_guard_running {
        (Severity::Ok, findings, "At least one credential protection mechanism (LSASS PPL or Credential Guard) is active.".to_string())
    } else {
        (
            Severity::Caution,
            findings,
            "Neither LSASS protection (RunAsPPL) nor Credential Guard is active - stored credentials are more exposed to memory-scraping tools.".to_string(),
        )
    }
}

impl SecurityCheck for CredentialProtectionCheck {
    fn id(&self) -> &'static str {
        "credential_protection"
    }

    fn name(&self) -> &'static str {
        "Credential & LSASS Protection"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::CredentialProtection
    }

    fn permission_description(&self) -> &'static str {
        "Reads whether LSASS is running as a protected process (RunAsPPL) and whether Credential Guard is active, via the registry and the read-only Win32_DeviceGuard CIM class."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let run_as_ppl = read_run_as_ppl();
        let command = "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning | Format-List";
        let credential_guard_running = match run_command("powershell", &["-NoProfile", "-NonInteractive", "-Command", command]) {
            Ok(output) => parse_credential_guard_running(&output),
            Err(_) => false,
        };

        let state = CredentialProtectionState { run_as_ppl, credential_guard_running };
        let (severity, mut findings, verdict) = evaluate(&state);
        let remediation = if severity != Severity::Ok {
            findings.push(open_core_isolation_action());
            Some("Open Windows Security > Device security > Core isolation and turn on Local Security Authority protection (or enable Credential Guard via Group Policy on supported editions).".to_string())
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_credential_guard_running() {
        let out = "\nSecurityServicesRunning : {1, 2}\n\n";
        assert!(parse_credential_guard_running(out));
    }

    #[test]
    fn parses_credential_guard_not_running() {
        let out = "\nSecurityServicesRunning : {2}\n\n";
        assert!(!parse_credential_guard_running(out));
    }

    #[test]
    fn lsa_protected_is_ok() {
        let state = CredentialProtectionState { run_as_ppl: Some(1), credential_guard_running: false };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn credential_guard_alone_is_ok() {
        let state = CredentialProtectionState { run_as_ppl: None, credential_guard_running: true };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn neither_is_caution() {
        let state = CredentialProtectionState { run_as_ppl: None, credential_guard_running: false };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Caution);
    }
}
