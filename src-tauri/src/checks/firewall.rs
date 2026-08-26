//! Windows Firewall status check.
//!
//! Data source: `netsh advfirewall show allprofiles state`. We check all
//! three profiles (Domain/Private/Public) since determining which one is
//! "active" reliably requires an additional network-category lookup; the
//! documented v1 behavior is to flag any disabled profile (see
//! `DECISIONS.md`).

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use std::collections::HashMap;

pub struct FirewallStatusCheck;

const DATA_SOURCE: &str = "netsh advfirewall show allprofiles state";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileState {
    pub profile: String,
    pub on: bool,
}

/// Parses `netsh advfirewall show allprofiles state` output.
pub fn parse_firewall_profiles(output: &str) -> Vec<ProfileState> {
    let mut profiles = Vec::new();
    let mut current: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_suffix("Profile Settings:") {
            current = Some(name.trim().to_string());
            continue;
        }
        if trimmed.starts_with("State") {
            if let Some(profile) = current.take() {
                let on = trimmed.to_ascii_uppercase().contains("ON") && !trimmed.to_ascii_uppercase().contains("OFF");
                profiles.push(ProfileState { profile, on });
            }
        }
    }
    profiles
}

pub fn evaluate(profiles: &[ProfileState]) -> (Severity, Vec<Finding>, String) {
    if profiles.is_empty() {
        return (
            Severity::Caution,
            vec![Finding::new("Firewall", "Could not determine firewall profile states")],
            "Could not read Windows Firewall status.".to_string(),
        );
    }

    let off: Vec<&ProfileState> = profiles.iter().filter(|p| !p.on).collect();
    let findings: Vec<Finding> = profiles
        .iter()
        .map(|p| {
            if p.on {
                Finding::new(format!("{} profile", p.profile), "Enabled")
            } else {
                let mut params = HashMap::new();
                params.insert("profile".to_string(), p.profile.to_ascii_lowercase());
                Finding::with_action(
                    format!("{} profile", p.profile),
                    "Disabled",
                    RemediationAction::DirectFix {
                        action_id: "firewall_enable_profile".to_string(),
                        label: format!("Turn on the {} firewall profile", p.profile),
                        params,
                    },
                )
            }
        })
        .collect();

    if off.is_empty() {
        (Severity::Ok, findings, "Windows Firewall is enabled for all profiles.".to_string())
    } else if off.len() == profiles.len() {
        (Severity::AtRisk, findings, "Windows Firewall is disabled for all profiles.".to_string())
    } else {
        let names = off.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", ");
        (Severity::Caution, findings, format!("Windows Firewall is disabled for: {names}."))
    }
}

impl SecurityCheck for FirewallStatusCheck {
    fn id(&self) -> &'static str {
        "firewall_status"
    }

    fn name(&self) -> &'static str {
        "Windows Firewall Status"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::FirewallStatus
    }

    fn permission_description(&self) -> &'static str {
        "Reads whether Windows Firewall is enabled for each network profile, via `netsh advfirewall show allprofiles state`."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        match run_command("netsh", &["advfirewall", "show", "allprofiles", "state"]) {
            Ok(output) => {
                let profiles = parse_firewall_profiles(&output);
                let (severity, findings, verdict) = evaluate(&profiles);
                let remediation = if severity != Severity::Ok {
                    Some("Open Windows Security > Firewall & network protection and turn the firewall on for every network profile.".to_string())
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
                verdict: "Could not read Windows Firewall status.".to_string(),
                findings: vec![Finding::new("netsh error", e)],
                remediation: Some("Ensure `netsh` is available and try again.".to_string()),
                data_source: DATA_SOURCE.to_string(),
                raw_keys: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ALL_ON: &str = r#"
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
"#;

    const SAMPLE_PUBLIC_OFF: &str = r#"
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
"#;

    #[test]
    fn parses_three_profiles() {
        let profiles = parse_firewall_profiles(SAMPLE_ALL_ON);
        assert_eq!(profiles.len(), 3);
        assert!(profiles.iter().all(|p| p.on));
    }

    #[test]
    fn all_on_is_ok() {
        let profiles = parse_firewall_profiles(SAMPLE_ALL_ON);
        let (sev, _, _) = evaluate(&profiles);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn one_off_is_caution() {
        let profiles = parse_firewall_profiles(SAMPLE_PUBLIC_OFF);
        let (sev, _, _) = evaluate(&profiles);
        assert_eq!(sev, Severity::Caution);
    }
}
