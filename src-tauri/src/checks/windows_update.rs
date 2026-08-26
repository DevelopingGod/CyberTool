//! Windows Update / patch currency check.
//!
//! Data source: PowerShell `Get-HotFix | Sort-Object InstalledOn -Descending
//! | Select-Object -First 1`. The registry path
//! (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\...\
//! LastSuccessTime`) was considered first per the spec, but `Get-HotFix` was
//! chosen instead after live verification on this dev machine: it reliably
//! returned a real, recent `InstalledOn` date, while the registry path for
//! `LastSuccessTime` varies by Update Agent version/branch and isn't
//! guaranteed present on every build. See `DECISIONS.md`.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use chrono::{NaiveDate, NaiveDateTime, Utc};

fn open_windows_update_action() -> Finding {
    Finding::with_action(
        "Fix this",
        "Open Windows Update to check for and install pending updates.",
        RemediationAction::DeepLink {
            uri: "ms-settings:windowsupdate".to_string(),
            label: "Open Windows Update".to_string(),
        },
    )
}

pub struct WindowsUpdateCheck;

const DATA_SOURCE: &str = "PowerShell Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1";

const CAUTION_DAYS: i64 = 30;
const AT_RISK_DAYS: i64 = 90;

/// Parses the `InstalledOn : <date>` line from `Get-HotFix ... | Format-List
/// InstalledOn`. PowerShell's default date rendering is locale-dependent
/// (observed as `13-Aug-26 12:00:00 AM` on this dev machine); this parser
/// accepts that format plus a couple of common fallbacks and gives up
/// gracefully (returns `None`) rather than guessing on anything else.
pub fn parse_last_hotfix_date(output: &str) -> Option<NaiveDateTime> {
    let value = output
        .lines()
        .find_map(|line| line.find(':').map(|idx| (line, idx)))
        .filter(|(line, _)| line.trim_start().to_ascii_lowercase().starts_with("installedon"))
        .map(|(line, idx)| line[idx + 1..].trim().to_string())?;

    if value.is_empty() {
        return None;
    }

    let formats = ["%d-%b-%y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S"];
    for fmt in formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(&value, fmt) {
            return Some(dt);
        }
    }
    // Date-only fallback (no time component).
    let date_formats = ["%d-%b-%y", "%m/%d/%Y", "%Y-%m-%d"];
    for fmt in date_formats {
        if let Ok(d) = NaiveDate::parse_from_str(&value, fmt) {
            return Some(d.and_hms_opt(0, 0, 0).unwrap());
        }
    }
    None
}

pub fn evaluate(last_installed: Option<NaiveDateTime>, now: NaiveDateTime) -> (Severity, Vec<Finding>, String) {
    match last_installed {
        None => (
            Severity::AtRisk,
            vec![Finding::new("Last update installed", "Could not be determined")],
            "Could not determine when Windows Update last installed successfully.".to_string(),
        ),
        Some(dt) => {
            let age_days = (now - dt).num_days().max(0);
            let findings = vec![
                Finding::new("Last update installed", dt.format("%Y-%m-%d").to_string()),
                Finding::new("Days since last update", age_days.to_string()),
            ];
            if age_days > AT_RISK_DAYS {
                (
                    Severity::AtRisk,
                    findings,
                    format!("The last Windows Update was installed {age_days} days ago."),
                )
            } else if age_days > CAUTION_DAYS {
                (
                    Severity::Caution,
                    findings,
                    format!("The last Windows Update was installed {age_days} days ago."),
                )
            } else {
                (Severity::Ok, findings, format!("Windows Update is current (last update {age_days} day(s) ago)."))
            }
        }
    }
}

impl SecurityCheck for WindowsUpdateCheck {
    fn id(&self) -> &'static str {
        "windows_update_currency"
    }

    fn name(&self) -> &'static str {
        "Windows Update Currency"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::UpdateStatus
    }

    fn permission_description(&self) -> &'static str {
        "Reads the install date of the most recently installed update via PowerShell's Get-HotFix, to flag a device that hasn't received updates in a while."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let command = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Format-List InstalledOn";
        match run_command("powershell", &["-NoProfile", "-NonInteractive", "-Command", command]) {
            Ok(output) => {
                let last_installed = parse_last_hotfix_date(&output);
                let now = Utc::now().naive_utc();
                let (severity, mut findings, verdict) = evaluate(last_installed, now);
                let remediation = if severity != Severity::Ok {
                    findings.push(open_windows_update_action());
                    Some("Open Settings > Windows Update and install any pending updates.".to_string())
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
                severity: Severity::AtRisk,
                verdict: "Could not determine Windows Update status.".to_string(),
                findings: vec![Finding::new("PowerShell error", e)],
                remediation: Some("Ensure PowerShell is available, then open Settings > Windows Update to check manually.".to_string()),
                data_source: DATA_SOURCE.to_string(),
                raw_keys: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn parses_observed_format() {
        let out = "\nInstalledOn : 13-Aug-26 12:00:00 AM\n\n";
        let dt = parse_last_hotfix_date(out);
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().format("%Y-%m-%d").to_string(), "2026-08-13");
    }

    #[test]
    fn missing_value_returns_none() {
        assert!(parse_last_hotfix_date("\nInstalledOn : \n").is_none());
        assert!(parse_last_hotfix_date("").is_none());
    }

    #[test]
    fn recent_update_is_ok() {
        let now = NaiveDate::from_ymd_opt(2026, 8, 26).unwrap().and_hms_opt(0, 0, 0).unwrap();
        let last = now - Duration::days(5);
        let (sev, _, _) = evaluate(Some(last), now);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn forty_days_is_caution() {
        let now = NaiveDate::from_ymd_opt(2026, 8, 26).unwrap().and_hms_opt(0, 0, 0).unwrap();
        let last = now - Duration::days(40);
        let (sev, _, _) = evaluate(Some(last), now);
        assert_eq!(sev, Severity::Caution);
    }

    #[test]
    fn hundred_days_is_at_risk() {
        let now = NaiveDate::from_ymd_opt(2026, 8, 26).unwrap().and_hms_opt(0, 0, 0).unwrap();
        let last = now - Duration::days(100);
        let (sev, _, _) = evaluate(Some(last), now);
        assert_eq!(sev, Severity::AtRisk);
    }

    #[test]
    fn undeterminable_is_at_risk() {
        let now = Utc::now().naive_utc();
        let (sev, _, _) = evaluate(None, now);
        assert_eq!(sev, Severity::AtRisk);
    }
}
