//! BitLocker / disk encryption status check.
//!
//! Data source: `manage-bde -status` (the classic BitLocker CLI tool, present
//! on every Windows edition that ships BitLocker - unlike the `BitLocker`
//! PowerShell module's `Get-BitLockerVolume`, which failed with an access
//! error in local testing even from an elevated-adjacent session; see
//! `DECISIONS.md`). Flags the OS volume specifically, since a Data volume
//! being unencrypted is a materially different risk than the boot volume.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;

fn open_bitlocker_action() -> Finding {
    Finding::with_action(
        "Fix this",
        "Open BitLocker Drive Encryption to turn on or resume protection.",
        RemediationAction::DeepLink {
            uri: "ms-settings:deviceencryption".to_string(),
            label: "Open BitLocker settings".to_string(),
        },
    )
}

pub struct BitLockerCheck;

const DATA_SOURCE: &str = "manage-bde -status";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeStatus {
    pub label: String,
    pub is_os_volume: bool,
    pub conversion_status: Option<String>,
    pub protection_status: Option<String>,
}

/// Parses `manage-bde -status` output into per-volume blocks. Each volume
/// starts with a line like `Volume C: [OS]` or `Volume D: [DATA]`.
pub fn parse_manage_bde_status(output: &str) -> Vec<VolumeStatus> {
    let mut volumes = Vec::new();
    let mut current: Option<VolumeStatus> = None;

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix("Volume ") {
            if let Some(v) = current.take() {
                volumes.push(v);
            }
            let is_os_volume = rest.to_ascii_uppercase().contains("[OS]") || rest.to_ascii_uppercase().contains("[OS VOLUME]");
            current = Some(VolumeStatus {
                label: rest.trim().to_string(),
                is_os_volume,
                conversion_status: None,
                protection_status: None,
            });
            continue;
        }
        if line.eq_ignore_ascii_case("[OS Volumes]") || line.eq_ignore_ascii_case("[OS Volume]") {
            if let Some(v) = current.as_mut() {
                v.is_os_volume = true;
            }
            continue;
        }
        if let Some(v) = current.as_mut() {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_ascii_lowercase();
                let value = line[idx + 1..].trim().to_string();
                match key.as_str() {
                    "conversion status" => v.conversion_status = Some(value),
                    "protection status" => v.protection_status = Some(value),
                    _ => {}
                }
            }
        }
    }
    if let Some(v) = current.take() {
        volumes.push(v);
    }
    volumes
}

fn is_fully_encrypted(v: &VolumeStatus) -> bool {
    v.conversion_status
        .as_deref()
        .map(|s| s.to_ascii_lowercase().contains("fully encrypted"))
        .unwrap_or(false)
}

fn is_protection_on(v: &VolumeStatus) -> bool {
    v.protection_status
        .as_deref()
        .map(|s| s.to_ascii_lowercase().contains("protection on"))
        .unwrap_or(false)
}

pub fn evaluate(volumes: &[VolumeStatus]) -> (Severity, Vec<Finding>, String) {
    let mut findings: Vec<Finding> = volumes
        .iter()
        .map(|v| {
            Finding::new(
                format!("Volume {}", v.label),
                format!(
                    "{} / {}",
                    v.conversion_status.as_deref().unwrap_or("unknown"),
                    v.protection_status.as_deref().unwrap_or("unknown")
                ),
            )
        })
        .collect();

    // Prefer the volume explicitly tagged as the OS volume; if manage-bde's
    // output didn't tag one (older builds sometimes omit it), fall back to
    // the first volume as the best available signal rather than reporting
    // nothing.
    let os_volume = volumes.iter().find(|v| v.is_os_volume).or_else(|| volumes.first());

    match os_volume {
        None => (
            Severity::Caution,
            {
                findings.push(Finding::new("BitLocker", "No volumes reported"));
                findings
            },
            "Could not determine BitLocker status - no volumes were reported.".to_string(),
        ),
        Some(v) => {
            if is_fully_encrypted(v) && is_protection_on(v) {
                (Severity::Ok, findings, "The system volume is fully encrypted with BitLocker protection on.".to_string())
            } else {
                (
                    Severity::AtRisk,
                    findings,
                    format!(
                        "The system volume is not fully protected by BitLocker (conversion: {}, protection: {}).",
                        v.conversion_status.as_deref().unwrap_or("unknown"),
                        v.protection_status.as_deref().unwrap_or("unknown")
                    ),
                )
            }
        }
    }
}

impl SecurityCheck for BitLockerCheck {
    fn id(&self) -> &'static str {
        "bitlocker_status"
    }

    fn name(&self) -> &'static str {
        "Disk Encryption (BitLocker)"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::DiskEncryption
    }

    fn permission_description(&self) -> &'static str {
        "Reads BitLocker encryption and protection status for the system volume via `manage-bde -status`. Requires administrator privileges to return a definitive answer; if it can't be determined, this is reported as needing attention rather than silently passing."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        match run_command("manage-bde", &["-status"]) {
            Ok(output) => {
                let volumes = parse_manage_bde_status(&output);
                if volumes.is_empty() {
                    return CheckResult {
                        id: self.id().to_string(),
                        name: self.name().to_string(),
                        category: self.category(),
                        severity: Severity::Caution,
                        verdict: "Could not read BitLocker status (this usually requires administrator privileges).".to_string(),
                        findings: vec![Finding::new("manage-bde", output.trim().to_string()), open_bitlocker_action()],
                        remediation: Some("Run NetGuard as an administrator, or check BitLocker status manually via Control Panel > BitLocker Drive Encryption.".to_string()),
                        data_source: DATA_SOURCE.to_string(),
                        raw_keys: Vec::new(),
                    };
                }
                let (severity, mut findings, verdict) = evaluate(&volumes);
                let remediation = if severity != Severity::Ok {
                    findings.push(open_bitlocker_action());
                    Some("Open Control Panel > BitLocker Drive Encryption and turn on BitLocker (or resume protection) for the system drive.".to_string())
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
                verdict: "Could not query BitLocker status.".to_string(),
                findings: vec![Finding::new("manage-bde error", e)],
                remediation: Some("Ensure `manage-bde` is available (Windows Pro/Enterprise/Education) and try running NetGuard as an administrator.".to_string()),
                data_source: DATA_SOURCE.to_string(),
                raw_keys: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ENCRYPTED: &str = r#"
BitLocker Drive Encryption: Configuration Tool version 10.0.19041
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

Volume C: [OS]
[OS Volume]

    Size:                 476.03 GB
    BitLocker Version:    2.0
    Conversion Status:    Fully Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 256
    Protection Status:    Protection On
    Lock Status:          Unlocked
"#;

    const SAMPLE_UNPROTECTED: &str = r#"
Volume C: [OS]
[OS Volume]

    Conversion Status:    Fully Decrypted
    Protection Status:    Protection Off
"#;

    #[test]
    fn parses_os_volume() {
        let volumes = parse_manage_bde_status(SAMPLE_ENCRYPTED);
        assert_eq!(volumes.len(), 1);
        assert!(volumes[0].is_os_volume);
        assert_eq!(volumes[0].conversion_status.as_deref(), Some("Fully Encrypted"));
    }

    #[test]
    fn fully_encrypted_is_ok() {
        let volumes = parse_manage_bde_status(SAMPLE_ENCRYPTED);
        let (sev, _, _) = evaluate(&volumes);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn unprotected_is_at_risk() {
        let volumes = parse_manage_bde_status(SAMPLE_UNPROTECTED);
        let (sev, _, _) = evaluate(&volumes);
        assert_eq!(sev, Severity::AtRisk);
    }

    #[test]
    fn empty_output_yields_no_volumes() {
        let volumes = parse_manage_bde_status("");
        assert!(volumes.is_empty());
    }
}
