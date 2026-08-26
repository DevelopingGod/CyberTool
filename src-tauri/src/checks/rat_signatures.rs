//! Known remote-access-tool signature check.
//!
//! Data source: the live process table via `sysinfo`. Presence of these
//! tools isn't proof of compromise - they are legitimate, widely used
//! software - so a match is always `Caution`, worth a manual review, never
//! `AtRisk` on its own.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};

pub struct RatSignatureCheck;

const DATA_SOURCE: &str = "live process table (sysinfo)";

/// Curated list of common, legitimate-but-often-abused remote-access tool
/// process names (lowercase, without path).
const KNOWN_TOOLS: &[(&str, &str)] = &[
    ("teamviewer.exe", "TeamViewer"),
    ("anydesk.exe", "AnyDesk"),
    ("ammyy.exe", "Ammyy Admin"),
    ("radmin.exe", "Radmin"),
    ("vncserver.exe", "VNC Server"),
    ("winvnc.exe", "VNC Server"),
    ("tvnserver.exe", "TightVNC Server"),
    ("ultraviewer_desktop.exe", "UltraViewer"),
    ("remotepc.exe", "RemotePC"),
    ("splashtop.exe", "Splashtop"),
    ("screenconnect.exe", "ScreenConnect / ConnectWise Control"),
    ("logmein.exe", "LogMeIn"),
    ("dwagent.exe", "DWAgent"),
    ("supremo.exe", "Supremo Remote Desktop"),
    ("gotoassist.exe", "GoToAssist"),
];

#[derive(Debug, Clone)]
pub struct ProcessNameInfo {
    pub pid: u32,
    pub name: String,
}

pub fn evaluate(processes: &[ProcessNameInfo]) -> (Severity, Vec<Finding>) {
    let mut findings = Vec::new();
    for p in processes {
        let lower = p.name.to_ascii_lowercase();
        if let Some((_, label)) = KNOWN_TOOLS.iter().find(|(exe, _)| *exe == lower) {
            findings.push(Finding::new(
                format!("{label} detected"),
                format!("Process {} (PID {}) matches a known remote-access tool signature", p.name, p.pid),
            ));
        }
    }

    let severity = if findings.is_empty() { Severity::Ok } else { Severity::Caution };
    if findings.is_empty() {
        findings.push(Finding::new("Result", "No known remote-access tool processes found"));
    }
    (severity, findings)
}

impl SecurityCheck for RatSignatureCheck {
    fn id(&self) -> &'static str {
        "rat_signature_scan"
    }

    fn name(&self) -> &'static str {
        "Remote-Access Tool Signatures"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Process
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::RatSignatures
    }

    fn permission_description(&self) -> &'static str {
        "Compares running process names against a curated list of common remote-access tools (e.g. TeamViewer, AnyDesk) so you can confirm you installed them intentionally."
    }

    fn run(&self, ctx: &ScanContext) -> CheckResult {
        let processes: Vec<ProcessNameInfo> = ctx
            .system
            .processes()
            .values()
            .map(|p| ProcessNameInfo {
                pid: p.pid().as_u32(),
                name: p.name().to_string_lossy().to_string(),
            })
            .collect();

        let (severity, findings) = evaluate(&processes);
        let verdict = if severity == Severity::Ok {
            "No known remote-access tool processes found.".to_string()
        } else {
            format!("{} known remote-access tool process(es) found - confirm you installed them.", findings.len())
        };
        let remediation = if severity != Severity::Ok {
            Some("If you recognize and use this tool, no action is needed. If not, uninstall it and change your passwords, since remote-access tools are a common way attackers maintain access.".to_string())
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
    fn detects_known_tool() {
        let procs = vec![ProcessNameInfo { pid: 1, name: "TeamViewer.exe".into() }];
        let (sev, findings) = evaluate(&procs);
        assert_eq!(sev, Severity::Caution);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn clean_list_is_ok() {
        let procs = vec![ProcessNameInfo { pid: 1, name: "explorer.exe".into() }];
        let (sev, _) = evaluate(&procs);
        assert_eq!(sev, Severity::Ok);
    }
}
