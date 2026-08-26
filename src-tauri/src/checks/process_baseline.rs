//! Running-process baseline diff.
//!
//! Data source: the live process table via the `sysinfo` crate (already
//! captured once per scan in [`ScanContext`]). Flags processes whose
//! executable path looks unfamiliar - running from a Temp directory, or
//! named with a random-looking hex string - against a small built-in
//! allowlist of common, expected Windows/vendor process names.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

pub struct ProcessBaselineCheck;

const DATA_SOURCE: &str = "live process table (sysinfo)";

/// Common, expected process names on a typical Windows laptop. Not
/// exhaustive - matching is by exact lowercase name, so this only
/// suppresses false positives for well-known names; anything else is
/// judged purely on path/naming heuristics below, not absence from this
/// list (absence alone never raises severity).
const BASELINE_ALLOWLIST: &[&str] = &[
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe", "dwm.exe", "svchost.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe", "searchapp.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "sihost.exe", "ctfmon.exe", "spoolsv.exe", "wmiprvse.exe",
    "conhost.exe", "chrome.exe", "msedge.exe", "firefox.exe", "code.exe", "cargo.exe", "node.exe",
];

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
}

fn random_name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // 8+ character hex-looking basename, e.g. "a1b2c3d4e5.exe" - a common
    // pattern for dropped/generated malware binaries.
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{8,}$").expect("valid regex"))
}

fn is_temp_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains(r"\appdata\local\temp\")
        || lower.contains(r"\windows\temp\")
        || lower.contains(r"\temp\")
}

fn has_random_looking_name(name: &str) -> bool {
    let stem = name.strip_suffix(".exe").unwrap_or(name).to_ascii_lowercase();
    random_name_regex().is_match(&stem)
}

/// A stable identifier for a process, used for next-scan baseline diffing.
/// Decision (see `DECISIONS.md`): `name|exe_path`, deliberately *not*
/// including the PID (PIDs are reused constantly across process lifetimes
/// and would make every process look "new" every scan, defeating the
/// diff's purpose).
pub fn raw_key(p: &ProcessInfo) -> String {
    format!("{}|{}", p.name, p.exe_path.as_deref().unwrap_or(""))
}

/// `previous_keys` is `None` on the first-ever scan - identical to today's
/// behavior. When present, a flagged process whose key wasn't running last
/// scan is "new since last scan," which escalates a Temp-path finding from
/// `Caution` to `AtRisk`.
pub fn evaluate(processes: &[ProcessInfo], previous_keys: Option<&HashSet<String>>) -> (Severity, Vec<Finding>) {
    let mut severity = Severity::Ok;
    let mut findings = Vec::new();
    let mut flagged = 0usize;

    for p in processes {
        let lower_name = p.name.to_ascii_lowercase();
        if BASELINE_ALLOWLIST.contains(&lower_name.as_str()) {
            continue;
        }

        let path = p.exe_path.clone().unwrap_or_default();
        let temp = !path.is_empty() && is_temp_path(&path);
        let random_name = has_random_looking_name(&p.name);
        let is_new = previous_keys.map(|prev| !prev.contains(&raw_key(p))).unwrap_or(false);

        if temp && random_name {
            severity = Severity::AtRisk;
            flagged += 1;
            let suffix = if is_new { " - new since last scan" } else { "" };
            findings.push(Finding::new(
                format!("{} (PID {}){suffix}", p.name, p.pid),
                format!("Runs from a Temp directory with a random-looking name: {path}"),
            ));
        } else if temp {
            if is_new {
                severity = Severity::AtRisk;
                flagged += 1;
                findings.push(Finding::new(
                    format!("{} (PID {}) - new since last scan", p.name, p.pid),
                    format!("Newly appeared, running from a Temp directory: {path}"),
                ));
            } else {
                if severity < Severity::Caution {
                    severity = Severity::Caution;
                }
                flagged += 1;
                findings.push(Finding::new(
                    format!("{} (PID {})", p.name, p.pid),
                    format!("Runs from a Temp directory: {path}"),
                ));
            }
        }
    }

    findings.push(Finding::new("Processes examined", processes.len().to_string()));
    if flagged == 0 {
        findings.insert(0, Finding::new("Result", "No unfamiliar processes running from Temp locations"));
    }

    (severity, findings)
}

impl SecurityCheck for ProcessBaselineCheck {
    fn id(&self) -> &'static str {
        "process_baseline_diff"
    }

    fn name(&self) -> &'static str {
        "Running Process Baseline"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Process
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::ProcessList
    }

    fn permission_description(&self) -> &'static str {
        "Reads the list of currently running processes and their executable paths to flag unfamiliar processes running from suspicious locations like Temp folders."
    }

    fn run(&self, ctx: &ScanContext) -> CheckResult {
        let processes: Vec<ProcessInfo> = ctx
            .system
            .processes()
            .values()
            .map(|p| ProcessInfo {
                pid: p.pid().as_u32(),
                name: p.name().to_string_lossy().to_string(),
                exe_path: p.exe().map(|path| path.display().to_string()),
            })
            .collect();

        let previous_keys: Option<HashSet<String>> = ctx
            .previous_raw_keys
            .get(self.id())
            .map(|keys| keys.iter().cloned().collect());

        let (severity, findings) = evaluate(&processes, previous_keys.as_ref());
        let verdict = match severity {
            Severity::Ok => "No unfamiliar processes running from suspicious locations.".to_string(),
            Severity::Caution => "Process(es) running from a Temp directory found.".to_string(),
            Severity::AtRisk => "New process(es) since the last scan running from Temp (some with randomly-named executables) found - review immediately.".to_string(),
        };
        let remediation = if severity != Severity::Ok {
            Some("Identify each flagged process in Task Manager. If you don't recognize it or its install source, end the process and investigate/remove it.".to_string())
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
            raw_keys: processes.iter().map(raw_key).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlisted_process_ignored() {
        let procs = vec![ProcessInfo { pid: 1, name: "explorer.exe".into(), exe_path: Some(r"C:\Windows\explorer.exe".into()) }];
        let (sev, _) = evaluate(&procs, None);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn temp_path_random_name_is_at_risk() {
        let procs = vec![ProcessInfo {
            pid: 2,
            name: "a1b2c3d4e5.exe".into(),
            exe_path: Some(r"C:\Users\bob\AppData\Local\Temp\a1b2c3d4e5.exe".into()),
        }];
        let (sev, findings) = evaluate(&procs, None);
        assert_eq!(sev, Severity::AtRisk);
        assert!(findings.iter().any(|f| f.detail.contains("random-looking")));
    }

    #[test]
    fn temp_path_normal_name_is_caution() {
        let procs = vec![ProcessInfo {
            pid: 3,
            name: "installer.exe".into(),
            exe_path: Some(r"C:\Users\bob\AppData\Local\Temp\installer.exe".into()),
        }];
        let (sev, _) = evaluate(&procs, None);
        assert_eq!(sev, Severity::Caution);
    }

    #[test]
    fn normal_program_files_path_is_ok() {
        let procs = vec![ProcessInfo {
            pid: 4,
            name: "somegame.exe".into(),
            exe_path: Some(r"C:\Program Files\Game\somegame.exe".into()),
        }];
        let (sev, _) = evaluate(&procs, None);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn new_temp_process_since_last_scan_is_at_risk() {
        let procs = vec![ProcessInfo {
            pid: 5,
            name: "installer.exe".into(),
            exe_path: Some(r"C:\Users\bob\AppData\Local\Temp\installer.exe".into()),
        }];
        let previous: HashSet<String> = HashSet::new();
        let (sev, findings) = evaluate(&procs, Some(&previous));
        assert_eq!(sev, Severity::AtRisk);
        assert!(findings.iter().any(|f| f.label.contains("new since last scan")));
    }

    #[test]
    fn known_temp_process_from_last_scan_stays_caution() {
        let procs = vec![ProcessInfo {
            pid: 6,
            name: "installer.exe".into(),
            exe_path: Some(r"C:\Users\bob\AppData\Local\Temp\installer.exe".into()),
        }];
        let previous: HashSet<String> = procs.iter().map(raw_key).collect();
        let (sev, _) = evaluate(&procs, Some(&previous));
        assert_eq!(sev, Severity::Caution);
    }
}
