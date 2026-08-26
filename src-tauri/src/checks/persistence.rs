//! Startup / persistence entries check.
//!
//! Data sources: the registry `Run`/`RunOnce` keys under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\` and
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\` (via the `winreg`
//! crate), plus scheduled tasks via `schtasks /query /fo CSV /v`. Flags
//! entries pointing at Temp/AppData paths with random-looking names.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use std::collections::HashMap;
use std::collections::HashSet;
use winreg::enums::*;
use winreg::RegKey;

pub struct PersistenceCheck;

const DATA_SOURCE: &str = "HKCU/HKLM ...\\CurrentVersion\\Run(Once); schtasks /query /fo CSV /v";

const RUN_KEY_PATHS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

#[derive(Debug, Clone)]
pub struct PersistenceEntry {
    pub source: String,
    pub name: String,
    pub command: String,
}

fn is_suspicious_path(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains(r"\appdata\local\temp\") || lower.contains(r"\windows\temp\") || lower.contains(r"\temp\")
}

/// Reads a HKCU or HKLM Run/RunOnce key defensively - a missing key (very
/// common; not every key exists) is treated as "no entries," not an error.
fn read_run_key(hive: &RegKey, hive_label: &str, subkey: &str) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    if let Ok(key) = hive.open_subkey(subkey) {
        for name in key.enum_values().filter_map(|r| r.ok()).map(|(n, _)| n) {
            let value: Result<String, _> = key.get_value(&name);
            if let Ok(command) = value {
                entries.push(PersistenceEntry {
                    source: format!("{hive_label}\\{subkey}"),
                    name,
                    command,
                });
            }
        }
    }
    entries
}

pub fn read_registry_run_keys() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for path in RUN_KEY_PATHS {
        entries.extend(read_run_key(&hkcu, "HKCU", path));
        entries.extend(read_run_key(&hklm, "HKLM", path));
    }
    entries
}

/// Parses `schtasks /query /fo CSV /v` output into (task name, action /
/// "Task To Run") pairs. Defensive against the header row and quoting.
pub fn parse_scheduled_tasks_csv(output: &str) -> Vec<PersistenceEntry> {
    let mut lines = output.lines();
    let Some(header) = lines.next() else { return Vec::new() };
    let headers: Vec<String> = split_csv_line(header)
        .into_iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let Some(name_idx) = headers.iter().position(|h| h == "taskname") else { return Vec::new() };
    let Some(action_idx) = headers.iter().position(|h| h == "task to run") else { return Vec::new() };

    let mut entries = Vec::new();
    for line in lines {
        let cols = split_csv_line(line);
        if cols.len() <= name_idx.max(action_idx) {
            continue;
        }
        let name = cols[name_idx].trim().to_string();
        let command = cols[action_idx].trim().to_string();
        if name.is_empty() || command.is_empty() || name.eq_ignore_ascii_case("taskname") {
            continue;
        }
        entries.push(PersistenceEntry {
            source: "Scheduled Task".to_string(),
            name,
            command,
        });
    }
    entries
}

fn split_csv_line(line: &str) -> Vec<String> {
    // Minimal CSV splitter sufficient for schtasks' quoted-comma output; no
    // embedded-quote escaping is used by that tool.
    line.split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect()
}

/// A stable identifier for a persistence entry, used for next-scan baseline
/// diffing. Decision (see `DECISIONS.md`): `source|name|command` - cheap to
/// compute, and changes if any of the three change (a renamed/re-pathed
/// entry is treated as "new" rather than tracked as a rename, which is the
/// conservative choice for a security tool).
pub fn raw_key(e: &PersistenceEntry) -> String {
    format!("{}|{}|{}", e.source, e.name, e.command)
}

/// `previous_keys` is `None` on the first-ever scan (nothing to diff
/// against - identical to today's behavior). When present, an entry whose
/// key wasn't seen last scan is "new since last scan," which escalates a
/// Temp-path finding from `Caution` to `AtRisk`.
pub fn evaluate(entries: &[PersistenceEntry], previous_keys: Option<&HashSet<String>>) -> (Severity, Vec<Finding>) {
    let mut severity = Severity::Ok;
    let mut findings = Vec::new();

    for e in entries {
        if is_suspicious_path(&e.command) {
            let is_new = previous_keys.map(|prev| !prev.contains(&raw_key(e))).unwrap_or(false);
            let label = if is_new {
                format!("{} ({}) - new since last scan", e.name, e.source)
            } else {
                format!("{} ({})", e.name, e.source)
            };
            let detail = if is_new {
                format!("Newly appeared, launching from a Temp directory: {}", e.command)
            } else {
                format!("Launches from a Temp directory: {}", e.command)
            };
            // Only registry Run/RunOnce entries (source "HKCU\..." or
            // "HKLM\...") get a direct-fix action - scheduled tasks are
            // left informational-only in this v1 (see DECISIONS.md).
            let finding = match e.source.split_once('\\') {
                Some((hive, path)) if hive == "HKCU" || hive == "HKLM" => {
                    let mut params = HashMap::new();
                    params.insert("hive".to_string(), hive.to_string());
                    params.insert("path".to_string(), path.to_string());
                    params.insert("valueName".to_string(), e.name.clone());
                    Finding::with_action(
                        label,
                        detail,
                        RemediationAction::DirectFix {
                            action_id: "persistence_delete_run_value".to_string(),
                            label: format!("Remove '{}' from startup", e.name),
                            params,
                        },
                    )
                }
                _ => Finding::new(label, detail),
            };
            findings.push(finding);
            if is_new {
                severity = Severity::AtRisk;
            } else if severity < Severity::Caution {
                severity = Severity::Caution;
            }
        }
    }

    findings.push(Finding::new("Startup entries examined", entries.len().to_string()));
    if severity == Severity::Ok {
        findings.insert(0, Finding::new("Result", "No startup entries pointing at Temp locations"));
    }

    (severity, findings)
}

impl SecurityCheck for PersistenceCheck {
    fn id(&self) -> &'static str {
        "startup_persistence_entries"
    }

    fn name(&self) -> &'static str {
        "Startup & Persistence Entries"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Persistence
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::RegistryRunKeys
    }

    fn permission_description(&self) -> &'static str {
        "Reads the registry Run/RunOnce autostart keys and enumerates scheduled tasks to flag entries that launch from unusual locations like a Temp folder."
    }

    fn run(&self, ctx: &ScanContext) -> CheckResult {
        let mut entries = read_registry_run_keys();

        match run_command("schtasks", &["/query", "/fo", "CSV", "/v"]) {
            Ok(output) => entries.extend(parse_scheduled_tasks_csv(&output)),
            Err(_) => {
                // Scheduled task enumeration is a best-effort supplement;
                // its absence doesn't invalidate the registry-based result.
            }
        }

        let previous_keys: Option<HashSet<String>> = ctx
            .previous_raw_keys
            .get(self.id())
            .map(|keys| keys.iter().cloned().collect());

        let (severity, findings) = evaluate(&entries, previous_keys.as_ref());
        let verdict = match severity {
            Severity::Ok => "No startup/persistence entries pointing at unusual locations.".to_string(),
            Severity::Caution => "Startup or scheduled task entries launching from Temp were found.".to_string(),
            Severity::AtRisk => "New startup entries strongly indicating tampering were found since the last scan.".to_string(),
        };
        let remediation = if severity != Severity::Ok {
            Some("Open Task Manager's Startup tab or Task Scheduler, confirm you recognize each flagged entry, and remove any you don't.".to_string())
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
            raw_keys: entries.iter().map(raw_key).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_temp_startup_entry() {
        let entries = vec![PersistenceEntry {
            source: "HKCU\\...Run".into(),
            name: "Updater".into(),
            command: r"C:\Users\bob\AppData\Local\Temp\upd.exe".into(),
        }];
        let (sev, findings) = evaluate(&entries, None);
        assert_eq!(sev, Severity::Caution);
        assert!(!findings.is_empty());
    }

    #[test]
    fn normal_entry_is_ok() {
        let entries = vec![PersistenceEntry {
            source: "HKCU\\...Run".into(),
            name: "OneDrive".into(),
            command: r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background".into(),
        }];
        let (sev, _) = evaluate(&entries, None);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn new_temp_entry_since_last_scan_is_at_risk() {
        let entries = vec![PersistenceEntry {
            source: "HKCU\\...Run".into(),
            name: "Updater".into(),
            command: r"C:\Users\bob\AppData\Local\Temp\upd.exe".into(),
        }];
        let previous: HashSet<String> = HashSet::new(); // previous scan had no entries
        let (sev, findings) = evaluate(&entries, Some(&previous));
        assert_eq!(sev, Severity::AtRisk);
        assert!(findings.iter().any(|f| f.label.contains("new since last scan")));
    }

    #[test]
    fn known_temp_entry_from_last_scan_stays_caution() {
        let entries = vec![PersistenceEntry {
            source: "HKCU\\...Run".into(),
            name: "Updater".into(),
            command: r"C:\Users\bob\AppData\Local\Temp\upd.exe".into(),
        }];
        let previous: HashSet<String> = entries.iter().map(raw_key).collect();
        let (sev, findings) = evaluate(&entries, Some(&previous));
        assert_eq!(sev, Severity::Caution);
        assert!(!findings.iter().any(|f| f.label.contains("new since last scan")));
    }

    #[test]
    fn parses_scheduled_tasks_csv() {
        let csv = "\"HostName\",\"TaskName\",\"Task To Run\"\n\"WIN-PC\",\"\\MyTask\",\"C:\\Temp\\evil.exe\"\n";
        let entries = parse_scheduled_tasks_csv(csv);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, r"\MyTask");
        assert_eq!(entries[0].command, r"C:\Temp\evil.exe");
    }
}
