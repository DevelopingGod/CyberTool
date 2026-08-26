//! Unusual outbound connections check.
//!
//! Data source: `netstat -ano` (established outbound TCP connections),
//! cross-referenced against a small curated list of ports/patterns
//! associated with remote-access tooling.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use crate::checks::ports::{parse_netstat, NetstatEntry};
use crate::sysutil::run_command;
use sysinfo::Pid;

pub struct OutboundConnectionsCheck;

const DATA_SOURCE: &str = "netstat -ano (established connections)";

struct WatchedPort {
    port: u16,
    label: &'static str,
    severity: Severity,
}

const WATCHED_FOREIGN_PORTS: &[WatchedPort] = &[
    WatchedPort { port: 4444, label: "Common exploit/backdoor callback port", severity: Severity::AtRisk },
    WatchedPort { port: 31337, label: "Classic backdoor port", severity: Severity::AtRisk },
    WatchedPort { port: 6667, label: "IRC - historically used for botnet command & control", severity: Severity::Caution },
    WatchedPort { port: 5938, label: "TeamViewer relay traffic", severity: Severity::Caution },
    WatchedPort { port: 7070, label: "AnyDesk relay traffic", severity: Severity::Caution },
    WatchedPort { port: 1080, label: "SOCKS proxy tunnel", severity: Severity::Caution },
];

fn is_established(e: &NetstatEntry) -> bool {
    e.state.as_deref().map(|s| s.eq_ignore_ascii_case("ESTABLISHED")).unwrap_or(false)
}

fn foreign_port(addr: &str) -> Option<u16> {
    let idx = addr.rfind(':')?;
    addr[idx + 1..].trim_end_matches(']').parse().ok()
}

fn process_name(ctx: &ScanContext, pid: u32) -> String {
    ctx.system
        .process(Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| format!("PID {pid} (process exited)"))
}

pub fn evaluate(entries: &[NetstatEntry], ctx: &ScanContext) -> (Severity, Vec<Finding>) {
    let mut severity = Severity::Ok;
    let mut findings = Vec::new();

    let outbound: Vec<&NetstatEntry> = entries.iter().filter(|e| is_established(e)).collect();

    for entry in &outbound {
        let Some(port) = foreign_port(&entry.foreign_addr) else { continue };
        if let Some(watched) = WATCHED_FOREIGN_PORTS.iter().find(|w| w.port == port) {
            if watched.severity > severity {
                severity = watched.severity;
            }
            findings.push(Finding::new(
                format!("Outbound to {} ({})", entry.foreign_addr, watched.label),
                format!("Owned by {}", process_name(ctx, entry.pid)),
            ));
        }
    }

    findings.push(Finding::new(
        "Established outbound connections",
        outbound.len().to_string(),
    ));
    if findings.len() == 1 {
        findings.insert(0, Finding::new("Result", "No connections matched known remote-access patterns"));
    }

    (severity, findings)
}

impl SecurityCheck for OutboundConnectionsCheck {
    fn id(&self) -> &'static str {
        "unusual_outbound_connections"
    }

    fn name(&self) -> &'static str {
        "Unusual Outbound Connections"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::OutboundConnections
    }

    fn permission_description(&self) -> &'static str {
        "Lists active outbound network connections and their owning process, via `netstat -ano`, and compares destination ports against known remote-access-tool patterns."
    }

    fn run(&self, ctx: &ScanContext) -> CheckResult {
        match run_command("netstat", &["-ano"]) {
            Ok(output) => {
                let entries = parse_netstat(&output);
                let (severity, findings) = evaluate(&entries, ctx);
                let verdict = match severity {
                    Severity::Ok => "No outbound connections matched known remote-access-tool patterns.".to_string(),
                    Severity::Caution => "Outbound connection(s) matching remote-access tooling patterns found - review if expected.".to_string(),
                    Severity::AtRisk => "Outbound connection(s) matching known backdoor/exploit patterns found.".to_string(),
                };
                let remediation = if severity != Severity::Ok {
                    Some("Confirm the owning process/connection is something you recognize and intentionally installed. If not, disconnect from the network and investigate the process.".to_string())
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
                verdict: "Could not enumerate outbound connections.".to_string(),
                findings: vec![Finding::new("netstat error", e)],
                remediation: Some("Ensure `netstat` is available and try again.".to_string()),
                data_source: DATA_SOURCE.to_string(),
                raw_keys: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.5:54321      93.184.216.34:4444     ESTABLISHED     5678
  TCP    192.168.1.5:54322      93.184.216.34:443      ESTABLISHED     5679
"#;

    #[test]
    fn flags_watched_port() {
        let entries = parse_netstat(SAMPLE);
        let ctx = ScanContext::new();
        let (severity, findings) = evaluate(&entries, &ctx);
        assert_eq!(severity, Severity::AtRisk);
        assert!(findings.iter().any(|f| f.label.contains("4444")));
    }

    #[test]
    fn normal_https_not_flagged() {
        let entries = vec![NetstatEntry {
            proto: "TCP".into(),
            local_addr: "192.168.1.5".into(),
            local_port: 54322,
            foreign_addr: "93.184.216.34:443".into(),
            state: Some("ESTABLISHED".into()),
            pid: 1,
        }];
        let ctx = ScanContext::new();
        let (severity, _) = evaluate(&entries, &ctx);
        assert_eq!(severity, Severity::Ok);
    }
}
