//! Open listening ports check.
//!
//! Data source: `netstat -ano` (listening TCP/UDP sockets + owning PID),
//! cross-referenced with the process table already captured in
//! [`ScanContext`] to name the owning process.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use sysinfo::Pid;

pub struct OpenPortsCheck;

const DATA_SOURCE: &str = "netstat -ano";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetstatEntry {
    pub proto: String,
    pub local_addr: String,
    pub local_port: u16,
    pub foreign_addr: String,
    pub state: Option<String>,
    pub pid: u32,
}

/// Parses `netstat -ano` output. Tolerant of the header rows, IPv6
/// addresses (`[::]:port`), and UDP rows that have no `State` column.
pub fn parse_netstat(output: &str) -> Vec<NetstatEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if !(trimmed.starts_with("TCP") || trimmed.starts_with("UDP")) {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        // TCP: Proto Local Foreign State PID (5 cols)
        // UDP: Proto Local Foreign PID       (4 cols)
        let (proto, local, foreign, state, pid_str) = match (cols.len(), cols.first().copied()) {
            (5, Some("TCP")) => (cols[0], cols[1], cols[2], Some(cols[3]), cols[4]),
            (4, Some("UDP")) => (cols[0], cols[1], cols[2], None, cols[3]),
            _ => continue,
        };

        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        let Some((addr, port_str)) = split_host_port(local) else { continue };
        let Ok(port) = port_str.parse::<u16>() else { continue };

        entries.push(NetstatEntry {
            proto: proto.to_string(),
            local_addr: addr,
            local_port: port,
            foreign_addr: foreign.to_string(),
            state: state.map(|s| s.to_string()),
            pid,
        });
    }
    entries
}

/// Splits `host:port`, handling bracketed IPv6 (`[::]:445`) and bare `*`.
fn split_host_port(s: &str) -> Option<(String, String)> {
    if let Some(rest) = s.strip_prefix('[') {
        let mut parts = rest.splitn(2, "]:");
        let host = parts.next()?;
        let port = parts.next()?;
        return Some((format!("[{host}]"), port.to_string()));
    }
    let idx = s.rfind(':')?;
    Some((s[..idx].to_string(), s[idx + 1..].to_string()))
}

fn is_listening(e: &NetstatEntry) -> bool {
    match &e.state {
        Some(s) => s.eq_ignore_ascii_case("LISTENING"),
        // UDP sockets bound locally behave like listeners for our purposes.
        None => true,
    }
}

fn is_all_interfaces(addr: &str) -> bool {
    addr == "0.0.0.0" || addr == "[::]" || addr == "*"
}

struct RiskyPort {
    port: u16,
    label: &'static str,
    severity: Severity,
}

const RISKY_PORTS: &[RiskyPort] = &[
    RiskyPort { port: 23, label: "Telnet (unencrypted remote shell)", severity: Severity::AtRisk },
    RiskyPort { port: 21, label: "FTP (unencrypted file transfer)", severity: Severity::Caution },
    RiskyPort { port: 3389, label: "RDP (Remote Desktop)", severity: Severity::Caution },
    RiskyPort { port: 5900, label: "VNC remote desktop", severity: Severity::Caution },
    RiskyPort { port: 5938, label: "TeamViewer remote access", severity: Severity::Caution },
    RiskyPort { port: 7070, label: "AnyDesk remote access", severity: Severity::Caution },
    RiskyPort { port: 4444, label: "Commonly used by exploit/backdoor tooling (e.g. Metasploit default)", severity: Severity::AtRisk },
    RiskyPort { port: 31337, label: "Classic backdoor port (\"elite\")", severity: Severity::AtRisk },
    RiskyPort { port: 6666, label: "Commonly used by IRC-based botnets/backdoors", severity: Severity::AtRisk },
    RiskyPort { port: 1080, label: "SOCKS proxy - can indicate tunneling malware", severity: Severity::Caution },
];

fn process_name(ctx: &ScanContext, pid: u32) -> String {
    ctx.system
        .process(Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| format!("PID {pid} (process exited)"))
}

pub fn evaluate(entries: &[NetstatEntry], ctx: &ScanContext) -> (Severity, Vec<Finding>) {
    let mut severity = Severity::Ok;
    let mut findings = Vec::new();
    let mut seen_ports = std::collections::HashSet::new();

    let listeners: Vec<&NetstatEntry> = entries.iter().filter(|e| is_listening(e)).collect();

    for entry in &listeners {
        if !seen_ports.insert((entry.local_port, entry.pid)) {
            continue;
        }
        if let Some(risky) = RISKY_PORTS.iter().find(|r| r.port == entry.local_port) {
            let scope = if is_all_interfaces(&entry.local_addr) {
                "all interfaces"
            } else {
                "localhost/specific interface only"
            };
            if risky.severity > severity {
                severity = risky.severity;
            }
            findings.push(Finding::new(
                format!("Port {} ({})", entry.local_port, risky.label),
                format!(
                    "{} listening on {} - owned by {}",
                    entry.proto,
                    scope,
                    process_name(ctx, entry.pid)
                ),
            ));
        }
    }

    findings.push(Finding::new(
        "Total listening sockets",
        listeners.len().to_string(),
    ));

    if findings.len() == 1 {
        findings.insert(0, Finding::new("Result", "No unusual listening ports found"));
    }

    (severity, findings)
}

impl SecurityCheck for OpenPortsCheck {
    fn id(&self) -> &'static str {
        "open_listening_ports"
    }

    fn name(&self) -> &'static str {
        "Open Listening Ports"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::ListeningPorts
    }

    fn permission_description(&self) -> &'static str {
        "Enumerates locally listening TCP/UDP ports and the process that owns each one, via `netstat -ano`."
    }

    fn run(&self, ctx: &ScanContext) -> CheckResult {
        match run_command("netstat", &["-ano"]) {
            Ok(output) => {
                let entries = parse_netstat(&output);
                let (severity, findings) = evaluate(&entries, ctx);
                let verdict = match severity {
                    Severity::Ok => "No unusual listening ports found.".to_string(),
                    Severity::Caution => "One or more listening ports are worth reviewing.".to_string(),
                    Severity::AtRisk => "Listening port(s) associated with high-risk / backdoor services found.".to_string(),
                };
                let remediation = if severity != Severity::Ok {
                    Some("Confirm each flagged port is expected (e.g. a remote-access tool you installed). If not, stop the service/process and consider uninstalling it.".to_string())
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
                verdict: "Could not enumerate listening ports.".to_string(),
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
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       999
  TCP    192.168.1.5:54321      93.184.216.34:443      ESTABLISHED     5678
  UDP    0.0.0.0:5353           *:*                                    4321
"#;

    #[test]
    fn parses_tcp_and_udp() {
        let entries = parse_netstat(SAMPLE);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].local_port, 135);
        assert_eq!(entries[0].state.as_deref(), Some("LISTENING"));
        assert_eq!(entries[3].proto, "UDP");
        assert!(entries[3].state.is_none());
    }

    #[test]
    fn flags_rdp_listening_on_all_interfaces() {
        let entries = parse_netstat(SAMPLE);
        let ctx = ScanContext::new();
        let (severity, findings) = evaluate(&entries, &ctx);
        assert_eq!(severity, Severity::Caution);
        assert!(findings.iter().any(|f| f.label.contains("3389")));
    }

    #[test]
    fn established_connection_not_counted_as_listener() {
        let entries = parse_netstat(SAMPLE);
        let listeners: Vec<_> = entries.iter().filter(|e| is_listening(e)).collect();
        assert!(!listeners.iter().any(|e| e.local_port == 54321));
    }
}
