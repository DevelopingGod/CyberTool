//! Default gateway / DNS / hosts file integrity check.
//!
//! Data sources: `ipconfig /all` (DNS servers + default gateway) and the
//! Windows hosts file at `%SystemRoot%\System32\drivers\etc\hosts`.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use std::path::PathBuf;

pub struct DnsGatewayCheck;

const DATA_SOURCE: &str = "ipconfig /all; %SystemRoot%\\System32\\drivers\\etc\\hosts";

/// Well-known public resolvers that are common and not treated as
/// suspicious even though they aren't private addresses.
const KNOWN_PUBLIC_RESOLVERS: &[&str] = &[
    "8.8.8.8", "8.8.4.4", // Google
    "1.1.1.1", "1.0.0.1", // Cloudflare
    "9.9.9.9", "149.112.112.112", // Quad9
    "208.67.222.222", "208.67.220.220", // OpenDNS
];

/// A representative sample of high-value domains that malware/hosts-file
/// hijacks commonly target (search engines, OS update, major banks/identity
/// providers). Not exhaustive - a documented, intentionally small v1 list.
const SENSITIVE_DOMAINS: &[&str] = &[
    "google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "windowsupdate.com",
    "update.microsoft.com",
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "apple.com",
    "icloud.com",
];

#[derive(Debug, Default, Clone)]
pub struct IpConfigInfo {
    pub dns_servers: Vec<String>,
    pub default_gateways: Vec<String>,
}

/// Parses `ipconfig /all` output defensively: DNS Servers can span multiple
/// lines (continuation lines have no `label :` prefix), and there can be
/// several adapters.
pub fn parse_ipconfig(output: &str) -> IpConfigInfo {
    let mut info = IpConfigInfo::default();
    let mut in_dns_block = false;

    for raw_line in output.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            in_dns_block = false;
            continue;
        }

        if let Some(idx) = line.find(':') {
            // Has a "Label . . . : value" form only if there's meaningful
            // text (not just dots/spaces) before the colon.
            let label_part = line[..idx].trim();
            let looks_like_label = label_part.chars().any(|c| c.is_alphabetic());
            if looks_like_label {
                let value = line[idx + 1..].trim().to_string();
                let label_lower = label_part.to_ascii_lowercase();
                if label_lower.contains("dns servers") {
                    in_dns_block = true;
                    if !value.is_empty() && is_ip_like(&value) {
                        info.dns_servers.push(value);
                    }
                    continue;
                }
                if label_lower.contains("default gateway") {
                    in_dns_block = false;
                    if !value.is_empty() && is_ip_like(&value) {
                        info.default_gateways.push(value);
                    }
                    continue;
                }
                in_dns_block = false;
                continue;
            }
        }

        // Continuation line: bare IP under a "DNS Servers" block.
        if in_dns_block && is_ip_like(trimmed) {
            info.dns_servers.push(trimmed.to_string());
        }
    }

    info
}

fn is_ip_like(s: &str) -> bool {
    // Accepts both IPv4 and IPv6 literals without pulling in a full parser.
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '%')
}

fn is_private_or_local(ip: &str) -> bool {
    if ip.contains(':') {
        return ip.starts_with("fe80") || ip == "::1";
    }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    match octets[0].parse::<u8>() {
        Ok(10) => true,
        Ok(172) => octets[1]
            .parse::<u8>()
            .map(|n| (16..=31).contains(&n))
            .unwrap_or(false),
        Ok(192) => octets[1] == "168",
        Ok(127) => true,
        _ => false,
    }
}

/// One parsed, non-comment `hosts` file entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    pub ip: String,
    pub hostname: String,
}

/// Parses the Windows hosts file format: `IP hostname [# comment]`, `#`
/// full-line comments, blank lines ignored.
pub fn parse_hosts_file(content: &str) -> Vec<HostsEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(ip), Some(hostname)) = (parts.next(), parts.next()) {
            entries.push(HostsEntry {
                ip: ip.to_string(),
                hostname: hostname.to_lowercase(),
            });
        }
    }
    entries
}

fn evaluate_hosts(entries: &[HostsEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for entry in entries {
        let is_loopback = entry.ip == "127.0.0.1" || entry.ip == "::1" || entry.ip == "0.0.0.0";
        if is_loopback {
            continue;
        }
        for domain in SENSITIVE_DOMAINS {
            if entry.hostname == *domain || entry.hostname.ends_with(&format!(".{domain}")) {
                findings.push(Finding::new(
                    "Suspicious hosts entry",
                    format!("{} is redirected to {} via the hosts file", entry.hostname, entry.ip),
                ));
            }
        }
    }
    findings
}

pub fn hosts_file_path() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(system_root).join("System32\\drivers\\etc\\hosts")
}

impl SecurityCheck for DnsGatewayCheck {
    fn id(&self) -> &'static str {
        "dns_gateway_integrity"
    }

    fn name(&self) -> &'static str {
        "DNS & Gateway Integrity"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::DnsHostsConfig
    }

    fn permission_description(&self) -> &'static str {
        "Reads your configured DNS servers and default gateway via `ipconfig /all`, and reads the local hosts file for unauthorized redirects."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let mut findings = Vec::new();
        let mut severity = Severity::Ok;
        let mut verdict_parts: Vec<String> = Vec::new();
        let mut remediation: Option<String> = None;

        match run_command("ipconfig", &["/all"]) {
            Ok(output) => {
                let info = parse_ipconfig(&output);
                if info.dns_servers.is_empty() {
                    findings.push(Finding::new("DNS servers", "None reported"));
                } else {
                    findings.push(Finding::new("DNS servers", info.dns_servers.join(", ")));
                }
                if !info.default_gateways.is_empty() {
                    findings.push(Finding::new("Default gateway", info.default_gateways.join(", ")));
                }

                let unexpected: Vec<&String> = info
                    .dns_servers
                    .iter()
                    .filter(|dns| {
                        !is_private_or_local(dns)
                            && !KNOWN_PUBLIC_RESOLVERS.contains(&dns.as_str())
                            && !info.default_gateways.contains(dns)
                    })
                    .collect();

                if !unexpected.is_empty() {
                    severity = Severity::Caution;
                    let list = unexpected
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    findings.push(Finding::new(
                        "Unfamiliar DNS server",
                        format!("{list} is a public IP not on the router/known-resolver list"),
                    ));
                    verdict_parts.push(format!("Using an unfamiliar DNS server ({list})."));
                    remediation = Some(
                        "Verify this DNS server is one you (or your VPN/router) intentionally configured. Unexpected DNS servers can redirect you to malicious sites."
                            .to_string(),
                    );
                }
            }
            Err(e) => {
                findings.push(Finding::new("ipconfig error", e));
                verdict_parts.push("Could not read network configuration.".to_string());
            }
        }

        match std::fs::read_to_string(hosts_file_path()) {
            Ok(content) => {
                let hosts_findings = evaluate_hosts(&parse_hosts_file(&content));
                if !hosts_findings.is_empty() {
                    severity = Severity::AtRisk;
                    verdict_parts.push(format!(
                        "{} suspicious hosts file redirect(s) found.",
                        hosts_findings.len()
                    ));
                    remediation = Some(
                        "Open the hosts file (System32\\drivers\\etc\\hosts) as Administrator and remove any entries you did not add."
                            .to_string(),
                    );
                    findings.extend(hosts_findings);
                }
            }
            Err(e) => {
                findings.push(Finding::new("hosts file", format!("could not be read: {e}")));
            }
        }

        if verdict_parts.is_empty() {
            verdict_parts.push("DNS servers and hosts file look normal.".to_string());
        }

        CheckResult {
            id: self.id().to_string(),
            name: self.name().to_string(),
            category: self.category(),
            severity,
            verdict: verdict_parts.join(" "),
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

    const SAMPLE_IPCONFIG: &str = r#"
Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
"#;

    #[test]
    fn parses_gateway_and_multiline_dns() {
        let info = parse_ipconfig(SAMPLE_IPCONFIG);
        assert_eq!(info.default_gateways, vec!["192.168.1.1"]);
        assert_eq!(info.dns_servers, vec!["192.168.1.1", "8.8.8.8"]);
    }

    #[test]
    fn private_ip_detection() {
        assert!(is_private_or_local("192.168.1.1"));
        assert!(is_private_or_local("10.0.0.1"));
        assert!(is_private_or_local("172.16.5.5"));
        assert!(!is_private_or_local("172.32.5.5"));
        assert!(!is_private_or_local("203.0.113.5"));
    }

    #[test]
    fn parses_hosts_file_ignoring_comments() {
        let content = "# comment\n127.0.0.1 localhost\n10.0.0.5 evil.example.com\n";
        let entries = parse_hosts_file(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].ip, "10.0.0.5");
    }

    #[test]
    fn flags_sensitive_domain_redirect() {
        let entries = vec![HostsEntry {
            ip: "203.0.113.9".to_string(),
            hostname: "login.microsoftonline.com".to_string(),
        }];
        let findings = evaluate_hosts(&entries);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_loopback_hosts_entries() {
        let entries = vec![HostsEntry {
            ip: "127.0.0.1".to_string(),
            hostname: "google.com".to_string(),
        }];
        assert!(evaluate_hosts(&entries).is_empty());
    }
}
