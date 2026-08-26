//! ARP table anomaly heuristic - a lightweight MITM/ARP-spoofing indicator
//! that reads the OS ARP cache rather than capturing packets.
//!
//! Data source: `arp -a` (ARP cache) and `ipconfig /all` (to identify the
//! default gateway IP).

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use crate::checks::dns_gateway::parse_ipconfig;
use crate::sysutil::run_command;
use std::collections::HashMap;

pub struct ArpAnomalyCheck;

const DATA_SOURCE: &str = "arp -a; ipconfig /all";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
}

/// Parses `arp -a` output across one or more interface sections.
pub fn parse_arp_table(output: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Interface") || trimmed.starts_with("Internet Address") {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 2 {
            let ip = cols[0];
            let mac = cols[1];
            let looks_like_ip = ip.chars().filter(|c| *c == '.').count() == 3;
            let looks_like_mac = mac.contains('-') || mac.contains(':');
            if looks_like_ip && looks_like_mac {
                entries.push(ArpEntry {
                    ip: ip.to_string(),
                    mac: mac.to_ascii_lowercase(),
                });
            }
        }
    }
    entries
}

/// Detects the two classic lightweight ARP-cache anomalies:
/// 1. The default gateway IP resolving to more than one distinct MAC.
/// 2. A single MAC address claiming an unusually large number of distinct
///    IPs (possible spoofing tool), reported as a softer heuristic.
pub fn find_anomalies(entries: &[ArpEntry], gateway_ips: &[String]) -> (Severity, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut severity = Severity::Ok;

    let mut ip_to_macs: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut mac_to_ips: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in entries {
        ip_to_macs.entry(e.ip.as_str()).or_default().push(e.mac.as_str());
        mac_to_ips.entry(e.mac.as_str()).or_default().push(e.ip.as_str());
    }

    for gw in gateway_ips {
        if let Some(macs) = ip_to_macs.get(gw.as_str()) {
            let unique_macs: std::collections::HashSet<&str> = macs.iter().copied().collect();
            if unique_macs.len() > 1 {
                severity = Severity::AtRisk;
                findings.push(Finding::new(
                    "Gateway MAC conflict",
                    format!(
                        "Default gateway {gw} maps to {} different MAC addresses: {}",
                        unique_macs.len(),
                        unique_macs.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                ));
            }
        }
    }

    const MANY_IPS_THRESHOLD: usize = 8;
    for (mac, ips) in mac_to_ips.iter() {
        let unique_ips: std::collections::HashSet<&str> = ips.iter().copied().collect();
        if unique_ips.len() >= MANY_IPS_THRESHOLD {
            if severity == Severity::Ok {
                severity = Severity::Caution;
            }
            findings.push(Finding::new(
                "Single MAC, many IPs",
                format!(
                    "{mac} appears in the ARP cache for {} different IP addresses, which can indicate ARP spoofing (or a router/virtualization NIC)",
                    unique_ips.len()
                ),
            ));
        }
    }

    if findings.is_empty() {
        findings.push(Finding::new(
            "ARP cache",
            format!("{} entries checked, no gateway MAC conflicts found", entries.len()),
        ));
    }

    (severity, findings)
}

impl SecurityCheck for ArpAnomalyCheck {
    fn id(&self) -> &'static str {
        "arp_anomaly_heuristic"
    }

    fn name(&self) -> &'static str {
        "ARP Table Anomaly Check"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::ArpCache
    }

    fn permission_description(&self) -> &'static str {
        "Reads the local ARP cache (`arp -a`) to look for signs of ARP spoofing, such as the gateway address resolving to more than one MAC address."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let gateway_ips = run_command("ipconfig", &["/all"])
            .map(|out| parse_ipconfig(&out).default_gateways)
            .unwrap_or_default();

        match run_command("arp", &["-a"]) {
            Ok(output) => {
                let entries = parse_arp_table(&output);
                let (severity, findings) = find_anomalies(&entries, &gateway_ips);
                let verdict = match severity {
                    Severity::Ok => "No ARP spoofing indicators found.".to_string(),
                    Severity::Caution => "Possible ARP anomaly detected - worth a closer look.".to_string(),
                    Severity::AtRisk => "Gateway MAC conflict detected - possible ARP spoofing / MITM.".to_string(),
                };
                let remediation = if severity != Severity::Ok {
                    Some(
                        "Disconnect from this network if untrusted, reconnect to refresh the ARP cache, and consider running a wired connection or trusted VPN."
                            .to_string(),
                    )
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
                verdict: "Could not read the ARP cache.".to_string(),
                findings: vec![Finding::new("arp error", e)],
                remediation: Some("Ensure the `arp` command is available and try again.".to_string()),
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
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1            aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.20           11-22-33-44-55-66     dynamic
  192.168.1.255          ff-ff-ff-ff-ff-ff     static
"#;

    #[test]
    fn parses_entries() {
        let entries = parse_arp_table(SAMPLE);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].ip, "192.168.1.1");
        assert_eq!(entries[0].mac, "aa-bb-cc-dd-ee-ff");
    }

    #[test]
    fn no_conflict_is_ok() {
        let entries = parse_arp_table(SAMPLE);
        let (sev, _) = find_anomalies(&entries, &["192.168.1.1".to_string()]);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn gateway_mac_conflict_is_at_risk() {
        let entries = vec![
            ArpEntry { ip: "192.168.1.1".to_string(), mac: "aa-aa-aa-aa-aa-aa".to_string() },
            ArpEntry { ip: "192.168.1.1".to_string(), mac: "bb-bb-bb-bb-bb-bb".to_string() },
        ];
        let (sev, findings) = find_anomalies(&entries, &["192.168.1.1".to_string()]);
        assert_eq!(sev, Severity::AtRisk);
        assert!(!findings.is_empty());
    }

    #[test]
    fn many_ips_single_mac_is_caution() {
        let entries: Vec<ArpEntry> = (0..10)
            .map(|i| ArpEntry {
                ip: format!("192.168.1.{i}"),
                mac: "aa-aa-aa-aa-aa-aa".to_string(),
            })
            .collect();
        let (sev, _) = find_anomalies(&entries, &[]);
        assert_eq!(sev, Severity::Caution);
    }
}
