//! Wi-Fi security posture check.
//!
//! Data source: `netsh wlan show interfaces` (no elevation required). We
//! parse the `State`, `SSID` and `Authentication` fields of the active
//! interface.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;
use std::collections::HashMap;

pub struct WifiSecurityCheck;

const DATA_SOURCE: &str = "netsh wlan show interfaces";

/// SSID substrings that suggest a public / default-router network, used as
/// a lightweight heuristic only - not a definitive signal.
const SUSPECT_SSID_HINTS: &[&str] = &[
    "free", "public", "guest", "airport", "cafe", "coffee", "hotel", "xfinitywifi",
    "attwifi", "linksys", "netgear", "dlink", "tp-link", "default",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiInterfaceInfo {
    pub state: String,
    pub ssid: Option<String>,
    pub authentication: Option<String>,
}

/// Parses the key/value block output of `netsh wlan show interfaces` for a
/// single interface. Defensive against missing fields, extra whitespace,
/// and localized colons inside values (splits only on the *first* `:`).
pub fn parse_wifi_interfaces(output: &str) -> Option<WifiInterfaceInfo> {
    let mut fields: HashMap<String, String> = HashMap::new();
    for line in output.lines() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_ascii_lowercase();
            let value = line[idx + 1..].trim().to_string();
            if !key.is_empty() {
                fields.insert(key, value);
            }
        }
    }

    let state = fields.get("state")?.clone();
    Some(WifiInterfaceInfo {
        state,
        ssid: fields.get("ssid").cloned().filter(|s| !s.is_empty()),
        authentication: fields.get("authentication").cloned().filter(|s| !s.is_empty()),
    })
}

fn looks_like_public_ssid(ssid: &str) -> bool {
    let lower = ssid.to_ascii_lowercase();
    SUSPECT_SSID_HINTS.iter().any(|hint| lower.contains(hint))
}

/// Pure evaluation logic, separated from OS interaction so it is
/// unit-testable without shelling out.
pub fn evaluate(info: Option<&WifiInterfaceInfo>) -> (Severity, String, Vec<Finding>, Option<String>) {
    let Some(info) = info else {
        return (
            Severity::Ok,
            "No active Wi-Fi interface detected (likely on wired Ethernet).".to_string(),
            vec![Finding::new(
                "Wi-Fi interface",
                "No connected wireless interface was reported by netsh.",
            )],
            None,
        );
    };

    if !info.state.eq_ignore_ascii_case("connected") {
        return (
            Severity::Ok,
            format!("Wi-Fi adapter present but not connected (state: {}).", info.state),
            vec![Finding::new("Adapter state", info.state.clone())],
            None,
        );
    }

    let ssid = info.ssid.clone().unwrap_or_else(|| "(unknown SSID)".to_string());
    let auth = info.authentication.clone().unwrap_or_else(|| "unknown".to_string());
    let auth_lower = auth.to_ascii_lowercase();

    let mut findings = vec![
        Finding::new("SSID", ssid.clone()),
        Finding::new("Authentication", auth.clone()),
    ];

    if auth_lower.contains("open") {
        findings.push(Finding::new(
            "Risk",
            "Open networks send all traffic unencrypted and allow anyone nearby to read it.",
        ));
        return (
            Severity::AtRisk,
            format!("Connected to \"{ssid}\" with no encryption (Open network)."),
            findings,
            Some(
                "Avoid transmitting sensitive data on this network. Prefer a WPA2/WPA3 network or use a trusted VPN."
                    .to_string(),
            ),
        );
    }

    if auth_lower.contains("wep") {
        findings.push(Finding::new(
            "Risk",
            "WEP encryption is broken and can be cracked in minutes with widely available tools.",
        ));
        return (
            Severity::AtRisk,
            format!("Connected to \"{ssid}\" using WEP, an obsolete and broken encryption standard."),
            findings,
            Some("Reconnect using a WPA2 or WPA3 network, or ask the network owner to upgrade their router.".to_string()),
        );
    }

    if looks_like_public_ssid(&ssid) {
        findings.push(Finding::new(
            "Heuristic",
            "SSID name resembles a public hotspot or default router name.",
        ));
        return (
            Severity::Caution,
            format!("Connected to \"{ssid}\" ({auth}) - the network name suggests a public or default-configured hotspot."),
            findings,
            Some("Public and default-named networks are more likely to be poorly secured or shared with strangers. Consider a VPN.".to_string()),
        );
    }

    (
        Severity::Ok,
        format!("Connected to \"{ssid}\" using {auth}."),
        findings,
        None,
    )
}

impl SecurityCheck for WifiSecurityCheck {
    fn id(&self) -> &'static str {
        "wifi_security_posture"
    }

    fn name(&self) -> &'static str {
        "Wi-Fi Security Posture"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::WifiProfile
    }

    fn permission_description(&self) -> &'static str {
        "Reads the security type (Open/WEP/WPA2/WPA3) and name of the Wi-Fi network you're currently connected to, via `netsh wlan show interfaces`."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let info = run_command("netsh", &["wlan", "show", "interfaces"])
            .ok()
            .and_then(|out| parse_wifi_interfaces(&out));

        let (severity, verdict, findings, remediation) = evaluate(info.as_ref());

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

    const SAMPLE_CONNECTED_WPA2: &str = r#"
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : HomeNetwork_5G
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
"#;

    const SAMPLE_OPEN: &str = r#"
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Free Airport WiFi
    Authentication         : Open
"#;

    const SAMPLE_DISCONNECTED: &str = r#"
    Name                   : Wi-Fi
    State                  : disconnected
"#;

    #[test]
    fn parses_connected_interface() {
        let info = parse_wifi_interfaces(SAMPLE_CONNECTED_WPA2).unwrap();
        assert_eq!(info.state, "connected");
        assert_eq!(info.ssid.as_deref(), Some("HomeNetwork_5G"));
        assert_eq!(info.authentication.as_deref(), Some("WPA2-Personal"));
    }

    #[test]
    fn wpa2_home_network_is_ok() {
        let info = parse_wifi_interfaces(SAMPLE_CONNECTED_WPA2).unwrap();
        let (sev, _, _, _) = evaluate(Some(&info));
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn open_network_is_at_risk() {
        let info = parse_wifi_interfaces(SAMPLE_OPEN).unwrap();
        let (sev, _, _, remediation) = evaluate(Some(&info));
        assert_eq!(sev, Severity::AtRisk);
        assert!(remediation.is_some());
    }

    #[test]
    fn public_sounding_ssid_is_caution_even_with_wpa2() {
        let info = WifiInterfaceInfo {
            state: "connected".to_string(),
            ssid: Some("Airport Free WiFi".to_string()),
            authentication: Some("WPA2-Personal".to_string()),
        };
        let (sev, _, _, _) = evaluate(Some(&info));
        assert_eq!(sev, Severity::Caution);
    }

    #[test]
    fn disconnected_adapter_is_ok() {
        let info = parse_wifi_interfaces(SAMPLE_DISCONNECTED).unwrap();
        let (sev, _, _, _) = evaluate(Some(&info));
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn missing_interface_is_ok_not_error() {
        let (sev, _, _, _) = evaluate(None);
        assert_eq!(sev, Severity::Ok);
    }
}
