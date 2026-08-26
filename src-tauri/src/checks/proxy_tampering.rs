//! Browser/system proxy tampering check.
//!
//! Data source: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
//! Settings` (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`) - the WinINET
//! settings that Edge, Chrome, and most other Windows apps inherit unless a
//! browser overrides them independently. Deliberately scoped to this system
//! proxy configuration only, not full per-browser extension/policy auditing;
//! see `DECISIONS.md` for why (matches the driver check's existing pattern of
//! documenting a narrowed v1 scope).

use super::{CheckCategory, CheckResult, Finding, PermissionKind, RemediationAction, ScanContext, SecurityCheck, Severity};
use winreg::enums::*;
use winreg::RegKey;

fn open_proxy_action() -> Finding {
    Finding::with_action(
        "Fix this",
        "Open Proxy settings to review or turn off the configured proxy/PAC script.",
        RemediationAction::DeepLink {
            uri: "ms-settings:network-proxy".to_string(),
            label: "Open Proxy settings".to_string(),
        },
    )
}

pub struct ProxyTamperingCheck;

const DATA_SOURCE: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyState {
    pub proxy_enabled: bool,
    pub proxy_server: Option<String>,
    pub auto_config_url: Option<String>,
}

pub fn read_proxy_settings() -> ProxyState {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") else {
        return ProxyState::default();
    };

    let proxy_enabled = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1;
    let proxy_server = key
        .get_value::<String, _>("ProxyServer")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let auto_config_url = key
        .get_value::<String, _>("AutoConfigURL")
        .ok()
        .filter(|s| !s.trim().is_empty());

    ProxyState { proxy_enabled, proxy_server, auto_config_url }
}

fn host_of(proxy_server: &str) -> String {
    // ProxyServer can be "host:port" or a per-protocol list like
    // "http=host:80;https=host:443" - take the first host found either way.
    let first_entry = proxy_server.split(';').next().unwrap_or(proxy_server);
    let after_eq = first_entry.split('=').next_back().unwrap_or(first_entry);
    after_eq.split(':').next().unwrap_or(after_eq).trim().to_ascii_lowercase()
}

fn is_loopback_host(host: &str) -> bool {
    host.is_empty() || host == "127.0.0.1" || host == "localhost" || host == "::1"
}

pub fn evaluate(state: &ProxyState) -> (Severity, Vec<Finding>, String) {
    let mut findings = vec![Finding::new("Proxy enabled", if state.proxy_enabled { "Yes" } else { "No" })];
    if let Some(server) = &state.proxy_server {
        findings.push(Finding::new("Proxy server", server.clone()));
    }
    if let Some(pac) = &state.auto_config_url {
        findings.push(Finding::new("Auto-configuration (PAC) URL", pac.clone()));
    }

    let proxy_host_is_suspicious = state.proxy_enabled
        && state
            .proxy_server
            .as_deref()
            .map(|s| !is_loopback_host(&host_of(s)))
            .unwrap_or(false);

    let pac_is_suspicious = state
        .auto_config_url
        .as_deref()
        .map(|url| {
            !(url.to_ascii_lowercase().starts_with("http://127.0.0.1")
                || url.to_ascii_lowercase().starts_with("http://localhost"))
        })
        .unwrap_or(false);

    if proxy_host_is_suspicious {
        (
            Severity::AtRisk,
            findings,
            "A system proxy server is configured, which routes this device's traffic through a third party.".to_string(),
        )
    } else if pac_is_suspicious {
        (
            Severity::Caution,
            findings,
            "A proxy auto-configuration (PAC) script is configured for this device.".to_string(),
        )
    } else {
        (Severity::Ok, findings, "No unexpected system proxy or auto-configuration script is set.".to_string())
    }
}

impl SecurityCheck for ProxyTamperingCheck {
    fn id(&self) -> &'static str {
        "browser_proxy_tampering"
    }

    fn name(&self) -> &'static str {
        "System Proxy Configuration"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::ProxySettings
    }

    fn permission_description(&self) -> &'static str {
        "Reads the current user's system proxy and PAC (auto-configuration) settings from the registry, to catch traffic silently being redirected through a proxy. Does not audit individual browser extensions or policies."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        let state = read_proxy_settings();
        let (severity, mut findings, verdict) = evaluate(&state);
        let remediation = if severity != Severity::Ok {
            findings.push(open_proxy_action());
            Some(
                "Open Settings > Network & Internet > Proxy and confirm the proxy server or PAC script shown is one you configured (e.g. a known corporate proxy). If not, disable it.".to_string(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_is_ok() {
        let state = ProxyState::default();
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn loopback_proxy_is_ok() {
        let state = ProxyState { proxy_enabled: true, proxy_server: Some("127.0.0.1:8080".to_string()), auto_config_url: None };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn external_proxy_is_at_risk() {
        let state = ProxyState { proxy_enabled: true, proxy_server: Some("evil.example.com:3128".to_string()), auto_config_url: None };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::AtRisk);
    }

    #[test]
    fn remote_pac_is_caution() {
        let state = ProxyState { proxy_enabled: false, proxy_server: None, auto_config_url: Some("http://10.0.0.5/proxy.pac".to_string()) };
        let (sev, _, _) = evaluate(&state);
        assert_eq!(sev, Severity::Caution);
    }

    #[test]
    fn extracts_host_from_protocol_list() {
        assert_eq!(host_of("http=proxy.corp.com:80;https=proxy.corp.com:443"), "proxy.corp.com");
        assert_eq!(host_of("proxy.corp.com:8080"), "proxy.corp.com");
    }
}
