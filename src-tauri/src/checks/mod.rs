//! Shared types and trait for all NetGuard security check-agents.
//!
//! Every check-agent is an independent, rule-based module that implements
//! [`SecurityCheck`]. Checks do not share hidden global state; anything a
//! check needs from the OS is either fetched inside `run()` or read from the
//! read-only [`ScanContext`] passed in.

pub mod arp;
pub mod bitlocker;
pub mod credential_protection;
pub mod defender;
pub mod dns_gateway;
pub mod drivers;
pub mod firewall;
pub mod memory_integrity;
pub mod outbound;
pub mod persistence;
pub mod ports;
pub mod process_baseline;
pub mod proxy_tampering;
pub mod rat_signatures;
pub mod rdp_exposure;
pub mod wifi;
pub mod windows_update;

use serde::{Deserialize, Serialize};
use sysinfo::System;

/// High level grouping used for UI iconography / filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckCategory {
    Network,
    Process,
    Persistence,
    System,
}

/// The OS-level capability a check-agent requires. Used both to group
/// permissions in Settings and to render an accurate description of what a
/// check touches before the user consents to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionKind {
    WifiProfile,
    DnsHostsConfig,
    ArpCache,
    ListeningPorts,
    OutboundConnections,
    ProcessList,
    RatSignatures,
    RegistryRunKeys,
    FirewallStatus,
    DefenderStatus,
    DriverList,
    DiskEncryption,
    MemoryIntegrity,
    RdpExposure,
    ProxySettings,
    CredentialProtection,
    UpdateStatus,
}

/// Severity of a single finding / overall check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Ok,
    Caution,
    AtRisk,
}

/// A single structured fact discovered by a check, so the UI can render
/// detail without re-parsing prose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub label: String,
    pub detail: String,
    /// An optional remediation action tied to this specific finding (not the
    /// check as a whole), since a check like Persistence can have several
    /// findings each with a different fixable target (e.g. one flagged
    /// startup entry vs. another). `#[serde(default)]` keeps deserializing
    /// older `history.json` entries (written before this field existed)
    /// working - see `raw_keys` for the same pattern.
    #[serde(default)]
    pub action: Option<RemediationAction>,
}

impl Finding {
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
            action: None,
        }
    }

    pub fn with_action(label: impl Into<String>, detail: impl Into<String>, action: RemediationAction) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
            action: Some(action),
        }
    }
}

/// One in-app remediation action offered on a finding. See `DECISIONS.md`
/// ("Direct in-app remediation safety model") for the full rationale.
///
/// - `DirectFix`: NetGuard performs the change itself, after an explicit
///   per-action confirmation dialog in the UI. Only offered for changes that
///   are safe, reversible, non-destructive, and require no more privilege
///   than the check itself already needed to observe the problem.
/// - `DeepLink`: NetGuard does not touch system state; it opens the correct
///   Windows Settings page / Control Panel applet so the user makes the
///   change themselves. Used for anything requiring elevation, GUI
///   interaction, or that's too consequential to automate (BitLocker,
///   Defender/Core Isolation, Windows Update).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum RemediationAction {
    DirectFix {
        action_id: String,
        label: String,
        #[serde(default)]
        params: std::collections::HashMap<String, String>,
    },
    DeepLink {
        uri: String,
        label: String,
    },
}

/// The outcome of running one check-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub name: String,
    pub category: CheckCategory,
    pub severity: Severity,
    pub verdict: String,
    pub findings: Vec<Finding>,
    pub remediation: Option<String>,
    /// Human readable description of exactly what data source was read
    /// (a specific command / API / registry path), so results are
    /// explainable rather than a black box.
    pub data_source: String,
    /// Stable per-entry identifiers for this check's raw findings (e.g. one
    /// key per startup entry or per process), used only for next-scan
    /// baseline diffing (see `ScanContext::previous_raw_keys`). Empty for
    /// checks that don't diff against a previous scan. Not shown directly in
    /// the UI - it's a diffing aid, not a finding. `#[serde(default)]` keeps
    /// deserializing older `history.json` entries (written before this field
    /// existed) working.
    #[serde(default)]
    pub raw_keys: Vec<String>,
}

/// Distinct state shown on the dashboard for a check that could not be run
/// because permission was denied or is pending an "ask every time" prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state", content = "result")]
pub enum CheckOutcome {
    Completed(CheckResult),
    /// The stored preference is `Denied`; the check was not executed.
    PermissionDenied {
        id: String,
        name: String,
        category: CheckCategory,
    },
    /// The check failed to run for a reason other than permissions (e.g. a
    /// system command was unavailable). Never a panic - always a value.
    Error {
        id: String,
        name: String,
        category: CheckCategory,
        message: String,
    },
}

impl CheckOutcome {
    pub fn id(&self) -> &str {
        match self {
            CheckOutcome::Completed(r) => &r.id,
            CheckOutcome::PermissionDenied { id, .. } => id,
            CheckOutcome::Error { id, .. } => id,
        }
    }

    /// Severity used for the overall rollup. Skipped/errored checks return
    /// `None` so they never silently count as `Ok`.
    pub fn severity(&self) -> Option<Severity> {
        match self {
            CheckOutcome::Completed(r) => Some(r.severity),
            _ => None,
        }
    }
}

/// Read-only shared context passed to every check. Holds data that is
/// expensive to gather so it can be captured once per scan (e.g. the
/// process table) without checks reaching into hidden global state.
pub struct ScanContext {
    pub system: System,
    /// Raw entry keys (`CheckResult::raw_keys`) from the previous scan's
    /// `Completed` outcomes, keyed by check id. Empty on the first-ever scan
    /// (no previous history) - checks that read this must treat an empty/
    /// absent entry as "nothing to diff against," not as "everything is
    /// new," so a first scan behaves exactly like today. Built in
    /// `scan.rs` from `history::latest()`, deliberately *not* from
    /// `history::ScanRecord` directly here, to avoid `checks` depending on
    /// `history` (which itself depends on `checks::CheckOutcome`).
    pub previous_raw_keys: std::collections::HashMap<String, Vec<String>>,
}

impl ScanContext {
    pub fn new() -> Self {
        Self::with_previous(std::collections::HashMap::new())
    }

    pub fn with_previous(previous_raw_keys: std::collections::HashMap<String, Vec<String>>) -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self { system, previous_raw_keys }
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared interface every check-agent implements.
pub trait SecurityCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn category(&self) -> CheckCategory;
    fn required_permission(&self) -> PermissionKind;
    /// Short, user-facing explanation of what OS-level access this check
    /// needs and why, shown in the consent dialog and the Settings list.
    fn permission_description(&self) -> &'static str;
    fn run(&self, ctx: &ScanContext) -> CheckResult;
}

/// Returns every check-agent in the standard v1 catalog, in the order they
/// should run / display.
pub fn all_checks() -> Vec<Box<dyn SecurityCheck>> {
    vec![
        Box::new(wifi::WifiSecurityCheck),
        Box::new(dns_gateway::DnsGatewayCheck),
        Box::new(arp::ArpAnomalyCheck),
        Box::new(ports::OpenPortsCheck),
        Box::new(outbound::OutboundConnectionsCheck),
        Box::new(process_baseline::ProcessBaselineCheck),
        Box::new(rat_signatures::RatSignatureCheck),
        Box::new(persistence::PersistenceCheck),
        Box::new(firewall::FirewallStatusCheck),
        Box::new(defender::DefenderStatusCheck),
        Box::new(drivers::DriverAnomalyCheck),
        Box::new(bitlocker::BitLockerCheck),
        Box::new(memory_integrity::MemoryIntegrityCheck),
        Box::new(rdp_exposure::RdpExposureCheck),
        Box::new(proxy_tampering::ProxyTamperingCheck),
        Box::new(credential_protection::CredentialProtectionCheck),
        Box::new(windows_update::WindowsUpdateCheck),
    ]
}
