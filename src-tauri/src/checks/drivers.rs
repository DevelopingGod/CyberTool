//! Driver anomaly check.
//!
//! Data source: `driverquery /fo csv /v` for the loaded-driver list, plus
//! real Authenticode signature verification for each driver's on-disk path
//! via the Win32 `WinVerifyTrust` API (through the `windows` crate). An
//! unsigned/invalid signature is the primary `AtRisk` signal; the original
//! v1 heuristic (driver loaded from outside the expected system
//! directories) is kept as a secondary `Caution`-level signal, since a
//! validly-signed driver in an unusual location is still worth a second
//! look but is a much weaker signal than a bad signature. See
//! `DECISIONS.md` for exactly what "invalid" is treated to mean here (any
//! non-success `WinVerifyTrust` result - not a full per-error-code PKI
//! taxonomy) and why.

use super::{CheckCategory, CheckResult, Finding, PermissionKind, ScanContext, SecurityCheck, Severity};
use crate::sysutil::run_command;

pub struct DriverAnomalyCheck;

const DATA_SOURCE: &str = "driverquery /fo csv /v; WinVerifyTrust (Authenticode signature check)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// `WinVerifyTrust` returned success (`ERROR_SUCCESS`) for a valid,
    /// trusted Authenticode signature chain.
    Trusted,
    /// `WinVerifyTrust` was called and returned a non-success result - the
    /// file is unsigned, the signature doesn't validate, or the chain isn't
    /// trusted. Treated uniformly as "invalid" rather than decoded into the
    /// dozens of specific `TRUST_E_*`/`CERT_E_*` codes - a deliberate v1
    /// scoping decision (see `DECISIONS.md`).
    Untrusted,
    /// Signature verification wasn't attempted - `driverquery` reported only
    /// a bare filename with no resolvable directory (common for some
    /// built-in drivers), so there's no path to hand `WinVerifyTrust`. Not
    /// treated as a risk signal either way.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DriverInfo {
    pub name: String,
    pub path: String,
}

fn split_csv_line(line: &str) -> Vec<String> {
    // driverquery's CSV output quotes every field and doesn't embed quotes,
    // so a simple split is sufficient and defensive against short/odd rows.
    line.split("\",\"")
        .map(|s| s.trim_matches('"').to_string())
        .collect()
}

pub fn parse_driverquery_csv(output: &str) -> Vec<DriverInfo> {
    let mut lines = output.lines();
    let Some(header) = lines.next() else { return Vec::new() };
    let headers: Vec<String> = split_csv_line(header).into_iter().map(|h| h.to_ascii_lowercase()).collect();
    let Some(name_idx) = headers.iter().position(|h| h == "module name") else { return Vec::new() };
    let Some(path_idx) = headers.iter().position(|h| h == "path") else { return Vec::new() };

    let mut drivers = Vec::new();
    for line in lines {
        let cols = split_csv_line(line);
        if cols.len() <= name_idx.max(path_idx) {
            continue;
        }
        let name = cols[name_idx].trim().to_string();
        let path = cols[path_idx].trim().to_string();
        if name.is_empty() || path.is_empty() {
            continue;
        }
        drivers.push(DriverInfo { name, path });
    }
    drivers
}

fn is_expected_location(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains(r"\system32\drivers\")
        || lower.contains(r"\syswow64\drivers\")
        || lower.contains(r"\system32\")
        // driverquery often reports a bare filename with no directory for
        // built-in drivers; treat that as expected rather than flagging it.
        || !lower.contains('\\')
}

/// Interprets a raw `WinVerifyTrust` return code (a Win32 `LONG`). `0`
/// (`ERROR_SUCCESS`) means a trusted, valid Authenticode signature; any
/// other value means the signature didn't validate. This is the pure,
/// unit-testable half of signature verification - the actual OS call
/// (`verify_file_signature`, below) can't be exercised in a unit test since
/// it depends on real files and the live WinTrust provider, but every
/// decision made *from* its result funnels through this function.
pub fn interpret_verify_trust_result(code: i32) -> SignatureStatus {
    if code == 0 {
        SignatureStatus::Trusted
    } else {
        SignatureStatus::Untrusted
    }
}

/// Verifies a single file's Authenticode signature via `WinVerifyTrust`.
/// Returns `Unknown` (never panics, never treats a lookup failure as
/// "untrusted") if the path doesn't look like a real, resolvable file path -
/// `driverquery` sometimes reports only a bare filename for built-in
/// drivers, and there's nothing to verify in that case.
pub fn verify_file_signature(path: &str) -> SignatureStatus {
    if !path.contains('\\') {
        return SignatureStatus::Unknown;
    }
    // SAFETY: see `verify_file_signature_unsafe` below - all buffers are
    // stack-allocated and outlive the call, and the returned code is only
    // ever read, never used to derive a pointer.
    let code = unsafe { verify_file_signature_unsafe(path) };
    match code {
        Some(c) => interpret_verify_trust_result(c),
        None => SignatureStatus::Unknown,
    }
}

/// Calls `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` against a
/// single file, with UI fully suppressed (`WTD_UI_NONE`) and revocation
/// checking skipped (`WTD_REVOKE_NONE` - this is a local diagnostic, not an
/// online trust decision, and we don't want a scan to depend on network
/// reachability to a CRL/OCSP endpoint). Returns `None` if the path can't be
/// encoded as UTF-16 (should not happen for a Windows path). Any other
/// failure surfaces as the raw non-zero return code, which
/// `interpret_verify_trust_result` treats as "untrusted".
///
/// # Safety
/// This function performs raw FFI into `wintrust.dll`. All structures are
/// stack-local, zero-initialized, and populated field-by-field before the
/// call; none of their pointers are retained past the function returning.
/// The `WTD_STATEACTION_CLOSE` call afterwards releases any state
/// `WinVerifyTrust` allocated internally, per the documented API contract.
unsafe fn verify_file_signature_unsafe(path: &str) -> Option<i32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_IGNORE, WTD_UI_NONE,
    };

    let mut wide: Vec<u16> = std::ffi::OsStr::new(path).encode_wide().collect();
    wide.push(0);
    let file_path = PCWSTR(wide.as_ptr());

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: file_path,
        hFile: windows::Win32::Foundation::HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_guid: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let code = WinVerifyTrust(HWND::default(), &mut action_guid, &mut trust_data as *mut _ as *mut core::ffi::c_void);

    // Release any internal state; a diagnostic tool shouldn't leak per-call
    // WinTrust provider state across a scan of many drivers.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(HWND::default(), &mut action_guid, &mut trust_data as *mut _ as *mut core::ffi::c_void);

    Some(code)
}

pub fn evaluate(drivers: &[(DriverInfo, SignatureStatus)]) -> (Severity, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut severity = Severity::Ok;

    for (d, sig) in drivers {
        match sig {
            SignatureStatus::Untrusted => {
                severity = Severity::AtRisk;
                findings.push(Finding::new(
                    format!("{} has an invalid/missing signature", d.name),
                    d.path.clone(),
                ));
            }
            SignatureStatus::Trusted | SignatureStatus::Unknown => {
                if !is_expected_location(&d.path) {
                    if severity < Severity::Caution {
                        severity = Severity::Caution;
                    }
                    findings.push(Finding::new(format!("{} in unusual location", d.name), d.path.clone()));
                }
            }
        }
    }

    findings.push(Finding::new("Drivers examined", drivers.len().to_string()));
    let unverified = drivers.iter().filter(|(_, s)| *s == SignatureStatus::Unknown).count();
    if unverified > 0 {
        findings.push(Finding::new(
            "Signature not verifiable",
            format!("{unverified} driver(s) reported without a resolvable file path"),
        ));
    }
    if severity == Severity::Ok {
        findings.insert(0, Finding::new("Result", "All drivers are validly signed and in expected system directories"));
    }
    (severity, findings)
}

impl SecurityCheck for DriverAnomalyCheck {
    fn id(&self) -> &'static str {
        "driver_certificate_anomalies"
    }

    fn name(&self) -> &'static str {
        "Driver Signature & Location Anomalies"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::System
    }

    fn required_permission(&self) -> PermissionKind {
        PermissionKind::DriverList
    }

    fn permission_description(&self) -> &'static str {
        "Lists loaded drivers via `driverquery`, verifies each one's Authenticode signature via WinVerifyTrust, and flags unsigned/invalid signatures or unusual install locations."
    }

    fn run(&self, _ctx: &ScanContext) -> CheckResult {
        match run_command("driverquery", &["/fo", "csv", "/v"]) {
            Ok(output) => {
                let drivers = parse_driverquery_csv(&output);
                let checked: Vec<(DriverInfo, SignatureStatus)> =
                    drivers.into_iter().map(|d| { let sig = verify_file_signature(&d.path); (d, sig) }).collect();
                let (severity, findings) = evaluate(&checked);
                let verdict = match severity {
                    Severity::Ok => "All loaded drivers are validly signed and in expected system locations.".to_string(),
                    Severity::Caution => "Driver(s) found outside standard system directories.".to_string(),
                    Severity::AtRisk => "Driver(s) with an invalid or missing Authenticode signature were found.".to_string(),
                };
                let remediation = if severity != Severity::Ok {
                    Some("Research each flagged driver's publisher and purpose. An unsigned or invalidly-signed driver outside System32\\drivers warrants immediate attention or a full antivirus scan.".to_string())
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
                verdict: "Could not enumerate drivers.".to_string(),
                findings: vec![Finding::new("driverquery error", e)],
                remediation: Some("Ensure `driverquery` is available and try again.".to_string()),
                data_source: DATA_SOURCE.to_string(),
                raw_keys: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\"Module Name\",\"Display Name\",\"Path\"\n\"Ntfs\",\"NTFS\",\"C:\\Windows\\System32\\drivers\\Ntfs.sys\"\n\"evil\",\"Evil Driver\",\"C:\\Users\\bob\\AppData\\Local\\Temp\\evil.sys\"\n";

    #[test]
    fn parses_csv() {
        let drivers = parse_driverquery_csv(SAMPLE);
        assert_eq!(drivers.len(), 2);
    }

    #[test]
    fn flags_unusual_location_as_caution() {
        let drivers = parse_driverquery_csv(SAMPLE);
        let checked: Vec<_> = drivers.into_iter().map(|d| (d, SignatureStatus::Trusted)).collect();
        let (sev, findings) = evaluate(&checked);
        assert_eq!(sev, Severity::Caution);
        assert!(findings.iter().any(|f| f.label.contains("evil")));
    }

    #[test]
    fn untrusted_signature_is_at_risk_even_in_expected_location() {
        let d = DriverInfo { name: "Ntfs".into(), path: r"C:\Windows\System32\drivers\Ntfs.sys".into() };
        let checked = vec![(d, SignatureStatus::Untrusted)];
        let (sev, findings) = evaluate(&checked);
        assert_eq!(sev, Severity::AtRisk);
        assert!(findings.iter().any(|f| f.label.contains("invalid/missing signature")));
    }

    #[test]
    fn trusted_and_expected_is_ok() {
        let d = DriverInfo { name: "Ntfs".into(), path: r"C:\Windows\System32\drivers\Ntfs.sys".into() };
        let checked = vec![(d, SignatureStatus::Trusted)];
        let (sev, _) = evaluate(&checked);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn interprets_success_code_as_trusted() {
        assert_eq!(interpret_verify_trust_result(0), SignatureStatus::Trusted);
    }

    #[test]
    fn interprets_nonzero_code_as_untrusted() {
        assert_eq!(interpret_verify_trust_result(-2146762751), SignatureStatus::Untrusted); // TRUST_E_NOSIGNATURE
        assert_eq!(interpret_verify_trust_result(1), SignatureStatus::Untrusted);
    }

    #[test]
    fn bare_filename_is_unknown_not_verified() {
        assert_eq!(verify_file_signature("Ntfs.sys"), SignatureStatus::Unknown);
    }
}
