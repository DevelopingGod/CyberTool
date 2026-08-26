//! Scan orchestration: applies the permission state machine to every
//! check-agent, runs allowed ones, and emits progress/result events as it
//! goes rather than blocking until the whole scan finishes.

use crate::checks::{all_checks, CheckCategory, CheckOutcome, ScanContext, Severity};
use crate::history::{self, ScanRecord};
use crate::permissions::{self, PermissionState};
use chrono::Utc;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

pub const EVENT_PROGRESS: &str = "netguard://scan-progress";
pub const EVENT_RESULT: &str = "netguard://scan-result";
pub const EVENT_COMPLETE: &str = "netguard://scan-complete";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgressEvent {
    completed: usize,
    total: usize,
    running_id: String,
    running_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCompleteEvent {
    pub id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub overall_severity: Severity,
    pub executed_count: usize,
    pub total_count: usize,
}

/// Worst severity among executed (non-skipped) checks. Skipped/errored
/// checks never count as `Ok` - if nothing executed, the rollup itself is
/// `Caution` ("unknown" is not safe to report as green).
fn rollup(outcomes: &[CheckOutcome]) -> (Severity, usize) {
    let executed: Vec<Severity> = outcomes.iter().filter_map(|o| o.severity()).collect();
    let executed_count = executed.len();
    if executed.is_empty() {
        return (Severity::Caution, 0);
    }
    let worst = executed.into_iter().max().unwrap_or(Severity::Caution);
    (worst, executed_count)
}

/// Runs a scan: for every check-agent (optionally restricted to
/// `categories` - `None` or an empty slice means "run the full catalog"),
/// apply the permission state machine (`approved_once` is the set of check
/// IDs the frontend obtained a one-time approval for, from an
/// `AskEveryTime` prompt shown *before* this call - there is no server-side
/// cache of that approval), execute or skip accordingly, and emit an event
/// per check as it completes. Category filtering only changes *which*
/// checks are considered - the permission state machine, events, rollup
/// rule, and history recording are all unchanged and apply identically to a
/// category-filtered run as to a full scan.
pub async fn run_scan(
    app: &AppHandle,
    approved_once: &[String],
    categories: Option<&[CheckCategory]>,
) -> Result<ScanCompleteEvent, String> {
    let all = all_checks();
    let checks: Vec<Box<dyn crate::checks::SecurityCheck>> = match categories {
        Some(cats) if !cats.is_empty() => all.into_iter().filter(|c| cats.contains(&c.category())).collect(),
        _ => all,
    };
    let total = checks.len();

    // Seed the context with the previous scan's raw entries (if any) so
    // baseline-diffing checks (persistence, process baseline) can flag
    // genuinely new entries. A first-ever scan has no previous record, so
    // this map is simply empty and those checks behave exactly as before.
    let previous_raw_keys: std::collections::HashMap<String, Vec<String>> = history::latest(app)
        .ok()
        .flatten()
        .map(|record| {
            record
                .outcomes
                .into_iter()
                .filter_map(|o| match o {
                    CheckOutcome::Completed(r) => Some((r.id, r.raw_keys)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let ctx = ScanContext::with_previous(previous_raw_keys);
    let mut outcomes = Vec::with_capacity(total);

    for (i, check) in checks.iter().enumerate() {
        let _ = app.emit(
            EVENT_PROGRESS,
            ScanProgressEvent {
                completed: i,
                total,
                running_id: check.id().to_string(),
                running_name: check.name().to_string(),
            },
        );

        let pref = permissions::get_one(app, check.id());
        let outcome = match pref {
            PermissionState::Denied => CheckOutcome::PermissionDenied {
                id: check.id().to_string(),
                name: check.name().to_string(),
                category: check.category(),
            },
            PermissionState::AskEveryTime if !approved_once.iter().any(|id| id == check.id()) => {
                // Never silently run - and never silently behave like
                // Allowed. If the frontend didn't obtain (and pass along) a
                // one-time approval for this run, the check is skipped and
                // visibly flagged as permission-needed.
                CheckOutcome::PermissionDenied {
                    id: check.id().to_string(),
                    name: check.name().to_string(),
                    category: check.category(),
                }
            }
            PermissionState::Allowed | PermissionState::AskEveryTime => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check.run(&ctx)));
                match result {
                    Ok(r) => CheckOutcome::Completed(r),
                    Err(_) => CheckOutcome::Error {
                        id: check.id().to_string(),
                        name: check.name().to_string(),
                        category: check.category(),
                        message: "The check failed unexpectedly while running.".to_string(),
                    },
                }
            }
        };

        let _ = app.emit(EVENT_RESULT, &outcome);
        outcomes.push(outcome);
    }

    let (overall_severity, executed_count) = rollup(&outcomes);
    let record = ScanRecord {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        overall_severity,
        executed_count,
        total_count: total,
        outcomes,
    };

    history::save(app, record.clone())?;

    let complete = ScanCompleteEvent {
        id: record.id.clone(),
        timestamp: record.timestamp,
        overall_severity: record.overall_severity,
        executed_count: record.executed_count,
        total_count: record.total_count,
    };

    let _ = app.emit(EVENT_COMPLETE, &complete);
    Ok(complete)
}

/// Static metadata for a check-agent, used to populate the Settings
/// permission list and pre-scan consent dialogs without running anything.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckMeta {
    pub id: String,
    pub name: String,
    pub category: CheckCategory,
    pub permission_description: String,
}

pub fn catalog() -> Vec<CheckMeta> {
    all_checks()
        .iter()
        .map(|c| CheckMeta {
            id: c.id().to_string(),
            name: c.name().to_string(),
            category: c.category(),
            permission_description: c.permission_description().to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same filtering logic `run_scan` applies to `all_checks()`,
    /// exercised directly against the real catalog (no `AppHandle`/I-O
    /// needed) so category-scoped scanning has a pure-logic regression test.
    fn filtered_ids(categories: Option<&[CheckCategory]>) -> Vec<String> {
        let all = all_checks();
        let checks: Vec<_> = match categories {
            Some(cats) if !cats.is_empty() => all.into_iter().filter(|c| cats.contains(&c.category())).collect(),
            _ => all,
        };
        checks.iter().map(|c| c.id().to_string()).collect()
    }

    #[test]
    fn none_or_empty_categories_means_full_catalog() {
        let full = all_checks().len();
        assert_eq!(filtered_ids(None).len(), full);
        assert_eq!(filtered_ids(Some(&[])).len(), full);
    }

    #[test]
    fn single_category_only_returns_matching_checks() {
        let network_ids = filtered_ids(Some(&[CheckCategory::Network]));
        assert!(!network_ids.is_empty());
        let all = all_checks();
        for id in &network_ids {
            let check = all.iter().find(|c| c.id() == id).unwrap();
            assert_eq!(check.category(), CheckCategory::Network);
        }
        // Fewer than the full catalog, since other categories exist too.
        assert!(network_ids.len() < all.len());
    }

    #[test]
    fn multiple_categories_union_their_checks() {
        let combined = filtered_ids(Some(&[CheckCategory::Network, CheckCategory::Persistence]));
        let network_only = filtered_ids(Some(&[CheckCategory::Network]));
        let persistence_only = filtered_ids(Some(&[CheckCategory::Persistence]));
        assert_eq!(combined.len(), network_only.len() + persistence_only.len());
    }
}
