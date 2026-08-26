//! Report export.
//!
//! `prepare_report_data` is the single shared data-preparation step used by
//! both exporters below, so the HTML report and the PDF report always show
//! the same grouping/summary/wording rather than duplicating report-content
//! logic in two places:
//! - `render_report_html`: a self-contained, printable HTML report (inline
//!   CSS reusing the app's severity colors), written to a temp file and
//!   opened via `tauri-plugin-opener` so a user who still wants the
//!   browser's own "Print to PDF" can use it.
//! - `pdf.rs` / `render_report_pdf`: a real PDF generated server-side via the
//!   `printpdf` crate (see that module's doc comment for why `printpdf` was
//!   chosen over `genpdf`), offered as a direct one-click download through
//!   the same `tauri-plugin-dialog` save-file flow already used for JSON.

use crate::checks::{CheckCategory, CheckOutcome, Severity};
use crate::history::ScanRecord;

pub fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Ok => "ok",
        Severity::Caution => "caution",
        Severity::AtRisk => "at-risk",
    }
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Ok => "OK",
        Severity::Caution => "Caution",
        Severity::AtRisk => "At Risk",
    }
}

fn category_label(category: CheckCategory) -> &'static str {
    match category {
        CheckCategory::Network => "Network",
        CheckCategory::Process => "Processes & Programs",
        CheckCategory::Persistence => "Startup & Persistence",
        CheckCategory::System => "System Security",
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One check's result, normalized for reporting regardless of whether it
/// completed, was skipped for permission, or errored.
#[derive(Debug, Clone)]
pub struct ReportItem {
    pub name: String,
    /// `None` for a skipped/errored check - it contributed no severity.
    pub severity: Option<Severity>,
    pub verdict: String,
    pub findings: Vec<(String, String)>,
    pub remediation: Option<String>,
    pub data_source: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReportSection {
    pub category_label: &'static str,
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Clone)]
pub struct ReportData {
    pub timestamp: String,
    pub overall_severity: Severity,
    pub executed_count: usize,
    pub total_count: usize,
    pub ok_count: usize,
    pub caution_count: usize,
    pub at_risk_count: usize,
    pub skipped_count: usize,
    pub sections: Vec<ReportSection>,
}

const CATEGORY_ORDER: [CheckCategory; 4] =
    [CheckCategory::Network, CheckCategory::Process, CheckCategory::Persistence, CheckCategory::System];

fn outcome_category(outcome: &CheckOutcome) -> CheckCategory {
    match outcome {
        CheckOutcome::Completed(r) => r.category,
        CheckOutcome::PermissionDenied { category, .. } => *category,
        CheckOutcome::Error { category, .. } => *category,
    }
}

fn to_report_item(outcome: &CheckOutcome) -> ReportItem {
    match outcome {
        CheckOutcome::Completed(r) => ReportItem {
            name: r.name.clone(),
            severity: Some(r.severity),
            verdict: r.verdict.clone(),
            findings: r.findings.iter().map(|f| (f.label.clone(), f.detail.clone())).collect(),
            remediation: r.remediation.clone(),
            data_source: Some(r.data_source.clone()),
        },
        CheckOutcome::PermissionDenied { name, .. } => ReportItem {
            name: name.clone(),
            severity: None,
            verdict: "Not run - permission was not granted for this scan.".to_string(),
            findings: Vec::new(),
            remediation: None,
            data_source: None,
        },
        CheckOutcome::Error { name, message, .. } => ReportItem {
            name: name.clone(),
            severity: None,
            verdict: message.clone(),
            findings: Vec::new(),
            remediation: None,
            data_source: None,
        },
    }
}

/// Pure data-preparation step, shared by both exporters. No I/O - takes the
/// already-persisted `ScanRecord` and produces a normalized, category-grouped
/// view with the executive-summary counts computed once.
pub fn prepare_report_data(record: &ScanRecord) -> ReportData {
    let mut ok_count = 0;
    let mut caution_count = 0;
    let mut at_risk_count = 0;
    let mut skipped_count = 0;

    for outcome in &record.outcomes {
        match outcome.severity() {
            Some(Severity::Ok) => ok_count += 1,
            Some(Severity::Caution) => caution_count += 1,
            Some(Severity::AtRisk) => at_risk_count += 1,
            None => skipped_count += 1,
        }
    }

    let sections: Vec<ReportSection> = CATEGORY_ORDER
        .iter()
        .filter_map(|cat| {
            let items: Vec<ReportItem> =
                record.outcomes.iter().filter(|o| outcome_category(o) == *cat).map(to_report_item).collect();
            if items.is_empty() {
                None
            } else {
                Some(ReportSection { category_label: category_label(*cat), items })
            }
        })
        .collect();

    ReportData {
        timestamp: record.timestamp.to_rfc2822(),
        overall_severity: record.overall_severity,
        executed_count: record.executed_count,
        total_count: record.total_count,
        ok_count,
        caution_count,
        at_risk_count,
        skipped_count,
        sections,
    }
}

fn overall_explanation(severity: Severity) -> &'static str {
    match severity {
        Severity::Ok => {
            "No problems were found among the checks that ran. This does not guarantee the device is fully secure - only that these specific checks found nothing concerning."
        }
        Severity::Caution => {
            "One or more checks found something worth reviewing. None of it is necessarily an active compromise, but it's worth addressing the items below."
        }
        Severity::AtRisk => {
            "One or more checks found something that indicates a real security problem. Review the flagged items below and act on the remediation guidance."
        }
    }
}

/// Renders a full `ScanRecord` as a self-contained, printable HTML report.
/// Pure function (no I/O) so it can be unit tested directly.
pub fn render_report_html(record: &ScanRecord) -> String {
    let data = prepare_report_data(record);

    let mut sections_html = String::new();
    for section in &data.sections {
        let mut checks_html = String::new();
        for item in &section.items {
            let (badge_class, badge_label) = match item.severity {
                Some(sev) => (severity_class(sev), severity_label(sev)),
                None => ("skipped", "Skipped"),
            };
            let findings: String = item
                .findings
                .iter()
                .map(|(label, detail)| {
                    format!("<li><strong>{}</strong>: {}</li>", escape_html(label), escape_html(detail))
                })
                .collect();
            let remediation = item
                .remediation
                .as_deref()
                .map(|rem| {
                    format!(
                        "<p class=\"remediation\"><strong>What to do:</strong> {}</p>",
                        escape_html(rem)
                    )
                })
                .unwrap_or_default();
            let data_source = item
                .data_source
                .as_deref()
                .map(|ds| format!("<p class=\"data-source\">Data source: {}</p>", escape_html(ds)))
                .unwrap_or_default();

            checks_html.push_str(&format!(
                r#"<article class="check {badge_class}">
  <h3><span class="badge {badge_class}">{badge_label}</span> {name}</h3>
  <p class="verdict">{verdict}</p>
  {findings_block}
  {remediation}
  {data_source}
</article>"#,
                badge_class = badge_class,
                badge_label = badge_label,
                name = escape_html(&item.name),
                verdict = escape_html(&item.verdict),
                findings_block = if findings.is_empty() {
                    String::new()
                } else {
                    format!("<ul class=\"findings\">{findings}</ul>")
                },
                remediation = remediation,
                data_source = data_source,
            ));
        }
        sections_html.push_str(&format!(
            r#"<section class="category">
  <h2>{label}</h2>
  {checks}
</section>"#,
            label = escape_html(section.category_label),
            checks = checks_html,
        ));
    }

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetGuard Scan Report - {timestamp}</title>
<style>
  :root {{
    --ok: #1f9d55; --caution: #b7791f; --at-risk: #c53030;
    --bg: #ffffff; --fg: #1a1f16; --muted: #5b6b57; --border: #dbe6da; --panel: #f4f9f2;
  }}
  body {{
    font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--fg); margin: 0; padding: 2.5rem;
    max-width: 900px; margin: 0 auto; line-height: 1.55;
  }}
  header {{ border-bottom: 3px solid #2f7a4d; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
  header h1 {{ margin: 0 0 0.25rem; font-size: 1.7rem; }}
  header p {{ margin: 0.15rem 0; color: var(--muted); }}
  .overall {{ display: inline-block; padding: 0.2rem 0.75rem; border-radius: 999px; font-weight: 600; color: #fff; }}
  .overall.ok {{ background: var(--ok); }}
  .overall.caution {{ background: var(--caution); }}
  .overall.at-risk {{ background: var(--at-risk); }}
  .summary {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 2rem; }}
  .summary h2 {{ margin-top: 0; font-size: 1.1rem; }}
  .summary p {{ margin: 0.35rem 0; }}
  .counts {{ display: flex; gap: 1.5rem; margin-top: 0.75rem; flex-wrap: wrap; }}
  .count {{ font-size: 0.85rem; color: var(--muted); }}
  .count strong {{ display: block; font-size: 1.3rem; color: var(--fg); }}
  .category {{ margin-bottom: 1.75rem; break-inside: avoid; }}
  .category h2 {{ font-size: 1.15rem; border-bottom: 2px solid var(--border); padding-bottom: 0.35rem; margin-bottom: 0.75rem; }}
  article.check {{ border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.25rem; margin-bottom: 0.85rem; break-inside: avoid; }}
  article.check.skipped {{ opacity: 0.75; }}
  h3 {{ margin: 0 0 0.5rem; font-size: 1.02rem; }}
  .badge {{ display: inline-block; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; padding: 0.15rem 0.5rem; border-radius: 999px; color: #fff; margin-right: 0.5rem; vertical-align: middle; }}
  .badge.ok {{ background: var(--ok); }}
  .badge.caution {{ background: var(--caution); }}
  .badge.at-risk {{ background: var(--at-risk); }}
  .badge.skipped {{ background: #8a8a8a; }}
  .verdict {{ font-weight: 500; margin: 0.25rem 0 0.5rem; }}
  ul.findings {{ margin: 0.5rem 0; padding-left: 1.25rem; color: var(--muted); font-size: 0.94rem; }}
  .remediation {{ background: var(--panel); border-left: 3px solid var(--caution); padding: 0.5rem 0.75rem; margin: 0.5rem 0; font-size: 0.92rem; }}
  .data-source {{ font-size: 0.76rem; color: var(--muted); margin-top: 0.5rem; }}
  footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--muted); }}
  @media print {{ body {{ padding: 0.5in; }} article.check {{ box-shadow: none; }} }}
</style>
</head>
<body>
<header>
  <h1>NetGuard Scan Report</h1>
  <p>Generated {timestamp}</p>
</header>
<section class="summary">
  <h2>Executive summary</h2>
  <p>Overall result: <span class="overall {overall_class}">{overall_label}</span> - based on {executed} of {total} checks that ran this scan.</p>
  <p>{explanation}</p>
  <div class="counts">
    <div class="count"><strong>{ok_count}</strong>OK</div>
    <div class="count"><strong>{caution_count}</strong>Caution</div>
    <div class="count"><strong>{at_risk_count}</strong>At Risk</div>
    <div class="count"><strong>{skipped_count}</strong>Skipped</div>
  </div>
</section>
{sections}
<footer>
  NetGuard is a diagnostic and triage tool, not an antivirus - it does not scan for malware or remove anything.
  This report reflects a single point-in-time scan of this device only.
</footer>
</body>
</html>"#,
        timestamp = data.timestamp,
        overall_class = severity_class(data.overall_severity),
        overall_label = severity_label(data.overall_severity),
        executed = data.executed_count,
        total = data.total_count,
        explanation = overall_explanation(data.overall_severity),
        ok_count = data.ok_count,
        caution_count = data.caution_count,
        at_risk_count = data.at_risk_count,
        skipped_count = data.skipped_count,
        sections = sections_html,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{CheckCategory, CheckResult, Finding};
    use chrono::Utc;

    fn sample_record() -> ScanRecord {
        ScanRecord {
            id: "abc".to_string(),
            timestamp: Utc::now(),
            overall_severity: Severity::Caution,
            executed_count: 1,
            total_count: 2,
            outcomes: vec![
                CheckOutcome::Completed(CheckResult {
                    id: "c1".to_string(),
                    name: "Sample Check".to_string(),
                    category: CheckCategory::System,
                    severity: Severity::Caution,
                    verdict: "Something <script> needs review".to_string(),
                    findings: vec![Finding::new("Label", "Detail & more")],
                    remediation: Some("Do the thing".to_string()),
                    data_source: "test".to_string(),
                    raw_keys: vec![],
                }),
                CheckOutcome::PermissionDenied { id: "c2".to_string(), name: "Denied Check".to_string(), category: CheckCategory::Network },
            ],
        }
    }

    #[test]
    fn prepares_grouped_report_data() {
        let data = prepare_report_data(&sample_record());
        assert_eq!(data.caution_count, 1);
        assert_eq!(data.skipped_count, 1);
        // Network section (Denied Check) should come before System (Sample Check).
        assert_eq!(data.sections.len(), 2);
        assert_eq!(data.sections[0].category_label, "Network");
        assert_eq!(data.sections[1].category_label, "System Security");
    }

    #[test]
    fn renders_completed_and_skipped_sections() {
        let html = render_report_html(&sample_record());
        assert!(html.contains("Sample Check"));
        assert!(html.contains("Denied Check"));
        assert!(html.contains("Skipped"));
        assert!(html.contains("Executive summary"));
    }

    #[test]
    fn escapes_html_in_content() {
        let html = render_report_html(&sample_record());
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Detail &amp; more"));
    }
}
