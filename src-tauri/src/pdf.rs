//! Real PDF report generation.
//!
//! Uses `printpdf` directly rather than `genpdf` (a higher-level layout
//! crate built on top of `printpdf`): `genpdf` needs an actual `.ttf` font
//! file to embed, and this project ships no font assets and shouldn't have
//! to reach out to the network or bundle a font just to draw text. `printpdf`
//! ships the 14 standard PDF fonts (Helvetica/Helvetica-Bold here) built in -
//! no font file, no embedding, no extra asset - which keeps this feature
//! self-contained. The tradeoff is that text layout (wrapping, page breaks)
//! is done by hand below instead of via a layout engine; `wrap_text` is a
//! pure function so that logic is unit-tested without touching `printpdf`
//! at all.
//!
//! Reuses `export::prepare_report_data` for content (see that module's doc
//! comment) so the PDF and HTML reports never drift out of sync on what
//! they say.

use crate::export::{prepare_report_data, severity_label};
use crate::history::ScanRecord;
use printpdf::*;
use std::io::BufWriter;

const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 18.0;
const LINE_HEIGHT_MM: f32 = 5.2;

/// Word-wraps `text` to at most `max_chars` characters per line. A pure,
/// no-I/O function so PDF text layout can be unit tested without touching
/// `printpdf`/font metrics at all.
pub fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            let candidate_len = if current.is_empty() { word.len() } else { current.len() + 1 + word.len() };
            if candidate_len > max_chars && !current.is_empty() {
                lines.push(current);
                current = String::new();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
            // A single word longer than max_chars is left as-is (not split
            // mid-word) rather than producing an unreadable hyphenation.
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

/// Renders a `ScanRecord` as a real PDF file (bytes ready to write to disk).
pub fn render_report_pdf(record: &ScanRecord) -> Result<Vec<u8>, String> {
    let data = prepare_report_data(record);

    let (doc, page1, layer1) = PdfDocument::new("NetGuard Scan Report", Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), "Layer 1");
    let font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
    let bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| e.to_string())?;

    let mut page_idx = page1;
    let mut layer_idx = layer1;
    let mut y = PAGE_HEIGHT_MM - MARGIN_MM;
    let content_width_mm = PAGE_WIDTH_MM - 2.0 * MARGIN_MM;

    let new_page = |doc: &PdfDocumentReference| -> (PdfPageIndex, PdfLayerIndex) {
        doc.add_page(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), "Layer 1")
    };

    macro_rules! ensure_space {
        ($needed:expr) => {
            if y - $needed < MARGIN_MM {
                let (p, l) = new_page(&doc);
                page_idx = p;
                layer_idx = l;
                y = PAGE_HEIGHT_MM - MARGIN_MM;
            }
        };
    }

    macro_rules! write_line {
        ($text:expr, $size:expr, $use_font:expr) => {{
            ensure_space!(LINE_HEIGHT_MM);
            let layer = doc.get_page(page_idx).get_layer(layer_idx);
            layer.use_text($text, $size, Mm(MARGIN_MM), Mm(y), $use_font);
            y -= LINE_HEIGHT_MM;
        }};
    }

    macro_rules! write_wrapped {
        ($text:expr, $size:expr, $use_font:expr, $chars_per_line:expr) => {{
            for line in wrap_text($text, $chars_per_line) {
                write_line!(&line, $size, $use_font);
            }
        }};
    }

    write_line!("NetGuard Scan Report", 18.0, &bold);
    y -= 2.0;
    write_line!(&format!("Generated {}", data.timestamp), 9.0, &font);
    y -= 3.0;

    write_line!("Executive summary", 13.0, &bold);
    write_line!(
        &format!(
            "Overall result: {} - based on {} of {} checks that ran this scan.",
            severity_label(data.overall_severity),
            data.executed_count,
            data.total_count
        ),
        10.5,
        &font
    );
    write_wrapped!(
        match data.overall_severity {
            crate::checks::Severity::Ok =>
                "No problems were found among the checks that ran. This does not guarantee the device is fully secure - only that these specific checks found nothing concerning.",
            crate::checks::Severity::Caution =>
                "One or more checks found something worth reviewing. None of it is necessarily an active compromise, but it's worth addressing the items below.",
            crate::checks::Severity::AtRisk =>
                "One or more checks found something that indicates a real security problem. Review the flagged items below and act on the remediation guidance.",
        },
        9.5,
        &font,
        100
    );
    write_line!(
        &format!(
            "OK: {}   Caution: {}   At Risk: {}   Skipped: {}",
            data.ok_count, data.caution_count, data.at_risk_count, data.skipped_count
        ),
        10.0,
        &font
    );
    y -= 4.0;

    for section in &data.sections {
        ensure_space!(LINE_HEIGHT_MM * 3.0);
        write_line!(section.category_label, 13.5, &bold);
        y -= 1.0;

        for item in &section.items {
            let label = match item.severity {
                Some(sev) => severity_label(sev),
                None => "Skipped",
            };
            write_wrapped!(&format!("[{}] {}", label, item.name), 11.0, &bold, 90);
            write_wrapped!(&item.verdict, 9.5, &font, 100);

            for (flabel, fdetail) in &item.findings {
                write_wrapped!(&format!("- {}: {}", flabel, fdetail), 9.0, &font, 96);
            }

            if let Some(remediation) = &item.remediation {
                write_wrapped!(&format!("What to do: {}", remediation), 9.0, &font, 96);
            }

            if let Some(source) = &item.data_source {
                write_wrapped!(&format!("Data source: {}", source), 8.0, &font, 100);
            }

            y -= 2.5;
        }
        y -= 2.0;
    }

    write_line!(
        "NetGuard is a diagnostic and triage tool, not an antivirus - it does not scan for malware or remove anything.",
        7.5,
        &font
    );

    let _ = content_width_mm;
    let _ = y;

    let mut buffer = Vec::new();
    {
        let mut writer = BufWriter::new(&mut buffer);
        doc.save(&mut writer).map_err(|e| format!("failed to render PDF: {e}"))?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_long_paragraph_into_multiple_lines() {
        let text = "This is a moderately long sentence that should wrap across more than one line when constrained.";
        let lines = wrap_text(text, 20);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 40); // allows one over-length word, but not runaway
        }
    }

    #[test]
    fn short_text_stays_on_one_line() {
        let lines = wrap_text("short", 50);
        assert_eq!(lines, vec!["short".to_string()]);
    }

    #[test]
    fn preserves_paragraph_breaks() {
        let lines = wrap_text("first\nsecond", 50);
        assert_eq!(lines, vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn zero_width_returns_original_text_unsplit() {
        let lines = wrap_text("hello world", 0);
        assert_eq!(lines, vec!["hello world".to_string()]);
    }

    #[test]
    fn renders_pdf_bytes_starting_with_pdf_header() {
        use crate::checks::{CheckCategory, CheckOutcome, CheckResult, Finding, Severity};
        use chrono::Utc;
        let record = ScanRecord {
            id: "abc".to_string(),
            timestamp: Utc::now(),
            overall_severity: Severity::Ok,
            executed_count: 1,
            total_count: 1,
            outcomes: vec![CheckOutcome::Completed(CheckResult {
                id: "c1".to_string(),
                name: "Sample Check".to_string(),
                category: CheckCategory::System,
                severity: Severity::Ok,
                verdict: "All good".to_string(),
                findings: vec![Finding::new("Label", "Detail")],
                remediation: None,
                data_source: "test".to_string(),
                raw_keys: vec![],
            })],
        };
        let bytes = render_report_pdf(&record).expect("pdf renders");
        assert!(bytes.starts_with(b"%PDF"));
    }
}
