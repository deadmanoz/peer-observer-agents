use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::fmt;

/// Investigation verdict indicating whether operator action is needed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    Benign,
    Investigate,
    ActionRequired,
}

impl Verdict {
    /// Machine-readable tag value for Grafana tags and log fields.
    pub(crate) fn as_tag(&self) -> &'static str {
        match self {
            Verdict::Benign => "benign",
            Verdict::Investigate => "investigate",
            Verdict::ActionRequired => "action_required",
        }
    }

    /// Human-readable label for display in annotations and logs.
    pub(crate) fn display_label(&self) -> &'static str {
        match self {
            Verdict::Benign => "BENIGN",
            Verdict::Investigate => "INVESTIGATE",
            Verdict::ActionRequired => "ACTION REQUIRED",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tag())
    }
}

/// Structured annotation output from Claude, parsed from JSON.
#[derive(Debug, Deserialize)]
pub(crate) struct StructuredAnnotation {
    pub(crate) verdict: Verdict,
    /// Specific operator action. Required for `action_required`, optional for
    /// `investigate` (e.g., "monitor for 15 minutes"), must be absent for `benign`.
    #[serde(default)]
    pub(crate) action: Option<String>,
    /// 1-2 sentence TL;DR with key metric values.
    pub(crate) summary: String,
    /// Root cause with supporting evidence.
    pub(crate) cause: String,
    /// Scope: "isolated to <host>" or "multi-host (<hosts>)".
    pub(crate) scope: String,
    /// 2-4 bullet points with specific metric values and timestamps.
    pub(crate) evidence: Vec<String>,
}

/// Validate a structured annotation against the schema contract.
fn validate_structured_annotation(ann: &StructuredAnnotation) -> Result<()> {
    ensure!(
        !ann.summary.trim().is_empty(),
        "summary must not be empty or whitespace-only"
    );
    ensure!(
        !ann.cause.trim().is_empty(),
        "cause must not be empty or whitespace-only"
    );
    ensure!(
        !ann.scope.trim().is_empty(),
        "scope must not be empty or whitespace-only"
    );

    ensure!(
        ann.evidence.len() >= 2,
        "evidence must have at least 2 items, got {}",
        ann.evidence.len()
    );
    ensure!(
        ann.evidence.len() <= 4,
        "evidence must have at most 4 items, got {}",
        ann.evidence.len()
    );
    ensure!(
        ann.evidence.iter().all(|e| !e.trim().is_empty()),
        "evidence items must not be empty or whitespace-only"
    );

    match ann.verdict {
        Verdict::Benign => {
            ensure!(
                ann.action.is_none(),
                "benign verdict must not have an action"
            );
        }
        Verdict::Investigate => {
            if let Some(ref a) = ann.action {
                ensure!(
                    !a.trim().is_empty(),
                    "action must not be empty or whitespace-only when present"
                );
            }
        }
        Verdict::ActionRequired => {
            let action = ann.action.as_deref().unwrap_or("");
            ensure!(
                !action.trim().is_empty(),
                "action_required verdict must have a non-empty action"
            );
        }
    }

    Ok(())
}

/// Parse Claude's result text as a structured annotation JSON object.
pub(crate) fn parse_structured_annotation(raw: &str) -> Result<StructuredAnnotation> {
    let ann: StructuredAnnotation = serde_json::from_str(raw)
        .context("Claude output is not valid StructuredAnnotation JSON")?;
    validate_structured_annotation(&ann)?;
    Ok(ann)
}

/// Escape text for safe inclusion in HTML annotation content.
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render a structured annotation as HTML for Grafana annotation tooltips.
///
/// HTML rendering verified against grafana/grafana main branch (2026-03):
/// AnnotationTooltip2.tsx uses dangerouslySetInnerHTML + DOMPurify sanitization.
/// Safe tags: <b>, <br>, &bull;. Does NOT render in Annotations List Panel (#26550).
/// If Grafana changes tooltip rendering, the structured format is still readable
/// as raw text with HTML tags visible.
pub(crate) fn render_annotation_html(ann: &StructuredAnnotation) -> String {
    let verdict_display = ann.verdict.display_label();

    let action_display = match &ann.action {
        Some(a) => html_escape(a.trim()),
        None => "none".to_string(),
    };

    let evidence_items: String = ann
        .evidence
        .iter()
        .map(|e| format!("&bull; {}<br>", html_escape(e.trim())))
        .collect();

    format!(
        "<b>VERDICT:</b> {verdict_display}<br>\
         <b>ACTION:</b> {action_display}<br>\
         <b>SUMMARY:</b> {summary}<br>\
         <br>\
         <b>CAUSE:</b> {cause}<br>\
         <b>SCOPE:</b> {scope}<br>\
         <b>EVIDENCE:</b><br>\
         {evidence_items}",
        summary = html_escape(ann.summary.trim()),
        cause = html_escape(ann.cause.trim()),
        scope = html_escape(ann.scope.trim()),
    )
}

/// Replace characters that would break the single-line pipe-delimited log format.
pub(crate) fn sanitize_log_field(s: &str) -> String {
    s.replace(['\n', '\r'], " ").replace('|', "/")
}

/// Render a structured annotation as a single-line pipe-delimited string for the log file.
pub(crate) fn render_annotation_plaintext(ann: &StructuredAnnotation) -> String {
    let action = ann.action.as_deref().unwrap_or("none");
    let evidence: String = ann
        .evidence
        .iter()
        .map(|e| sanitize_log_field(e.trim()))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "VERDICT: {} | ACTION: {} | SUMMARY: {} | CAUSE: {} | SCOPE: {} | EVIDENCE: {}",
        ann.verdict.display_label(),
        sanitize_log_field(action.trim()),
        sanitize_log_field(ann.summary.trim()),
        sanitize_log_field(ann.cause.trim()),
        sanitize_log_field(ann.scope.trim()),
        evidence,
    )
}

/// Strip HTML tags and entities produced by `render_annotation_html` for use in prompts.
/// Only handles the specific markup we generate — not a general-purpose HTML stripper.
///
/// Entity unescaping is only applied when the input is a structured annotation
/// (detected by `<b>VERDICT:</b>` marker). Fallback annotations are stored as
/// html_escape'd plain text — unescaping those would decode boundary strings like
/// `&lt;/alert-context-data&gt;` back to `</alert-context-data>`, breaking the
/// XML fence in the next investigation prompt.
pub(crate) fn strip_annotation_html(html: &str) -> String {
    let is_structured = html.contains("<b>VERDICT:</b>");

    let stripped = html
        .replace("<b>", "")
        .replace("</b>", "")
        .replace("<br>", "\n")
        .replace("&bull;", "-");

    if is_structured {
        // Only unescape entities for structured HTML we produced.
        // &amp; MUST be last to avoid double-decoding.
        stripped
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    } else {
        stripped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Verdict ───────────────────────────────────────────────────────

    #[test]
    fn verdict_display_and_tag() {
        assert_eq!(Verdict::Benign.as_tag(), "benign");
        assert_eq!(Verdict::Investigate.as_tag(), "investigate");
        assert_eq!(Verdict::ActionRequired.as_tag(), "action_required");
        assert_eq!(Verdict::Benign.to_string(), "benign");
        assert_eq!(Verdict::ActionRequired.to_string(), "action_required");
    }

    #[test]
    fn verdict_deserialize() {
        let v: Verdict = serde_json::from_str(r#""benign""#).unwrap();
        assert_eq!(v, Verdict::Benign);
        let v: Verdict = serde_json::from_str(r#""investigate""#).unwrap();
        assert_eq!(v, Verdict::Investigate);
        let v: Verdict = serde_json::from_str(r#""action_required""#).unwrap();
        assert_eq!(v, Verdict::ActionRequired);
    }

    #[test]
    fn verdict_deserialize_invalid() {
        let result = serde_json::from_str::<Verdict>(r#""critical""#);
        assert!(result.is_err());
    }

    // ── Structured annotation parsing ─────────────────────────────────

    fn benign_json() -> &'static str {
        r#"{
            "verdict": "benign",
            "action": null,
            "summary": "Marginal addr rate breach, already self-resolving.",
            "cause": "Distributed addr relay surge from multiple peers.",
            "scope": "multi-host (vps-prod-01, vps-dev-01 elevated; bitcoin-01 flat)",
            "evidence": [
                "addr_rate peak: 21.82/s at 14:09 UTC vs upper_band 18.99/s",
                "rate declining to 15.43/s by 14:10 UTC"
            ]
        }"#
    }

    fn action_required_json() -> &'static str {
        r#"{
            "verdict": "action_required",
            "action": "run getpeerinfo on vps-prod-01 and identify peers with addr_rate_limited=true",
            "summary": "Isolated addr spike on vps-prod-01 at 51.02/s vs 25.87/s threshold, sustained.",
            "cause": "Sudden jump from 14/s to 46.72/s at 00:18 UTC, source peer unidentified.",
            "scope": "isolated to vps-prod-01 (vps-dev-01: 3.79/s, bitcoin-01: 0.31/s)",
            "evidence": [
                "addr_rate: 51.02/s vs upper_band 25.87/s (1.97x)",
                "onset: step-change at 00:18 UTC from ~14/s baseline",
                "rate-limited peers: 3 (pre-existing, not new triggers)"
            ]
        }"#
    }

    fn investigate_json() -> &'static str {
        r#"{
            "verdict": "investigate",
            "action": "monitor for 15 minutes, escalate if rate exceeds 35/s",
            "summary": "Second consecutive addr spike within 14 minutes on vps-prod-01.",
            "cause": "Periodic addr relay re-broadcast cycle across inbound peer set.",
            "scope": "multi-host (vps-prod-01 and vps-dev-01 simultaneously)",
            "evidence": [
                "addr_rate: 26.09/s at 23:06 UTC, declining to 23.98/s",
                "adaptive upper band drifted from 19.7/s to 23.9/s"
            ]
        }"#
    }

    #[test]
    fn parse_benign_annotation() {
        let ann = parse_structured_annotation(benign_json()).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
        assert!(ann.action.is_none());
        assert!(ann.summary.contains("self-resolving"));
        assert_eq!(ann.evidence.len(), 2);
    }

    #[test]
    fn parse_action_required_annotation() {
        let ann = parse_structured_annotation(action_required_json()).unwrap();
        assert_eq!(ann.verdict, Verdict::ActionRequired);
        assert!(ann.action.as_ref().unwrap().contains("getpeerinfo"));
        assert_eq!(ann.evidence.len(), 3);
    }

    #[test]
    fn parse_investigate_annotation() {
        let ann = parse_structured_annotation(investigate_json()).unwrap();
        assert_eq!(ann.verdict, Verdict::Investigate);
        assert!(ann.action.as_ref().unwrap().contains("monitor"));
    }

    #[test]
    fn parse_investigate_without_action() {
        let json = r#"{
            "verdict": "investigate",
            "summary": "Elevated rate but declining.",
            "cause": "Network-wide propagation burst.",
            "scope": "multi-host",
            "evidence": ["metric_a: 10/s", "metric_b: 5/s"]
        }"#;
        let ann = parse_structured_annotation(json).unwrap();
        assert_eq!(ann.verdict, Verdict::Investigate);
        assert!(ann.action.is_none());
    }

    #[test]
    fn parse_fails_on_invalid_json() {
        assert!(parse_structured_annotation("not json").is_err());
    }

    #[test]
    fn parse_fails_on_invalid_verdict() {
        let json = r#"{
            "verdict": "critical",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    // ── Validation ────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_summary() {
        let json = r#"{
            "verdict": "benign",
            "summary": "", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_whitespace_only_summary() {
        let json = r#"{
            "verdict": "benign",
            "summary": "   ", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_whitespace_only_cause() {
        let json = r#"{
            "verdict": "benign",
            "summary": "test", "cause": "  \n  ", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_whitespace_only_scope() {
        let json = r#"{
            "verdict": "benign",
            "summary": "test", "cause": "test", "scope": "\t",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_single_evidence_item() {
        let json = r#"{
            "verdict": "benign",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["only one"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_five_evidence_items() {
        let json = r#"{
            "verdict": "benign",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b", "c", "d", "e"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_whitespace_only_evidence_item() {
        let json = r#"{
            "verdict": "benign",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["valid", "   "]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_benign_with_action() {
        let json = r#"{
            "verdict": "benign",
            "action": "restart node",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_action_required_without_action() {
        let json = r#"{
            "verdict": "action_required",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_action_required_with_empty_action() {
        let json = r#"{
            "verdict": "action_required",
            "action": "",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_action_required_with_whitespace_action() {
        let json = r#"{
            "verdict": "action_required",
            "action": "   ",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    #[test]
    fn validate_rejects_investigate_with_whitespace_action() {
        let json = r#"{
            "verdict": "investigate",
            "action": "  \t  ",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        assert!(parse_structured_annotation(json).is_err());
    }

    // ── HTML rendering ────────────────────────────────────────────────

    #[test]
    fn render_html_benign() {
        let ann = parse_structured_annotation(benign_json()).unwrap();
        let html = render_annotation_html(&ann);
        assert!(html.contains("<b>VERDICT:</b> BENIGN<br>"));
        assert!(html.contains("<b>ACTION:</b> none<br>"));
        assert!(html.contains("<b>SUMMARY:</b>"));
        assert!(html.contains("<b>CAUSE:</b>"));
        assert!(html.contains("<b>SCOPE:</b>"));
        assert!(html.contains("<b>EVIDENCE:</b>"));
        assert!(html.contains("&bull;"));
    }

    #[test]
    fn render_html_action_required() {
        let ann = parse_structured_annotation(action_required_json()).unwrap();
        let html = render_annotation_html(&ann);
        assert!(html.contains("<b>VERDICT:</b> ACTION REQUIRED<br>"));
        assert!(html.contains("<b>ACTION:</b> run getpeerinfo"));
    }

    #[test]
    fn render_html_escapes_special_chars() {
        let json = r#"{
            "verdict": "benign",
            "summary": "Rate < 10 & normal > baseline",
            "cause": "test", "scope": "test",
            "evidence": ["metric <5/s", "metric >10/s"]
        }"#;
        let ann = parse_structured_annotation(json).unwrap();
        let html = render_annotation_html(&ann);
        assert!(html.contains("Rate &lt; 10 &amp; normal &gt; baseline"));
        assert!(html.contains("metric &lt;5/s"));
    }

    #[test]
    fn render_html_trims_whitespace() {
        let json = r#"{
            "verdict": "benign",
            "summary": "  padded summary  ",
            "cause": "  padded cause  ", "scope": "  padded scope  ",
            "evidence": ["  padded evidence  ", "  more  "]
        }"#;
        let ann = parse_structured_annotation(json).unwrap();
        let html = render_annotation_html(&ann);
        assert!(html.contains("<b>SUMMARY:</b> padded summary<br>"));
        assert!(html.contains("<b>CAUSE:</b> padded cause<br>"));
        assert!(html.contains("&bull; padded evidence<br>"));
    }

    // ── Plaintext rendering ───────────────────────────────────────────

    #[test]
    fn render_plaintext_single_line() {
        let ann = parse_structured_annotation(benign_json()).unwrap();
        let text = render_annotation_plaintext(&ann);
        assert!(!text.contains('\n'), "plaintext must be single-line");
        assert!(!text.contains('\r'), "plaintext must not contain \\r");
        assert!(text.starts_with("VERDICT: BENIGN"));
        assert!(text.contains("| ACTION: none |"));
        assert!(text.contains("| SUMMARY:"));
        assert!(text.contains("| EVIDENCE:"));
    }

    #[test]
    fn render_plaintext_action_required() {
        let ann = parse_structured_annotation(action_required_json()).unwrap();
        let text = render_annotation_plaintext(&ann);
        assert!(text.contains("VERDICT: ACTION REQUIRED"));
        assert!(text.contains("| ACTION: run getpeerinfo"));
    }

    // ── Log field sanitization ────────────────────────────────────────

    #[test]
    fn sanitize_log_field_strips_newlines() {
        assert_eq!(sanitize_log_field("line1\nline2"), "line1 line2");
        assert_eq!(sanitize_log_field("line1\r\nline2"), "line1  line2");
    }

    #[test]
    fn sanitize_log_field_replaces_pipe() {
        assert_eq!(sanitize_log_field("a | b"), "a / b");
    }

    #[test]
    fn sanitize_log_field_preserves_normal_text() {
        assert_eq!(sanitize_log_field("normal text"), "normal text");
    }

    #[test]
    fn render_plaintext_sanitizes_multiline_fields() {
        let json = r#"{
            "verdict": "benign",
            "summary": "line1\nline2",
            "cause": "cause with\nnewline",
            "scope": "scope | piped",
            "evidence": ["evidence\nwith\nnewlines", "normal"]
        }"#;
        let ann = parse_structured_annotation(json).unwrap();
        let text = render_annotation_plaintext(&ann);
        assert!(
            !text.contains('\n'),
            "plaintext must be single-line after sanitization"
        );
        // Pipes in fields are replaced so they don't break delimiters
        assert!(!text.contains("scope | piped"));
        assert!(text.contains("scope / piped"));
    }

    // ── HTML stripping ────────────────────────────────────────────────

    #[test]
    fn strip_html_roundtrip() {
        let ann = parse_structured_annotation(benign_json()).unwrap();
        let html = render_annotation_html(&ann);
        let stripped = strip_annotation_html(&html);
        // Should contain readable field labels without HTML tags
        assert!(stripped.contains("VERDICT:"));
        assert!(stripped.contains("SUMMARY:"));
        assert!(!stripped.contains("<b>"));
        assert!(!stripped.contains("</b>"));
        assert!(!stripped.contains("<br>"));
    }

    #[test]
    fn strip_html_unescapes_entities_for_structured() {
        // Entity unescaping only applies to structured HTML (has <b>VERDICT:</b> marker)
        let structured = "<b>VERDICT:</b> BENIGN<br>rate &lt; 10 &amp; normal &gt; 5";
        let stripped = strip_annotation_html(structured);
        assert!(stripped.contains("rate < 10 & normal > 5"));
    }

    #[test]
    fn strip_html_preserves_entities_for_fallback() {
        // Fallback (non-structured) text must NOT have entities unescaped
        // to prevent XML fence breakout in prompt injection
        let fallback = "rate &lt; 10 &amp; normal &gt; 5";
        let stripped = strip_annotation_html(fallback);
        assert_eq!(stripped, "rate &lt; 10 &amp; normal &gt; 5");
    }

    #[test]
    fn strip_html_no_double_decode() {
        // Input containing a literal "&lt;" that was HTML-escaped to "&amp;lt;"
        // in structured output — must stop at "&lt;", not decode to "<"
        let structured = "<b>VERDICT:</b> BENIGN<br>value &amp;lt; threshold";
        let stripped = strip_annotation_html(structured);
        assert!(stripped.contains("value &lt; threshold"));
    }

    #[test]
    fn strip_html_converts_bullets() {
        let stripped = strip_annotation_html("&bull; item one<br>&bull; item two<br>");
        assert_eq!(stripped, "- item one\n- item two\n");
    }

    #[test]
    fn strip_html_passes_through_plain_text() {
        let text = "plain text without any html";
        assert_eq!(strip_annotation_html(text), text);
    }
}
