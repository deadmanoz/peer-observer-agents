use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::fmt;

/// Error from `parse_structured_annotation` — distinguishes policy violations
/// from structural/format failures so callers can route logging correctly.
#[derive(Debug)]
pub(crate) enum AnnotationError {
    /// The JSON was parsed and structurally valid, but contained a prohibited
    /// peer-intervention command.
    PolicyViolation(String),
    /// JSON parsing or structural validation failed.
    ParseError(anyhow::Error),
}

impl fmt::Display for AnnotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnotationError::PolicyViolation(msg) => write!(f, "{msg}"),
            AnnotationError::ParseError(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for AnnotationError {}

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
    /// `investigate` (e.g., "operator should review getpeerinfo for peers with elevated addr volumes"),
    /// must be absent for `benign`.
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

/// Validate a structured annotation against the schema contract (structure only).
///
/// This checks field presence, emptiness, evidence count, and verdict-action
/// consistency. It does NOT check content policy (peer-intervention commands).
/// Used by `extract_json_object` to identify valid annotation JSON among
/// preamble/commentary text.
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
            let is_absent = ann
                .action
                .as_deref()
                .map(|a| a.trim().is_empty() || a.trim().eq_ignore_ascii_case("none"))
                .unwrap_or(true);
            ensure!(is_absent, "benign verdict must not have an action");
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
                !action.trim().is_empty() && !action.trim().eq_ignore_ascii_case("none"),
                "action_required verdict must have a non-empty, non-'none' action"
            );
        }
    }

    Ok(())
}

/// Discriminating substring in policy-violation error messages. Used in
/// `check_peer_intervention_policy`'s bail message and in tests to avoid
/// hardcoding the error text. Callers in `main.rs` now use the typed
/// `AnnotationError` enum — this constant centralises the error-message
/// text to prevent test drift.
const POLICY_ERROR_MARKER: &str = "peer-intervention";

/// Check content policy: reject annotations containing peer-intervention commands.
///
/// Separated from `validate_structured_annotation` so that `extract_json_object`
/// can identify structurally valid JSON without policy errors causing it to skip
/// the real annotation object. Policy violations surface in `parse_structured_annotation`
/// with a clear error message, not as a misleading "failed to parse" fallback.
fn check_peer_intervention_policy(ann: &StructuredAnnotation) -> Result<()> {
    let all_text_fields = [
        ann.action.as_deref().unwrap_or(""),
        &ann.summary,
        &ann.cause,
        &ann.scope,
    ]
    .into_iter()
    .chain(ann.evidence.iter().map(|e| e.as_str()));

    for field_text in all_text_fields {
        // Check the deserialized text and also a decoded version to catch
        // double-escaped Unicode (\\uXXXX → \uXXXX after serde, then decoded here).
        // Two-pass decode mirrors sanitize_raw_fallback for nested encoding.
        let decoded = decode_unicode_escapes(field_text);
        let decoded = if decoded != field_text && decoded.contains("\\u") {
            let d2 = decode_unicode_escapes(&decoded);
            if d2 != decoded {
                d2
            } else {
                decoded
            }
        } else {
            decoded
        };
        let texts_to_check: &[&str] = if decoded != field_text {
            &[field_text, &decoded]
        } else {
            &[field_text]
        };
        for text in texts_to_check {
            if let Some(pattern) = contains_peer_intervention(text) {
                anyhow::bail!(
                    "annotation contains {POLICY_ERROR_MARKER} command ({pattern}); \
                     these are research/monitoring nodes — peer intervention is not permitted"
                );
            }
        }
    }

    Ok(())
}

/// Parse Claude's result text as a structured annotation JSON object.
///
/// Extracts the JSON object from the string before deserialising, tolerating
/// code fences, preambles, or trailing commentary that Claude may add despite
/// the strict prompt instruction.
///
/// Returns `AnnotationError::PolicyViolation` if the annotation is structurally
/// valid but contains prohibited peer-intervention commands, or
/// `AnnotationError::ParseError` for JSON/structural failures.
pub(crate) fn parse_structured_annotation(
    raw: &str,
) -> std::result::Result<StructuredAnnotation, AnnotationError> {
    let mut ann: StructuredAnnotation = serde_json::from_str(raw)
        .or_else(|first_err| {
            extract_json_object(raw)
                .ok_or_else(|| anyhow::anyhow!("{first_err}"))
                .and_then(|json_str| {
                    serde_json::from_str(json_str)
                        .context("extracted JSON object failed to deserialize")
                })
        })
        .context("Claude output is not valid StructuredAnnotation JSON")
        .map_err(AnnotationError::ParseError)?;
    validate_structured_annotation(&ann).map_err(AnnotationError::ParseError)?;
    check_peer_intervention_policy(&ann)
        .map_err(|e| AnnotationError::PolicyViolation(e.to_string()))?;
    // Normalize benign action to None so consumers don't need to re-filter
    // empty string / "none" variants that passed validation.
    if ann.verdict == Verdict::Benign {
        ann.action = None;
    }
    Ok(ann)
}

/// Extract a top-level JSON object from a string by counting balanced braces.
/// Scans all `{` positions in order and returns the first balanced object that
/// deserialises as a valid `StructuredAnnotation`, skipping incidental JSON
/// objects in preamble or commentary text.
fn extract_json_object(s: &str) -> Option<&str> {
    let mut search_from = 0;
    while let Some(rel) = s[search_from..].find('{') {
        let start = search_from + rel;
        if let Some(slice) = find_balanced_object(s, start) {
            if serde_json::from_str::<StructuredAnnotation>(slice)
                .map(|a| validate_structured_annotation(&a).is_ok())
                .unwrap_or(false)
            {
                return Some(slice);
            }
        }
        search_from = start + 1;
    }
    None
}

/// From a given start position (which must be a `{`), walk forward counting
/// balanced braces (skipping braces inside JSON string literals) and return
/// the slice from `start` to the matching `}`.
fn find_balanced_object(s: &str, start: usize) -> Option<&str> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, ch) in s[start..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..=start + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Peer-intervention command patterns that must not appear in annotations.
/// Scoped to peer-level intervention only — node-level remediation like
/// `setnetworkactive`, `systemctl restart`, etc. is intentionally allowed.
const PEER_INTERVENTION_PATTERNS: &[&str] = &[
    // Command-form patterns
    "disconnectnode",
    "setban",
    // Natural-language patterns (curated, kept minimal to avoid false positives)
    "disconnect the peer",
    "disconnect that peer",
    "disconnect this peer",
    "disconnect peer",
    "disconnect peers",
    "disconnecting the peer",
    "disconnecting peer",
    "disconnecting peers",
    "disconnecting from the peer",
    "disconnecting from peer",
    "disconnecting from peers",
    "disconnect from the peer",
    "disconnect from peer",
    "disconnect from peers",
    "disconnect and ban",
    "ban the peer",
    "ban that peer",
    "ban this peer",
    "ban peer",
    "ban peers",
    "ban these peers",
    "ban the peers",
    "disconnect the peers",
    "disconnecting the peers",
    "banning the peer",
    "banning peer",
    "banning peers",
];

/// Zero-width Unicode characters that could be inserted between letters of
/// a prohibited command to evade substring matching.
const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{FEFF}', // BOM / ZERO WIDTH NO-BREAK SPACE
    '\u{2060}', // WORD JOINER
    '\u{00AD}', // SOFT HYPHEN
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR
    '\u{2061}', // FUNCTION APPLICATION
    '\u{2062}', // INVISIBLE TIMES
    '\u{2063}', // INVISIBLE SEPARATOR
    '\u{2064}', // INVISIBLE PLUS
];

/// Check whether text contains peer-intervention commands.
/// Returns `Some(pattern)` if a match is found, `None` if clean.
///
/// Uses word-boundary-aware matching: each pattern must have non-alphanumeric
/// characters (or string boundaries) on both sides. This prevents false positives
/// like "urban peer" matching "ban peer" or "setbandwidth" matching "setban".
///
/// Known limitations:
/// - Bare "ban <IP>" without the word "peer" is not matched to avoid false
///   positives on observational text. The RPC command `setban` is covered separately.
/// - Unicode homoglyph/confusable characters (e.g., Cyrillic `а` for Latin `a`)
///   are not normalized. This is accepted because Claude does not output confusable
///   characters in practice — the prompt rewrite is the primary defense.
/// - Negated forms ("we should not ban peers") will trigger the guard. This is
///   accepted — the cost of occasionally redacting a valid annotation that restates
///   the no-intervention policy is lower than the cost of missing a real violation.
/// - Hyphen-split command names ("set-ban", "dis-connectnode") are not matched.
///   Claude does not produce hyphenated RPC names in practice.
pub(crate) fn contains_peer_intervention(text: &str) -> Option<&'static str> {
    let normalized: String = text
        .chars()
        .filter(|c| !ZERO_WIDTH_CHARS.contains(c))
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect::<String>()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    PEER_INTERVENTION_PATTERNS
        .iter()
        .find(|p| has_word_boundary_match(&normalized, p))
        .copied()
}

/// Check if `pattern` appears in `text` with word boundaries on both sides.
/// A word boundary means the adjacent character is not a word character or the
/// match is at the start/end of the text. Word characters include alphanumerics,
/// hyphens, and underscores (to avoid false positives on "peer-to-peer" etc.).
fn has_word_boundary_match(text: &str, pattern: &str) -> bool {
    let is_word_char = |c: char| c.is_alphanumeric() || c == '-' || c == '_';
    let mut idx = 0;
    while let Some(pos) = text[idx..].find(pattern) {
        let abs = idx + pos;
        let preceded_by_word_char =
            abs > 0 && text[..abs].chars().next_back().is_some_and(is_word_char);
        let end = abs + pattern.len();
        let followed_by_word_char = text[end..].chars().next().is_some_and(is_word_char);
        if !preceded_by_word_char && !followed_by_word_char {
            return true;
        }
        // Step past the first character of the match. All current patterns
        // are ASCII (1 byte), but use char width for safety if non-ASCII
        // patterns are ever added.
        idx = abs + pattern.chars().next().map_or(1, |c| c.len_utf8());
    }
    false
}

/// Result of checking raw fallback text against the peer-intervention policy.
pub(crate) struct RawFallbackResult {
    /// HTML body to post to Grafana.
    pub(crate) grafana_body: String,
    /// Text to store in the log `raw_text` field (visible in /logs viewer).
    pub(crate) log_text: String,
    /// Whether the policy was violated.
    pub(crate) policy_violated: bool,
    /// The pattern that matched, if any (for diagnostic logging).
    pub(crate) matched_pattern: Option<&'static str>,
}

/// Check raw fallback text against the peer-intervention policy and produce
/// safe content for both Grafana and the log viewer.
///
/// Scans both the raw text and a JSON-unescaped version (resolving `\uXXXX`
/// sequences) to catch Unicode-escaped prohibited commands that would evade
/// plain substring matching on the raw bytes.
pub(crate) fn sanitize_raw_fallback(raw: &str) -> RawFallbackResult {
    // First check the raw text directly.
    let matched = contains_peer_intervention(raw);
    // Also check a version with \uXXXX sequences decoded, to catch
    // Unicode-escaped prohibited commands. Uses a direct decoder instead
    // of JSON parsing to avoid failures from control chars or invalid escapes.
    let matched = matched.or_else(|| {
        if !raw.contains("\\u") {
            return None;
        }
        let decoded = decode_unicode_escapes(raw);
        if decoded == raw {
            return None; // No escapes were actually resolved
        }
        // Re-decode once if the first pass introduced a new \uXXXX sequence
        // (e.g. \u005Cu0064 → \u0064 → d, catching nested encoding).
        let decoded = if decoded.contains("\\u") {
            let d2 = decode_unicode_escapes(&decoded);
            if d2 != decoded {
                d2
            } else {
                decoded
            }
        } else {
            decoded
        };
        contains_peer_intervention(&decoded)
    });
    if let Some(pattern) = matched {
        let stub = "Investigation output contained a prohibited peer-intervention \
                     command. Original text redacted.";
        RawFallbackResult {
            grafana_body: format!("<b>POLICY VIOLATION:</b> {stub}"),
            log_text: stub.to_string(),
            policy_violated: true,
            matched_pattern: Some(pattern),
        }
    } else {
        RawFallbackResult {
            grafana_body: html_escape(raw),
            log_text: raw.to_string(),
            policy_violated: false,
            matched_pattern: None,
        }
    }
}

/// Decode `\uXXXX` escape sequences in a string, leaving all other content
/// (including invalid escapes, control chars, etc.) unchanged. This avoids
/// the fragility of JSON-wrapping the string for decoding.
fn decode_unicode_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for \u followed by exactly 4 hex digits
        if bytes[i] == b'\\' && i + 5 < bytes.len() && bytes[i + 1] == b'u' {
            let hex_bytes = &bytes[i + 2..i + 6];
            if hex_bytes.iter().all(|b| b.is_ascii_hexdigit()) {
                // Safety: all bytes are ASCII hex digits, so this is valid UTF-8.
                let hex = std::str::from_utf8(hex_bytes).expect("all ASCII hex");
                if let Ok(code) = u32::from_str_radix(hex, 16) {
                    if let Some(decoded) = char::from_u32(code) {
                        out.push(decoded);
                        i += 6;
                        continue;
                    }
                }
                // Valid hex but invalid codepoint (surrogate) — emit nothing
                // so adjacent characters remain contiguous for substring matching.
                i += 6;
                continue;
            }
        }
        // Not a \uXXXX sequence — emit the character unchanged.
        // Safety: we only index bytes for ASCII checks above; for output we
        // iterate chars to handle multi-byte UTF-8 correctly.
        let c = s[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out
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
        Some(a) if !a.trim().is_empty() && !a.trim().eq_ignore_ascii_case("none") => {
            html_escape(a.trim())
        }
        _ => "none".to_string(),
    };

    let last = ann.evidence.len().saturating_sub(1);
    let evidence_items: String = ann
        .evidence
        .iter()
        .enumerate()
        .map(|(i, e)| {
            if i < last {
                format!("&bull; {}<br>", html_escape(e.trim()))
            } else {
                format!("&bull; {}", html_escape(e.trim()))
            }
        })
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
            "action": "operator should review getpeerinfo for peers with elevated addr byte volumes and document findings",
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
        assert!(ann.action.as_ref().unwrap().contains("getpeerinfo"));
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
    fn parse_extracts_json_from_code_fence() {
        let wrapped = format!("```json\n{}\n```", benign_json());
        let ann = parse_structured_annotation(&wrapped).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
    }

    #[test]
    fn parse_extracts_json_from_preamble() {
        let wrapped = format!("Here is the analysis:\n{}", benign_json());
        let ann = parse_structured_annotation(&wrapped).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
    }

    #[test]
    fn parse_extracts_json_skipping_preamble_braces() {
        let wrapped = format!(
            "Note: the adaptive band is {{upper_band}}. Analysis:\n{}",
            benign_json()
        );
        let ann = parse_structured_annotation(&wrapped).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
    }

    #[test]
    fn parse_extracts_json_ignoring_trailing_braces() {
        let wrapped = format!(
            "{}\nNote: the adaptive band formula uses {{band_factor}}.",
            benign_json()
        );
        let ann = parse_structured_annotation(&wrapped).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
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
    fn validate_accepts_benign_with_empty_action() {
        let json = r#"{
            "verdict": "benign",
            "action": "",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        let ann = parse_structured_annotation(json).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
        // Normalized to None after parsing
        assert!(ann.action.is_none());
    }

    #[test]
    fn validate_accepts_benign_with_none_action() {
        let json = r#"{
            "verdict": "benign",
            "action": "none",
            "summary": "test", "cause": "test", "scope": "test",
            "evidence": ["a", "b"]
        }"#;
        let ann = parse_structured_annotation(json).unwrap();
        assert_eq!(ann.verdict, Verdict::Benign);
        // Normalized to None after parsing
        assert!(ann.action.is_none());
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
    fn validate_rejects_action_required_with_none_action() {
        let json = r#"{
            "verdict": "action_required",
            "action": "none",
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

    // ── Peer-intervention policy (contains_peer_intervention) ─────────

    #[test]
    fn peer_intervention_detects_disconnectnode() {
        assert!(contains_peer_intervention("bitcoin-cli disconnectnode 1.2.3.4").is_some());
    }

    #[test]
    fn peer_intervention_detects_setban() {
        assert!(contains_peer_intervention("bitcoin-cli setban 1.2.3.4 add 86400").is_some());
    }

    #[test]
    fn peer_intervention_case_insensitive() {
        assert!(contains_peer_intervention("DISCONNECTNODE").is_some());
        assert!(contains_peer_intervention("SetBan").is_some());
    }

    #[test]
    fn peer_intervention_detects_natural_language() {
        assert!(contains_peer_intervention("disconnect the peer at 1.2.3.4").is_some());
        assert!(contains_peer_intervention("ban the peer for 24 hours").is_some());
        assert!(contains_peer_intervention("disconnect and ban 1.2.3.4").is_some());
        assert!(contains_peer_intervention("disconnect peers with high misbehavior").is_some());
        assert!(contains_peer_intervention("ban peer 192.168.1.1 as it is sending spam").is_some());
        assert!(contains_peer_intervention("ban these peers for 24 hours").is_some());
        assert!(contains_peer_intervention("ban peers sending spam").is_some());
    }

    #[test]
    fn peer_intervention_allows_node_commands() {
        assert!(contains_peer_intervention("systemctl restart bitcoind").is_none());
        assert!(contains_peer_intervention("setnetworkactive true").is_none());
        assert!(contains_peer_intervention("getpeerinfo").is_none());
    }

    #[test]
    fn peer_intervention_no_false_positives() {
        // "disconnected" in prose (past tense observation) should not trigger
        assert!(contains_peer_intervention("peer disconnected at 12:00 UTC").is_none());
        // "banned" in prose should not trigger
        assert!(contains_peer_intervention("peer was previously banned").is_none());
        // "bandwidth" should not trigger
        assert!(contains_peer_intervention("high bandwidth usage").is_none());
        // "urban peer" / "suburban peer" must not trigger "ban peer" match
        assert!(
            contains_peer_intervention("the urban peer cluster shows elevated addr volumes")
                .is_none()
        );
        assert!(contains_peer_intervention("suburban peer group has high latency").is_none());
        // "setbandwidth" must not trigger "setban" match (trailing boundary)
        assert!(contains_peer_intervention("setbandwidth 1000").is_none());
        // "disconnect and bank" must not trigger "disconnect and ban" match
        assert!(contains_peer_intervention("disconnect and bank transfer").is_none());
        // "ban peer-to-peer" must not trigger "ban peer" match (hyphen is word char)
        assert!(
            contains_peer_intervention("do not ban peer-to-peer addr relay from this subnet")
                .is_none()
        );
        // multi-space runs must not evade multi-word patterns
        assert!(contains_peer_intervention("ban  peer sending spam").is_some());
        assert!(contains_peer_intervention("disconnect\t\tthe peer").is_some());
    }

    // ── Peer-intervention policy (structured path) ────────────────────

    #[test]
    fn validate_rejects_action_with_disconnectnode() {
        let json = r#"{"verdict":"action_required","action":"run bitcoin-cli disconnectnode 1.2.3.4:8333",
            "summary":"test","cause":"test","scope":"test","evidence":["a","b"]}"#;
        let err = parse_structured_annotation(json).unwrap_err();
        assert!(err.to_string().contains(POLICY_ERROR_MARKER));
    }

    #[test]
    fn validate_rejects_setban_in_summary() {
        let json = r#"{"verdict":"investigate","action":"check logs",
            "summary":"consider running setban on 1.2.3.4","cause":"test","scope":"test",
            "evidence":["a","b"]}"#;
        let err = parse_structured_annotation(json).unwrap_err();
        assert!(err.to_string().contains(POLICY_ERROR_MARKER));
    }

    #[test]
    fn validate_rejects_disconnectnode_in_evidence() {
        let json = r#"{"verdict":"investigate",
            "summary":"test","cause":"test","scope":"test",
            "evidence":["run disconnectnode to fix","metric b"]}"#;
        let err = parse_structured_annotation(json).unwrap_err();
        assert!(err.to_string().contains(POLICY_ERROR_MARKER));
    }

    #[test]
    fn validate_allows_node_level_actions() {
        let json = r#"{"verdict":"action_required","action":"systemctl restart bitcoind on bitcoin-01",
            "summary":"test","cause":"test","scope":"test","evidence":["a","b"]}"#;
        assert!(parse_structured_annotation(json).is_ok());
    }

    #[test]
    fn validate_rejects_policy_violation_in_preamble_wrapped_json() {
        // When Claude outputs preamble + JSON with a prohibited command,
        // the policy error must surface as "peer-intervention", not as a
        // misleading "failed to parse structured annotation" format error.
        let wrapped = r#"Here is the analysis:
{"verdict":"action_required","action":"run bitcoin-cli disconnectnode 1.2.3.4:8333",
"summary":"test","cause":"test","scope":"test","evidence":["a","b"]}"#;
        let err = parse_structured_annotation(wrapped).unwrap_err();
        assert!(
            err.to_string().contains(POLICY_ERROR_MARKER),
            "preamble-wrapped policy violation should surface as peer-intervention error, got: {err}"
        );
    }

    #[test]
    fn validate_allows_setnetworkactive() {
        let json = r#"{"verdict":"action_required","action":"bitcoin-cli setnetworkactive true",
            "summary":"test","cause":"test","scope":"test","evidence":["a","b"]}"#;
        assert!(parse_structured_annotation(json).is_ok());
    }

    // ── sanitize_raw_fallback ─────────────────────────────────────────

    #[test]
    fn raw_fallback_redacts_prohibited_text() {
        let result = sanitize_raw_fallback(
            "You should run bitcoin-cli disconnectnode 1.2.3.4:8333 to fix this.",
        );
        assert!(result.policy_violated);
        assert!(result.grafana_body.contains("POLICY VIOLATION"));
        assert!(!result.grafana_body.contains("disconnectnode"));
        assert!(!result.log_text.contains("disconnectnode"));
        assert!(result.log_text.contains("redacted"));
    }

    #[test]
    fn raw_fallback_redacts_unicode_escaped_prohibited_text() {
        // \u0064 = "d", so "\u0064isconnectnode" decodes to "disconnectnode"
        let result =
            sanitize_raw_fallback("You should run bitcoin-cli \\u0064isconnectnode 1.2.3.4:8333");
        assert!(result.policy_violated);
        assert!(result.matched_pattern.is_some());
    }

    #[test]
    fn raw_fallback_redacts_unicode_escape_with_newlines() {
        // Multi-line output with Unicode escape — must not be bypassed by
        // the presence of control characters in the raw text.
        let result = sanitize_raw_fallback(
            "The analysis is complete.\nRun bitcoin-cli \\u0064isconnectnode 1.2.3.4 to fix.",
        );
        assert!(result.policy_violated);
    }

    #[test]
    fn raw_fallback_exposes_matched_pattern() {
        let result = sanitize_raw_fallback("run bitcoin-cli setban 1.2.3.4 add");
        assert!(result.policy_violated);
        assert_eq!(result.matched_pattern, Some("setban"));
    }

    #[test]
    fn raw_fallback_passes_clean_text() {
        let raw = "The addr rate peaked at 25/s, check getpeerinfo for details.";
        let result = sanitize_raw_fallback(raw);
        assert!(!result.policy_violated);
        assert_eq!(result.log_text, raw);
        assert!(result.grafana_body.contains("addr rate peaked"));
    }
}
