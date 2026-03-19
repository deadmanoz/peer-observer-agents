// Shared sanitization helpers re-exported for prompt-internal use.
pub(super) use crate::sanitization::sanitize_host_for_prompt;

/// Sanitize a value for safe embedding inside a PromQL label selector string
/// (i.e., inside double quotes: `{label="VALUE"}`). Escapes `\` and `"` to
/// prevent selector injection, and strips ASCII control characters (U+0000–U+001F,
/// U+007F) and C1 control codes (U+0080–U+009F).
///
/// Also strips backticks, which are not a PromQL concern but are needed because
/// the investigation prompt wraps PromQL queries in markdown backtick code spans.
/// A backtick in the label value would prematurely close the code span, causing
/// Claude to receive a malformed query. If a real metric has a backtick in its
/// label, the sanitized query will return empty data and the fast-path will
/// correctly fall back to the full investigation.
///
/// IMPORTANT: Only safe for exact-match (`=`) and inequality (`!=`) label matchers.
/// For regex matchers (`=~`, `!~`) additional regex metacharacter escaping is required.
pub(super) fn sanitize_promql_label(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => result.push_str(r"\\"),
            '"' => result.push_str(r#"\""#),
            '`' => {} // strip: would break markdown code spans wrapping PromQL in the prompt
            c if c.is_ascii_control() || ('\u{0080}'..='\u{009F}').contains(&c) => {} // strip ASCII and C1 control characters
            _ => result.push(ch),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_promql_label_escapes_quotes_and_backslashes() {
        assert_eq!(sanitize_promql_label(r#"normal-host"#), "normal-host");
        assert_eq!(
            sanitize_promql_label(r#"foo",anomaly_name="evil"#),
            r#"foo\",anomaly_name=\"evil"#
        );
        assert_eq!(sanitize_promql_label(r"back\slash"), r"back\\slash");
        assert_eq!(sanitize_promql_label("line\nbreak"), "linebreak");
        assert_eq!(sanitize_promql_label("tab\there"), "tabhere");
        assert_eq!(sanitize_promql_label("null\0here"), "nullhere");
        // All ASCII control chars stripped (U+0000–U+001F, U+007F)
        assert_eq!(sanitize_promql_label("bell\x07here"), "bellhere");
        assert_eq!(sanitize_promql_label("del\x7fhere"), "delhere");
        // C1 control codes stripped (U+0080–U+009F)
        assert_eq!(sanitize_promql_label("c1\u{0085}here"), "c1here");
        // Backticks stripped (would break markdown code spans in prompt)
        assert_eq!(sanitize_promql_label("host`name"), "hostname");
        assert_eq!(sanitize_promql_label(""), "");
    }
}
