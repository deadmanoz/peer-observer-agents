//! Cursor pagination for the `/api/logs` endpoint.

use chrono::{DateTime, Utc};

use super::log_schema::LogEntry;

/// Opaque cursor encoding `(logged_at, alert_id)` as base64.
pub(super) fn encode_cursor(logged_at: &DateTime<Utc>, alert_id: &str) -> String {
    let raw = format!("{}|{}", logged_at.to_rfc3339(), alert_id);
    base64_encode(&raw)
}

pub(super) fn decode_cursor(cursor: &str) -> Option<(DateTime<Utc>, String)> {
    let raw = base64_decode(cursor)?;
    let (ts_str, alert_id) = raw.split_once('|')?;
    let ts = ts_str.parse::<DateTime<Utc>>().ok()?;
    Some((ts, alert_id.to_string()))
}

/// URL-safe base64 encoding without pulling in a crate.
/// Uses the URL-safe alphabet (A-Z, a-z, 0-9, -, _) with no padding,
/// so the output is safe to embed directly in URL query parameters
/// without percent-encoding.
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<String> {
    const DECODE: [u8; 128] = {
        let mut table = [255u8; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut i = 0;
        while i < 64 {
            table[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        table
    };
    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return Some(String::new());
    }
    let mut bytes = Vec::with_capacity(input.len() * 3 / 4);
    // Reject any non-base64 characters instead of silently dropping them.
    let mut chars = Vec::with_capacity(input.len());
    for b in input.bytes() {
        if b >= 128 || DECODE[b as usize] == 255 {
            return None; // invalid character
        }
        chars.push(DECODE[b as usize]);
    }
    for chunk in chars.chunks(4) {
        if chunk.len() < 2 {
            return None; // len % 4 == 1 is invalid base64
        }
        let b0 = (chunk[0] as u32) << 18
            | (chunk[1] as u32) << 12
            | if chunk.len() > 2 {
                (chunk[2] as u32) << 6
            } else {
                0
            }
            | if chunk.len() > 3 { chunk[3] as u32 } else { 0 };
        bytes.push((b0 >> 16) as u8);
        if chunk.len() > 2 {
            bytes.push((b0 >> 8) as u8);
        }
        if chunk.len() > 3 {
            bytes.push(b0 as u8);
        }
    }
    String::from_utf8(bytes).ok()
}

// ── Heap entry for bounded top-N collection ─────────────────────────

/// Wrapper around `LogEntry` that implements `Ord` by `(logged_at, alert_id)`
/// for use in a min-heap. The smallest entry (oldest by total order) sits at
/// the top so it can be evicted when the heap exceeds the collection bound.
pub(super) struct HeapEntry {
    pub(super) logged_at: DateTime<Utc>,
    pub(super) alert_id: String,
    pub(super) entry: LogEntry,
}

impl HeapEntry {
    pub(super) fn from_log_entry(entry: LogEntry) -> Self {
        Self {
            logged_at: entry.logged_at,
            alert_id: entry.alert_id.clone(),
            entry,
        }
    }
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        (&self.logged_at, &self.alert_id) == (&other.logged_at, &other.alert_id)
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.logged_at, &self.alert_id).cmp(&(&other.logged_at, &other.alert_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn cursor_roundtrip() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let alert_id = "PeerObserverBlockStale:bitcoin-03:20250615T120000Z";
        let encoded = encode_cursor(&ts, alert_id);
        let (decoded_ts, decoded_id) = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, alert_id);
    }

    #[test]
    fn cursor_decode_invalid() {
        assert!(decode_cursor("not-valid-base64!!!").is_none());
        assert!(decode_cursor("").is_none());
    }

    #[test]
    fn base64_rejects_trailing_garbage() {
        // A valid base64 string with trailing non-base64 chars must be rejected,
        // not silently decoded by dropping the garbage.
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let alert_id = "Test:host:ts";
        let valid = encode_cursor(&ts, alert_id);
        let tampered = format!("{}!!!", valid);
        assert!(
            decode_cursor(&tampered).is_none(),
            "cursor with trailing garbage should be rejected"
        );
    }

    #[test]
    fn base64_roundtrip() {
        let inputs = [
            "",
            "a",
            "ab",
            "abc",
            "abcd",
            "hello world!",
            "2025-06-15T12:00:00+00:00|AlertName:host:ts",
        ];
        for input in inputs {
            let encoded = base64_encode(input);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, input, "roundtrip failed for {input:?}");
        }
    }
}
