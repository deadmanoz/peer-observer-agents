//! JSONL file I/O for annotation log entries.

use tracing::warn;

use super::log_schema::LogEntry;

/// Append a JSONL log entry to the configured log file.
///
/// Serializes writes via the provided mutex to prevent interleaved bytes
/// when concurrent investigations complete simultaneously. `O_APPEND` alone
/// does not guarantee atomicity for payloads larger than `PIPE_BUF` (~4 KB),
/// and raw fallback entries can exceed that limit.
pub(crate) async fn append_jsonl_log(
    path: &str,
    entry: &LogEntry,
    write_mutex: &tokio::sync::Mutex<()>,
) {
    let mut line = match serde_json::to_string(entry) {
        Ok(json) => json,
        Err(e) => {
            warn!("failed to serialize log entry: {e}");
            return;
        }
    };
    line.push('\n');
    let _guard = write_mutex.lock().await;
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(mut f) => {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = f.write_all(line.as_bytes()).await {
                warn!(path, error = %e, "failed to write JSONL log entry");
            } else if let Err(e) = f.flush().await {
                warn!(path, error = %e, "failed to flush JSONL log entry");
            }
        }
        Err(e) => warn!(path, error = %e, "failed to open JSONL log file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::log_schema::tests::{
        sample_raw_fallback_entry, sample_structured_entry,
    };
    use super::super::log_schema::EntryKind;

    #[tokio::test]
    async fn append_and_read_jsonl() {
        // Use a unique temp file to avoid interference between parallel
        // test runs in sandboxed CI (Nix build sandbox).
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "peer-observer-jsonl-test-{}-append.jsonl",
            std::process::id()
        ));
        let path_str = path.to_str().unwrap();

        // Clean up any previous test file
        let _ = tokio::fs::remove_file(&path).await;

        let entry1 = sample_structured_entry();
        let entry2 = sample_raw_fallback_entry();

        let test_mutex = tokio::sync::Mutex::new(());
        append_jsonl_log(path_str, &entry1, &test_mutex).await;
        append_jsonl_log(path_str, &entry2, &test_mutex).await;

        // Read back and verify
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected 2 JSONL lines, got {}: {:?}",
            lines.len(),
            contents
        );

        let parsed1: LogEntry = serde_json::from_str(lines[0]).unwrap();
        let parsed2: LogEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed1.entry_kind, EntryKind::Structured);
        assert_eq!(parsed2.entry_kind, EntryKind::RawFallback);

        // Cleanup
        let _ = tokio::fs::remove_file(&path).await;
    }
}
