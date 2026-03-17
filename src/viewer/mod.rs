//! Annotation log viewer — JSONL log entries, `/api/logs` API, and `/logs` HTML page.
//!
//! Enabled only when both `ANNOTATION_AGENT_LOG_FILE` and
//! `ANNOTATION_AGENT_VIEWER_AUTH_TOKEN` are configured.

mod api;
mod cursor;
mod html;
mod log_file;
mod log_schema;

pub(crate) use api::api_logs;
pub(crate) use html::logs_page;
pub(crate) use log_file::append_jsonl_log;
pub(crate) use log_schema::{LogEntry, Telemetry};
