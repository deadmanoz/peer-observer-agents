//! Peer profiles — continuous polling of `getpeerinfo`, persistent per-peer profiles
//! in SQLite, and API/viewer endpoints.
//!
//! Enabled when `ANNOTATION_AGENT_PROFILES_DB` is set. The poller requires
//! `ANNOTATION_AGENT_RPC_HOSTS` to be configured. The viewer requires
//! `ANNOTATION_AGENT_VIEWER_AUTH_TOKEN`.

pub(crate) mod api;
pub(crate) mod db;
pub(crate) mod identity;
pub(crate) mod models;
pub(crate) mod poller;

pub(crate) use db::ProfileDb;
