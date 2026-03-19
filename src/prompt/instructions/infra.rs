use std::borrow::Cow;

pub(super) fn service_failed() -> Cow<'static, str> {
    r#"1. This is a CRITICAL alert — a systemd service has failed. The service name is in the `name` label.
2. Query `node_systemd_unit_state{state="failed"}` to identify which specific service(s) have failed.
3. Check if the failed service is bitcoind, peer-observer, NATS, or another infrastructure component.
4. If bitcoind failed: check for correlated block stale alerts and peer count drops.
5. If peer-observer failed: check for correlated anomaly detection down alerts — all monitoring is affected.
6. Conclude: identify the failed service and recommend restarting it. Check if this is a recurring failure pattern by looking at recent restart counts."#.into()
}

pub(super) fn metrics_down() -> Cow<'static, str> {
    r#"1. This is a CRITICAL alert — the peer-observer metrics endpoint is unreachable.
2. Confirm by querying `up{job="peer-observer-metrics"}` — a value of 0 means Prometheus cannot scrape the endpoint.
3. This is the most fundamental health check — if metrics are down, all P2P network alerts are blind.
4. Check if the peer-observer process is running via process exporter metrics.
5. Check for systemd service failures that might explain why the metrics endpoint is down.
6. Conclude: immediate operator action is required to restore metrics collection. All anomaly-based alerts are non-functional while this persists."#.into()
}

pub(super) fn disk_space_low() -> Cow<'static, str> {
    r#"1. This is a CRITICAL alert — disk space is below 10%.
2. Query `node_filesystem_avail_bytes{mountpoint="/"}` and `node_filesystem_size_bytes{mountpoint="/"}` to confirm the exact fill percentage and remaining space.
3. Check the trend — is disk usage growing rapidly (suggesting a log/data leak) or gradually?
4. Bitcoin Core will crash if disk fills completely, corrupting the chainstate.
5. Check which directories are consuming the most space — the Bitcoin datadir (blocks, chainstate) is typically the largest consumer.
6. Conclude: this requires immediate operator action. Bitcoin Core crashes on full disk. Recommend identifying and clearing large files, or expanding storage."#.into()
}

pub(super) fn high_memory() -> Cow<'static, str> {
    r#"1. Query `node_memory_MemAvailable_bytes` to confirm available memory is below 1GB.
2. Check the trend — is memory usage gradually increasing (memory leak) or did it spike suddenly?
3. Check per-process memory usage via process exporter to identify which process is consuming the most memory.
4. Bitcoin Core and peer-observer both consume significant memory — check their individual RSS.
5. Check if the system is swapping (`node_memory_SwapCached_bytes`, `node_vmstat_pswpin`) — swapping severely degrades performance.
6. Conclude: identify the memory-hungry process and whether this is a leak (needs restart) or expected growth (needs more RAM or configuration tuning like dbcache)."#.into()
}
