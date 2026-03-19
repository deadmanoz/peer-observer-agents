use std::borrow::Cow;

pub(super) fn anomaly_detection_down() -> Cow<'static, str> {
    r#"1. This is a META alert — the anomaly detection system itself has stopped producing data.
2. Check if the recording rules are generating data: query `peerobserver_anomaly:level` to see if any anomaly metrics exist.
3. Check Prometheus scrape targets — is peer-observer's metrics endpoint being scraped successfully?
4. Check if peer-observer itself is running by looking for its process metrics or up status.
5. Look at Prometheus rule evaluation metrics to see if rule evaluation is failing.
6. Conclude: determine whether peer-observer is down, Prometheus is failing to scrape, or the recording rules have an issue. This alert means all other anomaly-based alerts are also non-functional."#.into()
}
