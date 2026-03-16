# Deployment

## NixOS

This crate can be added as a flake input to [infra-library](https://github.com/peer-observer/infra-library) or any NixOS configuration. The NixOS module in infra-library (`modules/web/annotation-agent.nix`) handles service configuration, MCP config generation, and secret management via agenix — but consumers must explicitly add this repo as a flake input and wire it up.

### Flake Checks

The flake exposes checks for fmt, clippy, tests, and the package build on supported Linux systems:

```bash
nix flake check    # runs all checks
nix build          # build the package only
```

On Darwin development hosts, use `just pre-release` for local validation. The flake package itself is Linux-targeted and is validated in CI.

## Security Assumptions

This service is designed for deployment on trusted internal networks behind a reverse proxy or firewall:

- **Unauthenticated webhook endpoint**: The `/webhook` endpoint accepts Alertmanager payloads without authentication. It must not be exposed to the public internet — restrict access to Alertmanager's IP or a localhost-only bind address.
- **`--dangerously-skip-permissions`**: Claude CLI is invoked with this flag to enable autonomous MCP tool use. This is required for unattended operation but means the Claude process has unrestricted tool access. The MCP config should only expose the Prometheus read API.
- **Cooldown suppression**: Before invoking Claude, in-process cooldown suppression coalesces retriggers of the same `(alertname, host, threadname)` within a configurable window (`ANNOTATION_AGENT_COOLDOWN_SECS`, default 30 minutes). An RAII `CooldownGuard` manages state transitions — successful investigations (Claude + Grafana post) mark the entry as completed, while failures or panics clear the entry so Alertmanager retries are not suppressed. State does not survive process restarts.
- **Grafana idempotency**: After investigation, duplicate annotations are prevented by checking Grafana for existing annotations (±1s around `startsAt`) before posting. If Alertmanager retries a webhook after a partial failure, already-posted annotations will be skipped.

## Health Endpoint

`GET /healthz` returns `200 OK` — useful for reverse proxy health checks and uptime monitoring without sending fake alerts.

## MCP Config

The agent needs a JSON file pointing to a Prometheus MCP server:

```json
{
  "mcpServers": {
    "prometheus": {
      "command": "uvx",
      "args": ["prometheus-mcp-server@1.6.0"],
      "env": {
        "PROMETHEUS_URL": "http://127.0.0.1:9090"
      }
    }
  }
}
```

## Configuration Reference

All config via environment variables prefixed `ANNOTATION_AGENT_*`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANNOTATION_AGENT_LISTEN_ADDR` | `127.0.0.1:9099` | HTTP listen address |
| `ANNOTATION_AGENT_GRAFANA_URL` | `http://127.0.0.1:9321` | Grafana base URL |
| `ANNOTATION_AGENT_GRAFANA_API_KEY` | (required) | Grafana service account token |
| `ANNOTATION_AGENT_CLAUDE_BIN` | `claude` | Path to Claude CLI binary |
| `ANNOTATION_AGENT_CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model to use for investigations |
| `ANNOTATION_AGENT_MCP_CONFIG` | (required) | Path to MCP config JSON for Prometheus |
| `ANNOTATION_AGENT_LOG_FILE` | (optional) | Path to append plain-text annotation log |
| `ANNOTATION_AGENT_HTTP_TIMEOUT_SECS` | `30` | HTTP client timeout for Grafana API calls |
| `ANNOTATION_AGENT_CLAUDE_TIMEOUT_SECS` | `600` | Max wall-clock time for a Claude CLI investigation |
| `ANNOTATION_AGENT_MAX_CONCURRENT` | `4` | Max concurrent Claude investigations (values below 1 are coerced to 1) |
| `ANNOTATION_AGENT_COOLDOWN_SECS` | `1800` | Cooldown window for suppressing retriggers of the same `(alertname, host, threadname)` (0 = disabled) |
| `ANNOTATION_AGENT_RPC_HOSTS` | (optional) | JSON map of host names to WireGuard IPs for Bitcoin Core RPC pre-fetch |
| `ANNOTATION_AGENT_RPC_USER` | `rpc-extractor` | Bitcoin Core RPC username |
| `ANNOTATION_AGENT_RPC_PASSWORD` | (required if RPC_HOSTS set) | Bitcoin Core RPC password |
| `ANNOTATION_AGENT_RPC_PORT` | `9000` | Bitcoin Core RPC port (via WireGuard nginx proxy) |

## Bitcoin Core RPC Pre-Fetch

When `ANNOTATION_AGENT_RPC_HOSTS` is set, the agent pre-fetches relevant Bitcoin Core RPC data before invoking Claude. This provides per-peer details (IP addresses, user agents, rate-limited status) that Prometheus aggregate metrics cannot capture.

The RPC pre-fetch maps each alert type to specific RPC methods:
- **P2P message alerts** (PeerObserverAddressMessageSpike, PeerObserverMisbehaviorSpike): `getpeerinfo`
- **Connection alerts** (PeerObserverInboundConnectionDrop, PeerObserverOutboundConnectionDrop, PeerObserverTotalPeersDrop): `getpeerinfo` + `getnetworkinfo`
- **Network inactive** (PeerObserverNetworkInactive): `getnetworkinfo`
- **INV queue alerts** (PeerObserverINVQueueDepthAnomaly, PeerObserverINVQueueDepthExtreme): `getpeerinfo`
- **Chain health alerts** (PeerObserverBlockStale, PeerObserverBlockStaleCritical, PeerObserverNodeInIBD, PeerObserverHeaderBlockGap): `getblockchaininfo`
- **Mempool alerts** (PeerObserverMempoolFull, PeerObserverMempoolEmpty): `getmempoolinfo`
- **Restart alerts** (PeerObserverBitcoinCoreRestart): `getblockchaininfo` + `uptime`
- **CPU/thread alerts** (PeerObserverHighCPU, PeerObserverThreadSaturation): `getblockchaininfo` (IBD correlation)
- **Infrastructure/meta alerts** (PeerObserverServiceFailed, PeerObserverMetricsToolDown, PeerObserverDiskSpaceLow, PeerObserverHighMemory, PeerObserverAnomalyDetectionDown): no RPC pre-fetch

RPC responses are filtered per alert type to keep token cost low (e.g., `getpeerinfo` extracts only relevant fields per peer). The filtered data is injected into the investigation prompt as a `<rpc-data>` section.

**Configuration:**
- `RPC_HOSTS` is a JSON map: `{"bitcoin-03": "10.0.0.3", "vps-dev-01": "10.0.0.4"}`
- Host names must match the `host` label in Alertmanager alerts
- RPC credentials use the `rpc-extractor` user (configured with `-rpcwhitelist` for read-only methods)
- If RPC is unreachable or the host is unmapped, the investigation proceeds with Prometheus data only

**Startup behavior:**
- `RPC_HOSTS` unset: RPC feature disabled, no error
- `RPC_HOSTS` set with valid JSON + `RPC_PASSWORD` set: RPC feature enabled
- `RPC_HOSTS` set with malformed JSON or missing `RPC_PASSWORD`: startup fails fast

The NixOS module in infra-library will need to be updated to generate the `RPC_HOSTS` mapping from `config.infra.nodes` and pass RPC credentials. This is tracked as a separate follow-up.
