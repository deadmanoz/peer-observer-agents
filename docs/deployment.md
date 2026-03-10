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
- **Idempotency**: Duplicate annotations are prevented by checking Grafana for existing annotations before posting. If Alertmanager retries a webhook after a partial failure, already-posted annotations will be skipped.

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
