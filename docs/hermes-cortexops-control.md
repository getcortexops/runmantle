# Hermes CortexOps Control Adapter

Install RunMantle, then run `runmantle-hermes-control-install` and enable it with
`hermes plugins enable runmantle-cortexops-control`. Select the presentation
transport with `security.approval.transport: cortexops`.

The plugin controls only `plugins.entries.runmantle-cortexops-control.settings.controlled_tools`.
It never treats a Hermes terminal result as runtime confirmation. CortexOps must approve
`REQUIRE_APPROVAL` decisions through its authenticated approval API; unavailable, stale,
malformed, denied, or timed-out responses block execution.

```yaml
plugins:
  enabled: [runmantle-cortexops-control]
  entries:
    runmantle-cortexops-control:
      settings:
        cortexops_url: http://127.0.0.1:8000
        authorization: "Bearer REPLACE_ME" # secret; keep outside committed config where possible
        runtime_id: hermes-local
        decision_timeout_seconds: 5
        approval_timeout_seconds: 300
        approval_poll_initial_seconds: 0.25
        approval_poll_max_seconds: 2
        controlled_tools:
          terminal:
            action_name: local-deployment
            capability: terminal.deploy
            risk_level: high
security:
  approval:
    transport: cortexops
```

`cortexops_url` is the CortexOps origin (as above). The transport creates a CortexOps pending approval
for every `REQUIRE_APPROVAL`; it polls that authoritative record and returns
only Hermes's `once` response. It never returns `session` or `always`.

For a local end-to-end run, install both checked-out projects, configure a
runtime bearer token and an operator bearer token in CortexOps, start its
dashboard/API on port 8000, then run Hermes with the profile containing this
plugin. The opt-in fixture below starts a local CortexOps HTTP server itself:

```bash
# CortexOps (terminal 1)
cd /path/to/cortexops
uv sync --extra dev
CORTEXOPS_GOVERNANCE_IDENTITIES_JSON='[{"token":"runtime-token","principal_id":"hermes-runtime","roles":["runtime"]},{"token":"operator-token","principal_id":"operator","roles":["operator"]}]' \
  uv run cortexops dashboard demo --port 8000

# RunMantle + Hermes (terminal 2)
cd /path/to/RunMantle
./.venv/bin/pip install -e '.[dev]'
runmantle-hermes-control-install --hermes-home "$HERMES_HOME"
hermes plugins enable runmantle-cortexops-control
# Configure the YAML above in $HERMES_HOME/config.yaml, then start Hermes.
hermes chat

# Automated local HTTP E2E (Approve and Deny)
RUNMANTLE_CORTEXOPS_PROCESS_TEST=1 CORTEXOPS_REPOSITORY=/path/to/cortexops \
  ./.venv/bin/python -m pytest -q tests/test_hermes_control_e2e.py
```

The E2E fixture exercises both approve (one execution, receipt, runtime
confirmation) and deny (no execution) against the local CortexOps API.
