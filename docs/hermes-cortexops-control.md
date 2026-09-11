# Hermes CortexOps Control Adapter

Install RunMantle, then run `runmantle-hermes-control-install` and enable it with
`hermes plugins enable runmantle-cortexops-control`. Select the presentation
transport with `security.approval.transport: cortexops`.

The plugin discovers tools from Hermes's live central tool registry. RunMantle classifies
the exposed name, toolset, schema, and description into a normalized capability and risk.
Known read-only tools remain observable-only by default. Every side-effecting tool and
every unknown or insufficiently classified tool is sent through CortexOps governance.
This applies to built-in, plugin-provided, and dynamically registered tools, so adding an
alternate tool does not create an allowlist bypass.

It never treats a Hermes tool result as runtime confirmation. CortexOps must approve
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
        # Enabled by default. Only successful runs verified by the configured
        # post-action probes become reusable measured baselines.
        verified_action_cache_enabled: true
        verified_action_cache_similarity_threshold: 0.8
        # Required: do not poll CortexOps from Hermes's short-lived hook.
        blocking_hook_approval: false
        # Optional overrides; discovery does not require a tool list.
        classification_overrides:
          terminal:
            action_name: local-deployment
            capability: terminal.deploy
            risk_level: high
            side_effecting: true
security:
  approval:
    transport: cortexops
```

`classification_overrides` is optional and is applied after automatic classification.
The former `controlled_tools` setting is accepted as a backward-compatible override map,
not as the scope of governed tools. Set `govern_read_only_tools: true` to route reads
through policy as well.

The plugin also wires RunMantle's Verified Action Cache into Hermes's turn and
tool hooks. `pre_llm_call` retains its context-injection behavior and performs
exact-first recipe lookup. On an exact match, `pre_model_completion` may replay
the recorded action through Hermes's turn-scoped normal tool dispatcher before
any provider request. Similar matches, missing replay data, and changed
preconditions fall through to normal model planning. `pre_tool_call` freshly
checks the discovered tool descriptor, capability, argument hash, and configured
runtime probe before the usual CortexOps policy and approval flow; no permit or
prior receipt is reused.

After execution, the normal receipt is delivered first and the configured
`post_action_probes` are evaluated by RunMantle's rule verifier. Only a
successful, runtime-confirmed, verified task can create a recipe. Provider-
reported usage from Hermes's `post_api_request` hook is summed across the turn;
when it is unavailable, the plugin neither invents a measurement nor creates a
measured recipe baseline. `post_llm_call` sends the resulting miss/baseline or
hit/reuse observation to CortexOps's
`/api/runmantle/v1/verified-action-cache/telemetry` endpoint. An independently
verified pre-model replay reports the recorded measured baseline and measured
reuse token counts of zero because Hermes actually avoided the provider call.
Only JSON-safe arguments unchanged by redaction are retained for replay; secret-
bearing actions remain normal model turns. Recipes persist in the plugin's
SQLite `state_path`, while approvals, receipts, confirmation, and verification
are performed anew after a restart.

`cortexops_url` is the CortexOps origin (as above). The transport creates a CortexOps
pending approval for every `REQUIRE_APPROVAL`; it polls that authoritative record and
returns only Hermes's `once` response. It never returns `session` or `always`.

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
CORTEXOPS_REPOSITORY=../cortexops pytest -q
```

The full local suite includes the E2E fixture, exercising both approve (one
execution, receipt, runtime confirmation) and deny (no execution) against the
local CortexOps API.

## One-command local proof

From the RunMantle checkout, with `cortexops` and `hermes-agent` checkouts next
to the directory containing the RunMantle checkout, run:

```bash
./.venv/bin/python scripts/hermes_cortexops_demo.py
```

Override checkout locations with `CORTEXOPS_REPOSITORY` and
`HERMES_REPOSITORY`. The runner builds a RunMantle wheel, creates a clean
temporary virtual environment and `HERMES_HOME`, installs and enables the
plugin with the real Hermes CLI, and starts authenticated CortexOps plus an
isolated local version/health service. It executes both operator outcomes and
writes the exact Hermes command, pending approval snapshot, logs, SQLite
databases, and combined audit trace below
`artifacts/hermes-cortexops-demo/<UTC timestamp>/`. CortexOps listens on the
loopback URL recorded as `cortexops_url` in each scenario trace and is stopped
when the proof completes.

Hermes routes an `approve` directive returned by `pre_tool_call` through the
selected `security.approval.transport`. Keep `blocking_hook_approval: false` so
the hook returns immediately and Hermes owns the user-facing wait. The CortexOps
transport then polls its authoritative pending approval, validates the exact
action permit, consumes it once, and only then allows the tool to execute. No
inter-service response is mocked.

Troubleshooting:

- Hermes requires Python below 3.14; the runner prefers `python3.13` and then
  the Hermes checkout's `.venv/bin/python`.
- If a checkout is elsewhere, set its repository environment variable rather
  than editing the script or a global Hermes config.
- Port conflicts are avoided with loopback ephemeral ports. Inspect
  `cortexops.log`, `hermes.log`, and `deployment.log` in the newest artifact
  directory if a child process exits.
- CortexOps's full dashboard currently fails to import on Python 3.13 because
  of its `threading.RLock | None` annotation. The runner mounts its official
  authenticated RunMantle/OpenClaw routers in FastAPI, which provides the same
  real database, policy, operator endpoints, and `/docs` API without the broken
  dashboard module.
