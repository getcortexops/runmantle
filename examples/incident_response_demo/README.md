# Incident-response demo

This consumer-owned demo runs a deterministic incident workflow without real
external side effects. A diagnosis worker reports completion while a fake
runtime health signal is unhealthy, so Runmantle verification fails. The task,
recovery plan, exact preflight confirmation, approval request, decision,
executor receipt, postcondition evidence, and final verification are persisted
to SQLite.

The first recovery process pauses at `awaiting_approval`. A separately opened
store records an authenticated-boundary decision over the exact immutable
request hash. A second `DurableRecoveryExecutor` instance resumes the same plan,
executes the simulation handler once, acquires health evidence independently,
and re-verifies the original task to `verified`. This demonstrates framework
restart boundaries; it does not perform real infrastructure recovery.

Every Runmantle lifecycle, evidence, verification, recovery, and runtime
confirmation event is exported through
`runmantle.integrations.cortexops.CortexOpsJsonlExporter`.

The optional validation command needs both the `cortexops_sdk` Python package
and the CortexOps application package (which owns the SDK JSONL parser) on
`PYTHONPATH`:

```bash
PYTHONPATH=src:/path/to/cortexops:/path/to/cortexops/packages/python-sdk \
  python -m examples.incident_response_demo \
  --events ./incident_response_events.jsonl
```

The command validates every row with `cortexops_sdk.events.Event.from_dict`
and then parses the full file with
`cortexops.adapters.cortexops_sdk.parser.parse_events_file`.
