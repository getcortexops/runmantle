# Simple release-readiness agent

This is a deterministic consumer application built only on Runmantle's public
APIs. `ReleaseReadinessWorker` reads a local fixture, records one structured
evidence item for each required check, reports completion, and lets Runmantle's
existing `RuleBasedVerifier` decide the final status. It uses no LLM, API key,
cloud service, shell command, deployment, or external side effect.

From the Runmantle repository root, run the ready fixture and validate the
exported JSONL with the real CortexOps SDK and parser:

```console
PYTHONPATH=src:../../cortexops:../../cortexops/packages/python-sdk \
  .venv/bin/python -m examples.simple_agent \
  --events ./release_readiness_events.jsonl
```

To see a failed verification while the worker still reports completion:

```console
PYTHONPATH=src:../../cortexops:../../cortexops/packages/python-sdk \
  .venv/bin/python -m examples.simple_agent \
  --fixture examples/simple_agent/fixtures/failed_release \
  --events ./release_readiness_failed_events.jsonl
```

The three acceptance checks are:

1. `README.md`, `release.json`, and `src/sample.py` exist.
2. `release.json` reports `ci_status = passed`.
3. `release.json` reports `review_status = approved`.

The JSONL export is enabled through `runmantle.integrations.cortexops`. The
command validates every row with `cortexops_sdk.events.Event.from_dict` and the
complete file with
`cortexops.adapters.cortexops_sdk.parser.parse_events_file`.
