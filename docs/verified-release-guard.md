# Verified Release Guard

The packaged reference workflow is the shortest honest demonstration of the
Runmantle product promise. It wraps an existing agent through the supported
`AgentAdapterWorker` boundary, but uses a deterministic local adapter so the
quickstart requires no provider account, network, or API key. Replace that
adapter with `OpenAIAgentsAdapter` without changing the contract or verification
boundary.

The same contract and recovery flow also have a production OpenAI adapter
variant backed by an offline SDK model, with no API key or network:

```bash
python -m pip install -e '.[openai-agents]'
env -u OPENAI_API_KEY python -m examples.verified_release_guard.openai_offline
```

## Run it

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install runmantle==1.0.1
mkdir release-guard && cd release-guard
runmantle init .
runmantle doctor
runmantle run || test $? -eq 3
runmantle inspect
runmantle verify || test $? -eq 4
runmantle resume || test $? -eq 5
runmantle resume --approve-current-plan
runmantle inspect
```

`runmantle init` creates only a reference Git repository under the chosen
directory and refuses to overwrite an existing Runmantle project. The initial
`release.json` says the release is not ready. The adapter deliberately returns
`{"release_ready": true}` anyway.

`runmantle run` persists that claim and stops at `AWAITING_EVIDENCE` (exit 3).
`runmantle verify` routes bounded Git/filesystem inspection through
`MediatedActionExecutor`, records a receipt, reacquires the same local state as
`RUNTIME_OBSERVED` evidence, and ends `FAILED` (exit 4). Executor return is not
verification.

The first `runmantle resume` persists an exact recovery plan and stops at
`AWAITING_APPROVAL` (exit 5). `--approve-current-plan` is an explicit local CLI
identity assertion, not remote authentication. It approves only the stored
request hash, consumes the approval once, writes and commits the artifact,
reacquires evidence, and re-runs the task verifier. Only the resulting
`VERIFIED` task returns exit 0.

Every command opens the SQLite database anew, so the example demonstrates
process restart rather than an in-process simulation. A second resume cannot
repeat the commit. An injected crash after filesystem effects is covered by the
test suite: status becomes `UNKNOWN` and Runmantle will not blindly retry.

Framework-managed fixture recovery rejects a repository root that is itself a
symlink, parent traversal, and symlinked nested path components. It uses
descriptor-relative no-follow operations immediately before file mutation.
Git receives fixed repository-relative paths with repository hooks,
global/system config, and commit signing disabled. This is a boundary for this
packaged fixture, not a generic filesystem sandbox for arbitrary worker code.

## CLI reference

- `runmantle init [directory] [--cortexops]`: create the bounded fixture and
  manifest. CortexOps export is disabled unless the flag is supplied.
- `runmantle run`: run the wrapped agent from a durable `PENDING` boundary.
- `runmantle inspect`: print content-free task, evidence, recovery, and event
  metadata. Add `--json` for machine-readable output.
- `runmantle verify`: execute mediated acceptance inspection and continue
  evidence verification.
- `runmantle resume [--approve-current-plan]`: resume the exact persisted
  recovery boundary. It never restores an arbitrary Python frame.
- `runmantle doctor`: check Python, Git, bounded paths, SQLite schema, and
  optional adapter/SDK availability without contacting a network service.

## Optional CortexOps lifecycle export

Use `runmantle init . --cortexops` to explicitly enable the local, redacted,
observation-only CortexOps path. It writes SDK-compatible JSONL plus a durable
outbox under `.runmantle/`. It does not grant CortexOps control authority and
does not configure a network endpoint. See [CortexOps integration](cortexops.md)
for explicit OTLP and control-loop configuration.

## Trust and enforcement boundaries

The acceptance provider reads the same local host as Runmantle. Its trust level
is therefore `RUNTIME_OBSERVED`, not `INDEPENDENT`. It proves what that process
observed at the collection timestamp, subject to a ten-minute freshness bound;
it does not prove remote deployment, supply-chain provenance, or that state
cannot change later.

Capability, policy, approval, timeout, idempotency, and recovery enforcement
applies only to calls routed through mediated actions. Unrestricted Python can
still mutate files, use credentials, or call external APIs directly. A secure
application keeps consequential clients and credentials outside agent reach
and exposes only narrow mediated tools.
