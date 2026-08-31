# Security, privacy, and operations

## Defaults

- Core has no provider or CortexOps dependency and performs no implicit network
  calls.
- `SQLiteStore` is the durable default; `InMemoryRuntime` is non-durable and is
  intended for tests and demos.
- Persistence uses deterministic JSON, never pickle. Input limits constrain
  oversized, deeply nested, and collection-amplifying documents.
- The reference manifest accepts relative paths only, rejects `..`, absolute
  paths, and symlinks that resolve outside the project root.
- `runmantle inspect` emits evidence metadata and checksums, not evidence
  content. CLI errors are bounded and redact secret-bearing diagnostics.
- CortexOps integration is disabled by default. Its exporter redacts secret,
  prompt, tool-argument, output, and evidence-content fields unless the
  application explicitly opts into a narrower content class.

## Operational guarantees

SQLite task transitions and their ordered lifecycle events commit in one
transaction with optimistic version checks. WAL, busy timeout, foreign keys,
and `BEGIN IMMEDIATE` protect local concurrent writers. The test suite covers
competing transitions, competing resume, important restart states, schema
migration, corrupt rows, immutable evidence, and duplicate effects.

`BufferedEventSink` and the CortexOps durable outbox provide bounded pressure
and explicit cleanup. Runtime SQLite history remains the authority if an
external event sink fails. CortexOps delivery is at least once, so receivers
must deduplicate stable event IDs.

Cancellation is cooperative before action execution. After a consequential
handler starts, timeout, cancellation, process loss, or an exception may leave
partial external effects; Runmantle records `UNKNOWN` and consumes the durable
execution claim instead of reporting success or retrying blindly.

## Known risks

- This is a single-node runtime. It does not provide leader election,
  distributed leases, or a clustered database.
- SQLite durability still depends on filesystem and host guarantees. Back up
  the database and its WAL consistently.
- Application callables, predicates, providers, and handlers are trusted code
  and must be supplied again after restart.
- Local approver identity is an application assertion. Production deployments
  need an authenticated identity boundary or explicit CortexOps control client.
- Runtime-observed evidence is not automatically independent evidence. Choose
  acquisition authority and trust levels that match the external outcome.
- Runmantle does not sandbox arbitrary agent or Python code.

Supported Python versions are 3.11, 3.12, 3.13, and 3.14. The optional OpenAI
adapter is pinned to `openai-agents>=0.22,<0.23`; CortexOps SDK integration is
pinned to `cortexops-sdk>=0.1,<0.2` until compatibility tests justify widening.
