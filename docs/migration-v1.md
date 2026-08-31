# Migrating from the developer preview to 1.0.1

The 1.0 release candidate keeps the existing worker, contract, verifier,
durable runtime, action, approval, recovery, OpenAI adapter, and CortexOps APIs.
No database reset is required.

## Database migration

Opening an older SQLite database runs monotonic migrations through schema
version 7 in a transaction. Versions 1–6 retain tasks, events, evidence,
idempotency records, and reported/verified separation. Legacy evidence gains
calculated checksums and conservative trust metadata. Because pre-v5 rows have
no framework-established trust origin, migration 5 downgrades every legacy
evidence row to `AGENT_REPORTED` / `AGENT_CLAIM`. A legacy `VERIFIED` task that
depended on required evidence is demoted to `INCONCLUSIVE` for re-verification;
the migration never invents trusted provenance. Legacy approvals are
preserved as unverified, legacy-scoped assertions and do not gain authority for
new exact-hash actions. Databases newer than the supported version or rows with
invalid checksums, enums, JSON, timestamps, or transition state fail closed.

The approval-bound action manifest is now version 2 and includes execution
handler and evidence-provider semantics. A pending pre-release action created
with the older, narrower hash cannot consume its old approval after upgrade;
submit a new action ID/idempotency key and obtain a new exact approval. Finished
action receipts remain readable and are not upgraded into verification proof.

Migration 6 adds the ordinary-action postcondition phase. Existing
`executor_succeeded` actions become `pending`, allowing an exact reconstructed
request to reacquire missing postcondition evidence without repeating the
external handler; other action records begin at `not_started`.

Migration 7 binds action authorization to the task execution context and adds
explicit, atomic per-postcondition completion markers. It also rechecks every
legacy `VERIFIED` row at its original decision time; rows that cannot establish
the trusted-evidence commit invariant become `INCONCLUSIVE`.

Recovery actions now bind a stable handler identity and security-relevant JSON
configuration. Recovery plan hashes also bind every required postcondition
provider identity and configuration. Pending plans using the older default
handler identity require reconstruction with `RecoveryHandlerRegistration`
and a new approval. Stable identities must be application/version identifiers,
not object addresses; configurations must contain every setting that can alter
execution or verification semantics.

Back up the database and WAL before upgrading. Test the application-supplied
contract and callable reconstruction against a copy. Downgrade after migration
is not supported.

## Behavioral changes

- The package version is `1.0.1` and status is Beta.
- The CLI keeps `runmantle demo` and adds `init`, `run`, `inspect`, `verify`,
  `resume`, and `doctor` for the packaged reference workflow.
- `SafeJsonCodec` now applies default size, depth, and collection-count limits.
  Applications intentionally persisting larger declarations must inject a
  codec with reviewed limits.
- `BufferedEventSink` adds explicit bounded backpressure and cleanup. It does
  not replace durable SQLite lifecycle history.
- `RuntimeConfirmation` remains an alias for
  `PreActionCapabilityConfirmation`; new code should use the precise name.
- `InMemoryRuntime` remains compatible but is explicitly non-durable.
- Worker collector `trust_level` and `acquisition_method` arguments remain
  source-compatible, but caller-selected elevation is downgraded to an agent
  claim. Register custom trusted providers at the executor boundary instead.
- `EvidenceRequirement.minimum_trust_level` now defaults to
  `RUNTIME_OBSERVED`. Contracts without an explicitly declared and satisfied
  requirement at that level or `INDEPENDENT` remain `AWAITING_EVIDENCE`, even
  when a custom verifier or output-only criterion reports success.

The release candidate does not migrate arbitrary in-memory runtime state or
resume Python in the middle of a function. Start new durable tasks or provide
explicit application checkpoints.
