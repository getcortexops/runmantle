# Changelog

All notable changes to Runmantle are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2] - 2026-09-11

### Added

- capability-scoped post-action probes for Hermes, including a generic
  `filesystem_content` probe that reads the action's own path back and compares
  content hashes without storing the content in telemetry.

## [1.2.1] - 2026-09-11

### Fixed

- Hermes now refreshes its CortexOps runtime handshake after a workspace reset
  removes the control-plane registration, then retries the task registration
  once without weakening fail-closed behavior for other control rejections.

## [1.2.0] - 2026-09-11

### Added

- end-to-end Verified Action Cache integration in the Hermes control path,
  including exact-first lookup, persisted recipes, fresh precondition checks,
  governed reuse, and independent outcome re-verification;
- measured CortexOps baseline and reuse telemetry sourced from Hermes provider
  token usage, with no estimated or fabricated savings;
- Hermes regression coverage proving a measured first-run baseline followed by
  measured cache reuse, plus rejection of failed or unverified recipe sources.

### Changed

- the Hermes plugin now observes LLM calls and API usage in addition to tool
  calls while preserving policy, approval, receipt, and runtime confirmation
  gates for every execution.

## [1.1.2] - 2026-09-11

### Fixed

- CortexOps runtime confirmations now reference their audited execution receipt
  in `evidence_ids` while preserving independent provider evidence identifiers.

## [1.1.1] - 2026-09-09

### Added

- minimal, framework-neutral verified action cache with exact-first matching,
  fresh-state validation, repeat verification, and avoided-token metrics;
- a governed file-write reuse demo that validates current file hashes before
  reuse and verifies the resulting content after every execution.

## [1.1.0] - 2026-09-04

### Added

- framework-neutral tool descriptors, discovery adapter protocol, conservative
  semantic capability/risk classification, and explicit classification overrides;
- live Hermes registry discovery that automatically governs every side-effecting
  or insufficiently classified tool while leaving known reads observable-only;

### Changed

- Hermes `controlled_tools` is now a backward-compatible override map rather
  than a manually maintained governance allowlist.

## [1.0.0] - 2026-08-31

### Added

- optional `runmantle[cortexops]` SDK integration using CortexOps' existing
  JSONL/OTLP exporters and parser contracts;
- transactional SQLite delivery outbox with stable IDs, batches, delivery
  leases, bounded exponential retry/jitter, restart recovery, flush/close, and
  dead-letter health visibility;
- explicit content and secret redaction controls, structural task-contract
  telemetry, evidence provenance/trust/freshness, verifier decisions, and
  action, approval, and recovery lifecycle mappings;
- non-skipping combined-workspace compatibility tests against the real sibling
  CortexOps SDK and parser;
- optional synchronous CortexOps control client and controlled action/recovery
  wrappers with authenticated runtime handshake, task status sync, exact-hash
  approvals, current-policy dispatch, recovery review, and runtime receipts;
- versioned sibling CortexOps Runmantle coordination tables/routes plus
  cross-repository happy, offline, duplicate, expiry, staleness, unsupported
  capability, recovery failure, and verified-recovery tests.

### Changed

- CortexOps SDK OTLP export now preserves a bounded defensively redacted custom
  payload and stable event ID through the real OTLP ingest parser;
- agent claims, executor receipts, observation, enforcement, and verified
  outcomes carry explicit, distinct trust semantics;
- `observe`/`demo` CortexOps registrations are non-authoritative; `control` +
  `live` requests fail closed on network, identity, hash, expiry, capability, or
  policy mismatch.

## [0.10.0] - 2026-08-30

### Added

- optional `runmantle[openai-agents]` integration tested against OpenAI Agents
  SDK 0.22;
- `OpenAIAgentsAdapter` over the real asynchronous `Runner.run` API, including
  input/output/evidence mapping, task-local context, timeout, cancellation,
  SDK exception mapping, and lifecycle observations;
- schema-preserving `mediate_openai_function_tool` routing local SDK function
  tools through Runmantle's durable `ActionExecutor`;
- conservative static enforcement inspection with explicit fail-closed and
  observe-only modes for unsupported SDK execution surfaces;
- network-free scripted-model tests and a concise OpenAI adapter quickstart.

### Changed

- package version is now `0.10.0`;
- OpenAI runner completion, function output, and tracing are explicitly
  documented as claims and observations rather than verified outcomes.

## [0.9.0] - 2026-08-29

### Added

- immutable exact-hash `ApprovalRequest`, authenticated-boundary
  `ApprovalDecision`, revocation, expiration, and one-time consumption models;
- schema version 4 approval and recovery execution records with transactional
  approval consumption and recovery idempotency reservation;
- `DurableRecoveryExecutor` with persisted pause/resume, crash-to-`UNKNOWN`,
  preconditions, postcondition evidence, and final task re-verification;
- `PreActionCapabilityConfirmation`, `RecoveryExecutionReceipt`,
  `RecoveryPostcondition`, and optional compensation interfaces;
- crash/restart, expired/mismatched/revoked/duplicate approval, duplicate
  recovery, migration, and failed-postcondition tests;
- a real SQLite pause/decision/restart/resume recovery example.

### Changed

- `RuntimeConfirmation` is now a compatibility alias for the semantically exact
  `PreActionCapabilityConfirmation`; the legacy capability/policy flag is
  documented as pre-action confirmation;
- only `RecoveryStatus.VERIFIED` makes `RecoveryResult.succeeded` true;
- package version is now `0.9.0`.

## [0.8.0] - 2026-08-29

### Added

- capability-mediated `ActionRequest`, policy, authorization, execution,
  receipt, postcondition, and outcome-evidence models;
- durable `MediatedActionExecutor` with fail-closed capabilities, optimistic
  action transitions, idempotency, dry-run, timeout, cancellation, and
  restart-to-`UNKNOWN` behavior;
- `SafeFunctionTool` for native workers and adapters;
- calculated evidence checksums, acquisition methods, trust levels, expiry and
  maximum-age requirements, and immutable SQLite evidence;
- file, callable, and action-receipt evidence providers;
- schema version 3 action storage and legacy evidence migration;
- lifecycle events for each mediated action decision and postcondition result;
- action, restart, duplicate, tamper, freshness, and independent-evidence tests.

### Changed

- executor-reported success is explicitly separate from independently observed
  evidence and task verification;
- package version is now `0.8.0`.

## [0.7.0] - 2026-08-29

### Added

- the `PersistenceStore` abstraction and default transactional `SQLiteStore`;
- durable task, evidence, event, checkpoint, approval, confirmation, recovery,
  and idempotency records with safe JSON serialization;
- versioned migrations, WAL mode, optimistic transition locking, and corruption
  validation;
- `DurableRuntime` start, load, resume, continuation, and ordered history APIs;
- explicit `CheckpointedWorker` and `TaskContext.save_checkpoint` boundaries;
- `AWAITING_APPROVAL` and deterministic `ApprovalCriterion` support;
- restart, duplicate-resume, concurrency, migration, corruption, and durable
  evidence/event tests.

### Changed

- `InMemoryRuntime` is now explicitly documented as non-durable.

## [0.6.0] - 2026-08-26

### Added

- initial open-source developer-preview documentation and status labels;
- packaged `runmantle demo` CLI and `python -m runmantle` entry point;
- native worker, existing-agent adapter, false-completion, and guarded-recovery
  examples;
- public API reference and contributor guide;
- complete execution, verification, recovery-decision, and confirmed-recovery
  flow coverage;
- configured pytest, Ruff, strict mypy, wheel build, and clean installation
  checks.

### Changed

- developer dependencies now include the configured build, lint, and type-check
  tools.

## [0.5.0] - 2026-08-26

### Added

- generic existing-agent adapter contract and native worker bridge;
- optional structural LangGraph boundary without a core dependency;
- JSONL and transport-neutral CortexOps telemetry boundaries;
- semantic execution, evidence, verification, failure, and recovery events.

## [0.4.0] - 2026-08-26

### Added

- explicit capability declarations and safe, runtime-confirmed recovery;
- recovery policy, approval, risk, task-state, and idempotency gates.

## [0.3.0] - 2026-08-26

### Added

- structured evidence and deterministic rule-based verification;
- explicit failed, inconclusive, awaiting-evidence, and
  awaiting-runtime-confirmation verification results.

## [0.2.0] - 2026-08-26

### Added

- asynchronous typed worker and task execution model;
- lifecycle states that separate agent-reported completion from verification;
- timeout, cancellation, dependency injection, and structured lifecycle events.
