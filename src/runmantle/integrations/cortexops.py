"""Observation-only export of Runmantle lifecycle events to CortexOps.

The integration targets the structural ``cortexops_sdk.exporter.EventExporter``
contract.  The SDK is optional: applications can inject its exporters, while the
bundled JSONL exporter provides a dependency-free local bridge using the same
document shape.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Protocol, TypedDict

from runmantle.integrations.cortexops_outbox import (
    CortexOpsDeliveryConfig,
    DurableCortexOpsOutboxExporter,
    OutboxRecord,
    OutboxStats,
)
from runmantle.telemetry import (
    EventSink,
    LifecycleEvent,
    LifecycleEventType,
    NullEventSink,
    lifecycle_event_to_dict,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "runmantle.cortexops.event.v1"

_SECRET_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "cookie",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
        "access_token",
    }
)
_PROMPT_KEYS = frozenset({"prompt", "system_prompt", "instructions", "messages"})
_ARGUMENT_KEYS = frozenset({"arguments", "parameters", "tool_arguments", "kwargs"})
_OUTPUT_KEYS = frozenset({"output", "result", "tool_result", "response"})
_EVIDENCE_CONTENT_KEYS = frozenset({"content", "payload", "value", "artifact"})

_SAFE_DETAIL_FIELDS: dict[LifecycleEventType, frozenset[str]] = {
    LifecycleEventType.STATE_TRANSITION: frozenset(
        {
            "task_contract",
            "risk_level",
            "reason",
            "error_type",
            "verification_status",
            "worker_name",
            "worker_role",
            "worker_version",
            "declared_capabilities",
        }
    ),
    LifecycleEventType.TASK_STARTED: frozenset(
        {
            "worker_name",
            "worker_role",
            "worker_version",
            "declared_capabilities",
        }
    ),
    LifecycleEventType.WORKER_STARTED: frozenset(
        {
            "worker_name",
            "worker_role",
            "worker_version",
            "declared_capabilities",
        }
    ),
    LifecycleEventType.WORKER_COMPLETED: frozenset({"reported_status"}),
    LifecycleEventType.WORKER_FAILED: frozenset({"reason", "error_type"}),
    LifecycleEventType.EVIDENCE_COLLECTED: frozenset(
        {
            "evidence_id",
            "evidence_type",
            "source",
            "artifact_reference",
            "checksum",
            "acquisition_method",
            "trust_level",
            "effective_trust_level",
            "trust_established",
            "trust_origin",
            "origin_hash",
            "expires_at",
            "provenance",
        }
    ),
    LifecycleEventType.VERIFICATION_RESULT: frozenset(
        {
            "status",
            "missing_evidence",
            "contradictory_evidence",
            "criteria",
            "error_type",
        }
    ),
    LifecycleEventType.RECOVERY_REQUESTED: frozenset(
        {
            "plan_id",
            "plan_hash",
            "action_id",
            "action_hash",
            "failure_diagnosis",
            "context_reference",
            "action_count",
            "actions",
            "dry_run",
            "declared_recovery_capability",
            "risk_level",
            "approval_required",
            "preconditions",
            "postconditions",
            "compensation_id",
            "proposed_by",
        }
    ),
    LifecycleEventType.RECOVERY_BLOCKED: frozenset(
        {"action_id", "capability", "status", "reason_code"}
    ),
    LifecycleEventType.RUNTIME_CONFIRMATION_RECEIVED: frozenset(
        {
            "confirmation_id",
            "action_id",
            "capability",
            "idempotency_key",
            "supported",
            "safe",
            "confirmed_at",
            "confirmed_by",
        }
    ),
    LifecycleEventType.APPROVAL_RECEIVED: frozenset(
        {
            "approval_id",
            "decision_id",
            "request_hash",
            "approval_key",
            "approved",
            "approved_by",
            "approver_subject",
            "approver_issuer",
            "capability",
            "idempotency_key",
        }
    ),
    LifecycleEventType.APPROVAL_REQUESTED: frozenset(
        {
            "approval_id",
            "approval_key",
            "target_id",
            "target_hash",
            "request_hash",
            "required_scope",
            "risk_level",
            "expires_at",
            "one_time_use",
        }
    ),
    LifecycleEventType.APPROVAL_REVOKED: frozenset(
        {"approval_id", "revocation_id", "request_hash", "revoked_by"}
    ),
    LifecycleEventType.APPROVAL_CONSUMED: frozenset(
        {"approval_id", "request_hash", "required_scope", "consumed_by"}
    ),
    LifecycleEventType.CHECKPOINT_SAVED: frozenset({"checkpoint_id", "label"}),
    LifecycleEventType.TASK_RESUMED: frozenset({"checkpoint_id"}),
    LifecycleEventType.ACTION_REQUESTED: frozenset(
        {
            "action_id",
            "action_name",
            "required_capability",
            "action_hash",
            "input_hash",
            "idempotency_key",
            "risk_level",
            "dry_run",
            "claim_source",
        }
    ),
    LifecycleEventType.ACTION_POLICY_DECIDED: frozenset(
        {"action_id", "allowed", "reasons", "requires_approval", "decided_by"}
    ),
    LifecycleEventType.ACTION_AUTHORIZED: frozenset(
        {
            "action_id",
            "authorized",
            "reason",
            "preconditions",
            "approved_by",
            "awaiting_approval",
        }
    ),
    LifecycleEventType.ACTION_AWAITING_APPROVAL: frozenset(
        {
            "action_id",
            "authorized",
            "reason",
            "preconditions",
            "approved_by",
            "awaiting_approval",
        }
    ),
    LifecycleEventType.ACTION_BLOCKED: frozenset(
        {"action_id", "authorized", "reason", "preconditions", "approved_by"}
    ),
    LifecycleEventType.ACTION_EXECUTION_STARTED: frozenset(
        {
            "action_id",
            "action_hash",
            "required_capability",
            "execution_owner_id",
        }
    ),
    LifecycleEventType.ACTION_EXECUTOR_SUCCEEDED: frozenset(
        {
            "action_id",
            "receipt_id",
            "executor_id",
            "execution_status",
            "output_hash",
            "error_type",
        }
    ),
    LifecycleEventType.ACTION_EXECUTION_FAILED: frozenset(
        {
            "action_id",
            "receipt_id",
            "executor_id",
            "execution_status",
            "output_hash",
            "error_type",
        }
    ),
    LifecycleEventType.ACTION_EXECUTION_UNKNOWN: frozenset(
        {
            "action_id",
            "receipt_id",
            "executor_id",
            "execution_status",
            "output_hash",
            "error_type",
            "reason",
        }
    ),
    LifecycleEventType.ACTION_DUPLICATE_PREVENTED: frozenset(
        {"action_id", "execution_status", "idempotency_key"}
    ),
    LifecycleEventType.ACTION_DRY_RUN_COMPLETED: frozenset(
        {"action_id", "receipt_id", "executor_id", "execution_status"}
    ),
    LifecycleEventType.ACTION_POSTCONDITION_EVIDENCE: frozenset(
        {"action_id", "evidence_id", "postcondition"}
    ),
    LifecycleEventType.ACTION_POSTCONDITION_FAILED: frozenset(
        {"action_id", "postcondition", "required", "error_type"}
    ),
    LifecycleEventType.RECOVERY_CONFIRMED: frozenset(
        {"action_id", "capability", "status", "reason_code"}
    ),
    LifecycleEventType.RECOVERY_AWAITING_APPROVAL: frozenset(
        {"plan_id", "plan_hash", "approval_id"}
    ),
    LifecycleEventType.RECOVERY_PREFLIGHT_CONFIRMED: frozenset(
        {"plan_id", "action_id", "action_hash", "confirmation_id"}
    ),
    LifecycleEventType.RECOVERY_EXECUTION_STARTED: frozenset(
        {
            "plan_id",
            "plan_hash",
            "action_id",
            "action_hash",
            "capability",
            "idempotency_key",
            "execution_owner_id",
        }
    ),
    LifecycleEventType.RECOVERY_EXECUTOR_SUCCEEDED: frozenset(
        {
            "plan_id",
            "action_id",
            "receipt_id",
            "receipt_status",
            "executor_id",
            "output_hash",
            "proves_external_postcondition",
            "proves_verified_outcome",
        }
    ),
    LifecycleEventType.RECOVERY_EXECUTION_FAILED: frozenset(
        {
            "plan_id",
            "action_id",
            "receipt_id",
            "receipt_status",
            "executor_id",
            "output_hash",
            "proves_external_postcondition",
            "proves_verified_outcome",
        }
    ),
    LifecycleEventType.RECOVERY_EXECUTION_UNKNOWN: frozenset(
        {"plan_id", "action_id", "reason"}
    ),
    LifecycleEventType.RECOVERY_POSTCONDITION_EVIDENCE: frozenset(
        {"plan_id", "evidence_id", "postcondition"}
    ),
    LifecycleEventType.RECOVERY_POSTCONDITION_FAILED: frozenset(
        {"plan_id", "failures", "executor_succeeded", "outcome_verified"}
    ),
    LifecycleEventType.RECOVERY_OUTCOME_VERIFIED: frozenset(
        {"plan_id", "recovery_status", "task_status", "only_verified_is_success"}
    ),
    LifecycleEventType.RECOVERY_DUPLICATE_PREVENTED: frozenset(
        {"plan_id", "persisted_status"}
    ),
    LifecycleEventType.TASK_FAILED: frozenset({"reason", "error_type"}),
}


class RunmantlePayload(TypedDict):
    """Versioned payload carried inside a CortexOps SDK custom event."""

    schema_version: str
    lifecycle_event: dict[str, Any]
    telemetry_semantics: str
    proves_external_side_effects: bool
    agent_claim_is_verification: bool
    executor_receipt_is_independent_proof: bool
    observation_implies_enforcement: bool
    verified_outcome: bool


class CortexOpsEventDocument(TypedDict):
    """The CortexOps SDK event fields emitted by this integration."""

    event_id: str
    event_type: str
    timestamp: str
    project: str
    environment: str
    service_name: str
    trace_id: str
    span_id: str
    observation_type: str
    session_id: str
    agent_id: str
    status: str
    payload: RunmantlePayload
    attributes: dict[str, Any]


@dataclass(frozen=True, slots=True)
class CortexOpsRedactionConfig:
    """Explicit opt-ins for content-bearing fields.

    Secret-bearing keys remain removed unless ``include_secrets`` is also true.
    """

    include_task_objective: bool = False
    include_task_input: bool = False
    include_prompts: bool = False
    include_tool_arguments: bool = False
    include_outputs: bool = False
    include_evidence_content: bool = False
    include_evidence_provenance_values: bool = False
    include_recovery_diagnosis: bool = False
    include_custom_details: bool = False
    include_secrets: bool = False


class CortexOpsEventExporter(Protocol):
    """Structural match for ``cortexops_sdk.exporter.EventExporter``."""

    def export(self, event: Any) -> None:
        """Export one CortexOps SDK event document."""

    def flush(self) -> None:
        """Flush buffered documents."""

    def close(self) -> None:
        """Close exporter resources."""


class CortexOpsSdkExporter:
    """Validate and export documents through the installed CortexOps SDK."""

    def __init__(self, exporter: CortexOpsEventExporter) -> None:
        try:
            events_module = importlib.import_module("cortexops_sdk.events")
        except ModuleNotFoundError as error:
            raise ModuleNotFoundError(
                "CortexOps SDK export requires the optional dependency; install "
                "with `pip install 'runmantle[cortexops]'`"
            ) from error
        self.exporter = exporter
        self._event_type = events_module.Event
        self._validate_event = events_module.validate_event

    def export(self, event: Any) -> None:
        self.export_batch([event])

    def export_batch(self, events: list[Any]) -> None:
        documents: list[dict[str, Any]] = []
        for event in events:
            if hasattr(event, "to_dict"):
                event = event.to_dict()
            if not isinstance(event, Mapping):
                raise TypeError("CortexOps SDK event must be a mapping")
            sdk_event = self._event_type.from_dict(dict(event))
            errors = self._validate_event(sdk_event, strict=True)
            if errors:
                raise CortexOpsEnvelopeError("; ".join(errors))
            documents.append(sdk_event.to_dict())
        batch = getattr(self.exporter, "export_batch", None)
        if callable(batch):
            batch(documents)
        else:
            for document in documents:
                self.exporter.export(document)

    def flush(self) -> None:
        self.exporter.flush()

    def close(self) -> None:
        self.exporter.close()


def create_cortexops_sdk_exporter(
    config: CortexOpsIntegrationConfig,
) -> CortexOpsSdkExporter:
    """Build the official SDK JSONL/OTLP exporter selected by explicit config."""

    try:
        exporter_module = importlib.import_module("cortexops_sdk.exporter")
    except ModuleNotFoundError as error:
        raise ModuleNotFoundError(
            "CortexOps SDK export requires the optional dependency; install "
            "with `pip install 'runmantle[cortexops]'`"
        ) from error
    exporters: list[Any] = []
    if config.include_local_jsonl:
        exporters.append(exporter_module.JsonlExporter(config.export_path, strict=True))
    if config.otlp_endpoint is not None:
        exporters.append(
            exporter_module.OtlpHttpJsonExporter(
                config.otlp_endpoint,
                timeout=config.otlp_timeout_seconds,
            )
        )
    if not exporters:
        raise ValueError("CortexOps SDK exporter has no configured destination")
    delegate = (
        exporters[0]
        if len(exporters) == 1
        else exporter_module.CompositeExporter(exporters)
    )
    return CortexOpsSdkExporter(delegate)


@dataclass(frozen=True, slots=True)
class CortexOpsIntegrationConfig:
    """Configuration for the disabled-by-default CortexOps telemetry bridge."""

    enabled: bool = False
    project: str = "runmantle"
    environment: str = "local"
    service_name: str = "runmantle"
    export_path: Path = Path("./cortexops_events.jsonl")
    outbox_path: Path | None = None
    durable_delivery: bool = True
    delivery: CortexOpsDeliveryConfig = field(default_factory=CortexOpsDeliveryConfig)
    redaction: CortexOpsRedactionConfig = field(
        default_factory=CortexOpsRedactionConfig
    )
    otlp_endpoint: str | None = None
    otlp_timeout_seconds: float = 10.0
    include_local_jsonl: bool = True

    def __post_init__(self) -> None:
        for name in ("project", "environment", "service_name"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"CortexOps configuration {name} must not be empty")
        object.__setattr__(self, "export_path", Path(self.export_path))
        if self.outbox_path is not None:
            object.__setattr__(self, "outbox_path", Path(self.outbox_path))
        if self.otlp_endpoint is not None and not self.otlp_endpoint.strip():
            raise ValueError("CortexOps OTLP endpoint must not be empty")
        if self.otlp_timeout_seconds <= 0:
            raise ValueError("CortexOps OTLP timeout must be positive")
        if not self.include_local_jsonl and self.otlp_endpoint is None:
            raise ValueError("CortexOps integration has no configured destination")

    @property
    def resolved_outbox_path(self) -> Path:
        if self.outbox_path is not None:
            return self.outbox_path
        return self.export_path.with_suffix(self.export_path.suffix + ".outbox.sqlite3")


@dataclass(frozen=True, slots=True)
class ExportFailure:
    """Observable record of a mapping or exporter failure."""

    operation: str
    error_type: str
    message: str
    occurred_at: datetime
    task_id: str | None = None
    lifecycle_event_type: str | None = None


FailureHandler = Callable[[ExportFailure], None]


class CortexOpsEnvelopeError(ValueError):
    """Raised when a mapped event does not satisfy the bridge contract."""


@dataclass(slots=True)
class CortexOpsJsonlExporter:
    """Dependency-free JSONL exporter accepted by CortexOps' SDK loader."""

    path: str | Path
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def export(self, event: Any) -> None:
        if not isinstance(event, Mapping):
            raise TypeError("CortexOps event must be a mapping")
        validate_cortexops_event(event)
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self._lock:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with Path(self.path).open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.write("\n")

    def flush(self) -> None:
        """Each export opens and closes the file, so no buffer remains."""

    def close(self) -> None:
        """Each export opens and closes the file, so no handle remains."""


@dataclass(slots=True)
class CortexOpsEventSink:
    """Non-fatal, observation-only EventSink for a CortexOps SDK exporter."""

    exporter: CortexOpsEventExporter
    config: CortexOpsIntegrationConfig
    failure_handler: FailureHandler | None = None
    _failures: list[ExportFailure] = field(default_factory=list, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.config.enabled:
            raise ValueError("CortexOpsEventSink requires enabled configuration")

    def emit(self, event: LifecycleEvent) -> None:
        try:
            document = lifecycle_event_to_cortexops_event(event, config=self.config)
            validate_cortexops_event(
                document,
                schema_version=SCHEMA_VERSION,
            )
            self.exporter.export(document)
        except Exception as error:  # noqa: BLE001 - telemetry cannot break workers
            self._record_failure("export", error, event)

    def flush(self) -> None:
        self._exporter_action("flush")

    def close(self) -> None:
        self._exporter_action("close")

    def failures(self) -> tuple[ExportFailure, ...]:
        """Return a stable snapshot suitable for health checks and tests."""

        with self._lock:
            return tuple(self._failures)

    def delivery_status(self) -> OutboxStats | None:
        """Return durable delivery counts when this sink owns an outbox."""

        if isinstance(self.exporter, DurableCortexOpsOutboxExporter):
            return self.exporter.stats()
        return None

    def dead_letters(self) -> tuple[OutboxRecord, ...]:
        """Return terminal delivery failures without exposing event content."""

        if isinstance(self.exporter, DurableCortexOpsOutboxExporter):
            return self.exporter.dead_letters()
        return ()

    @property
    def last_failure(self) -> ExportFailure | None:
        with self._lock:
            return self._failures[-1] if self._failures else None

    def _exporter_action(self, operation: str) -> None:
        try:
            action = getattr(self.exporter, operation)
            action()
        except Exception as error:  # noqa: BLE001 - telemetry cannot break workers
            self._record_failure(operation, error)

    def _record_failure(
        self,
        operation: str,
        error: Exception,
        event: LifecycleEvent | None = None,
    ) -> None:
        failure = ExportFailure(
            operation=operation,
            error_type=type(error).__name__,
            message=str(error),
            occurred_at=datetime.now(UTC),
            task_id=event.task_id if event is not None else None,
            lifecycle_event_type=(
                event.event_type.value if event is not None else None
            ),
        )
        with self._lock:
            self._failures.append(failure)
        logger.warning(
            "CortexOps telemetry %s failed (%s)",
            operation,
            failure.error_type,
        )
        if self.failure_handler is not None:
            try:
                self.failure_handler(failure)
            except Exception:  # noqa: BLE001 - a diagnostic hook is also non-fatal
                logger.warning("CortexOps telemetry failure handler failed")


def create_cortexops_event_sink(
    config: CortexOpsIntegrationConfig | None = None,
    *,
    exporter: CortexOpsEventExporter | None = None,
    failure_handler: FailureHandler | None = None,
) -> EventSink:
    """Create a disabled no-op sink or an enabled CortexOps sink.

    Local JSONL is the default. A network exporter is constructed only when an
    OTLP endpoint is explicitly configured. Enabled factory-created sinks use
    a durable SQLite outbox unless ``durable_delivery`` is disabled.
    """

    resolved = config or CortexOpsIntegrationConfig()
    if not resolved.enabled:
        return NullEventSink()
    if exporter is not None:
        destination = exporter
    elif resolved.otlp_endpoint is not None:
        destination = create_cortexops_sdk_exporter(resolved)
    else:
        destination = CortexOpsJsonlExporter(resolved.export_path)
    resolved_exporter: CortexOpsEventExporter
    if resolved.durable_delivery:
        resolved_exporter = DurableCortexOpsOutboxExporter(
            resolved.resolved_outbox_path,
            destination,
            delivery=resolved.delivery,
        )
    else:
        resolved_exporter = destination
    return CortexOpsEventSink(
        exporter=resolved_exporter,
        config=resolved,
        failure_handler=failure_handler,
    )


def lifecycle_event_to_cortexops_event(
    event: LifecycleEvent,
    *,
    config: CortexOpsIntegrationConfig,
) -> CortexOpsEventDocument:
    """Map one typed Runmantle event to a CortexOps SDK custom event."""

    if not isinstance(event, LifecycleEvent):
        raise TypeError("event must be a LifecycleEvent")
    safe_event = replace(
        event,
        details=_safe_details(event, event.details, config.redaction),
    )
    lifecycle = lifecycle_event_to_dict(safe_event)
    event_key = (
        f"{event.correlation_id}:{event.task_id}:{event.sequence}:"
        f"{event.event_type.value}:"
        f"{event.occurred_at.isoformat()}"
    )
    payload: RunmantlePayload = {
        "schema_version": SCHEMA_VERSION,
        "lifecycle_event": lifecycle,
        "telemetry_semantics": "observation_only",
        "proves_external_side_effects": False,
        "agent_claim_is_verification": False,
        "executor_receipt_is_independent_proof": False,
        "observation_implies_enforcement": False,
        "verified_outcome": _is_verified_outcome(event),
    }
    document: CortexOpsEventDocument = {
        "event_id": f"runmantle-{_digest(event_key, 24)}",
        "event_type": "custom.event",
        "timestamp": event.occurred_at.isoformat(),
        "project": config.project,
        "environment": config.environment,
        "service_name": config.service_name,
        "trace_id": _digest(event.correlation_id, 32),
        "span_id": _digest(event_key, 16),
        "observation_type": _observation_type(event.event_type),
        "session_id": event.correlation_id,
        "agent_id": event.worker_id,
        "status": _status(event),
        "payload": payload,
        "attributes": {
            "name": event.name or event.event_type.value,
            "runmantle.schema_version": SCHEMA_VERSION,
            "runmantle.lifecycle_event": event.event_type.value,
            "runmantle.task_id": event.task_id,
            "runmantle.task_state": event.state.value,
            "runmantle.sequence": event.sequence,
            "runmantle.telemetry_semantics": "observation_only",
            "runmantle.proves_external_side_effects": False,
            "runmantle.agent_claim_is_verification": False,
            "runmantle.executor_receipt_is_independent_proof": False,
            "runmantle.observation_implies_enforcement": False,
            "runmantle.verified_outcome": _is_verified_outcome(event),
        },
    }
    return document


def validate_cortexops_event(
    event: Mapping[str, Any],
    *,
    schema_version: str = SCHEMA_VERSION,
) -> None:
    """Validate fields relied upon by both the SDK JSONL and OTLP exporters."""

    for field_name in (
        "event_id",
        "event_type",
        "timestamp",
        "project",
        "trace_id",
        "span_id",
        "session_id",
        "agent_id",
    ):
        value = event.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise CortexOpsEnvelopeError(f"{field_name} must be a non-empty string")
    if event["event_type"] != "custom.event":
        raise CortexOpsEnvelopeError("event_type must be custom.event")
    for field_name, length in (("trace_id", 32), ("span_id", 16)):
        value = str(event[field_name])
        invalid_hex = any(char not in "0123456789abcdef" for char in value)
        if len(value) != length or invalid_hex:
            raise CortexOpsEnvelopeError(
                f"{field_name} must be a {length}-character hexadecimal string"
            )
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise CortexOpsEnvelopeError("payload must be an object")
    if payload.get("schema_version") != schema_version:
        raise CortexOpsEnvelopeError("unsupported Runmantle envelope schema_version")
    lifecycle = payload.get("lifecycle_event")
    if not isinstance(lifecycle, Mapping):
        raise CortexOpsEnvelopeError("payload.lifecycle_event must be an object")
    for field_name in (
        "event_type",
        "task_id",
        "correlation_id",
        "worker_id",
        "occurred_at",
        "sequence",
        "state",
        "details",
    ):
        if field_name not in lifecycle:
            raise CortexOpsEnvelopeError(
                f"payload.lifecycle_event is missing {field_name}"
            )
    if not isinstance(lifecycle["details"], Mapping):
        raise CortexOpsEnvelopeError(
            "payload.lifecycle_event.details must be an object"
        )


def _digest(value: str, length: int) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def _safe_details(
    event: LifecycleEvent,
    details: Any,
    redaction: CortexOpsRedactionConfig,
) -> dict[str, Any]:
    if not isinstance(details, Mapping):
        return {}
    allowed = _SAFE_DETAIL_FIELDS.get(event.event_type, frozenset())
    selected = {
        str(key): value
        for key, value in details.items()
        if key in allowed
        or redaction.include_custom_details
        or _content_field_opted_in(str(key), redaction)
    }
    return {
        key: cleaned
        for key, value in selected.items()
        if (cleaned := _redact_value(key, value, redaction)) is not _OMITTED
    }


_OMITTED = object()


def _content_field_opted_in(
    key: str,
    redaction: CortexOpsRedactionConfig,
) -> bool:
    normalized = key.lower()
    return (
        (normalized == "objective" and redaction.include_task_objective)
        or (normalized in {"input", "task_input"} and redaction.include_task_input)
        or (normalized in _PROMPT_KEYS and redaction.include_prompts)
        or (normalized in _ARGUMENT_KEYS and redaction.include_tool_arguments)
        or (normalized in _OUTPUT_KEYS and redaction.include_outputs)
        or (normalized in _EVIDENCE_CONTENT_KEYS and redaction.include_evidence_content)
    )


def _redact_value(
    key: str,
    value: Any,
    redaction: CortexOpsRedactionConfig,
) -> Any:
    normalized = key.lower()
    if normalized in _SECRET_KEYS and not redaction.include_secrets:
        return _OMITTED
    if normalized == "objective" and not redaction.include_task_objective:
        return _OMITTED
    if normalized in {"input", "task_input"} and not redaction.include_task_input:
        return _OMITTED
    if normalized in _PROMPT_KEYS and not redaction.include_prompts:
        return _OMITTED
    if normalized in _ARGUMENT_KEYS and not redaction.include_tool_arguments:
        return _OMITTED
    if normalized in _OUTPUT_KEYS and not redaction.include_outputs:
        return _OMITTED
    if normalized in _EVIDENCE_CONTENT_KEYS and not redaction.include_evidence_content:
        return _OMITTED
    if normalized == "failure_diagnosis" and not redaction.include_recovery_diagnosis:
        return {"sha256": _content_digest(value)}
    if normalized == "provenance" and not redaction.include_evidence_provenance_values:
        if not isinstance(value, Mapping):
            return {"sha256": _content_digest(value)}
        return {
            "keys": sorted(str(item) for item in value),
            "sha256": _content_digest(value),
        }
    if isinstance(value, Mapping):
        return {
            str(child_key): cleaned
            for child_key, child_value in value.items()
            if (cleaned := _redact_value(str(child_key), child_value, redaction))
            is not _OMITTED
        }
    if isinstance(value, (list, tuple)):
        return [
            cleaned
            for child in value
            if (cleaned := _redact_value(key, child, redaction)) is not _OMITTED
        ]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _content_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _is_verified_outcome(event: LifecycleEvent) -> bool:
    if event.event_type is LifecycleEventType.VERIFICATION_RESULT:
        return str(event.details.get("status", "")).lower() == "verified"
    if event.event_type is LifecycleEventType.STATE_TRANSITION:
        return event.state.value == "verified"
    if event.event_type is LifecycleEventType.RECOVERY_OUTCOME_VERIFIED:
        return str(event.details.get("task_status", "")).lower() == "verified"
    return False


def _observation_type(event_type: LifecycleEventType) -> str:
    if event_type in {
        LifecycleEventType.WORKER_STARTED,
        LifecycleEventType.WORKER_COMPLETED,
        LifecycleEventType.WORKER_FAILED,
    }:
        return "agent"
    if event_type is LifecycleEventType.VERIFICATION_RESULT:
        return "evaluator"
    return "event"


def _status(event: LifecycleEvent) -> str:
    if event.event_type in {
        LifecycleEventType.TASK_FAILED,
        LifecycleEventType.WORKER_FAILED,
        LifecycleEventType.ACTION_EXECUTION_FAILED,
        LifecycleEventType.RECOVERY_EXECUTION_FAILED,
    }:
        return "failed"
    if event.event_type in {
        LifecycleEventType.RECOVERY_BLOCKED,
        LifecycleEventType.ACTION_BLOCKED,
        LifecycleEventType.ACTION_AWAITING_APPROVAL,
        LifecycleEventType.ACTION_EXECUTION_UNKNOWN,
        LifecycleEventType.ACTION_POSTCONDITION_FAILED,
        LifecycleEventType.RECOVERY_AWAITING_APPROVAL,
        LifecycleEventType.RECOVERY_EXECUTION_UNKNOWN,
        LifecycleEventType.RECOVERY_POSTCONDITION_FAILED,
    }:
        return "WARNING"
    if event.event_type in {
        LifecycleEventType.TASK_STARTED,
        LifecycleEventType.WORKER_STARTED,
    }:
        return "started"
    if event.event_type in {
        LifecycleEventType.WORKER_COMPLETED,
        LifecycleEventType.AGENT_REPORTED_COMPLETION,
        LifecycleEventType.RECOVERY_CONFIRMED,
        LifecycleEventType.RECOVERY_OUTCOME_VERIFIED,
    }:
        return "completed"
    verification_status = str(event.details.get("status") or "")
    if event.event_type is LifecycleEventType.VERIFICATION_RESULT:
        if verification_status == "verified":
            return "completed"
        if verification_status == "failed":
            return "failed"
        return "WARNING"
    return "OK"


__all__ = [
    "SCHEMA_VERSION",
    "CortexOpsDeliveryConfig",
    "CortexOpsEnvelopeError",
    "CortexOpsEventDocument",
    "CortexOpsEventSink",
    "CortexOpsIntegrationConfig",
    "CortexOpsJsonlExporter",
    "CortexOpsRedactionConfig",
    "CortexOpsSdkExporter",
    "ExportFailure",
    "create_cortexops_event_sink",
    "create_cortexops_sdk_exporter",
    "lifecycle_event_to_cortexops_event",
    "validate_cortexops_event",
]
