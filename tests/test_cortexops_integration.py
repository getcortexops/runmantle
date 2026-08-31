from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from typing import Any, Literal, cast
from unittest.mock import patch

import pytest

from examples.cortexops_workspace import (
    configure_cortexops_workspace,
    cortexops_workspace_available,
)
from runmantle import (
    CapabilityDeclaration,
    FunctionWorker,
    InMemoryRuntime,
    LifecycleEvent,
    LifecycleEventType,
    PredicateCriterion,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    TaskStatus,
    WorkerReport,
)
from runmantle.integrations.cortexops import (
    SCHEMA_VERSION,
    CortexOpsEnvelopeError,
    CortexOpsEventSink,
    CortexOpsIntegrationConfig,
    CortexOpsJsonlExporter,
    CortexOpsRedactionConfig,
    ExportFailure,
    create_cortexops_event_sink,
    lifecycle_event_to_cortexops_event,
    validate_cortexops_event,
)
from runmantle.integrations.cortexops_outbox import (
    CortexOpsDeliveryConfig,
    CortexOpsOutboxFlushError,
    DurableCortexOpsOutboxExporter,
    OutboxStatus,
)

OCCURRED_AT = datetime(2026, 8, 26, 9, 30, tzinfo=UTC)


class RecordingExporter:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.flushed = False
        self.closed = False

    def export(self, event: Any) -> None:
        if not isinstance(event, dict):
            raise TypeError("expected a dict")
        self.events.append(event)

    def flush(self) -> None:
        self.flushed = True

    def close(self) -> None:
        self.closed = True


class FailingExporter:
    def export(self, event: Any) -> None:
        del event
        raise OSError("simulated exporter outage")

    def flush(self) -> None:
        raise OSError("simulated flush outage")

    def close(self) -> None:
        raise OSError("simulated close outage")


class BatchRecordingExporter(RecordingExporter):
    def __init__(self, *, fail: bool = False) -> None:
        super().__init__()
        self.fail = fail
        self.batches: list[list[dict[str, Any]]] = []

    def export_batch(self, events: list[Any]) -> None:
        if self.fail:
            raise OSError("simulated secret-bearing transport outage")
        documents = [dict(event) for event in events]
        self.batches.append(documents)
        self.events.extend(documents)


def lifecycle_event(
    event_type: LifecycleEventType = LifecycleEventType.EVIDENCE_COLLECTED,
    *,
    details: dict[str, Any] | None = None,
) -> LifecycleEvent:
    return LifecycleEvent(
        event_type=event_type,
        task_id="task-1",
        correlation_id="session-1",
        worker_id="worker-1",
        occurred_at=OCCURRED_AT,
        sequence=3,
        state=TaskStatus.RUNNING,
        name=event_type.value,
        details=details
        or {
            "evidence_id": "evidence-1",
            "evidence_type": "health",
            "source": "runtime",
            "checksum": "sha256:example",
        },
    )


def enabled_config(path: Path | None = None) -> CortexOpsIntegrationConfig:
    return CortexOpsIntegrationConfig(
        enabled=True,
        project="integration-tests",
        environment="test",
        service_name="runmantle-tests",
        export_path=path or Path("cortexops_events.jsonl"),
    )


def verified_worker_and_contract() -> tuple[
    FunctionWorker[int, int], TaskContract[int, int]
]:
    async def execute(
        task: TaskContract[int, int],
        context: TaskContext,
    ) -> WorkerReport[int]:
        context.evidence.record(
            "calculation",
            {"value": task.input},
            source="core-worker",
            evidence_id="core-evidence",
        )
        return WorkerReport.completed(task.input)

    worker = FunctionWorker[int, int](
        id="core-worker",
        name="Core worker",
        role="test",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name="calculate",
                description="Perform an in-memory calculation.",
            ),
        ),
        handler=execute,
    )
    contract = TaskContract[int, int](
        task_id="core-task",
        objective="Return the supplied value.",
        input=42,
        acceptance_criteria=(
            PredicateCriterion(
                name="is-42",
                description="The value must be 42.",
                predicate=lambda output, evidence: output == 42,
            ),
        ),
        required_evidence=(),
        allowed_capabilities=frozenset({"calculate"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=1),
        idempotency_key="core-task-key",
    )
    return worker, contract


class CortexOpsMappingTest(unittest.TestCase):
    def test_maps_versioned_observation_only_custom_event(self) -> None:
        document = lifecycle_event_to_cortexops_event(
            lifecycle_event(),
            config=enabled_config(),
        )

        self.assertEqual(document["event_type"], "custom.event")
        self.assertEqual(document["project"], "integration-tests")
        self.assertEqual(len(document["trace_id"]), 32)
        self.assertEqual(len(document["span_id"]), 16)
        self.assertEqual(document["payload"]["schema_version"], SCHEMA_VERSION)
        self.assertEqual(
            document["payload"]["lifecycle_event"]["event_type"],
            "evidence.collected",
        )
        self.assertEqual(document["payload"]["telemetry_semantics"], "observation_only")
        self.assertFalse(document["payload"]["proves_external_side_effects"])
        validate_cortexops_event(document)

    def test_every_runmantle_lifecycle_event_has_a_mapping(self) -> None:
        for event_type in LifecycleEventType:
            with self.subTest(event_type=event_type):
                document = lifecycle_event_to_cortexops_event(
                    lifecycle_event(event_type),
                    config=enabled_config(),
                )
                self.assertEqual(
                    document["attributes"]["runmantle.lifecycle_event"],
                    event_type.value,
                )
                validate_cortexops_event(document)

    def test_agent_reported_completion_is_not_mapped_as_verification(self) -> None:
        document = lifecycle_event_to_cortexops_event(
            lifecycle_event(LifecycleEventType.AGENT_REPORTED_COMPLETION),
            config=enabled_config(),
        )

        self.assertEqual(document["status"], "completed")
        self.assertEqual(
            document["payload"]["lifecycle_event"]["event_type"],
            "agent.reported_completion",
        )
        self.assertNotEqual(
            document["payload"]["lifecycle_event"]["event_type"],
            "verification.result",
        )

    def test_content_like_and_custom_details_are_not_exported_by_default(self) -> None:
        transition = lifecycle_event_to_cortexops_event(
            lifecycle_event(
                LifecycleEventType.STATE_TRANSITION,
                details={"objective": "sensitive task text", "risk_level": "low"},
            ),
            config=enabled_config(),
        )
        progress = lifecycle_event_to_cortexops_event(
            lifecycle_event(
                LifecycleEventType.WORKER_EVENT,
                details={
                    "prompt": "sensitive prompt",
                    "output": "sensitive output",
                    "application_object": object(),
                },
            ),
            config=enabled_config(),
        )

        self.assertEqual(
            transition["payload"]["lifecycle_event"]["details"],
            {"risk_level": "low"},
        )
        self.assertEqual(progress["payload"]["lifecycle_event"]["details"], {})

    def test_redaction_requires_explicit_content_and_secret_opt_in(self) -> None:
        event = lifecycle_event(
            LifecycleEventType.WORKER_EVENT,
            details={
                "prompt": "private prompt",
                "tool_arguments": {"path": "/tmp/x", "api_key": "secret"},
                "output": "private output",
            },
        )
        content_config = CortexOpsRedactionConfig(
            include_prompts=True,
            include_tool_arguments=True,
            include_outputs=True,
        )
        without_secrets = lifecycle_event_to_cortexops_event(
            event,
            config=CortexOpsIntegrationConfig(
                enabled=True,
                redaction=content_config,
            ),
        )["payload"]["lifecycle_event"]["details"]
        with_secrets = lifecycle_event_to_cortexops_event(
            event,
            config=CortexOpsIntegrationConfig(
                enabled=True,
                redaction=CortexOpsRedactionConfig(
                    include_prompts=True,
                    include_tool_arguments=True,
                    include_outputs=True,
                    include_secrets=True,
                ),
            ),
        )["payload"]["lifecycle_event"]["details"]

        self.assertNotIn("api_key", without_secrets["tool_arguments"])
        self.assertEqual(with_secrets["tool_arguments"]["api_key"], "secret")

    def test_claim_receipt_observation_and_verification_semantics_are_explicit(
        self,
    ) -> None:
        claim = lifecycle_event_to_cortexops_event(
            lifecycle_event(LifecycleEventType.AGENT_REPORTED_COMPLETION),
            config=enabled_config(),
        )
        verified = lifecycle_event_to_cortexops_event(
            lifecycle_event(
                LifecycleEventType.VERIFICATION_RESULT,
                details={"status": "verified"},
            ),
            config=enabled_config(),
        )

        self.assertFalse(claim["payload"]["agent_claim_is_verification"])
        self.assertFalse(claim["payload"]["verified_outcome"])
        self.assertFalse(claim["payload"]["executor_receipt_is_independent_proof"])
        self.assertFalse(claim["payload"]["observation_implies_enforcement"])
        self.assertTrue(verified["payload"]["verified_outcome"])

    def test_verification_and_runtime_confirmation_remain_distinct(self) -> None:
        verification = lifecycle_event_to_cortexops_event(
            lifecycle_event(
                LifecycleEventType.VERIFICATION_RESULT,
                details={"status": "verified", "missing_evidence": []},
            ),
            config=enabled_config(),
        )
        confirmation = lifecycle_event_to_cortexops_event(
            lifecycle_event(
                LifecycleEventType.RUNTIME_CONFIRMATION_RECEIVED,
                details={
                    "confirmation_id": "confirmation-1",
                    "action_id": "action-1",
                    "supported": True,
                    "safe": True,
                },
            ),
            config=enabled_config(),
        )

        self.assertEqual(verification["observation_type"], "evaluator")
        self.assertEqual(verification["status"], "completed")
        self.assertEqual(confirmation["status"], "OK")
        self.assertNotEqual(
            verification["payload"]["lifecycle_event"]["event_type"],
            confirmation["payload"]["lifecycle_event"]["event_type"],
        )

    def test_rejects_missing_and_malformed_event_documents(self) -> None:
        with self.assertRaisesRegex(CortexOpsEnvelopeError, "event_id"):
            validate_cortexops_event({})

        document = lifecycle_event_to_cortexops_event(
            lifecycle_event(),
            config=enabled_config(),
        )
        document["payload"]["lifecycle_event"].pop("details")
        with self.assertRaisesRegex(CortexOpsEnvelopeError, "missing details"):
            validate_cortexops_event(document)

        malformed_event: Any = {"event_type": "task.started"}
        with self.assertRaisesRegex(TypeError, "LifecycleEvent"):
            lifecycle_event_to_cortexops_event(
                malformed_event,
                config=enabled_config(),
            )


class CortexOpsBridgeTest(unittest.IsolatedAsyncioTestCase):
    def test_local_jsonl_bridge_writes_sdk_compatible_documents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            sink = create_cortexops_event_sink(enabled_config(path))
            sink.emit(lifecycle_event(LifecycleEventType.WORKER_STARTED))
            sink.emit(lifecycle_event(LifecycleEventType.EVIDENCE_COLLECTED))
            rows = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["event_type"] == "custom.event" for row in rows))
        self.assertEqual(
            [row["payload"]["lifecycle_event"]["event_type"] for row in rows],
            ["worker.started", "evidence.collected"],
        )
        for row in rows:
            validate_cortexops_event(row)

    def test_injected_exporter_matches_real_sdk_exporter_contract(self) -> None:
        exporter = RecordingExporter()
        sink = CortexOpsEventSink(exporter=exporter, config=enabled_config())

        sink.emit(lifecycle_event())
        sink.flush()
        sink.close()

        self.assertEqual(len(exporter.events), 1)
        self.assertTrue(exporter.flushed)
        self.assertTrue(exporter.closed)

    def test_disabled_integration_is_a_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disabled.jsonl"
            sink = create_cortexops_event_sink(
                CortexOpsIntegrationConfig(enabled=False, export_path=path)
            )
            sink.emit(lifecycle_event())
            self.assertFalse(path.exists())

    async def test_exporter_failure_is_observable_and_does_not_break_runtime(
        self,
    ) -> None:
        observed: list[ExportFailure] = []
        sink = CortexOpsEventSink(
            exporter=FailingExporter(),
            config=enabled_config(),
            failure_handler=observed.append,
        )
        worker, contract = verified_worker_and_contract()

        result = await InMemoryRuntime(
            verifier=RuleBasedVerifier(),
            event_sink=sink,
        ).execute(worker, contract, correlation_id="failure-test")
        sink.flush()
        sink.close()

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertGreater(len(sink.failures()), 0)
        self.assertEqual(len(observed), len(sink.failures()))
        self.assertEqual(sink.failures()[0].error_type, "OSError")
        self.assertEqual(sink.failures()[-2].operation, "flush")
        self.assertEqual(sink.failures()[-1].operation, "close")

    async def test_runtime_exports_required_task_and_worker_events(self) -> None:
        exporter = RecordingExporter()
        sink = CortexOpsEventSink(exporter=exporter, config=enabled_config())
        worker, contract = verified_worker_and_contract()

        result = await InMemoryRuntime(
            verifier=RuleBasedVerifier(),
            event_sink=sink,
        ).execute(worker, contract, correlation_id="mapping-test")
        exported_types = {
            event["payload"]["lifecycle_event"]["event_type"]
            for event in exporter.events
        }

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertTrue(
            {
                "task.started",
                "worker.started",
                "evidence.collected",
                "worker.completed",
                "agent.reported_completion",
                "verification.result",
            }.issubset(exported_types)
        )

    async def test_core_runtime_works_without_cortexops_configuration(self) -> None:
        worker, contract = verified_worker_and_contract()

        result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
            worker,
            contract,
        )

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertFalse(result.succeeded)

    def test_jsonl_exporter_rejects_malformed_documents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exporter = CortexOpsJsonlExporter(Path(directory) / "events.jsonl")
            with self.assertRaisesRegex(CortexOpsEnvelopeError, "event_id"):
                exporter.export({"event_type": "custom.event"})

    @pytest.mark.cortexops_integration
    @pytest.mark.skipif(
        not cortexops_workspace_available(),
        reason="real CortexOps checkout unavailable",
    )
    def test_real_sibling_sdk_and_parser_accept_factory_jsonl(self) -> None:
        configure_cortexops_workspace()
        parser_module = import_module("cortexops.adapters.cortexops_sdk.parser")
        events_module = import_module("cortexops_sdk.events")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            sink = cast(
                CortexOpsEventSink,
                create_cortexops_event_sink(enabled_config(path)),
            )
            sink.emit(lifecycle_event())
            sink.flush()
            rows = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
            parsed = parser_module.parse_events_file(path)

        self.assertEqual(len(rows), 1)
        sdk_event = events_module.Event.from_dict(rows[0])
        self.assertEqual(events_module.validate_event(sdk_event, strict=True), [])
        self.assertEqual(parsed.total, 1)
        self.assertEqual(parsed.skipped, 0)
        self.assertEqual(len(parsed.events), 1)

    @pytest.mark.cortexops_integration
    @pytest.mark.skipif(
        not cortexops_workspace_available(),
        reason="real CortexOps checkout unavailable",
    )
    def test_explicit_otlp_uses_real_sdk_exporter_without_network(self) -> None:
        configure_cortexops_workspace()
        exporter_module = import_module("cortexops_sdk.exporter")
        captured: list[Any] = []

        class Response:
            def __enter__(self) -> Response:
                return self

            def __exit__(self, *args: Any) -> Literal[False]:
                return False

            def read(self) -> bytes:
                return b"{}"

        config = CortexOpsIntegrationConfig(
            enabled=True,
            otlp_endpoint="http://127.0.0.1:8000/v1/traces",
            include_local_jsonl=False,
            durable_delivery=False,
        )

        def capture(request: Any, timeout: float) -> Response:
            del timeout
            captured.append(request)
            return Response()

        with patch.object(
            exporter_module,
            "urlopen",
            side_effect=capture,
        ):
            sink = cast(CortexOpsEventSink, create_cortexops_event_sink(config))
            sink.emit(lifecycle_event())

        self.assertEqual(len(captured), 1)
        otlp = json.loads(captured[0].data)
        span = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        attributes = {
            item["key"]: next(iter(item["value"].values()))
            for item in span["attributes"]
        }
        self.assertIn("cortexops.custom.payload_json", attributes)


class CortexOpsOutboxTest(unittest.TestCase):
    def test_outage_survives_restart_and_reuses_stable_event_id(self) -> None:
        delivery = CortexOpsDeliveryConfig(
            base_backoff_seconds=0.001,
            max_backoff_seconds=0.002,
            jitter_ratio=0,
            flush_timeout_seconds=1,
        )
        document = lifecycle_event_to_cortexops_event(
            lifecycle_event(), config=enabled_config()
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outbox.sqlite3"
            failed = BatchRecordingExporter(fail=True)
            first = DurableCortexOpsOutboxExporter(path, failed, delivery=delivery)
            first.export(document)
            self.assertEqual(first.stats().pending, 1)

            recovered = BatchRecordingExporter()
            second = DurableCortexOpsOutboxExporter(path, recovered, delivery=delivery)
            second.flush()
            second.export(document)

            self.assertEqual(second.stats().delivered, 1)
            self.assertEqual(len(recovered.events), 1)
            self.assertEqual(recovered.events[0]["event_id"], document["event_id"])

    def test_batching_and_dead_letter_visibility(self) -> None:
        documents = [
            lifecycle_event_to_cortexops_event(
                LifecycleEvent(
                    event_type=LifecycleEventType.TASK_PROGRESS,
                    task_id="task-1",
                    correlation_id="session-1",
                    worker_id="worker-1",
                    occurred_at=OCCURRED_AT,
                    sequence=index,
                    state=TaskStatus.RUNNING,
                ),
                config=enabled_config(),
            )
            for index in range(1, 4)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "batch.sqlite3"
            recording = BatchRecordingExporter()
            outbox = DurableCortexOpsOutboxExporter(
                path,
                recording,
                delivery=CortexOpsDeliveryConfig(batch_size=3),
            )
            outbox.export_batch(documents)
            self.assertEqual([len(batch) for batch in recording.batches], [3])

            failing = DurableCortexOpsOutboxExporter(
                Path(directory) / "dead.sqlite3",
                BatchRecordingExporter(fail=True),
                delivery=CortexOpsDeliveryConfig(
                    max_attempts=1,
                    base_backoff_seconds=0.001,
                    max_backoff_seconds=0.001,
                    jitter_ratio=0,
                ),
            )
            failing.export(documents[0])
            self.assertEqual(failing.stats().dead_letter, 1)
            self.assertEqual(failing.dead_letters()[0].status, OutboxStatus.DEAD_LETTER)
            self.assertEqual(failing.dead_letters()[0].last_error_message, "OSError")
            with self.assertRaises(CortexOpsOutboxFlushError):
                failing.flush()


if __name__ == "__main__":
    unittest.main()
