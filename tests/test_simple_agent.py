from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from examples.simple_agent.agent import (
    FAILED_FIXTURE,
    OBJECTIVE,
    READY_FIXTURE,
    format_summary,
    run_release_readiness_agent,
)
from examples.simple_agent.sdk_validation import validate_cortexops_jsonl
from runmantle import (
    LifecycleEventType,
    TaskStatus,
    VerificationStatus,
    WorkerReportedStatus,
)


def _event_type(row: dict[str, object]) -> str:
    payload = row["payload"]
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")
    lifecycle = payload["lifecycle_event"]
    if not isinstance(lifecycle, dict):
        raise TypeError("lifecycle_event must be an object")
    event_type = lifecycle["event_type"]
    if not isinstance(event_type, str):
        raise TypeError("event_type must be a string")
    return event_type


class SimpleAgentTest(unittest.IsolatedAsyncioTestCase):
    async def test_successful_release_claim_awaits_trusted_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_release_readiness_agent(
                READY_FIXTURE,
                Path(directory) / "events.jsonl",
            )

        self.assertEqual(result.task.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertFalse(result.task.succeeded)
        self.assertEqual(len(result.task.evidence), 3)
        self.assertTrue(result.task.output and result.task.output.ready)
        self.assertEqual(
            {item.type for item in result.task.evidence},
            {
                "required_files_check",
                "ci_status_check",
                "review_status_check",
            },
        )
        self.assertTrue(
            all(
                item.payload and item.payload["passed"] for item in result.task.evidence
            )
        )

    async def test_failed_release_claim_awaits_trusted_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_release_readiness_agent(
                FAILED_FIXTURE,
                Path(directory) / "events.jsonl",
            )

        self.assertEqual(result.task.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertFalse(result.task.succeeded)
        self.assertFalse(result.task.output and result.task.output.ready)
        verification = result.task.final_verification_result
        self.assertIsNotNone(verification)
        self.assertEqual(
            verification.status if verification else None,
            VerificationStatus.AWAITING_EVIDENCE,
        )

    async def test_agent_completion_is_separate_from_verified(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_release_readiness_agent(
                FAILED_FIXTURE,
                Path(directory) / "events.jsonl",
            )

        self.assertEqual(result.task.reported_status, WorkerReportedStatus.COMPLETED)
        self.assertIsNotNone(result.task.timestamps.agent_reported_complete_at)
        self.assertEqual(result.task.status, TaskStatus.AWAITING_EVIDENCE)

        event_types = [_event_type(row) for row in result.exported_events]
        completion_index = event_types.index(
            LifecycleEventType.AGENT_REPORTED_COMPLETION.value
        )
        verification_index = event_types.index(
            LifecycleEventType.VERIFICATION_RESULT.value
        )
        self.assertLess(completion_index, verification_index)

    async def test_end_to_end_emits_complete_lifecycle_and_output(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_release_readiness_agent(
                READY_FIXTURE,
                Path(directory) / "events.jsonl",
            )
            event_types = [_event_type(row) for row in result.exported_events]
            sequences = [
                row["payload"]["lifecycle_event"]["sequence"]
                for row in result.exported_events
            ]

        self.assertEqual(result.task.task_id, "sample-release-readiness")
        self.assertEqual(OBJECTIVE, "Determine whether the sample release is ready.")
        self.assertEqual(
            event_types.count(LifecycleEventType.EVIDENCE_COLLECTED.value),
            3,
        )
        self.assertEqual(sequences, list(range(1, len(sequences) + 1)))
        for required in (
            LifecycleEventType.TASK_STARTED,
            LifecycleEventType.WORKER_STARTED,
            LifecycleEventType.WORKER_COMPLETED,
            LifecycleEventType.AGENT_REPORTED_COMPLETION,
            LifecycleEventType.VERIFICATION_RESULT,
        ):
            self.assertIn(required.value, event_types)

    @pytest.mark.cortexops_integration
    async def test_real_cortexops_sdk_parses_every_exported_event(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_release_readiness_agent(
                READY_FIXTURE,
                Path(directory) / "events.jsonl",
            )
            validation = validate_cortexops_jsonl(result.event_path)
            summary = format_summary(result, validation)

        self.assertEqual(validation.skipped_events, 0)
        self.assertEqual(validation.model_events, len(result.exported_events))
        self.assertEqual(validation.parsed_events, len(result.exported_events))
        self.assertIn("agent started: yes", summary)
        self.assertIn("task started: yes", summary)
        self.assertIn("evidence collected: 3", summary)
        self.assertIn("agent reported completion: yes", summary)
        self.assertIn("verification result: AWAITING_EVIDENCE", summary)
        self.assertIn("final status: AWAITING_EVIDENCE", summary)
        self.assertIn(
            f"exported event count: {len(result.exported_events)}",
            summary,
        )


if __name__ == "__main__":
    unittest.main()
