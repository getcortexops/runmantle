from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest

from examples.incident_response_demo import (
    run_incident_response_demo,
    validate_cortexops_jsonl,
)
from runmantle import (
    LifecycleEventType,
    RecoveryReasonCode,
    RecoveryStatus,
    TaskStatus,
    VerificationStatus,
    WorkerReportedStatus,
)
from runmantle.integrations.cortexops import validate_cortexops_event


def _lifecycle(row: dict[str, Any]) -> dict[str, Any]:
    payload = row["payload"]
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")
    lifecycle = payload["lifecycle_event"]
    if not isinstance(lifecycle, dict):
        raise TypeError("lifecycle_event must be an object")
    return lifecycle


class IncidentResponseDemoTest(unittest.IsolatedAsyncioTestCase):
    async def test_completion_recovery_confirmation_and_final_verification(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            event_path = Path(directory) / "incident-events.jsonl"
            result = await run_incident_response_demo(event_path)

            self.assertEqual(result.triage.status, TaskStatus.AWAITING_EVIDENCE)
            self.assertEqual(
                result.initial_diagnosis.reported_status,
                WorkerReportedStatus.COMPLETED,
            )
            self.assertEqual(result.initial_diagnosis.status, TaskStatus.FAILED)
            self.assertFalse(result.initial_diagnosis.succeeded)
            self.assertIsNotNone(
                result.initial_diagnosis.timestamps.agent_reported_complete_at
            )
            initial_verification = result.initial_diagnosis.final_verification_result
            self.assertIsNotNone(initial_verification)
            self.assertEqual(
                initial_verification.status if initial_verification else None,
                VerificationStatus.FAILED,
            )

            self.assertEqual(
                result.blocked_recovery.status,
                RecoveryStatus.AWAITING_APPROVAL,
            )
            self.assertEqual(
                result.blocked_recovery.actions[0].reason.code,
                RecoveryReasonCode.APPROVAL_REQUIRED,
            )
            self.assertEqual(result.recovery_executions_after_block, 0)
            self.assertEqual(
                result.confirmed_recovery.status,
                RecoveryStatus.VERIFIED,
            )
            self.assertTrue(result.confirmed_recovery.executed)
            self.assertTrue(result.confirmed_recovery.succeeded)
            self.assertEqual(result.simulated_recovery_executions, 1)
            self.assertTrue(result.approval.approved)
            self.assertEqual(result.final_diagnosis.status, TaskStatus.VERIFIED)
            self.assertTrue(result.final_diagnosis.succeeded)

            rows = [
                json.loads(line)
                for line in event_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(tuple(rows), result.exported_events)
            for row in rows:
                validate_cortexops_event(row)

            lifecycle_events = [_lifecycle(row) for row in rows]
            names = [event["name"] for event in lifecycle_events]
            event_types = [event["event_type"] for event in lifecycle_events]
            self.assertIn("incident.received", names)
            self.assertIn("triage.investigating", names)
            self.assertIn("diagnosis.investigating", names)
            self.assertEqual(names.count("health.check.completed"), 1)
            self.assertGreaterEqual(
                event_types.count(LifecycleEventType.EVIDENCE_COLLECTED.value),
                4,
            )
            self.assertIn(
                LifecycleEventType.RUNTIME_CONFIRMATION_RECEIVED.value,
                event_types,
            )
            self.assertIn(
                LifecycleEventType.RECOVERY_AWAITING_APPROVAL.value,
                event_types,
            )
            self.assertIn(
                LifecycleEventType.RECOVERY_OUTCOME_VERIFIED.value,
                event_types,
            )

            verification_rows = [
                row
                for row in rows
                if _lifecycle(row)["event_type"]
                == LifecycleEventType.VERIFICATION_RESULT.value
            ]
            verification_statuses = [
                _lifecycle(row)["details"]["status"] for row in verification_rows
            ]
            self.assertIn(VerificationStatus.FAILED.value, verification_statuses)
            self.assertEqual(
                verification_statuses[-1], VerificationStatus.VERIFIED.value
            )
            self.assertEqual(verification_rows[-1]["status"], "completed")
            self.assertEqual(lifecycle_events[-1]["state"], TaskStatus.VERIFIED.value)

    @pytest.mark.cortexops_integration
    async def test_real_cortexops_sdk_parser_accepts_complete_jsonl(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_incident_response_demo(
                Path(directory) / "incident-events.jsonl"
            )
            validation = validate_cortexops_jsonl(result.event_path)

        self.assertEqual(validation.adapter_skipped, 0)
        self.assertEqual(
            validation.sdk_model_events,
            len(result.exported_events),
        )
        self.assertEqual(
            validation.adapter_parsed,
            len(result.exported_events),
        )


if __name__ == "__main__":
    unittest.main()
