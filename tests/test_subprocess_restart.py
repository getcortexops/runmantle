from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

PROBE = Path(__file__).parent / "fixtures" / "restart_probe.py"


def probe(phase: str, database: Path, scenario: str) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, str(PROBE), phase, str(database), scenario],
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise TypeError("restart probe output must be an object")
    return cast(dict[str, object], value)


class RealProcessRestartTest(unittest.TestCase):
    def test_task_lifecycle_restart_matrix_and_duplicate_resume(self) -> None:
        scenarios = (
            "pending",
            "checkpoint",
            "agent_reported_complete",
            "awaiting_evidence",
            "awaiting_approval",
            "awaiting_runtime_confirmation",
            "inconclusive",
            "verified",
            "failed",
        )
        with TemporaryDirectory() as directory:
            for scenario in scenarios:
                with self.subTest(scenario=scenario):
                    database = Path(directory) / f"{scenario}.db"
                    seeded = probe("seed", database, scenario)
                    resumed = probe("resume", database, scenario)
                    duplicate = probe("duplicate", database, scenario)
                    expected = "failed" if scenario == "failed" else "verified"
                    self.assertEqual(resumed["status"], expected)
                    self.assertEqual(duplicate["status"], expected)
                    self.assertEqual(duplicate["events"], resumed["events"])
                    expected_effects = (
                        []
                        if scenario in {"agent_reported_complete", "inconclusive"}
                        else ["checkpoint"]
                        if scenario == "checkpoint"
                        else ["execute"]
                    )
                    self.assertEqual(duplicate["effects"], expected_effects)
                    self.assertGreaterEqual(
                        cast(int, resumed["events"]), cast(int, seeded["events"])
                    )

    def test_action_and_recovery_ambiguity_never_repeat_effects(self) -> None:
        with TemporaryDirectory() as directory:
            for scenario in ("action_unknown", "recovery_ambiguity"):
                with self.subTest(scenario=scenario):
                    database = Path(directory) / f"{scenario}.db"
                    probe("seed", database, scenario)
                    resumed = probe("resume", database, scenario)
                    duplicate = probe("duplicate", database, scenario)
                    self.assertEqual(resumed["status"], "unknown")
                    self.assertEqual(duplicate["status"], "unknown")
                    self.assertEqual(duplicate["effects"], [])

    def test_action_postconditions_resume_in_a_later_process(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "action-postconditions.db"
            seeded = probe("seed", database, "action_postcondition_restart")
            resumed = probe("resume", database, "action_postcondition_restart")
            duplicate = probe("duplicate", database, "action_postcondition_restart")

            self.assertEqual(seeded["status"], "executor_succeeded")
            self.assertEqual(seeded["postcondition_status"], "pending")
            self.assertEqual(resumed["status"], "executor_succeeded")
            self.assertEqual(resumed["postcondition_status"], "completed")
            self.assertEqual(resumed["effects"], ["postcondition"])
            self.assertEqual(duplicate["effects"], ["postcondition"])

    def test_recovery_pause_resumes_once_in_a_later_process(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "recovery-pause.db"
            seeded = probe("seed", database, "recovery_pause")
            self.assertEqual(seeded["status"], "awaiting_approval")
            resumed = probe("resume", database, "recovery_pause")
            duplicate = probe("duplicate", database, "recovery_pause")
            self.assertEqual(resumed["status"], "verified")
            self.assertEqual(duplicate["status"], "verified")
            self.assertEqual(duplicate["effects"], ["recovery"])


if __name__ == "__main__":
    unittest.main()
