from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from runmantle.cli import main


class CliTest(unittest.TestCase):
    def test_deterministic_demo_keeps_worker_evidence_as_a_claim(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = main(["demo", "--json"])

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(document["status"], "awaiting_evidence")
        self.assertEqual(document["reported_status"], "completed")
        self.assertEqual(document["verification_status"], "awaiting_evidence")
        self.assertEqual(document["output"], 42)
        self.assertEqual(document["evidence_count"], 1)
        self.assertGreater(document["event_count"], 0)


if __name__ == "__main__":
    unittest.main()
