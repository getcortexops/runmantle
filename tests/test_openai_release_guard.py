from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

pytest.importorskip("agents")

from examples.verified_release_guard.openai_offline import run_openai_release_guard


class OpenAIReleaseGuardTest(unittest.IsolatedAsyncioTestCase):
    async def test_release_guard_runs_through_real_openai_adapter_offline(self) -> None:
        with TemporaryDirectory() as directory:
            result = await run_openai_release_guard(Path(directory))

        self.assertEqual(
            result,
            {
                "claim": "awaiting_evidence",
                "checked": "failed",
                "recovery_pause": "awaiting_approval",
                "recovery": "verified",
                "final": "verified",
            },
        )
