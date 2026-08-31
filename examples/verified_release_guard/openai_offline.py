"""Verified Release Guard variant using the real OpenAI adapter, fully offline."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from agents import Agent

from runmantle import AgentAdapterWorker, TaskStatus
from runmantle.cli import _init
from runmantle.integrations.openai_agents import OpenAIAgentsAdapter
from runmantle.openai_quickstart import ScriptedModel, output_message
from runmantle.project import load_project
from runmantle.release_guard import (
    ExistingReleaseAgentAdapter,
    release_contract,
    resume_recovery,
    runtime,
    verify_repository,
)


async def run_openai_release_guard(root: Path) -> dict[str, Any]:
    _init(root, cortexops=False)
    project = load_project(root)
    boundary = ExistingReleaseAgentAdapter().adapter_contract
    adapter: OpenAIAgentsAdapter[dict[str, Any], dict[str, Any]] = OpenAIAgentsAdapter(
        agent=Agent(
            name="existing-release-agent", model=ScriptedModel([output_message()])
        ),
        adapter_contract=boundary,
        output_mapper=lambda output, result: {
            "release_ready": str(output) == "done",
            "agent_claim": True,
        },
        run_config={"tracing_disabled": True},
    )
    claim = await runtime(project).execute(
        AgentAdapterWorker(adapter),
        release_contract(project),
        correlation_id=project.correlation_id,
    )
    checked = await verify_repository(project)
    waiting = await resume_recovery(project)
    recovered = await resume_recovery(project, approve_current=True)
    final = runtime(project).load(project.task_id)
    if final.status is not TaskStatus.VERIFIED:
        raise RuntimeError(f"reference workflow stopped at {final.status.value}")
    return {
        "claim": claim.status.value,
        "checked": checked.status.value,
        "recovery_pause": waiting.status.value,
        "recovery": recovered.status.value,
        "final": final.status.value,
    }


def main() -> None:
    with TemporaryDirectory() as directory:
        result = asyncio.run(run_openai_release_guard(Path(directory)))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
