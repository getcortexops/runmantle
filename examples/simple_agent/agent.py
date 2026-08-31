"""A native Runmantle worker that checks a local release fixture."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from runmantle import (
    CapabilityDeclaration,
    EvidenceRequirement,
    FieldEqualsCriterion,
    InMemoryRuntime,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    TaskResult,
    WorkerReport,
)
from runmantle.integrations.cortexops import (
    CortexOpsIntegrationConfig,
    create_cortexops_event_sink,
)

from .sdk_validation import SdkValidationResult, validate_cortexops_jsonl

OBJECTIVE = "Determine whether the sample release is ready."
FIXTURES = Path(__file__).parent / "fixtures"
READY_FIXTURE = FIXTURES / "ready_release"
FAILED_FIXTURE = FIXTURES / "failed_release"
DEFAULT_EVENT_PATH = Path("./release_readiness_events.jsonl")
REQUIRED_FILES = ("README.md", "release.json", "src/sample.py")


@dataclass(frozen=True, slots=True)
class ReleaseProject:
    root: Path
    required_files: tuple[str, ...] = REQUIRED_FILES


@dataclass(frozen=True, slots=True)
class ReleaseReadiness:
    files_present: bool
    ci_status: str | None
    review_status: str | None
    ready: bool


class ReleaseReadinessWorker:
    """Inspect local files and report completion without claiming verification."""

    id = "release-readiness-worker"
    name = "ReleaseReadinessWorker"
    role = "release-readiness"
    version = "1.0.0"
    capabilities = (
        CapabilityDeclaration(
            name="inspect-local-fixture",
            description="Read deterministic fixture files from the local project.",
            requires_runtime_confirmation=False,
        ),
    )

    async def execute(
        self,
        task: TaskContract[ReleaseProject, ReleaseReadiness],
        context: TaskContext,
    ) -> WorkerReport[ReleaseReadiness]:
        context.require_capability("inspect-local-fixture")
        project = task.input

        missing_files = tuple(
            name
            for name in project.required_files
            if not (project.root / name).is_file()
        )
        files_present = not missing_files
        context.evidence.record(
            "required_files_check",
            {
                "passed": files_present,
                "required_files": list(project.required_files),
                "missing_files": list(missing_files),
            },
            source=self.id,
            artifact_reference=str(project.root),
            evidence_id="required-files-check",
        )

        release_data = _read_release_data(project.root / "release.json")
        ci_status = _optional_string(release_data.get("ci_status"))
        review_status = _optional_string(release_data.get("review_status"))
        context.evidence.record(
            "ci_status_check",
            {"passed": ci_status == "passed", "actual": ci_status},
            source=self.id,
            artifact_reference=str(project.root / "release.json"),
            evidence_id="ci-status-check",
        )
        context.evidence.record(
            "review_status_check",
            {"passed": review_status == "approved", "actual": review_status},
            source=self.id,
            artifact_reference=str(project.root / "release.json"),
            evidence_id="review-status-check",
        )

        return WorkerReport.completed(
            ReleaseReadiness(
                files_present=files_present,
                ci_status=ci_status,
                review_status=review_status,
                ready=(
                    files_present
                    and ci_status == "passed"
                    and review_status == "approved"
                ),
            )
        )


@dataclass(frozen=True, slots=True)
class DemoResult:
    task: TaskResult[ReleaseReadiness]
    event_path: Path
    exported_events: tuple[dict[str, Any], ...]


def create_task_contract(
    project_root: str | Path,
) -> TaskContract[ReleaseProject, ReleaseReadiness]:
    """Create the single release-readiness task contract."""

    return TaskContract(
        task_id="sample-release-readiness",
        objective=OBJECTIVE,
        input=ReleaseProject(Path(project_root)),
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="required-project-files-exist",
                description="Every required fixture project file must exist.",
                field_path="passed",
                expected=True,
                evidence_type="required_files_check",
            ),
            FieldEqualsCriterion(
                name="ci-passed",
                description="The fixture must report ci_status = passed.",
                field_path="passed",
                expected=True,
                evidence_type="ci_status_check",
            ),
            FieldEqualsCriterion(
                name="review-approved",
                description="The fixture must report review_status = approved.",
                field_path="passed",
                expected=True,
                evidence_type="review_status_check",
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                "required_files_check",
                "The complete required-file check result.",
            ),
            EvidenceRequirement("ci_status_check", "The fixture CI status check."),
            EvidenceRequirement(
                "review_status_check",
                "The fixture review status check.",
            ),
        ),
        allowed_capabilities=frozenset({"inspect-local-fixture"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key="sample-release-readiness-v1",
    )


async def run_release_readiness_agent(
    project_root: str | Path = READY_FIXTURE,
    event_path: str | Path = DEFAULT_EVENT_PATH,
) -> DemoResult:
    """Execute the worker and export every runtime event to local JSONL."""

    output_path = Path(event_path)
    output_path.unlink(missing_ok=True)
    sink = create_cortexops_event_sink(
        CortexOpsIntegrationConfig(
            enabled=True,
            project="runmantle-simple-agent",
            environment="local",
            service_name="release-readiness-agent",
            export_path=output_path,
        )
    )
    task = await InMemoryRuntime(
        verifier=RuleBasedVerifier(),
        event_sink=sink,
    ).execute(
        ReleaseReadinessWorker(),
        create_task_contract(project_root),
        correlation_id="sample-release-readiness-run",
    )
    return DemoResult(
        task=task,
        event_path=output_path,
        exported_events=_read_exported_events(output_path),
    )


def format_summary(result: DemoResult, sdk: SdkValidationResult) -> str:
    """Build the concise, human-readable demo output."""

    event_types = tuple(_event_type(row) for row in result.exported_events)
    verification = result.task.final_verification_result
    verification_status = verification.status.value.upper() if verification else "NONE"
    return "\n".join(
        (
            f"agent started: {_yes_no('worker.started' in event_types)}",
            f"task started: {_yes_no('task.started' in event_types)}",
            f"evidence collected: {event_types.count('evidence.collected')}",
            "agent reported completion: "
            f"{_yes_no('agent.reported_completion' in event_types)}",
            f"verification result: {verification_status}",
            f"final status: {result.task.status.value.upper()}",
            f"exported event count: {len(result.exported_events)}",
            f"CortexOps SDK parsed events: {sdk.parsed_events}",
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=READY_FIXTURE)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENT_PATH)
    arguments = parser.parse_args()

    result = asyncio.run(
        run_release_readiness_agent(arguments.fixture, arguments.events)
    )
    sdk = validate_cortexops_jsonl(result.event_path)
    print(format_summary(result, sdk))


def _read_release_data(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _read_exported_events(path: Path) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise TypeError("CortexOps JSONL row must be an object")
        events.append(value)
    return tuple(events)


def _event_type(row: dict[str, Any]) -> str:
    payload = row.get("payload")
    if not isinstance(payload, dict):
        raise TypeError("CortexOps event payload must be an object")
    lifecycle = payload.get("lifecycle_event")
    if not isinstance(lifecycle, dict):
        raise TypeError("CortexOps lifecycle event must be an object")
    event_type = lifecycle.get("event_type")
    if not isinstance(event_type, str):
        raise TypeError("Runmantle lifecycle event type must be a string")
    return event_type


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


if __name__ == "__main__":
    main()
