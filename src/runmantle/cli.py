"""Command-line entry point for the durable local-first Runmantle runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from . import __version__
from .demo import run_deterministic_demo
from .persistence import LATEST_SCHEMA_VERSION, SQLiteStore
from .project import (
    PROJECT_FILE,
    ProjectConfigurationError,
    load_project,
    project_document,
)
from .release_guard import (
    recovery_plan,
    resume_recovery,
    run_agent,
    runtime,
    verify_repository,
)
from .serialization import SafeJsonCodec

_SECRET_KEYS = frozenset(
    {"api_key", "authorization", "cookie", "password", "secret", "token"}
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runmantle",
        description="Evidence-gated, durable execution for existing AI agents.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser(
        "init", help="Create the Verified Release Guard fixture."
    )
    init.add_argument("directory", nargs="?", default=".")
    init.add_argument(
        "--cortexops",
        action="store_true",
        help="Explicitly enable redacted observation-only local CortexOps export.",
    )
    init.add_argument("--json", action="store_true")

    for name, help_text in (
        ("run", "Run the wrapped agent and persist its completion claim."),
        ("inspect", "Inspect durable task, evidence, recovery, and event state."),
        ("verify", "Run mediated acceptance checks and verify their evidence."),
        ("doctor", "Check environment, project, storage, and optional integrations."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--project", default=PROJECT_FILE)
        command.add_argument("--json", action="store_true")

    resume = commands.add_parser(
        "resume", help="Resume the exact durable recovery boundary."
    )
    resume.add_argument("--project", default=PROJECT_FILE)
    resume.add_argument(
        "--approve-current-plan",
        action="store_true",
        help="Approve the exact current plan using a local identity assertion.",
    )
    resume.add_argument(
        "--fault-after-write", action="store_true", help=argparse.SUPPRESS
    )
    resume.add_argument("--json", action="store_true")

    demo = commands.add_parser("demo", help="Run the original in-memory demo.")
    demo.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process-compatible status code."""

    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "init":
            init_result = _init(
                Path(arguments.directory), cortexops=arguments.cortexops
            )
            _write(init_result, arguments.json)
            return 0
        if arguments.command == "demo":
            demo = asyncio.run(run_deterministic_demo())
            verification = demo.result.final_verification_result
            demo_document = {
                "task_id": demo.result.task_id,
                "status": demo.result.status.value,
                "reported_status": _enum_value(demo.result.reported_status),
                "verification_status": _enum_value(
                    verification.status if verification else None
                ),
                "output": demo.result.output,
                "evidence_count": len(demo.result.evidence),
                "event_count": len(demo.events),
            }
            _write(demo_document, arguments.json)
            return 0 if demo.result.succeeded else 1

        project = load_project(arguments.project)
        if arguments.command == "run":
            task_result = asyncio.run(run_agent(project))
            document = _result_document(
                task_result, len(runtime(project).event_history(project.task_id))
            )
            _write(document, arguments.json)
            return 0 if task_result.succeeded else 3
        if arguments.command == "inspect":
            _write(_inspect(project), arguments.json)
            return 0
        if arguments.command == "verify":
            verification_result = asyncio.run(verify_repository(project))
            document = _result_document(
                verification_result,
                len(runtime(project).event_history(project.task_id)),
            )
            _write(document, arguments.json)
            return 0 if verification_result.succeeded else 4
        if arguments.command == "resume":
            recovery_result = asyncio.run(
                resume_recovery(
                    project,
                    approve_current=arguments.approve_current_plan,
                    fault_after_write=arguments.fault_after_write,
                )
            )
            task = runtime(project).load(project.task_id)
            document = {
                "task_id": project.task_id,
                "task_status": task.status.value,
                "recovery_plan_id": recovery_result.plan_id,
                "recovery_plan_hash": recovery_plan(project).plan_hash,
                "recovery_status": recovery_result.status.value,
                "executed": recovery_result.executed,
                "verified": recovery_result.succeeded,
                "message": recovery_result.actions[0].reason.message,
            }
            _write(document, arguments.json)
            return 0 if recovery_result.succeeded else 5
        if arguments.command == "doctor":
            document = _doctor(project)
            _write(document, arguments.json)
            return 0 if document["healthy"] else 2
    except KeyboardInterrupt:
        _write_error("operation cancelled by user")
        return 130
    except Exception as error:  # noqa: BLE001 - CLI boundary returns sanitized errors
        _write_error(f"{type(error).__name__}: {_sanitize_message(str(error))}")
        return 2
    return 2


def _init(directory: Path, *, cortexops: bool) -> dict[str, Any]:
    target = directory.resolve()
    target.mkdir(parents=True, exist_ok=True)
    manifest = target / PROJECT_FILE
    repository = target / "repository"
    state = target / ".runmantle"
    if manifest.exists() or repository.exists() or state.exists():
        raise ProjectConfigurationError(
            "refusing to overwrite an existing Runmantle project"
        )
    if shutil.which("git") is None:
        raise RuntimeError("git is required for the Verified Release Guard fixture")
    repository.mkdir()
    state.mkdir()
    (repository / "release.json").write_text(
        '{"artifact_sha256": null, "ready": false}\n', encoding="utf-8"
    )
    (repository / "README.md").write_text(
        "# Release fixture\n\nThe initial agent claim is intentionally false.\n",
        encoding="utf-8",
    )
    _git(repository, "init", "--quiet")
    _git(repository, "add", "README.md", "release.json")
    _git(
        repository,
        "-c",
        "user.name=Runmantle",
        "-c",
        "user.email=local@runmantle.dev",
        "commit",
        "--quiet",
        "-m",
        "Initial failing release fixture",
    )
    document = project_document(
        task_id=f"release-{uuid4()}",
        correlation_id=f"session-{uuid4()}",
        created_at=datetime.now(UTC),
        cortexops_enabled=cortexops,
    )
    manifest.write_text(SafeJsonCodec().dumps(document) + "\n", encoding="utf-8")
    return {
        "initialized": True,
        "project": str(manifest),
        "workflow": "verified_release_guard",
        "cortexops_enabled": cortexops,
        "next": "runmantle run",
    }


def _inspect(project: Any) -> dict[str, Any]:
    active = runtime(project)
    task = active.load(project.task_id)
    events = active.event_history(project.task_id)
    evidence = active.store.evidence(project.task_id)
    recovery = active.store.load_recovery_state(recovery_plan(project).plan_id)
    return _redact_document(
        {
            "task_id": task.task_id,
            "status": task.status.value,
            "reported_status": _enum_value(task.reported_status),
            "verified": task.status.value == "verified",
            "version": task.version,
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "type": item.type,
                    "source": item.source,
                    "checksum": item.checksum,
                    "trust_level": item.trust_level.name,
                    "acquisition_method": item.acquisition_method.value,
                    "collected_at": item.collected_at.isoformat(),
                    "expires_at": (
                        item.expires_at.isoformat() if item.expires_at else None
                    ),
                }
                for item in evidence
            ],
            "event_count": len(events),
            "last_event_sequence": events[-1].sequence if events else None,
            "recovery": (
                None
                if recovery is None
                else {
                    "plan_id": recovery.plan_id,
                    "status": recovery.status,
                    "version": recovery.version,
                }
            ),
            "content_exported": False,
        }
    )


def _doctor(project: Any) -> dict[str, Any]:
    checks: list[dict[str, Any]] = [
        {
            "name": "python",
            "ok": sys.version_info >= (3, 11),
            "detail": platform.python_version(),
        },
        {
            "name": "git",
            "ok": shutil.which("git") is not None,
            "detail": shutil.which("git"),
        },
        {
            "name": "repository",
            "ok": (project.repository / ".git").is_dir(),
            "detail": "bounded project path",
        },
    ]
    try:
        schema = SQLiteStore(project.database_path).schema_version
        checks.append(
            {
                "name": "sqlite",
                "ok": schema == LATEST_SCHEMA_VERSION,
                "detail": f"schema {schema}, WAL enabled",
            }
        )
    except Exception as error:  # noqa: BLE001 - diagnostic result
        checks.append({"name": "sqlite", "ok": False, "detail": type(error).__name__})
    for package, extra in (
        ("openai-agents", "openai-agents"),
        ("cortexops-sdk", "cortexops"),
    ):
        try:
            detail = f"installed {metadata.version(package)}"
        except metadata.PackageNotFoundError:
            detail = f"optional; install runmantle[{extra}]"
        checks.append({"name": package, "ok": True, "detail": detail})
    return _redact_document(
        {
            "healthy": all(item["ok"] for item in checks),
            "runmantle_version": __version__,
            "checks": checks,
        }
    )


def _result_document(result: Any, event_count: int) -> dict[str, Any]:
    verification = result.final_verification_result
    return _redact_document(
        {
            "task_id": result.task_id,
            "status": result.status.value,
            "reported_status": _enum_value(result.reported_status),
            "verification_status": _enum_value(
                verification.status if verification else None
            ),
            "verified": result.succeeded,
            "evidence_count": len(result.evidence),
            "event_count": event_count,
            "agent_claim_is_success": False,
        }
    )


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _redact(value: Any, *, key: str | None = None) -> Any:
    if key is not None and key.lower() in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): _redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def _redact_document(value: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], _redact(value))


def _sanitize_message(message: str) -> str:
    lowered = message.lower()
    if any(key in lowered for key in _SECRET_KEYS):
        return "sensitive diagnostic was redacted"
    return message[:500]


def _enum_value(value: Any) -> Any:
    return None if value is None else value.value


def _write(document: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(document, sort_keys=True))
    else:
        for key, value in document.items():
            print(f"{key}: {value}")


def _write_error(message: str) -> None:
    print(f"runmantle: {message}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
