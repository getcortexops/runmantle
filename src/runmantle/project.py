"""Safe loading and path resolution for local Runmantle projects."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .serialization import SafeJsonCodec, SerializationError

PROJECT_SCHEMA_VERSION = 1
PROJECT_FILE = "runmantle.json"


class ProjectConfigurationError(ValueError):
    """Raised when a local project file is invalid or escapes its root."""


@dataclass(frozen=True, slots=True)
class RunmantleProject:
    """Validated configuration for the packaged reference workflow."""

    root: Path
    task_id: str
    correlation_id: str
    created_at: datetime
    repository: Path
    state_directory: Path
    cortexops_enabled: bool = False

    @property
    def database_path(self) -> Path:
        return self.state_directory / "runmantle.db"

    @property
    def event_path(self) -> Path:
        return self.state_directory / "events.jsonl"


def resolve_within(root: Path, relative: str, *, must_exist: bool = False) -> Path:
    """Resolve a manifest-controlled relative path without allowing escape."""

    if not relative.strip():
        raise ProjectConfigurationError("project paths must not be empty")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ProjectConfigurationError(
            "project paths must be relative and contain no '..'"
        )
    resolved_root = root.resolve(strict=True)
    try:
        resolved = (resolved_root / candidate).resolve(strict=must_exist)
        resolved.relative_to(resolved_root)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        raise ProjectConfigurationError(
            f"project path {relative!r} does not resolve within the project root"
        ) from error
    return resolved


def load_project(path: str | Path = PROJECT_FILE) -> RunmantleProject:
    """Load a bounded, non-executable JSON project manifest."""

    manifest = Path(path)
    if manifest.is_dir():
        manifest /= PROJECT_FILE
    try:
        raw = manifest.read_text(encoding="utf-8")
    except OSError as error:
        raise ProjectConfigurationError(f"cannot read {manifest}: {error}") from error
    if len(raw.encode("utf-8")) > 64 * 1024:
        raise ProjectConfigurationError("project manifest exceeds 64 KiB")
    try:
        value = SafeJsonCodec().loads(raw)
    except SerializationError as error:
        raise ProjectConfigurationError(
            f"project manifest is invalid: {error}"
        ) from error
    if not isinstance(value, Mapping):
        raise ProjectConfigurationError("project manifest must contain a JSON object")
    if value.get("schema_version") != PROJECT_SCHEMA_VERSION:
        raise ProjectConfigurationError("unsupported project schema_version")
    if value.get("workflow") != "verified_release_guard":
        raise ProjectConfigurationError("unsupported workflow")
    root = manifest.parent.resolve(strict=True)
    created = value.get("created_at")
    if not isinstance(created, datetime):
        raise ProjectConfigurationError("created_at must be a Runmantle aware datetime")
    task_id = _required_string(value, "task_id")
    correlation_id = _required_string(value, "correlation_id")
    repository = resolve_within(
        root, _required_string(value, "repository"), must_exist=True
    )
    state_directory = resolve_within(root, _required_string(value, "state_directory"))
    cortexops = value.get("cortexops", {})
    if not isinstance(cortexops, Mapping):
        raise ProjectConfigurationError("cortexops must be a JSON object")
    return RunmantleProject(
        root=root,
        task_id=task_id,
        correlation_id=correlation_id,
        created_at=created,
        repository=repository,
        state_directory=state_directory,
        cortexops_enabled=cortexops.get("enabled") is True,
    )


def project_document(
    *,
    task_id: str,
    correlation_id: str,
    created_at: datetime,
    cortexops_enabled: bool = False,
) -> dict[str, Any]:
    """Return the canonical manifest document created by ``runmantle init``."""

    return {
        "schema_version": PROJECT_SCHEMA_VERSION,
        "workflow": "verified_release_guard",
        "task_id": task_id,
        "correlation_id": correlation_id,
        "created_at": created_at,
        "repository": "repository",
        "state_directory": ".runmantle",
        "cortexops": {"enabled": cortexops_enabled},
    }


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ProjectConfigurationError(f"{key} must be a non-empty string")
    return item
