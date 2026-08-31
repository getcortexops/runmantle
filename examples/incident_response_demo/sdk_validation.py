"""Validation adapters for the optional, application-owned CortexOps install."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol, cast

from examples.cortexops_workspace import configure_cortexops_workspace


class _SdkEvent(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


class _SdkEventType(Protocol):
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> _SdkEvent: ...


class _ParserResult(Protocol):
    total: int
    skipped: int
    events: list[Any]


@dataclass(frozen=True, slots=True)
class SdkValidationResult:
    sdk_model_events: int
    adapter_total: int
    adapter_parsed: int
    adapter_skipped: int


def validate_cortexops_jsonl(path: str | Path) -> SdkValidationResult:
    """Parse every row with the real SDK model and CortexOps JSONL adapter."""

    event_path = Path(path)
    configure_cortexops_workspace()
    try:
        sdk_events = import_module("cortexops_sdk.events")
        parser_module = import_module("cortexops.adapters.cortexops_sdk.parser")
    except ModuleNotFoundError as error:
        raise RuntimeError(
            "CortexOps SDK validation requires cortexops_sdk and the CortexOps "
            "SDK JSONL adapter on PYTHONPATH"
        ) from error

    event_type = cast(_SdkEventType, sdk_events.Event)
    parser = cast(
        Callable[[str | Path], _ParserResult],
        parser_module.parse_events_file,
    )
    sdk_model_events = 0
    with event_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError(f"CortexOps JSONL row {line_number} is not an object")
            normalized = event_type.from_dict(value).to_dict()
            if normalized.get("event_id") != value.get("event_id"):
                raise ValueError(f"SDK changed event_id on row {line_number}")
            sdk_model_events += 1

    parsed = parser(event_path)
    parsed_count = len(parsed.events)
    if (
        parsed.skipped
        or parsed.total != sdk_model_events
        or parsed_count != sdk_model_events
    ):
        raise ValueError(
            "CortexOps SDK parser did not accept every exported event "
            f"(rows={sdk_model_events}, total={parsed.total}, "
            f"parsed={parsed_count}, skipped={parsed.skipped})"
        )
    return SdkValidationResult(
        sdk_model_events=sdk_model_events,
        adapter_total=parsed.total,
        adapter_parsed=parsed_count,
        adapter_skipped=parsed.skipped,
    )
