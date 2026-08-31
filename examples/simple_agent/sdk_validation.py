"""Validate exported JSONL with the real CortexOps SDK and file parser."""

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
    model_events: int
    parsed_events: int
    skipped_events: int


def validate_cortexops_jsonl(path: str | Path) -> SdkValidationResult:
    """Require both CortexOps SDK parsers to accept every exported event."""

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
    parse_events_file = cast(
        Callable[[str | Path], _ParserResult],
        parser_module.parse_events_file,
    )
    event_path = Path(path)
    model_events = 0
    with event_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError(f"CortexOps JSONL row {line_number} is not an object")
            parsed_model = event_type.from_dict(value).to_dict()
            if parsed_model.get("event_id") != value.get("event_id"):
                raise ValueError(f"SDK changed event_id on row {line_number}")
            model_events += 1

    parsed = parse_events_file(event_path)
    parsed_events = len(parsed.events)
    if parsed.skipped or parsed.total != model_events or parsed_events != model_events:
        raise ValueError(
            "CortexOps SDK parser did not accept every exported event "
            f"(rows={model_events}, total={parsed.total}, "
            f"parsed={parsed_events}, skipped={parsed.skipped})"
        )
    return SdkValidationResult(
        model_events=model_events,
        parsed_events=parsed_events,
        skipped_events=parsed.skipped,
    )
