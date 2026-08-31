"""Safe, deterministic JSON serialization for durable local state."""

from __future__ import annotations

import base64
import binascii
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


class SerializationError(ValueError):
    """Raised when a value cannot be represented by the safe JSON codec."""


class JsonCodec(Protocol):
    """Application-replaceable safe JSON codec boundary."""

    def dumps(self, value: Any) -> str:
        """Serialize a value to deterministic JSON without executable objects."""

    def loads(self, value: str) -> Any:
        """Deserialize JSON to safe primitive and explicitly supported values."""


@dataclass(frozen=True, slots=True)
class SafeJsonCodec:
    """Bounded JSON codec supporting a small non-executable type set."""

    max_bytes: int = 8 * 1024 * 1024
    max_depth: int = 64
    max_collection_items: int = 100_000

    def __post_init__(self) -> None:
        if self.max_bytes < 1 or self.max_depth < 1 or self.max_collection_items < 1:
            raise ValueError("safe JSON limits must be positive")

    def dumps(self, value: Any) -> str:
        try:
            encoded = json.dumps(
                _to_json(value),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            if len(encoded.encode("utf-8")) > self.max_bytes:
                raise SerializationError(
                    "serialized value exceeds the configured limit"
                )
            return encoded
        except (RecursionError, TypeError, ValueError) as error:
            if isinstance(error, SerializationError):
                raise
            raise SerializationError(str(error)) from error

    def loads(self, value: str) -> Any:
        if not isinstance(value, str):
            raise SerializationError("persisted value must be JSON text")
        if len(value.encode("utf-8")) > self.max_bytes:
            raise SerializationError("persisted value exceeds the configured limit")
        try:
            decoded = json.loads(value)
        except (RecursionError, TypeError, json.JSONDecodeError) as error:
            raise SerializationError("persisted value is not valid JSON") from error
        try:
            _validate_decoded_shape(
                decoded,
                max_depth=self.max_depth,
                max_collection_items=self.max_collection_items,
            )
            return _from_json(decoded)
        except (RecursionError, TypeError, ValueError) as error:
            if isinstance(error, SerializationError):
                raise
            raise SerializationError(str(error)) from error


def _to_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SerializationError("non-finite floats are not supported")
        return value
    if isinstance(value, bytes):
        return {
            "$runmantle_type": "bytes",
            "base64": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise SerializationError("datetime values must be timezone-aware")
        return {"$runmantle_type": "datetime", "value": value.isoformat()}
    if isinstance(value, timedelta):
        return {"$runmantle_type": "timedelta", "seconds": value.total_seconds()}
    if isinstance(value, Path):
        return {"$runmantle_type": "path", "value": str(value)}
    if isinstance(value, Enum):
        return _to_json(value.value)
    if is_dataclass(value) and not isinstance(value, type):
        return _to_json(asdict(value))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise SerializationError("JSON object keys must be strings")
        return {key: _to_json(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        converted = [_to_json(item) for item in value]
        return sorted(converted, key=_stable_sort_key)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_to_json(item) for item in value]
    raise SerializationError(
        f"value of type {type(value).__name__} is not safely JSON serializable"
    )


def _from_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, list):
        return [_from_json(item) for item in value]
    if not isinstance(value, dict):
        raise SerializationError("decoded JSON contained an unsupported value")
    marker = value.get("$runmantle_type")
    if marker is None:
        return {str(key): _from_json(item) for key, item in value.items()}
    if marker == "bytes" and set(value) == {"$runmantle_type", "base64"}:
        try:
            return base64.b64decode(str(value["base64"]), validate=True)
        except (ValueError, binascii.Error) as error:
            raise SerializationError(
                "persisted bytes contain invalid base64"
            ) from error
    if marker == "datetime" and set(value) == {"$runmantle_type", "value"}:
        result = datetime.fromisoformat(str(value["value"]))
        if result.tzinfo is None or result.utcoffset() is None:
            raise SerializationError("persisted datetime is not timezone-aware")
        return result
    if marker == "timedelta" and set(value) == {"$runmantle_type", "seconds"}:
        return timedelta(seconds=float(value["seconds"]))
    if marker == "path" and set(value) == {"$runmantle_type", "value"}:
        return Path(str(value["value"]))
    raise SerializationError("persisted JSON contains an invalid type marker")


def _stable_sort_key(value: Any) -> str:
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _validate_decoded_shape(
    value: Any,
    *,
    max_depth: int,
    max_collection_items: int,
) -> None:
    """Reject resource-amplifying JSON before reconstructing supported types."""

    stack: list[tuple[Any, int]] = [(value, 1)]
    collection_items = 0
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise SerializationError("persisted value exceeds the maximum depth")
        if isinstance(item, dict):
            collection_items += len(item)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            collection_items += len(item)
            stack.extend((child, depth + 1) for child in item)
        if collection_items > max_collection_items:
            raise SerializationError(
                "persisted value exceeds the maximum collection item count"
            )
