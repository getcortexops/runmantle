"""SQLite outbox for at-least-once CortexOps event delivery."""

from __future__ import annotations

import json
import random
import sqlite3
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any, Protocol
from uuid import uuid4


class BatchEventExporter(Protocol):
    def export(self, event: Any) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class OutboxStatus(StrEnum):
    PENDING = "pending"
    DELIVERING = "delivering"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class CortexOpsDeliveryConfig:
    """Bounded retry and lease policy for one durable delivery outbox."""

    batch_size: int = 50
    max_attempts: int = 8
    base_backoff_seconds: float = 0.25
    max_backoff_seconds: float = 30.0
    jitter_ratio: float = 0.2
    lease_seconds: float = 30.0
    flush_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.batch_size < 1:
            raise ValueError("CortexOps delivery batch_size must be positive")
        if self.max_attempts < 1:
            raise ValueError("CortexOps delivery max_attempts must be positive")
        for name in (
            "base_backoff_seconds",
            "max_backoff_seconds",
            "lease_seconds",
            "flush_timeout_seconds",
        ):
            if float(getattr(self, name)) <= 0:
                raise ValueError(f"CortexOps delivery {name} must be positive")
        if self.max_backoff_seconds < self.base_backoff_seconds:
            raise ValueError("maximum backoff must not be less than base backoff")
        if not 0 <= self.jitter_ratio <= 1:
            raise ValueError("CortexOps delivery jitter_ratio must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    event_id: str
    status: OutboxStatus
    attempts: int
    created_at: datetime
    updated_at: datetime
    next_attempt_at: datetime
    delivered_at: datetime | None
    last_error_type: str | None
    last_error_message: str | None


@dataclass(frozen=True, slots=True)
class OutboxStats:
    pending: int
    delivering: int
    delivered: int
    dead_letter: int


class CortexOpsOutboxError(RuntimeError):
    """Base error for durable CortexOps delivery."""


class CortexOpsOutboxConflictError(CortexOpsOutboxError):
    """A stable event ID was reused for different serialized content."""


class CortexOpsOutboxFlushError(CortexOpsOutboxError):
    """Flush could not deliver every retained event within its bound."""


Clock = Callable[[], datetime]
RandomValue = Callable[[], float]
Sleeper = Callable[[float], None]


class DurableCortexOpsOutboxExporter:
    """Persist SDK documents before attempting at-least-once delivery.

    A successful downstream return followed by a process crash may cause a
    duplicate delivery. Stable event IDs let CortexOps deduplicate that replay.
    """

    _SCHEMA_VERSION = 1

    def __init__(
        self,
        path: str | Path,
        exporter: BatchEventExporter,
        *,
        delivery: CortexOpsDeliveryConfig | None = None,
        instance_id: str | None = None,
        clock: Clock | None = None,
        random_value: RandomValue = random.random,
        sleeper: Sleeper = time.sleep,
        busy_timeout_ms: int = 5000,
    ) -> None:
        self.path = Path(path)
        self.exporter = exporter
        self.delivery = delivery or CortexOpsDeliveryConfig()
        self.instance_id = instance_id or f"outbox-{uuid4()}"
        self._clock = clock or (lambda: datetime.now(UTC))
        self._random_value = random_value
        self._sleeper = sleeper
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = Lock()
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def export(self, event: Any) -> None:
        self.export_batch([event])

    def export_batch(self, events: list[Any]) -> None:
        self._require_open()
        documents = [_document(item) for item in events]
        if not documents:
            return
        with self._lock:
            self._enqueue(documents)
            self._drain_ready(max_batches=1)

    def flush(self) -> None:
        self._require_open()
        deadline = time.monotonic() + self.delivery.flush_timeout_seconds
        with self._lock:
            while True:
                self._drain_ready()
                stats = self.stats()
                if stats.pending == 0 and stats.delivering == 0:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CortexOpsOutboxFlushError(
                        "CortexOps outbox flush timed out with "
                        f"{stats.pending + stats.delivering} retained event(s)"
                    )
                wait = min(self._seconds_until_next_attempt(), remaining, 0.25)
                self._sleeper(max(0.001, wait))
            self.exporter.flush()
            if stats.dead_letter:
                raise CortexOpsOutboxFlushError(
                    "CortexOps outbox contains "
                    f"{stats.dead_letter} dead-letter event(s)"
                )

    def close(self) -> None:
        if self._closed:
            return
        failure: Exception | None = None
        try:
            self.flush()
        except Exception as error:  # noqa: BLE001 - close still releases delegate
            failure = error
        try:
            self.exporter.close()
        except Exception as error:  # noqa: BLE001 - preserve first failure
            if failure is None:
                failure = error
        self._closed = True
        if failure is not None:
            raise failure

    def stats(self) -> OutboxStats:
        with self._connect() as connection:
            counts = {
                str(row["status"]): int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count "
                    "FROM outbox_events GROUP BY status"
                ).fetchall()
            }
        return OutboxStats(
            pending=counts.get(OutboxStatus.PENDING.value, 0),
            delivering=counts.get(OutboxStatus.DELIVERING.value, 0),
            delivered=counts.get(OutboxStatus.DELIVERED.value, 0),
            dead_letter=counts.get(OutboxStatus.DEAD_LETTER.value, 0),
        )

    def records(
        self,
        *,
        status: OutboxStatus | None = None,
    ) -> tuple[OutboxRecord, ...]:
        query = "SELECT * FROM outbox_events"
        parameters: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            parameters = (status.value,)
        query += " ORDER BY created_at, event_id"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(_record(dict(row)) for row in rows)

    def dead_letters(self) -> tuple[OutboxRecord, ...]:
        return self.records(status=OutboxStatus.DEAD_LETTER)

    def retry_dead_letters(self, event_ids: Sequence[str] | None = None) -> int:
        now = _iso(self._clock())
        with self._transaction() as connection:
            if event_ids is None:
                cursor = connection.execute(
                    """
                    UPDATE outbox_events
                    SET status = ?, attempts = 0, next_attempt_at = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        updated_at = ?
                    WHERE status = ?
                    """,
                    (
                        OutboxStatus.PENDING.value,
                        now,
                        now,
                        OutboxStatus.DEAD_LETTER.value,
                    ),
                )
            else:
                identifiers = tuple(event_ids)
                if not identifiers:
                    return 0
                placeholders = ",".join("?" for _ in identifiers)
                cursor = connection.execute(
                    f"""
                    UPDATE outbox_events
                    SET status = ?, attempts = 0, next_attempt_at = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        updated_at = ?
                    WHERE status = ? AND event_id IN ({placeholders})
                    """,
                    (
                        OutboxStatus.PENDING.value,
                        now,
                        now,
                        OutboxStatus.DEAD_LETTER.value,
                        *identifiers,
                    ),
                )
        return int(cursor.rowcount)

    def _initialize(self) -> None:
        with self._connect() as connection:
            version_row = connection.execute("PRAGMA user_version").fetchone()
            version = int(version_row[0]) if version_row is not None else 0
            if version not in {0, self._SCHEMA_VERSION}:
                raise CortexOpsOutboxError(
                    f"unsupported CortexOps outbox schema version {version}"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS outbox_events (
                    event_id TEXT PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    last_error_type TEXT,
                    last_error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    delivered_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_delivery
                    ON outbox_events(status, next_attempt_at, created_at);
                """
            )
            connection.execute(f"PRAGMA user_version = {self._SCHEMA_VERSION}")

    def _enqueue(self, documents: list[dict[str, Any]]) -> None:
        now = _iso(self._clock())
        with self._transaction() as connection:
            for document in documents:
                event_id = str(document["event_id"])
                encoded = json.dumps(
                    document,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                existing = connection.execute(
                    "SELECT event_json FROM outbox_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing["event_json"]) != encoded:
                        raise CortexOpsOutboxConflictError(
                            f"CortexOps event ID {event_id!r} has conflicting content"
                        )
                    continue
                connection.execute(
                    """
                    INSERT INTO outbox_events(
                        event_id, event_json, status, next_attempt_at,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        encoded,
                        OutboxStatus.PENDING.value,
                        now,
                        now,
                        now,
                    ),
                )

    def _drain_ready(self, *, max_batches: int | None = None) -> int:
        delivered = 0
        batches = 0
        while max_batches is None or batches < max_batches:
            claimed = self._claim_batch()
            if not claimed:
                break
            batches += 1
            documents = [item[1] for item in claimed]
            try:
                batch_export = getattr(self.exporter, "export_batch", None)
                if callable(batch_export):
                    batch_export(documents)
                else:
                    for document in documents:
                        self.exporter.export(document)
            except Exception as error:  # noqa: BLE001 - retained for retry
                self._record_batch_failure(claimed, error)
            else:
                self._record_batch_success(claimed)
                delivered += len(claimed)
        return delivered

    def _claim_batch(self) -> list[tuple[OutboxRecord, dict[str, Any]]]:
        now = self._clock()
        lease_until = now + timedelta(seconds=self.delivery.lease_seconds)
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM outbox_events
                WHERE (
                    status = ? AND next_attempt_at <= ?
                ) OR (
                    status = ? AND lease_expires_at <= ?
                )
                ORDER BY created_at, event_id
                LIMIT ?
                """,
                (
                    OutboxStatus.PENDING.value,
                    _iso(now),
                    OutboxStatus.DELIVERING.value,
                    _iso(now),
                    self.delivery.batch_size,
                ),
            ).fetchall()
            claimed: list[tuple[OutboxRecord, dict[str, Any]]] = []
            for row in rows:
                attempts = int(row["attempts"]) + 1
                connection.execute(
                    """
                    UPDATE outbox_events
                    SET status = ?, attempts = ?, lease_owner = ?,
                        lease_expires_at = ?, updated_at = ?
                    WHERE event_id = ?
                    """,
                    (
                        OutboxStatus.DELIVERING.value,
                        attempts,
                        self.instance_id,
                        _iso(lease_until),
                        _iso(now),
                        str(row["event_id"]),
                    ),
                )
                values = dict(row)
                values.update(
                    {
                        "status": OutboxStatus.DELIVERING.value,
                        "attempts": attempts,
                        "updated_at": _iso(now),
                    }
                )
                document = json.loads(str(row["event_json"]))
                if not isinstance(document, dict):
                    raise CortexOpsOutboxError(
                        "persisted outbox event is not an object"
                    )
                claimed.append((_record(values), document))
        return claimed

    def _record_batch_success(
        self,
        claimed: list[tuple[OutboxRecord, dict[str, Any]]],
    ) -> None:
        now = _iso(self._clock())
        with self._transaction() as connection:
            for record, _ in claimed:
                connection.execute(
                    """
                    UPDATE outbox_events
                    SET status = ?, delivered_at = ?, updated_at = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        last_error_type = NULL, last_error_message = NULL
                    WHERE event_id = ? AND status = ? AND lease_owner = ?
                    """,
                    (
                        OutboxStatus.DELIVERED.value,
                        now,
                        now,
                        record.event_id,
                        OutboxStatus.DELIVERING.value,
                        self.instance_id,
                    ),
                )

    def _record_batch_failure(
        self,
        claimed: list[tuple[OutboxRecord, dict[str, Any]]],
        error: Exception,
    ) -> None:
        now = self._clock()
        with self._transaction() as connection:
            for record, _ in claimed:
                dead = record.attempts >= self.delivery.max_attempts
                delay = self._retry_delay(record.attempts)
                connection.execute(
                    """
                    UPDATE outbox_events
                    SET status = ?, next_attempt_at = ?, updated_at = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        last_error_type = ?, last_error_message = ?
                    WHERE event_id = ? AND status = ? AND lease_owner = ?
                    """,
                    (
                        (
                            OutboxStatus.DEAD_LETTER.value
                            if dead
                            else OutboxStatus.PENDING.value
                        ),
                        _iso(now + timedelta(seconds=delay)),
                        _iso(now),
                        type(error).__name__,
                        _safe_error_message(error),
                        record.event_id,
                        OutboxStatus.DELIVERING.value,
                        self.instance_id,
                    ),
                )

    def _retry_delay(self, attempts: int) -> float:
        unjittered = min(
            self.delivery.max_backoff_seconds,
            self.delivery.base_backoff_seconds * (2 ** max(0, attempts - 1)),
        )
        jitter = unjittered * self.delivery.jitter_ratio * self._random_value()
        return float(min(self.delivery.max_backoff_seconds, unjittered + jitter))

    def _seconds_until_next_attempt(self) -> float:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT MIN(next_attempt_at) AS next_attempt_at
                FROM outbox_events WHERE status = ?
                """,
                (OutboxStatus.PENDING.value,),
            ).fetchone()
        if row is None or row["next_attempt_at"] is None:
            return 0.01
        next_attempt = _datetime(str(row["next_attempt_at"]))
        return max(0.0, (next_attempt - self._clock()).total_seconds())

    def _require_open(self) -> None:
        if self._closed:
            raise CortexOpsOutboxError("CortexOps outbox exporter is closed")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self._busy_timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _document(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("CortexOps outbox event must be a mapping or expose to_dict()")
    document = dict(value)
    event_id = document.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("CortexOps outbox event_id must be a non-empty string")
    return document


def _record(row: Mapping[str, Any]) -> OutboxRecord:
    return OutboxRecord(
        event_id=str(row["event_id"]),
        status=OutboxStatus(str(row["status"])),
        attempts=int(row["attempts"]),
        created_at=_datetime(str(row["created_at"])),
        updated_at=_datetime(str(row["updated_at"])),
        next_attempt_at=_datetime(str(row["next_attempt_at"])),
        delivered_at=(
            None
            if row.get("delivered_at") is None
            else _datetime(str(row["delivered_at"]))
        ),
        last_error_type=_optional_string(row.get("last_error_type")),
        last_error_message=_optional_string(row.get("last_error_message")),
    )


def _datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise CortexOpsOutboxError("outbox timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("CortexOps outbox clock must return an aware datetime")
    return value.astimezone(UTC).isoformat()


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(value)


def _safe_error_message(error: Exception) -> str:
    # Transport exception messages commonly contain URLs, headers, or response
    # bodies. Persist a diagnostic class only; applications can log richer
    # details at their own explicitly configured boundary.
    return type(error).__name__


__all__ = [
    "CortexOpsDeliveryConfig",
    "CortexOpsOutboxConflictError",
    "CortexOpsOutboxError",
    "CortexOpsOutboxFlushError",
    "DurableCortexOpsOutboxExporter",
    "OutboxRecord",
    "OutboxStats",
    "OutboxStatus",
]
