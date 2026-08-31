"""Small built-in providers for independently acquired outcome evidence."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from ._validation import require_non_empty
from .actions import ActionReceipt, ActionRequest
from .evidence import (
    Clock,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceTrustLevel,
    IdFactory,
    new_id,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class FileEvidenceProvider:
    """Inspect local file existence, content, size, and SHA-256 after an action."""

    path: str | Path
    evidence_type: str = "file_postcondition"
    include_content: bool = False
    source: str = "runmantle.file_evidence_provider"
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.RUNTIME_OBSERVED
    ttl: timedelta | None = None
    clock: Clock = field(default=utc_now, compare=False, repr=False)
    id_factory: IdFactory = field(default=new_id, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))
        require_non_empty(self.evidence_type, "file evidence_type")
        require_non_empty(self.source, "file evidence source")
        object.__setattr__(self, "trust_level", EvidenceTrustLevel(self.trust_level))
        if self.ttl is not None and self.ttl.total_seconds() <= 0:
            raise ValueError("file evidence ttl must be greater than zero")

    async def acquire(
        self,
        request: ActionRequest,
        receipt: ActionReceipt,
    ) -> EvidenceItem:
        observed = await asyncio.to_thread(self._inspect)
        collected_at = self.clock()
        content = observed.pop("content", None)
        return EvidenceItem(
            evidence_id=self.id_factory(),
            type=self.evidence_type,
            source=self.source,
            collected_at=collected_at,
            content=content,
            payload=observed,
            provenance={
                "provider": type(self).__name__,
                "action_id": request.action_id,
                "receipt_id": receipt.receipt_id,
                "path": str(self.path),
            },
            artifact_reference=str(self.path),
            acquisition_method=EvidenceAcquisitionMethod.FILESYSTEM_INSPECTION,
            trust_level=self.trust_level,
            expires_at=(collected_at + self.ttl if self.ttl is not None else None),
        )

    def _inspect(self) -> dict[str, Any]:
        path = Path(self.path)
        if not path.is_file():
            return {
                "exists": False,
                "path": str(path),
                "size": None,
                "sha256": None,
            }
        content = path.read_bytes()
        result: dict[str, Any] = {
            "exists": True,
            "path": str(path),
            "size": len(content),
            "sha256": f"sha256:{hashlib.sha256(content).hexdigest()}",
        }
        if self.include_content:
            result["content"] = content
        return result


CallableEvidenceValue = EvidenceItem | Mapping[str, Any] | str | bytes
CallableEvidenceFunction = Callable[
    [ActionRequest, ActionReceipt],
    CallableEvidenceValue | Awaitable[CallableEvidenceValue],
]


@dataclass(frozen=True, slots=True)
class CallableEvidenceProvider:
    """Adapt application-owned observation code to the evidence provider port."""

    provider: CallableEvidenceFunction = field(compare=False, repr=False)
    evidence_type: str = "callable_postcondition"
    source: str = "application.callable_evidence_provider"
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.RUNTIME_OBSERVED
    acquisition_method: EvidenceAcquisitionMethod = (
        EvidenceAcquisitionMethod.CALLABLE_PROVIDER
    )
    ttl: timedelta | None = None
    provenance: Mapping[str, Any] = field(default_factory=dict)
    clock: Clock = field(default=utc_now, compare=False, repr=False)
    id_factory: IdFactory = field(default=new_id, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not callable(self.provider):
            raise TypeError("callable evidence provider requires a callable")
        require_non_empty(self.evidence_type, "callable evidence_type")
        require_non_empty(self.source, "callable evidence source")
        object.__setattr__(self, "trust_level", EvidenceTrustLevel(self.trust_level))
        object.__setattr__(
            self,
            "acquisition_method",
            EvidenceAcquisitionMethod(self.acquisition_method),
        )
        object.__setattr__(self, "provenance", dict(self.provenance))
        if self.ttl is not None and self.ttl.total_seconds() <= 0:
            raise ValueError("callable evidence ttl must be greater than zero")

    async def acquire(
        self,
        request: ActionRequest,
        receipt: ActionReceipt,
    ) -> EvidenceItem:
        value = self.provider(request, receipt)
        if inspect.isawaitable(value):
            value = await value
        if isinstance(value, EvidenceItem):
            return value
        collected_at = self.clock()
        content: str | bytes | None = None
        payload: Mapping[str, Any] | None = None
        if isinstance(value, Mapping):
            payload = value
        elif isinstance(value, (str, bytes)):
            content = value
        else:
            raise TypeError("callable evidence provider returned an unsupported value")
        return EvidenceItem(
            evidence_id=self.id_factory(),
            type=self.evidence_type,
            source=self.source,
            collected_at=collected_at,
            content=content,
            payload=payload,
            provenance={
                **dict(self.provenance),
                "provider": type(self).__name__,
                "action_id": request.action_id,
                "receipt_id": receipt.receipt_id,
            },
            acquisition_method=self.acquisition_method,
            trust_level=self.trust_level,
            expires_at=(collected_at + self.ttl if self.ttl is not None else None),
        )


@dataclass(frozen=True, slots=True)
class ActionReceiptEvidenceProvider:
    """Convert an executor receipt to low-trust evidence without upgrading it."""

    evidence_type: str = "action_receipt"
    source: str = "runmantle.action_executor"
    clock: Clock = field(default=utc_now, compare=False, repr=False)
    id_factory: IdFactory = field(default=new_id, compare=False, repr=False)

    def __post_init__(self) -> None:
        require_non_empty(self.evidence_type, "receipt evidence_type")
        require_non_empty(self.source, "receipt evidence source")

    async def acquire(
        self,
        request: ActionRequest,
        receipt: ActionReceipt,
    ) -> EvidenceItem:
        return EvidenceItem(
            evidence_id=self.id_factory(),
            type=self.evidence_type,
            source=self.source,
            collected_at=self.clock(),
            payload={
                "action_id": receipt.action_id,
                "receipt_id": receipt.receipt_id,
                "executor_id": receipt.executor_id,
                "status": receipt.status.value,
                "action_hash": receipt.action_hash,
                "input_hash": receipt.input_hash,
                "idempotency_key": receipt.idempotency_key,
                "output": receipt.output,
                "output_hash": receipt.output_hash,
                "started_at": receipt.started_at,
                "finished_at": receipt.finished_at,
            },
            provenance={
                "provider": type(self).__name__,
                "action_id": request.action_id,
                "receipt_id": receipt.receipt_id,
            },
            acquisition_method=EvidenceAcquisitionMethod.EXECUTOR_REPORTED,
            trust_level=EvidenceTrustLevel.EXECUTOR_RECEIPT,
        )
