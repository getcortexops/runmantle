"""Durable, exact-hash-bound approval requests and decisions."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from ._validation import require_aware, require_non_empty_attributes
from .contracts import RiskLevel
from .serialization import SafeJsonCodec


class ApprovalState(StrEnum):
    """Authoritative durable state of one approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class ApproverIdentity:
    """Identity assertion supplied by an application authentication boundary.

    Runmantle persists this assertion but does not authenticate a human or service.
    """

    subject: str
    issuer: str
    authenticated_at: datetime
    authentication_method: str
    claims: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("subject", "issuer", "authentication_method"),
            prefix="approver identity",
        )
        require_aware(
            self.authenticated_at,
            "approver authenticated_at must be timezone-aware",
        )
        object.__setattr__(self, "claims", _freeze_mapping(self.claims))


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Immutable request bound to an exact action or recovery-plan hash."""

    approval_id: str
    task_id: str
    target_id: str
    target_hash: str
    required_scope: str
    risk_level: RiskLevel
    reason: str
    created_at: datetime
    expires_at: datetime
    one_time_use: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)
    request_hash: str = field(init=False)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            (
                "approval_id",
                "task_id",
                "target_id",
                "target_hash",
                "required_scope",
                "reason",
            ),
            prefix="approval request",
        )
        require_aware(self.created_at, "approval created_at must be timezone-aware")
        require_aware(self.expires_at, "approval expires_at must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("approval expiration must be after creation")
        metadata = _freeze_mapping(self.metadata)
        request_hash = _sha256(
            SafeJsonCodec().dumps(
                {
                    "approval_id": self.approval_id,
                    "task_id": self.task_id,
                    "target_id": self.target_id,
                    "target_hash": self.target_hash,
                    "required_scope": self.required_scope,
                    "risk_level": self.risk_level.value,
                    "reason": self.reason,
                    "created_at": self.created_at,
                    "expires_at": self.expires_at,
                    "one_time_use": self.one_time_use,
                    "metadata": metadata,
                }
            )
        )
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "request_hash", request_hash)


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """One immutable decision by an authenticated application principal."""

    decision_id: str
    approval_id: str
    request_hash: str
    approved: bool
    approver: ApproverIdentity
    decided_at: datetime
    reason: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("decision_id", "approval_id", "request_hash", "reason"),
            prefix="approval decision",
        )
        require_aware(self.decided_at, "approval decided_at must be timezone-aware")
        if self.decided_at < self.approver.authenticated_at:
            raise ValueError("approval decision predates authentication")
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class ApprovalRevocation:
    """Immutable revocation supplied by an authenticated application principal."""

    revocation_id: str
    approval_id: str
    request_hash: str
    revoked_by: ApproverIdentity
    revoked_at: datetime
    reason: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("revocation_id", "approval_id", "request_hash", "reason"),
            prefix="approval revocation",
        )
        require_aware(self.revoked_at, "approval revoked_at must be timezone-aware")
        if self.revoked_at < self.revoked_by.authenticated_at:
            raise ValueError("approval revocation predates authentication")
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class StoredApproval:
    """Complete authoritative snapshot of a persisted approval."""

    request: ApprovalRequest
    decision: ApprovalDecision | None
    revocation: ApprovalRevocation | None
    consumed_at: datetime | None
    consumed_by: str | None
    version: int

    def state_at(self, now: datetime) -> ApprovalState:
        require_aware(now, "approval evaluation time must be timezone-aware")
        if self.revocation is not None:
            return ApprovalState.REVOKED
        if self.request.expires_at <= now:
            return ApprovalState.EXPIRED
        if self.consumed_at is not None:
            return ApprovalState.CONSUMED
        if self.decision is None:
            return ApprovalState.PENDING
        return (
            ApprovalState.APPROVED if self.decision.approved else ApprovalState.REJECTED
        )

    def authorizes(self, *, request_hash: str, scope: str, now: datetime) -> bool:
        return (
            self.request.request_hash == request_hash
            and self.request.required_scope == scope
            and self.state_at(now) is ApprovalState.APPROVED
        )


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    encoded = SafeJsonCodec().dumps(dict(value))
    decoded = SafeJsonCodec().loads(encoded)
    if not isinstance(decoded, Mapping):
        raise TypeError("approval metadata must be a JSON object")
    return MappingProxyType(dict(decoded))
