"""Structured evidence models and in-memory collection."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator, Mapping
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from threading import Lock
from types import MappingProxyType
from typing import Any, Protocol, overload, runtime_checkable
from uuid import uuid4

from ._validation import require_aware, require_non_empty, require_unique
from .serialization import SafeJsonCodec

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]


class EvidenceIntegrityError(ValueError):
    """Raised when supplied or persisted evidence does not match its content."""


class EvidenceTrustLevel(IntEnum):
    """Ordered confidence assigned to how evidence was acquired."""

    UNTRUSTED = 0
    AGENT_CLAIM = 10
    EXECUTOR_RECEIPT = 20
    RUNTIME_OBSERVED = 30
    INDEPENDENT = 40


class EvidenceAcquisitionMethod(StrEnum):
    """Portable description of the mechanism that acquired evidence."""

    AGENT_REPORTED = "agent_reported"
    EXECUTOR_REPORTED = "executor_reported"
    RUNTIME_OBSERVED = "runtime_observed"
    FILESYSTEM_INSPECTION = "filesystem_inspection"
    CALLABLE_PROVIDER = "callable_provider"
    INDEPENDENT_PROVIDER = "independent_provider"


_TRUST_ORIGIN_TOKEN = object()


@dataclass(frozen=True, slots=True)
class EvidenceProviderRegistration:
    """Application-owned grant for one exact evidence provider instance.

    The stable identity and configuration are persisted with every item the
    framework accepts through this registration. Merely constructing an
    ``EvidenceItem`` with a high trust enum never creates such a grant.
    """

    provider: object = field(compare=False, repr=False)
    provider_identity: str
    provider_configuration: Mapping[str, Any]
    trust_level: EvidenceTrustLevel
    acquisition_method: EvidenceAcquisitionMethod

    def __post_init__(self) -> None:
        require_non_empty(self.provider_identity, "evidence provider identity")
        if self.trust_level <= EvidenceTrustLevel.AGENT_CLAIM:
            raise ValueError("trusted provider registration requires elevated trust")
        object.__setattr__(
            self,
            "provider_configuration",
            _freeze_mapping(self.provider_configuration),
        )
        object.__setattr__(self, "trust_level", EvidenceTrustLevel(self.trust_level))
        object.__setattr__(
            self,
            "acquisition_method",
            EvidenceAcquisitionMethod(self.acquisition_method),
        )


class EvidenceProviderRegistry:
    """Registry controlled by the runtime application, never exposed to workers."""

    def __init__(
        self,
        registrations: tuple[EvidenceProviderRegistration, ...] = (),
    ) -> None:
        self._registrations: dict[int, EvidenceProviderRegistration] = {}
        self._lock = Lock()
        self._sealed = False
        for registration in registrations:
            self.register(registration)

    def register(self, registration: EvidenceProviderRegistration) -> None:
        key = id(registration.provider)
        with self._lock:
            if self._sealed:
                raise RuntimeError("evidence provider registry is sealed")
            if key in self._registrations:
                raise ValueError("evidence provider instance is already registered")
            self._registrations[key] = registration

    def seal(self) -> None:
        """Prevent trust grants from changing after executor construction."""

        with self._lock:
            self._sealed = True

    def registration_for(
        self,
        provider: object,
        *,
        provider_identity: str,
        provider_configuration: Mapping[str, Any],
    ) -> EvidenceProviderRegistration | None:
        with self._lock:
            registration = self._registrations.get(id(provider))
        if registration is None:
            return None
        if registration.provider is not provider:
            return None
        if registration.provider_identity != provider_identity:
            raise EvidenceIntegrityError("registered provider identity changed")
        if SafeJsonCodec().dumps(
            registration.provider_configuration
        ) != SafeJsonCodec().dumps(provider_configuration):
            raise EvidenceIntegrityError("registered provider configuration changed")
        return registration

    def _establish(
        self,
        provider: object,
        item: EvidenceItem,
        *,
        boundary: str,
        provider_identity: str,
        provider_configuration: Mapping[str, Any],
    ) -> EvidenceItem | None:
        """Establish trust for an exact provider at an executor-only boundary."""

        registration = self.registration_for(
            provider,
            provider_identity=provider_identity,
            provider_configuration=provider_configuration,
        )
        if registration is None:
            return None
        return _establish_evidence_origin(
            item,
            boundary=boundary,
            provider_identity=registration.provider_identity,
            provider_configuration=registration.provider_configuration,
            trust_level=registration.trust_level,
            acquisition_method=registration.acquisition_method,
        )


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


def new_id() -> str:
    """Return the framework's default random identifier."""

    return str(uuid4())


def calculate_evidence_checksum(
    content: str | bytes | None,
    payload: Mapping[str, Any] | None,
) -> str:
    """Calculate the canonical SHA-256 checksum for evidence content."""

    encoded = SafeJsonCodec().dumps(
        {
            "content": content,
            "payload": payload,
        }
    )
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _calculate_origin_hash(
    *,
    evidence_id: str,
    evidence_type: str,
    source: str,
    collected_at: datetime,
    checksum: str,
    provenance: Mapping[str, Any],
    acquisition_method: EvidenceAcquisitionMethod,
    trust_level: EvidenceTrustLevel,
    expires_at: datetime | None,
    trust_origin: Mapping[str, Any],
) -> str:
    encoded = SafeJsonCodec().dumps(
        {
            "evidence_id": evidence_id,
            "type": evidence_type,
            "source": source,
            "collected_at": collected_at,
            "checksum": checksum,
            "provenance": provenance,
            "acquisition_method": acquisition_method.value,
            "trust_level": int(trust_level),
            "expires_at": expires_at,
            "trust_origin": trust_origin,
        }
    )
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _establish_evidence_origin(
    item: EvidenceItem,
    *,
    boundary: str,
    provider_identity: str,
    provider_configuration: Mapping[str, Any],
    trust_level: EvidenceTrustLevel,
    acquisition_method: EvidenceAcquisitionMethod,
) -> EvidenceItem:
    """Return an item whose trust was established at a framework boundary.

    This function is intentionally not part of the worker ``EvidenceCollector``
    API. Runtime integrations call it only after invoking the exact configured
    provider through a mediated postcondition boundary.
    """

    require_non_empty(boundary, "evidence trust boundary")
    require_non_empty(provider_identity, "evidence provider identity")
    normalized_trust = EvidenceTrustLevel(trust_level)
    if normalized_trust <= EvidenceTrustLevel.AGENT_CLAIM:
        raise ValueError("established evidence must have elevated trust")
    origin = {
        "schema_version": 1,
        "boundary": boundary,
        "provider_identity": provider_identity,
        "provider_configuration": dict(provider_configuration),
    }
    return EvidenceItem(
        evidence_id=item.evidence_id,
        type=item.type,
        source=item.source,
        collected_at=item.collected_at,
        content=item.content,
        payload=item.payload,
        provenance=item.provenance,
        artifact_reference=item.artifact_reference,
        checksum=item.checksum,
        metadata=item.metadata,
        acquisition_method=acquisition_method,
        trust_level=normalized_trust,
        expires_at=item.expires_at,
        _origin_token=_TRUST_ORIGIN_TOKEN,
        _established_origin=origin,
    )


def _restore_evidence_origin(
    *,
    origin_hash: str,
    trust_origin: Mapping[str, Any],
    **values: Any,
) -> EvidenceItem:
    """Rehydrate a persisted established origin after integrity validation."""

    return EvidenceItem(
        **values,
        _origin_token=_TRUST_ORIGIN_TOKEN,
        _established_origin=trust_origin,
        _established_origin_hash=origin_hash,
    )


def _as_agent_claim(item: EvidenceItem) -> EvidenceItem:
    """Strip caller-selected trust and any claimed acquisition classification."""

    return EvidenceItem(
        evidence_id=item.evidence_id,
        type=item.type,
        source=item.source,
        collected_at=item.collected_at,
        content=item.content,
        payload=item.payload,
        provenance=item.provenance,
        artifact_reference=item.artifact_reference,
        checksum=item.checksum,
        metadata=item.metadata,
        acquisition_method=EvidenceAcquisitionMethod.AGENT_REPORTED,
        trust_level=EvidenceTrustLevel.AGENT_CLAIM,
        expires_at=item.expires_at,
    )


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if any(not isinstance(key, str) for key in value):
        raise ValueError("evidence mapping keys must be strings")
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One attributable item offered as support for a reported outcome."""

    evidence_id: str
    type: str
    source: str
    collected_at: datetime
    content: str | bytes | None = None
    payload: Mapping[str, Any] | None = None
    provenance: Mapping[str, Any] = field(default_factory=dict)
    artifact_reference: str | None = None
    checksum: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    acquisition_method: EvidenceAcquisitionMethod = (
        EvidenceAcquisitionMethod.AGENT_REPORTED
    )
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.AGENT_CLAIM
    expires_at: datetime | None = None
    trust_origin: Mapping[str, Any] = field(default_factory=dict, init=False)
    origin_hash: str | None = field(default=None, init=False)
    _origin_token: InitVar[object | None] = None
    _established_origin: InitVar[Mapping[str, Any] | None] = None
    _established_origin_hash: InitVar[str | None] = None

    def __post_init__(
        self,
        _origin_token: object | None,
        _established_origin: Mapping[str, Any] | None,
        _established_origin_hash: str | None,
    ) -> None:
        require_non_empty(self.evidence_id, "evidence_id")
        require_non_empty(self.type, "evidence type")
        require_non_empty(self.source, "evidence source")
        require_aware(
            self.collected_at,
            "collected_at must include timezone information",
        )
        if self.content is None and self.payload is None:
            raise ValueError("evidence requires content or a structured payload")
        if self.artifact_reference is not None and not self.artifact_reference.strip():
            raise ValueError("artifact_reference must not be empty when provided")
        acquisition_method = EvidenceAcquisitionMethod(self.acquisition_method)
        trust_level = EvidenceTrustLevel(self.trust_level)
        if self.expires_at is not None:
            require_aware(
                self.expires_at,
                "evidence expiry must include timezone information",
            )
            if self.expires_at <= self.collected_at:
                raise ValueError("evidence expiry must be after collection")
        payload = None if self.payload is None else _freeze_mapping(self.payload)
        provenance = _freeze_mapping(self.provenance)
        metadata = _freeze_mapping(self.metadata)
        calculated = calculate_evidence_checksum(self.content, payload)
        if self.checksum is not None and self.checksum != calculated:
            raise EvidenceIntegrityError(
                "caller-provided evidence checksum does not match its content"
            )
        trusted_origin = _origin_token is _TRUST_ORIGIN_TOKEN
        origin = (
            _freeze_mapping(_established_origin or {})
            if trusted_origin
            else MappingProxyType({})
        )
        if trusted_origin and not origin:
            raise EvidenceIntegrityError("trusted evidence requires origin provenance")
        origin_hash = (
            _calculate_origin_hash(
                evidence_id=self.evidence_id,
                evidence_type=self.type,
                source=self.source,
                collected_at=self.collected_at,
                checksum=calculated,
                provenance=provenance,
                acquisition_method=acquisition_method,
                trust_level=trust_level,
                expires_at=self.expires_at,
                trust_origin=origin,
            )
            if trusted_origin
            else None
        )
        if (
            trusted_origin
            and _established_origin_hash is not None
            and _established_origin_hash != origin_hash
        ):
            raise EvidenceIntegrityError(
                "persisted evidence origin hash does not match"
            )
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "checksum", calculated)
        object.__setattr__(self, "acquisition_method", acquisition_method)
        object.__setattr__(self, "trust_level", trust_level)
        object.__setattr__(self, "trust_origin", origin)
        object.__setattr__(self, "origin_hash", origin_hash)

    @property
    def trust_established(self) -> bool:
        """Whether Runmantle established this item's elevated trust boundary."""

        return self.origin_hash is not None and bool(self.trust_origin)

    @property
    def effective_trust_level(self) -> EvidenceTrustLevel:
        """Trust usable by verification; caller-selected labels are claims only."""

        if self.trust_established:
            return self.trust_level
        return min(self.trust_level, EvidenceTrustLevel.AGENT_CLAIM)

    @property
    def kind(self) -> str:
        """Compatibility alias for the original evidence API."""

        return self.type

    @property
    def data(self) -> Mapping[str, Any]:
        """Return the structured payload, or a mapping around textual content."""

        if self.payload is not None:
            return self.payload
        return MappingProxyType({"content": self.content})

    @property
    def recorded_at(self) -> datetime:
        """Compatibility alias for collected_at."""

        return self.collected_at

    def is_fresh(self, at: datetime, *, max_age: timedelta | None = None) -> bool:
        """Return whether this evidence is valid at the requested decision time."""

        require_aware(at, "evidence decision time must be timezone-aware")
        if self.collected_at > at:
            return False
        if self.expires_at is not None and at >= self.expires_at:
            return False
        return max_age is None or at - self.collected_at <= max_age


# Compatibility name retained for callers of the initial API.
Evidence = EvidenceItem


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    """Evidence a contract requires before its outcome can be verified."""

    evidence_type: str
    description: str
    minimum_count: int = 1
    consistent_fields: tuple[str, ...] = ()
    minimum_trust_level: EvidenceTrustLevel = EvidenceTrustLevel.RUNTIME_OBSERVED
    max_age: timedelta | None = None

    def __post_init__(self) -> None:
        require_non_empty(self.evidence_type, "evidence_type")
        require_non_empty(self.description, "evidence requirement description")
        if self.minimum_count < 1:
            raise ValueError("minimum_count must be at least one")
        if any(not path.strip() for path in self.consistent_fields):
            raise ValueError("consistent field paths must not be empty")
        object.__setattr__(self, "consistent_fields", tuple(self.consistent_fields))
        object.__setattr__(
            self,
            "minimum_trust_level",
            EvidenceTrustLevel(self.minimum_trust_level),
        )
        if self.max_age is not None and self.max_age.total_seconds() <= 0:
            raise ValueError("evidence max_age must be greater than zero")

    @property
    def kind(self) -> str:
        """Compatibility alias for evidence_type."""

        return self.evidence_type

    def accepts(self, item: EvidenceItem, *, at: datetime) -> bool:
        """Apply type, trust, checksum, and freshness requirements."""

        return (
            item.type == self.evidence_type
            and item.effective_trust_level >= self.minimum_trust_level
            and item.is_fresh(at, max_age=self.max_age)
        )


@dataclass(frozen=True, slots=True)
class EvidenceCollection:
    """Immutable collection with stable evidence identifiers."""

    items: tuple[EvidenceItem, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        require_unique(
            (item.evidence_id for item in self.items),
            "evidence identifiers must be unique within a collection",
        )

    def __iter__(self) -> Iterator[EvidenceItem]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __bool__(self) -> bool:
        return bool(self.items)

    @overload
    def __getitem__(self, index: int) -> EvidenceItem: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[EvidenceItem, ...]: ...

    def __getitem__(
        self,
        index: int | slice,
    ) -> EvidenceItem | tuple[EvidenceItem, ...]:
        return self.items[index]

    def __add__(self, other: EvidenceCollection) -> EvidenceCollection:
        return EvidenceCollection(self.items + other.items)

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return next(
            (item for item in self.items if item.evidence_id == evidence_id),
            None,
        )

    def of_type(self, evidence_type: str) -> EvidenceCollection:
        return EvidenceCollection(
            tuple(item for item in self.items if item.type == evidence_type)
        )

    def append(self, item: EvidenceItem) -> EvidenceCollection:
        return EvidenceCollection((*self.items, item))


class EvidenceCollector(Protocol):
    """Port used by workers to record and retrieve evidence."""

    def record(
        self,
        evidence_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        content: str | bytes | None = None,
        source: str = "worker",
        provenance: Mapping[str, Any] | None = None,
        artifact_reference: str | None = None,
        checksum: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        acquisition_method: EvidenceAcquisitionMethod = (
            EvidenceAcquisitionMethod.AGENT_REPORTED
        ),
        trust_level: EvidenceTrustLevel = EvidenceTrustLevel.AGENT_CLAIM,
        expires_at: datetime | None = None,
        evidence_id: str | None = None,
    ) -> EvidenceItem:
        """Record one structured or textual evidence item."""

    def snapshot(self) -> EvidenceCollection:
        """Return an immutable view of all evidence recorded so far."""


@runtime_checkable
class ObservableEvidenceCollector(Protocol):
    """Optional collector extension for immediate evidence telemetry."""

    def add_listener(self, listener: Callable[[EvidenceItem], None]) -> None:
        """Subscribe to evidence recorded after this call."""


@dataclass(slots=True)
class InMemoryEvidenceCollector:
    """Thread-safe local collector with injectable identifiers and timestamps."""

    clock: Clock = utc_now
    id_factory: IdFactory = new_id
    on_record: Callable[[EvidenceItem], None] | None = None
    _items: list[EvidenceItem] = field(default_factory=list, init=False, repr=False)
    _listeners: list[Callable[[EvidenceItem], None]] = field(
        default_factory=list,
        init=False,
        repr=False,
    )
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def record(
        self,
        evidence_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        content: str | bytes | None = None,
        source: str = "worker",
        provenance: Mapping[str, Any] | None = None,
        artifact_reference: str | None = None,
        checksum: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        acquisition_method: EvidenceAcquisitionMethod = (
            EvidenceAcquisitionMethod.AGENT_REPORTED
        ),
        trust_level: EvidenceTrustLevel = EvidenceTrustLevel.AGENT_CLAIM,
        expires_at: datetime | None = None,
        evidence_id: str | None = None,
    ) -> EvidenceItem:
        del acquisition_method, trust_level
        item = EvidenceItem(
            evidence_id=evidence_id or self.id_factory(),
            type=evidence_type,
            content=content,
            payload=payload,
            source=source,
            collected_at=self.clock(),
            provenance=provenance or {},
            artifact_reference=artifact_reference,
            checksum=checksum,
            metadata=metadata or {},
            acquisition_method=EvidenceAcquisitionMethod.AGENT_REPORTED,
            trust_level=EvidenceTrustLevel.AGENT_CLAIM,
            expires_at=expires_at,
        )
        with self._lock:
            if any(
                existing.evidence_id == item.evidence_id for existing in self._items
            ):
                raise ValueError(f"duplicate evidence id {item.evidence_id!r}")
            self._items.append(item)
            listeners = tuple(self._listeners)
        if self.on_record is not None:
            self.on_record(item)
        for listener in listeners:
            listener(item)
        return item

    def snapshot(self) -> EvidenceCollection:
        with self._lock:
            return EvidenceCollection(tuple(self._items))

    def add_listener(self, listener: Callable[[EvidenceItem], None]) -> None:
        with self._lock:
            self._listeners.append(listener)
