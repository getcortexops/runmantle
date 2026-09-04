"""Framework-neutral agent tool discovery and conservative classification."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from threading import RLock
from typing import Any, Protocol

from ._validation import require_non_empty
from .contracts import RiskLevel


@dataclass(frozen=True, slots=True)
class DiscoveredTool:
    """Raw framework adapter output before RunMantle classification."""

    name: str
    provider: str
    framework: str
    discovery_source: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "tool name")
        require_non_empty(self.provider, "tool provider")
        require_non_empty(self.framework, "tool framework")
        require_non_empty(self.discovery_source, "tool discovery source")
        object.__setattr__(self, "input_schema", dict(self.input_schema))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """Normalized RunMantle view of one tool exposed by an agent runtime."""

    name: str
    provider: str
    framework: str
    capability: str
    risk_level: RiskLevel
    side_effecting: bool
    discovery_source: str
    classification_confidence: float
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "tool name")
        require_non_empty(self.provider, "tool provider")
        require_non_empty(self.framework, "tool framework")
        require_non_empty(self.capability, "tool capability")
        require_non_empty(self.discovery_source, "tool discovery source")
        if not 0 <= self.classification_confidence <= 1:
            raise ValueError("classification confidence must be between zero and one")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def read_only(self) -> bool:
        """Whether observation without pre-execution governance is safe."""

        return not self.side_effecting

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "framework": self.framework,
            "capability": self.capability,
            "risk_level": self.risk_level.value,
            "read_only": self.read_only,
            "side_effecting": self.side_effecting,
            "discovery_source": self.discovery_source,
            "classification_confidence": self.classification_confidence,
        }


class ToolDiscoveryAdapter(Protocol):
    """Framework-specific boundary that enumerates currently exposed tools."""

    def discover_tools(self) -> Iterable[DiscoveredTool]:
        """Return a coherent snapshot of tools exposed by the runtime."""


class ToolDiscoveryError(RuntimeError):
    """The runtime's tool registry could not be read safely."""


@dataclass(frozen=True, slots=True)
class _Rule:
    capability: str
    risk_level: RiskLevel
    side_effecting: bool
    patterns: tuple[str, ...]
    confidence: float = 0.9


# Mutating rules intentionally precede read rules. A tool described as supporting
# both reads and writes is governed as a writer, preventing broad clients such as
# generic SQL or HTTP tools from receiving a read-only classification.
_RULES = (
    _Rule(
        "infrastructure.modify",
        RiskLevel.CRITICAL,
        True,
        (
            r"\b(terraform|kubectl|infrastructure|cloudformation)\b",
            r"\b(deploy|provision|scale|restart_service|destroy_stack)\b",
        ),
    ),
    _Rule(
        "email.send",
        RiskLevel.HIGH,
        True,
        (r"\b(send|reply|forward|compose)[_ ]?(email|mail)\b", r"\bemail[_ ]?send\b"),
    ),
    _Rule(
        "database.write",
        RiskLevel.HIGH,
        True,
        (
            r"\b(database|db|sql)[_ ]?(write|execute|mutate|insert|update|delete)\b",
            r"\b(insert|update|delete|upsert)[_ ]?(row|record|query|sql)?\b",
        ),
    ),
    _Rule(
        "filesystem.write",
        RiskLevel.HIGH,
        True,
        (
            r"\b(write|edit|patch|delete|remove|move|rename|copy|upload)"
            r"[_ ]?(file|directory|path)?\b",
            r"\b(file|filesystem)[_ ]?(write|edit|delete|remove|move|upload)\b",
            r"\b(create|make)[_ ]?(file|directory|folder)\b",
        ),
    ),
    _Rule(
        "shell.execute",
        RiskLevel.HIGH,
        True,
        (
            r"\b(shell|terminal|command|subprocess)[_ ]?(execute|exec|run)?\b",
            r"\b(execute|run)[_ ]?(code|command|process|script)\b",
            r"\bprocess\b",
        ),
    ),
    _Rule(
        "network.request",
        RiskLevel.HIGH,
        True,
        (
            r"\b(http|network|api)[_ ]?(request|call|client)\b",
            r"\b(browser)[_ ]?(click|type|submit|interact)\b",
            r"\b(download|upload)[_ ]?(url|http|network)?\b",
        ),
    ),
    _Rule(
        "external_api.mutate",
        RiskLevel.HIGH,
        True,
        (
            r"\b(create|update|delete|publish|send|submit|approve|reject|cancel|trigger)"
            r"[_ ]?(issue|ticket|message|post|event|job|task|release|reaction|"
            r"playlist)?\b",
            r"\b(turn_on|turn_off|set_state|add_reaction|play|pause|skip_track)\b",
        ),
        0.75,
    ),
    _Rule(
        "database.read",
        RiskLevel.LOW,
        False,
        (
            r"\b(database|db|sql)[_ ]?(read|select|search|inspect)\b",
            r"\b(select|read)[_ ]?(row|record|query)\b",
        ),
    ),
    _Rule(
        "filesystem.read",
        RiskLevel.LOW,
        False,
        (
            r"\b(read|list|search|find|grep|glob|inspect)"
            r"[_ ]?(file|files|directory|path|filesystem)\b",
            r"\b(file|filesystem)[_ ]?(read|list|search|inspect)\b",
        ),
    ),
    _Rule(
        "network.request",
        RiskLevel.LOW,
        False,
        (
            r"\b(web|internet|network)[_ ]?(search|read|fetch|lookup)\b",
            r"\b(fetch|read|open)[_ ]?(url|page)\b",
        ),
    ),
)


def _normalize(value: str) -> str:
    value = value.lower()
    return re.sub(r"[^a-z0-9]+", "_", value).strip("_").replace("_", " ")


def _searchable_details(tool: DiscoveredTool) -> str:
    schema_description = tool.input_schema.get("description", "")
    toolset = tool.metadata.get("toolset", "")
    return _normalize(
        " ".join((tool.description, str(schema_description), str(toolset)))
    )


def _confidence(value: Any) -> float:
    if isinstance(value, str):
        named = {"low": 0.25, "medium": 0.6, "high": 1.0}
        if value.lower() in named:
            return named[value.lower()]
    result = float(value)
    if not 0 <= result <= 1:
        raise ValueError("classification confidence must be between zero and one")
    return result


def _boolean(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} classification override must be a boolean")
    return value


class ToolClassifier:
    """Classify by semantic capability, applying explicit operator overrides last."""

    def __init__(
        self, overrides: Mapping[str, Mapping[str, Any]] | None = None
    ) -> None:
        self._overrides = {
            str(name): dict(value)
            for name, value in (overrides or {}).items()
            if isinstance(value, Mapping)
        }

    def classify(self, tool: DiscoveredTool) -> ToolDescriptor:
        matched: _Rule | None = None
        confidence = 0.0
        # A registry name is a stronger semantic signal than prose, which often
        # mentions alternative tools (for example read_file says not to use cat).
        for searchable, confidence_ceiling in (
            (_normalize(tool.name), 1.0),
            (_searchable_details(tool), 0.7),
        ):
            matched = next(
                (
                    rule
                    for rule in _RULES
                    if any(
                        re.search(pattern, searchable) for pattern in rule.patterns
                    )
                ),
                None,
            )
            if matched is not None:
                confidence = min(matched.confidence, confidence_ceiling)
                break
        if matched is None:
            # Insufficient classification is itself a governance reason. The
            # conservative external mutation capability prevents silent bypass.
            descriptor = ToolDescriptor(
                name=tool.name,
                provider=tool.provider,
                framework=tool.framework,
                capability="external_api.mutate",
                risk_level=RiskLevel.HIGH,
                side_effecting=True,
                discovery_source=tool.discovery_source,
                classification_confidence=0,
                description=tool.description,
                metadata={**tool.metadata, "classification": "conservative_default"},
            )
        else:
            descriptor = ToolDescriptor(
                name=tool.name,
                provider=tool.provider,
                framework=tool.framework,
                capability=matched.capability,
                risk_level=matched.risk_level,
                side_effecting=matched.side_effecting,
                discovery_source=tool.discovery_source,
                classification_confidence=confidence,
                description=tool.description,
                metadata={**tool.metadata, "classification": "semantic_rule"},
            )
        return self._apply_override(descriptor)

    def _apply_override(self, descriptor: ToolDescriptor) -> ToolDescriptor:
        override = self._overrides.get(descriptor.name)
        classification_fields = {
            "provider",
            "framework",
            "capability",
            "risk_level",
            "side_effecting",
            "read_only",
            "classification_confidence",
        }
        if override is None or not classification_fields.intersection(override):
            return descriptor
        side_effecting = descriptor.side_effecting
        if "side_effecting" in override:
            side_effecting = _boolean(override["side_effecting"], "side_effecting")
        if "read_only" in override:
            read_only = _boolean(override["read_only"], "read_only")
            if "side_effecting" in override and side_effecting == read_only:
                raise ValueError(
                    "contradictory read_only and side_effecting override for "
                    f"{descriptor.name!r}"
                )
            side_effecting = not read_only
        return replace(
            descriptor,
            provider=str(override.get("provider") or descriptor.provider),
            framework=str(override.get("framework") or descriptor.framework),
            capability=str(override.get("capability") or descriptor.capability),
            risk_level=RiskLevel(
                str(override.get("risk_level") or descriptor.risk_level.value)
            ),
            side_effecting=side_effecting,
            classification_confidence=_confidence(
                override.get("classification_confidence", 1)
            ),
            metadata={**descriptor.metadata, "classification": "explicit_override"},
        )


class ToolInventory:
    """Atomic normalized snapshot populated by a framework discovery adapter."""

    def __init__(self, classifier: ToolClassifier | None = None) -> None:
        self.classifier = classifier or ToolClassifier()
        self._tools: dict[str, ToolDescriptor] = {}
        self._lock = RLock()

    def refresh(self, adapter: ToolDiscoveryAdapter) -> tuple[ToolDescriptor, ...]:
        classified: dict[str, ToolDescriptor] = {}
        try:
            discovered = adapter.discover_tools()
            for tool in discovered:
                descriptor = self.classifier.classify(tool)
                if descriptor.name in classified:
                    raise ToolDiscoveryError(
                        f"runtime exposed duplicate tool name {descriptor.name!r}"
                    )
                classified[descriptor.name] = descriptor
        except ToolDiscoveryError:
            raise
        except Exception as error:
            raise ToolDiscoveryError("runtime tool discovery failed") from error
        with self._lock:
            self._tools = classified
        return self.snapshot()

    def get(self, name: str) -> ToolDescriptor | None:
        with self._lock:
            return self._tools.get(name)

    def snapshot(self) -> tuple[ToolDescriptor, ...]:
        with self._lock:
            return tuple(self._tools[name] for name in sorted(self._tools))

    def classify_unknown(
        self,
        name: str,
        *,
        provider: str,
        framework: str,
        discovery_source: str,
    ) -> ToolDescriptor:
        """Fail closed for a tool observed at invocation but absent from discovery."""

        return self.classifier.classify(
            DiscoveredTool(
                name=name,
                provider=provider,
                framework=framework,
                discovery_source=discovery_source,
                metadata={"discovery_gap": True},
            )
        )


__all__ = [
    "DiscoveredTool",
    "ToolClassifier",
    "ToolDescriptor",
    "ToolDiscoveryAdapter",
    "ToolDiscoveryError",
    "ToolInventory",
]
