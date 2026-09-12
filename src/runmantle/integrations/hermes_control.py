"""Fail-closed CortexOps approval transport for the Hermes plugin API.

Hermes owns execution and its approval gate.  This module only maps a single,
persisted Hermes gate request to an exact CortexOps approval and dispatch permit.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
import shutil
import sqlite3
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from runmantle.actions import ActionRequest
from runmantle.contracts import RiskLevel, TaskContract
from runmantle.evidence import (
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    _establish_evidence_origin,
)
from runmantle.integrations.cortexops_control import (
    CortexOpsControlClient,
    CortexOpsControlError,
    CortexOpsControlRejected,
    UrllibCortexOpsControlTransport,
    _digest,
)
from runmantle.telemetry import task_contract_telemetry
from runmantle.tool_discovery import (
    DiscoveredTool,
    ToolClassifier,
    ToolDescriptor,
    ToolDiscoveryError,
    ToolInventory,
)
from runmantle.verification import (
    FieldEqualsCriterion,
    RuleBasedVerifier,
    VerificationResult,
    VerificationStatus,
)
from runmantle.verified_action_cache import (
    CacheMatch,
    PreconditionResult,
    RecipeStep,
    ReuseRequest,
    VerificationEvidence,
    VerifiedActionCache,
    VerifiedActionRecipe,
)


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _same_hash(left: Any, right: Any) -> bool:
    return str(left).lower().removeprefix("sha256:") == str(right).lower().removeprefix(
        "sha256:"
    )


def _plain(value: Any) -> Any:
    """Return JSON-compatible recipe data without retaining live objects."""

    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    return value


def redact(value: Any, keys: frozenset[str]) -> Any:
    if isinstance(value, Mapping):
        return {
            str(k): (
                {"redacted_sha256": _hash({"value": str(v)})}
                if str(k).lower() in keys
                else redact(v, keys)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(item, keys) for item in value]
    return value


def _safe_replay_args(
    value: Mapping[str, Any], keys: frozenset[str]
) -> dict[str, Any] | None:
    """Return exact JSON replay arguments only when redaction changes nothing.

    A recipe that contains a secret-bearing field remains useful as a planning
    hint, but it is deliberately ineligible for model-free replay. This keeps
    authorization material out of the durable recipe while avoiding a lossy
    redacted replay that could target a different action.
    """

    plain = _plain(value)
    if not isinstance(plain, dict) or redact(plain, keys) != plain:
        return None
    try:
        encoded = json.dumps(
            plain,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict) or decoded != plain:
        return None
    return decoded


def _safe_usage_metadata(value: Any) -> str | None:
    """Keep only bounded, content-free model-cost metadata from Hermes hooks."""

    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:256] if value else None


_PARAMETER_KEY = "$runmantle_parameter"


def _string_leaves(value: Any) -> tuple[str, ...]:
    """Return distinct, non-empty JSON string leaves in stable order."""

    leaves: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, str) and item:
            leaves.append(item)
        elif isinstance(item, Mapping):
            for child in item.values():
                visit(child)
        elif isinstance(item, list | tuple):
            for child in item:
                visit(child)

    visit(value)
    return tuple(dict.fromkeys(leaves))


def _parameterized_recipe(
    intent: str, args: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Make a local, deterministic template from safe arguments in a request.

    The template never infers an argument: every substituted value must occur
    verbatim in the original user request, and the resulting template must
    later match the entire new request.  It is therefore safe to use before a
    model call while still permitting changed paths, IDs, content, and other
    JSON argument values for any governed Hermes tool.
    """

    if len(intent) > 100_000:
        return None
    candidates = tuple(
        value
        for value in _string_leaves(args)
        if len(value) <= 50_000 and value in intent
    )
    if not candidates:
        return None
    names = {value: f"p{index}" for index, value in enumerate(candidates)}
    ordered = tuple(sorted(candidates, key=lambda value: (-len(value), value)))
    segments: list[dict[str, str]] = []
    cursor = 0
    while cursor < len(intent):
        choices = [
            (intent.find(value, cursor), value)
            for value in ordered
            if intent.find(value, cursor) >= 0
        ]
        if not choices:
            segments.append({"literal": intent[cursor:]})
            break
        position, value = min(choices, key=lambda item: (item[0], -len(item[1])))
        if position > cursor:
            segments.append({"literal": intent[cursor:position]})
        segments.append({"parameter": names[value]})
        cursor = position + len(value)
    if cursor == len(intent):
        segments.append({"literal": ""})

    def parameterize(item: Any) -> Any:
        if isinstance(item, str) and item in names:
            return {_PARAMETER_KEY: names[item]}
        if isinstance(item, Mapping):
            return {str(key): parameterize(child) for key, child in item.items()}
        if isinstance(item, list | tuple):
            return [parameterize(child) for child in item]
        return item

    args_template = parameterize(args)
    if not isinstance(args_template, dict):
        return None
    return {
        "intent_segments": segments,
        "args_template": args_template,
        "args_template_hash": _hash({"args_template": args_template}),
    }


def _parameter_values(intent_segments: Any, intent: str) -> dict[str, str] | None:
    if not isinstance(intent_segments, (list, tuple)) or not intent_segments:
        return None
    pattern: list[str] = ["^"]
    seen: set[str] = set()
    for segment in intent_segments:
        if not isinstance(segment, Mapping) or len(segment) != 1:
            return None
        literal = segment.get("literal")
        parameter = segment.get("parameter")
        if isinstance(literal, str):
            pattern.append(re.escape(literal))
        elif isinstance(parameter, str) and re.fullmatch(r"p[0-9]+", parameter):
            if parameter in seen:
                pattern.append(f"(?P={parameter})")
            else:
                pattern.append(f"(?P<{parameter}>.+?)")
                seen.add(parameter)
        else:
            return None
    pattern.append("$")
    try:
        match = re.fullmatch("".join(pattern), intent, flags=re.DOTALL)
    except re.error:
        return None
    if match is None:
        return None
    values = {name: value for name, value in match.groupdict().items() if value}
    return values or None


def _bind_parameterized_value(value: Any, values: Mapping[str, str]) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {_PARAMETER_KEY} and isinstance(value[_PARAMETER_KEY], str):
            return values.get(value[_PARAMETER_KEY])
        return {
            str(key): _bind_parameterized_value(item, values)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_bind_parameterized_value(item, values) for item in value]
    return value


def _expected_leaves(
    value: Mapping[str, Any], prefix: str = ""
) -> list[tuple[str, Any]]:
    leaves: list[tuple[str, Any]] = []
    for key in sorted(value):
        path = f"{prefix}.{key}" if prefix else str(key)
        item = value[key]
        if isinstance(item, Mapping):
            leaves.extend(_expected_leaves(item, path))
        else:
            leaves.append((path, item))
    return leaves


def hermes_task_contract(
    task_id: str,
    session_id: str,
    *,
    capability: str,
    risk_level: RiskLevel,
    expected_state: Mapping[str, Any],
) -> TaskContract[dict[str, str], dict[str, bool]]:
    """Build the immutable task contract shared by the plugin and verifier."""

    evidence_type = "hermes_tool_runtime"
    criteria: list[Any] = [
        FieldEqualsCriterion(
            name="hermes_execution_reported",
            description="Hermes reported that the governed tool returned successfully.",
            field_path="executed",
            expected=True,
        )
    ]
    criteria.extend(
        FieldEqualsCriterion(
            name=f"postcondition_{path.replace('.', '_')}",
            description=f"The runtime probe must observe {path!r} exactly.",
            field_path=path,
            expected=expected,
            evidence_type=evidence_type,
        )
        for path, expected in _expected_leaves(expected_state)
    )
    return TaskContract(
        task_id=task_id,
        objective="Verify one CortexOps-governed Hermes tool action.",
        input={"session_id": session_id},
        acceptance_criteria=tuple(criteria),
        required_evidence=(
            EvidenceRequirement(
                evidence_type,
                "Fresh runtime observations from the deployment version and "
                "health probes.",
            ),
        ),
        allowed_capabilities=frozenset({capability}),
        risk_level=risk_level,
        timeout=timedelta(minutes=10),
        idempotency_key=f"hermes:{task_id}:verified-once",
        metadata={"runtime": "hermes", "session_id": session_id},
    )


@dataclass(frozen=True)
class HermesControlConfig:
    cortexops_url: str
    authorization: str | None
    runtime_id: str
    state_path: Path
    controlled_tools: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    post_action_probes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    decision_timeout_seconds: float = 5
    approval_timeout_seconds: float = 300
    approval_poll_initial_seconds: float = 0.25
    approval_poll_max_seconds: float = 2
    blocking_hook_approval: bool = False
    govern_read_only_tools: bool = False
    verified_action_cache_enabled: bool = True
    verified_action_cache_similarity_threshold: float = 0.8
    redact_keys: frozenset[str] = frozenset(
        {"authorization", "token", "secret", "password", "api_key"}
    )

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> HermesControlConfig:
        url = str(settings.get("cortexops_url") or "").rstrip("/")
        legacy_tools = settings.get("controlled_tools")
        configured_overrides = settings.get("classification_overrides")
        probes = settings.get("post_action_probes")
        if not url:
            raise ValueError("cortexops_url is required")
        overrides: dict[str, Mapping[str, Any]] = {}
        for configured in (legacy_tools, configured_overrides):
            if configured is None:
                continue
            if not isinstance(configured, Mapping):
                raise ValueError("tool classification overrides must be a mapping")
            for name, value in configured.items():
                if not isinstance(value, Mapping):
                    raise ValueError(
                        f"classification override for {name!r} must be a mapping"
                    )
                overrides[str(name)] = dict(value)
        initial, maximum = (
            float(settings.get("approval_poll_initial_seconds") or 0.25),
            float(settings.get("approval_poll_max_seconds") or 2),
        )
        if initial <= 0 or maximum < initial:
            raise ValueError("approval polling intervals must be positive and ordered")
        configured_cache_threshold = settings.get(
            "verified_action_cache_similarity_threshold"
        )
        cache_threshold = (
            0.8
            if configured_cache_threshold is None
            else float(configured_cache_threshold)
        )
        if not 0 <= cache_threshold <= 1:
            raise ValueError(
                "verified action cache similarity threshold must be between 0 and 1"
            )
        return cls(
            cortexops_url=url,
            authorization=settings.get("authorization"),
            runtime_id=str(settings.get("runtime_id") or "hermes"),
            state_path=Path(
                str(
                    settings.get("state_path") or "~/.hermes/runmantle-cortexops.sqlite"
                )
            ).expanduser(),
            controlled_tools=overrides,
            post_action_probes=probes if isinstance(probes, Mapping) else {},
            decision_timeout_seconds=float(
                settings.get("decision_timeout_seconds") or 5
            ),
            approval_timeout_seconds=float(
                settings.get("approval_timeout_seconds") or 300
            ),
            approval_poll_initial_seconds=initial,
            approval_poll_max_seconds=maximum,
            blocking_hook_approval=settings.get("blocking_hook_approval") is True,
            govern_read_only_tools=settings.get("govern_read_only_tools") is True,
            verified_action_cache_enabled=(
                settings.get("verified_action_cache_enabled") is not False
            ),
            verified_action_cache_similarity_threshold=cache_threshold,
            redact_keys=(
                frozenset(str(v).lower() for v in (settings.get("redact_keys") or []))
                or cls.redact_keys
            ),
        )


@dataclass(frozen=True)
class _HermesProbeVerification:
    result: VerificationResult
    evidence: EvidenceItem
    contract: TaskContract[dict[str, str], dict[str, bool]]


@dataclass(frozen=True)
class _HermesRecipePreconditionValidator:
    """Validate current Hermes call facts before treating a recipe as reused."""

    tool: ToolDescriptor
    args_hash: str
    probe_hash: str
    args_template_hash: str | None = None

    def validate(
        self, recipe: VerifiedActionRecipe, request: ReuseRequest
    ) -> Sequence[PreconditionResult]:
        del request
        expected = recipe.preconditions
        checks = (
            (
                "tool",
                expected.get("tool") == self.tool.name,
                "the currently selected Hermes tool matches the recipe",
            ),
            (
                "capability",
                expected.get("capability") == self.tool.capability,
                "the freshly classified capability matches the recipe",
            ),
            (
                "tool_descriptor",
                expected.get("tool_descriptor_hash")
                == _hash({"descriptor": self.tool.as_dict()}),
                "the freshly discovered tool descriptor matches the recipe",
            ),
            (
                "arguments",
                expected.get("args_hash") == self.args_hash
                or (
                    self.args_template_hash is not None
                    and expected.get("args_template_hash") == self.args_template_hash
                ),
                "the current argument identity or verified template matches the recipe",
            ),
            (
                "verification_probe",
                expected.get("probe_hash") == self.probe_hash,
                "the current runtime verification probe matches the recipe",
            ),
        )
        return tuple(
            PreconditionResult(
                name=name,
                passed=passed,
                message=message
                if passed
                else message.replace("matches", "changed from"),
            )
            for name, passed, message in checks
        )


class HermesToolDiscoveryAdapter:
    """Read registered tools from Hermes's live, profile-scoped registry."""

    def __init__(self, registry: Any | None = None) -> None:
        self._registry = registry

    def _active_registry(self) -> Any:
        if self._registry is not None:
            return self._registry
        try:
            return importlib.import_module("tools.registry").registry
        except (AttributeError, ImportError) as error:
            raise ToolDiscoveryError("Hermes tool registry is unavailable") from error

    def discover_tools(self) -> tuple[DiscoveredTool, ...]:
        registry = self._active_registry()
        try:
            entries = tuple(registry.get_all_entries())
        except Exception as error:
            raise ToolDiscoveryError("Hermes tool registry discovery failed") from error

        tools: list[DiscoveredTool] = []
        for entry in entries:
            schema = entry.schema if isinstance(entry.schema, Mapping) else {}
            handler_module = str(getattr(entry.handler, "__module__", "") or "")
            provider = (
                handler_module.split(".", 2)[1]
                if handler_module.startswith("hermes_plugins.")
                else "hermes"
            )
            description = str(
                getattr(entry, "description", "") or schema.get("description") or ""
            )
            tools.append(
                DiscoveredTool(
                    name=str(entry.name),
                    provider=provider,
                    framework="hermes",
                    discovery_source="hermes.tool_registry",
                    description=description,
                    input_schema=schema,
                    metadata={
                        "toolset": str(getattr(entry, "toolset", "") or ""),
                        "handler_module": handler_module,
                    },
                )
            )
        return tuple(tools)


class HermesControlAdapter:
    """Durable, one-decision-per-Hermes-call CortexOps mediator."""

    _RULE_PREFIX = "plugin_rule:cortexops:"

    def __init__(
        self,
        config: HermesControlConfig,
        tool_discovery: HermesToolDiscoveryAdapter | None = None,
    ) -> None:
        self.config = config
        self.client = CortexOpsControlClient(
            UrllibCortexOpsControlTransport(
                config.cortexops_url,
                lambda: config.authorization,
                config.decision_timeout_seconds,
            ),
            config.runtime_id,
            "hermes-plugin-v1",
        )
        self._lock = threading.RLock()
        self._cache = VerifiedActionCache(
            similarity_threshold=config.verified_action_cache_similarity_threshold
        )
        self._tool_discovery = tool_discovery or HermesToolDiscoveryAdapter()
        self.tool_inventory = ToolInventory(ToolClassifier(config.controlled_tools))
        self._refresh_tools()
        config.state_path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS hermes_actions (
                tool_call_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL, action_hash TEXT NOT NULL,
                decision_id TEXT NOT NULL, decision_json TEXT NOT NULL,
                request_json TEXT NOT NULL, approval_id TEXT,
                hermes_request_id TEXT, hermes_request_digest TEXT,
                state TEXT NOT NULL DEFAULT 'evaluated', dispatch_attempt_id TEXT,
                receipt_json TEXT, receipt_delivered INTEGER NOT NULL DEFAULT 0,
                confirmation_delivered INTEGER NOT NULL DEFAULT 0)""")
            existing_columns = {
                str(row[1])
                for row in db.execute("PRAGMA table_info(hermes_actions)").fetchall()
            }
            for column, declaration in (
                ("run_id", "TEXT"),
                ("cache_status", "TEXT"),
                ("recipe_id", "TEXT"),
                ("match_type", "TEXT"),
                ("match_confidence", "REAL"),
                ("validation_json", "TEXT"),
                ("verification_status", "TEXT"),
                ("verification_hash", "TEXT"),
                ("evidence_json", "TEXT"),
            ):
                if column not in existing_columns:
                    db.execute(
                        f"ALTER TABLE hermes_actions ADD COLUMN {column} {declaration}"
                    )
            db.execute("""CREATE TABLE IF NOT EXISTS hermes_cache_runs (
                run_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                turn_id TEXT NOT NULL,
                task_intent TEXT NOT NULL,
                candidate_recipe_id TEXT,
                match_type TEXT,
                match_confidence REAL,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                usage_observed INTEGER NOT NULL DEFAULT 0,
                estimated_cost_usd REAL,
                cost_complete INTEGER NOT NULL DEFAULT 1,
                provider TEXT,
                model TEXT,
                cost_status TEXT,
                cost_source TEXT,
                lookup_completed INTEGER NOT NULL DEFAULT 0,
                finalized INTEGER NOT NULL DEFAULT 0)""")
            db.execute("""CREATE TABLE IF NOT EXISTS hermes_api_usage (
                api_request_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                estimated_cost_usd REAL,
                provider TEXT,
                model TEXT,
                cost_status TEXT,
                cost_source TEXT)""")
            for table, columns in {
                "hermes_cache_runs": {
                    "estimated_cost_usd": "REAL",
                    "cost_complete": "INTEGER NOT NULL DEFAULT 1",
                    "provider": "TEXT",
                    "model": "TEXT",
                    "cost_status": "TEXT",
                    "cost_source": "TEXT",
                },
                "hermes_api_usage": {
                    "estimated_cost_usd": "REAL",
                    "provider": "TEXT",
                    "model": "TEXT",
                    "cost_status": "TEXT",
                    "cost_source": "TEXT",
                },
            }.items():
                existing_columns = {
                    str(row[1]) for row in db.execute(f"PRAGMA table_info({table})")
                }
                for column, declaration in columns.items():
                    if column not in existing_columns:
                        db.execute(
                            f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
                        )
            db.execute("""CREATE TABLE IF NOT EXISTS hermes_verified_recipes (
                recipe_id TEXT PRIMARY KEY,
                recipe_json TEXT NOT NULL,
                stored_at TEXT NOT NULL)""")
        self._hydrate_cache()

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.config.state_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _run_id(values: Mapping[str, Any]) -> str:
        return str(values.get("turn_id") or values.get("task_id") or "")

    @staticmethod
    def _recipe_document(recipe: VerifiedActionRecipe) -> dict[str, Any]:
        return {
            "recipe_id": recipe.recipe_id,
            "normalized_task_intent": recipe.normalized_task_intent,
            "tool_capability_sequence": [
                {
                    "tool": step.tool,
                    "capability": step.capability,
                    "side_effecting": step.side_effecting,
                }
                for step in recipe.tool_capability_sequence
            ],
            "relevant_inputs": _plain(recipe.relevant_inputs),
            "preconditions": _plain(recipe.preconditions),
            "execution_strategy": _plain(recipe.execution_strategy),
            "expected_outcome": _plain(recipe.expected_outcome),
            "verification_evidence": [
                {"summary": item.summary, "reference": item.reference}
                for item in recipe.verification_evidence
            ],
            "recipe_version": recipe.recipe_version,
            "source_task_id": recipe.source_task_id,
            "source_run_id": recipe.source_run_id,
            "original_token_usage": recipe.original_token_usage,
            "successful": recipe.successful,
            "verified": recipe.verified,
        }

    @staticmethod
    def _recipe_from_document(value: Mapping[str, Any]) -> VerifiedActionRecipe:
        return VerifiedActionRecipe(
            recipe_id=str(value["recipe_id"]),
            normalized_task_intent=str(value["normalized_task_intent"]),
            tool_capability_sequence=tuple(
                RecipeStep(
                    tool=str(item["tool"]),
                    capability=str(item["capability"]),
                    side_effecting=item.get("side_effecting") is True,
                )
                for item in value["tool_capability_sequence"]
                if isinstance(item, Mapping)
            ),
            relevant_inputs=dict(value.get("relevant_inputs") or {}),
            preconditions=dict(value.get("preconditions") or {}),
            execution_strategy=dict(value.get("execution_strategy") or {}),
            expected_outcome=dict(value.get("expected_outcome") or {}),
            verification_evidence=tuple(
                VerificationEvidence(
                    summary=str(item["summary"]),
                    reference=(
                        str(item["reference"])
                        if item.get("reference") is not None
                        else None
                    ),
                )
                for item in value["verification_evidence"]
                if isinstance(item, Mapping)
            ),
            recipe_version=str(value["recipe_version"]),
            source_task_id=str(value["source_task_id"]),
            source_run_id=str(value["source_run_id"]),
            original_token_usage=int(value["original_token_usage"]),
            successful=value.get("successful") is True,
            verified=value.get("verified") is True,
        )

    def _hydrate_cache(self) -> None:
        if not self.config.verified_action_cache_enabled:
            return
        with self._db() as db:
            documents = tuple(
                row[0]
                for row in db.execute(
                    "SELECT recipe_json FROM hermes_verified_recipes ORDER BY stored_at"
                )
            )
        for document in documents:
            try:
                value = json.loads(document)
                if isinstance(value, Mapping):
                    self._cache.store(self._recipe_from_document(value))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                # A malformed persisted recipe is never eligible for reuse.
                continue

    def _parameterized_match(self, intent: str) -> CacheMatch | None:
        """Find a fully deterministic variable binding for a verified recipe."""

        for recipe in self._cache.recipes():
            strategy = recipe.execution_strategy.get("parameterized_replay")
            if not isinstance(strategy, Mapping):
                continue
            values = _parameter_values(strategy.get("intent_segments"), intent)
            template = strategy.get("args_template")
            if values is None or not isinstance(template, Mapping):
                continue
            bound = _bind_parameterized_value(template, values)
            if not isinstance(bound, Mapping):
                continue
            if _safe_replay_args(bound, self.config.redact_keys) is None:
                continue
            from runmantle.verified_action_cache import CacheMatchKind

            return CacheMatch(recipe, CacheMatchKind.PARAMETERIZED, 1.0)
        return None

    def _parameterized_replay_args(
        self, recipe: VerifiedActionRecipe, intent: str
    ) -> tuple[dict[str, Any], str] | None:
        strategy = recipe.execution_strategy.get("parameterized_replay")
        if not isinstance(strategy, Mapping):
            return None
        values = _parameter_values(strategy.get("intent_segments"), intent)
        template = strategy.get("args_template")
        template_hash = strategy.get("args_template_hash")
        if (
            values is None
            or not isinstance(template, Mapping)
            or not isinstance(template_hash, str)
        ):
            return None
        bound = _bind_parameterized_value(template, values)
        if not isinstance(bound, Mapping):
            return None
        safe_args = _safe_replay_args(bound, self.config.redact_keys)
        return (safe_args, template_hash) if safe_args is not None else None

    def pre_llm_call(self, **kw: Any) -> dict[str, str] | None:
        """Look up a verified strategy before Hermes plans the current turn."""

        if not self.config.verified_action_cache_enabled:
            return None
        run_id = self._run_id(kw)
        task_id = str(kw.get("task_id") or "")
        session_id = str(kw.get("session_id") or "")
        turn_id = str(kw.get("turn_id") or "")
        intent = str(kw.get("user_message") or "").strip()
        if not run_id or not task_id or not session_id or not intent:
            return None
        with self._lock, self._db() as db:
            existing = db.execute(
                "SELECT lookup_completed,candidate_recipe_id,match_type,"
                "match_confidence FROM hermes_cache_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            match: CacheMatch | None = None
            if existing is None or not existing["lookup_completed"]:
                request = ReuseRequest(
                    task_id=task_id,
                    run_id=run_id,
                    task_intent=intent,
                    relevant_inputs={},
                )
                match = self._cache.lookup(request)
                if match is None or match.kind.value == "similar":
                    parameterized = self._parameterized_match(intent)
                    if parameterized is not None:
                        match = parameterized
                db.execute(
                    "INSERT INTO hermes_cache_runs("
                    "run_id,task_id,session_id,turn_id,task_intent,"
                    "candidate_recipe_id,match_type,match_confidence,lookup_completed"
                    ") VALUES(?,?,?,?,?,?,?,?,1) "
                    "ON CONFLICT(run_id) DO UPDATE SET "
                    "task_id=excluded.task_id,session_id=excluded.session_id,"
                    "turn_id=excluded.turn_id,task_intent=excluded.task_intent,"
                    "candidate_recipe_id=excluded.candidate_recipe_id,"
                    "match_type=excluded.match_type,"
                    "match_confidence=excluded.match_confidence,lookup_completed=1",
                    (
                        run_id,
                        task_id,
                        session_id,
                        turn_id,
                        intent,
                        None if match is None else match.recipe.recipe_id,
                        None if match is None else match.kind.value,
                        None if match is None else match.score,
                    ),
                )
            elif existing["candidate_recipe_id"]:
                recipe = self._recipe_by_id(str(existing["candidate_recipe_id"]))
                if recipe is not None:
                    from runmantle.verified_action_cache import CacheMatchKind

                    match = CacheMatch(
                        recipe=recipe,
                        kind=CacheMatchKind(str(existing["match_type"])),
                        score=float(existing["match_confidence"]),
                    )
        if match is None:
            return None
        steps = ", ".join(
            f"{step.tool} ({step.capability})"
            for step in match.recipe.tool_capability_sequence
        )
        argument_keys = match.recipe.execution_strategy.get("argument_keys") or ()
        return {
            "context": (
                "RunMantle found a previously successful, verified execution recipe "
                f"({match.kind.value} match, confidence {match.score:.3f}). "
                f"Candidate tool sequence: {steps}. Expected argument keys: "
                f"{', '.join(str(key) for key in argument_keys) or 'none'}. "
                "Use current task inputs only. This recipe is not authorization; "
                "the current policy, approval, dispatch, receipt, runtime "
                "confirmation, and verification gates still apply."
            )
        }

    def post_api_request(self, **kw: Any) -> None:
        """Accumulate Hermes usage plus safe, provider-derived cost metadata."""

        if not self.config.verified_action_cache_enabled:
            return
        run_id = self._run_id(kw)
        api_request_id = str(kw.get("api_request_id") or "")
        usage = kw.get("usage")
        if not run_id or not api_request_id or not isinstance(usage, Mapping):
            return
        try:
            raw_input_tokens = (
                usage.get("prompt_tokens")
                if usage.get("prompt_tokens") is not None
                else usage.get("input_tokens") or 0
            )
            input_tokens = int(str(raw_input_tokens))
            output_tokens = int(str(usage.get("output_tokens") or 0))
            duration_ms = max(0, round(float(kw.get("api_duration") or 0) * 1000))
            raw_cost = usage.get("estimated_cost_usd", usage.get("cost_usd"))
            estimated_cost_usd = None if raw_cost is None else float(raw_cost)
        except (TypeError, ValueError):
            return
        if (
            input_tokens < 0
            or output_tokens < 0
            or (
                estimated_cost_usd is not None
                and (estimated_cost_usd < 0 or not math.isfinite(estimated_cost_usd))
            )
        ):
            return
        provider = _safe_usage_metadata(kw.get("provider"))
        model = _safe_usage_metadata(kw.get("response_model") or kw.get("model"))
        cost_status = _safe_usage_metadata(usage.get("cost_status"))
        cost_source = _safe_usage_metadata(usage.get("cost_source"))
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            inserted = db.execute(
                "INSERT OR IGNORE INTO hermes_api_usage("
                "api_request_id,run_id,input_tokens,output_tokens,duration_ms,"
                "estimated_cost_usd,provider,model,cost_status,cost_source"
                ") VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    api_request_id,
                    run_id,
                    input_tokens,
                    output_tokens,
                    duration_ms,
                    estimated_cost_usd,
                    provider,
                    model,
                    cost_status,
                    cost_source,
                ),
            ).rowcount
            if inserted:
                db.execute(
                    "UPDATE hermes_cache_runs SET "
                    "input_tokens=input_tokens+?,output_tokens=output_tokens+?,"
                    "duration_ms=duration_ms+?,usage_observed=1,"
                    "estimated_cost_usd=CASE WHEN ? IS NULL THEN estimated_cost_usd "
                    "ELSE COALESCE(estimated_cost_usd, 0)+? END,"
                    "cost_complete=CASE WHEN ? IS NULL THEN 0 ELSE cost_complete END,"
                    "provider=COALESCE(provider, ?),model=COALESCE(model, ?),"
                    "cost_status=COALESCE(cost_status, ?),"
                    "cost_source=COALESCE(cost_source, ?) "
                    "WHERE run_id=?",
                    (
                        input_tokens,
                        output_tokens,
                        duration_ms,
                        estimated_cost_usd,
                        estimated_cost_usd,
                        estimated_cost_usd,
                        provider,
                        model,
                        cost_status,
                        cost_source,
                        run_id,
                    ),
                )

    def post_llm_call(self, **kw: Any) -> None:
        """Finalize verified cache evidence after Hermes finishes the turn."""

        if not self.config.verified_action_cache_enabled:
            return
        run_id = self._run_id(kw)
        if run_id:
            self._finalize_cache_run(
                run_id,
                assistant_response=kw.get("assistant_response"),
            )

    def pre_model_completion(self, **kw: Any) -> dict[str, Any] | None:
        """Replay one exact verified recipe before Hermes calls a model.

        Every replay re-enters Hermes's dispatcher, so the current CortexOps
        policy, approval, dispatch permit, execution receipt, runtime probe,
        and task-status verification all run again. Any missing or
        inconclusive fact falls through to ordinary model planning.
        """

        if not self.config.verified_action_cache_enabled:
            return None
        run_id = self._run_id(kw)
        dispatch_tool = kw.get("dispatch_tool")
        if not run_id or not callable(dispatch_tool):
            return None
        try:
            with self._lock, self._db() as db:
                run = db.execute(
                    "SELECT * FROM hermes_cache_runs WHERE run_id=?", (run_id,)
                ).fetchone()
            match_type = str(run["match_type"] or "") if run is not None else ""
            if (
                run is None
                or match_type not in {"exact", "parameterized"}
                or not run["candidate_recipe_id"]
            ):
                return None
            recipe = self._recipe_by_id(str(run["candidate_recipe_id"]))
            if recipe is None or not recipe.successful or not recipe.verified:
                return None
            if not self._recipe_source_is_available(recipe):
                # A workspace reset can leave the local cache intact while
                # deleting the measured baseline that makes its savings
                # claim auditable. Do not replay such a recipe. Removing it
                # makes this turn's ordinary model path create a new measured
                # baseline for the current workspace instead of repeatedly
                # producing an unfinalized local hit.
                self._discard_recipe(recipe.recipe_id)
                return None
            replay = recipe.execution_strategy.get("replay")
            if not isinstance(replay, Mapping):
                return None
            tool_name = replay.get("tool")
            raw_args = replay.get("args")
            final_response = replay.get("final_response")
            if (
                not isinstance(tool_name, str)
                or not tool_name
                or not isinstance(raw_args, Mapping)
                or not isinstance(final_response, str)
                or not final_response.strip()
                or len(recipe.tool_capability_sequence) != 1
                or recipe.tool_capability_sequence[0].tool != tool_name
            ):
                return None
            template_hash = None
            if match_type == "parameterized":
                parameterized = self._parameterized_replay_args(
                    recipe, str(run["task_intent"])
                )
                if parameterized is None:
                    return None
                replay_args, template_hash = parameterized
                final_response = (
                    "Completed the governed action and independently verified "
                    "the requested outcome."
                )
            else:
                replay_args = _safe_replay_args(raw_args, self.config.redact_keys)
                if replay_args is None:
                    return None
            tool = self._tool(tool_name)
            cache_status, match, validation = self._cache_decision_for_call(
                kw,
                tool,
                _hash(replay_args),
                args_template_hash=template_hash,
            )
            if (
                cache_status != "hit"
                or match is None
                or match.kind.value != match_type
                or match.recipe.recipe_id != recipe.recipe_id
                or not validation
                or not all(item.passed for item in validation)
            ):
                return None

            dispatch = dispatch_tool(tool_name, replay_args)
            if not isinstance(dispatch, Mapping):
                return None
            tool_call_id = dispatch.get("tool_call_id")
            if not isinstance(tool_call_id, str) or not tool_call_id:
                return None
            with self._lock, self._db() as db:
                action = db.execute(
                    "SELECT * FROM hermes_actions WHERE tool_call_id=? AND run_id=?",
                    (tool_call_id, run_id),
                ).fetchone()
            if not self._verified_replay_action(action, recipe, match_type):
                return None
            if not self._record_pre_model_reuse(run, action, recipe, match_type):
                return None
            return {"complete_turn": True, "response": final_response}
        except (
            CortexOpsControlError,
            ToolDiscoveryError,
            KeyError,
            RuntimeError,
            TypeError,
            ValueError,
            OSError,
            sqlite3.Error,
        ):
            return None

    def _recipe_source_is_available(self, recipe: VerifiedActionRecipe) -> bool:
        """Check that CortexOps still retains this recipe's verified source."""

        try:
            response = self.client.transport.request(
                "GET",
                "/api/runmantle/v1/tasks/"
                f"{self.config.runtime_id}/{recipe.source_task_id}",
            )
        except CortexOpsControlError:
            return False
        return response.get("verified_status") == "verified"

    def _discard_recipe(self, recipe_id: str) -> None:
        """Remove a stale recipe from durable and in-memory lookup state."""

        with self._lock, self._db() as db:
            db.execute(
                "DELETE FROM hermes_verified_recipes WHERE recipe_id=?", (recipe_id,)
            )
            db.execute(
                "UPDATE hermes_cache_runs SET candidate_recipe_id=NULL,"
                "match_type=NULL,match_confidence=NULL WHERE candidate_recipe_id=?",
                (recipe_id,),
            )
        self._cache.discard(recipe_id)

    @staticmethod
    def _verified_replay_action(
        action: sqlite3.Row | None,
        recipe: VerifiedActionRecipe,
        match_type: str,
    ) -> bool:
        if action is None:
            return False
        if (
            action["state"] != "executed"
            or action["cache_status"] != "hit"
            or action["recipe_id"] != recipe.recipe_id
            or action["match_type"] != match_type
            or not action["receipt_json"]
            or not action["receipt_delivered"]
            or not action["confirmation_delivered"]
            or action["verification_status"] != "verified"
            or not action["verification_hash"]
            or not action["evidence_json"]
        ):
            return False
        try:
            receipt = json.loads(action["receipt_json"])
            evidence = json.loads(action["evidence_json"])
        except (TypeError, json.JSONDecodeError):
            return False
        return bool(
            isinstance(receipt, Mapping)
            and receipt.get("outcome") == "succeeded"
            and receipt.get("receipt_id")
            and isinstance(evidence, Mapping)
            and evidence.get("evidence_id")
            and evidence.get("checksum")
        )

    def _record_pre_model_reuse(
        self,
        run: sqlite3.Row,
        action: sqlite3.Row,
        recipe: VerifiedActionRecipe,
        match_type: str,
    ) -> bool:
        """Emit measured zero-token reuse telemetry after fresh verification."""

        baseline = recipe.execution_strategy.get("baseline")
        if (
            not isinstance(baseline, Mapping)
            or baseline.get("kind") != "measured"
            or int(baseline.get("total_tokens") or 0) <= 0
        ):
            return False
        try:
            receipt = json.loads(action["receipt_json"])
            duration_ms = max(0, int(receipt.get("duration_ms") or 0))
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        reused: dict[str, Any] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "duration_ms": duration_ms,
            "kind": "measured",
        }
        if baseline.get("estimated_cost_usd") is not None:
            reused["estimated_cost_usd"] = 0.0
        for metadata_key in ("provider", "model", "cost_status", "cost_source"):
            if baseline.get(metadata_key) is not None:
                reused[metadata_key] = baseline[metadata_key]
        payload = {
            "message_id": f"hermes:{run['run_id']}:verified-action-cache",
            "runtime_id": self.config.runtime_id,
            "run_id": str(run["run_id"]),
            "task_id": str(run["task_id"]),
            "decision_id": str(action["decision_id"]),
            "receipt_id": str(receipt["receipt_id"]),
            "cache_status": "hit",
            "recipe_id": recipe.recipe_id,
            "match_type": match_type,
            "match_confidence": 1.0,
            "validation_result": "verified",
            "fallback_reason": None,
            "baseline": dict(baseline),
            "reused": reused,
            "final_task_success": True,
            "verification_status": "verified",
            "human_intervention": action["approval_id"] is not None,
            "recipe_source_run_id": recipe.source_run_id,
            "recipe_source_task_id": recipe.source_task_id,
        }
        if not self._record_cache_telemetry(payload):
            return False
        self._cache.metrics.successful_reuse += 1
        self._cache.metrics.tokens_avoided += recipe.original_token_usage
        with self._db() as db:
            db.execute(
                "UPDATE hermes_cache_runs SET finalized=1 WHERE run_id=?",
                (run["run_id"],),
            )
        return True

    def _record_cache_telemetry(self, payload: Mapping[str, Any]) -> bool:
        """Record a cache measurement without losing it to an older control API.

        Provider and pricing fields are additive metadata.  A locally running
        CortexOps process can briefly lag the installed plugin during an
        upgrade; retry the otherwise identical measurement without those
        optional fields only when that older schema explicitly rejects them.
        Other control-plane failures remain fail-closed for cache reuse.
        """

        try:
            self.client.record_verified_action_cache_telemetry(payload)
            return True
        except CortexOpsControlRejected as error:
            if "Extra inputs are not permitted" not in str(error):
                return False
            legacy_payload = dict(payload)
            for measurement_name in ("baseline", "reused"):
                measurement = legacy_payload.get(measurement_name)
                if not isinstance(measurement, Mapping):
                    continue
                legacy_payload[measurement_name] = {
                    key: value
                    for key, value in measurement.items()
                    if key
                    not in {
                        "provider",
                        "model",
                        "cost_status",
                        "cost_source",
                    }
                }
            try:
                self.client.record_verified_action_cache_telemetry(legacy_payload)
                return True
            except (AttributeError, CortexOpsControlError, TypeError, ValueError):
                return False
        except (AttributeError, CortexOpsControlError, TypeError, ValueError):
            return False

    def _recipe_by_id(self, recipe_id: str) -> VerifiedActionRecipe | None:
        with self._db() as db:
            row = db.execute(
                "SELECT recipe_json FROM hermes_verified_recipes WHERE recipe_id=?",
                (recipe_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
            return (
                self._recipe_from_document(value)
                if isinstance(value, Mapping)
                else None
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _cache_decision_for_call(
        self,
        kw: Mapping[str, Any],
        tool: ToolDescriptor,
        args_hash: str,
        *,
        args_template_hash: str | None = None,
    ) -> tuple[str, CacheMatch | None, tuple[PreconditionResult, ...]]:
        """Bind a pre-LLM candidate to fresh current-call facts."""

        run_id = self._run_id(kw)
        if not self.config.verified_action_cache_enabled or not run_id:
            return "miss", None, ()
        with self._db() as db:
            run = db.execute(
                "SELECT * FROM hermes_cache_runs WHERE run_id=?", (run_id,)
            ).fetchone()
        if run is None or not run["candidate_recipe_id"]:
            return "miss", None, ()
        recipe = self._recipe_by_id(str(run["candidate_recipe_id"]))
        if recipe is None:
            return "miss", None, ()
        from runmantle.verified_action_cache import CacheMatchKind

        match = CacheMatch(
            recipe=recipe,
            kind=CacheMatchKind(str(run["match_type"])),
            score=float(run["match_confidence"]),
        )
        if match.kind.value == "parameterized" and args_template_hash is None:
            parameterized = self._parameterized_replay_args(
                recipe, str(run["task_intent"])
            )
            if parameterized is not None:
                bound_args, candidate_template_hash = parameterized
                if _hash(bound_args) == args_hash:
                    args_template_hash = candidate_template_hash
        probe_material = self._probe_for(tool.name, tool.capability)
        validation = tuple(
            _HermesRecipePreconditionValidator(
                tool=tool,
                args_hash=args_hash,
                probe_hash=_hash(
                    {"probe": redact(probe_material, self.config.redact_keys)}
                ),
                args_template_hash=args_template_hash,
            ).validate(
                recipe,
                ReuseRequest(
                    task_id=str(kw.get("task_id") or ""),
                    run_id=run_id,
                    task_intent=str(run["task_intent"]),
                    relevant_inputs={},
                ),
            )
        )
        if validation and all(item.passed for item in validation):
            return "hit", match, validation
        self._cache.metrics.validation_failure += 1
        self._cache.metrics.fallback += 1
        return "miss", match, validation

    @staticmethod
    def _measurement(
        run: sqlite3.Row, *, tool_duration_ms: Any = None
    ) -> dict[str, Any]:
        duration_ms = int(run["duration_ms"])
        try:
            if tool_duration_ms is not None:
                duration_ms += max(0, int(tool_duration_ms))
        except (TypeError, ValueError):
            pass
        input_tokens = int(run["input_tokens"])
        output_tokens = int(run["output_tokens"])
        measurement: dict[str, Any] = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "duration_ms": duration_ms,
            "kind": "measured",
        }
        if (
            run["usage_observed"]
            and run["cost_complete"]
            and run["estimated_cost_usd"] is not None
        ):
            measurement["estimated_cost_usd"] = float(run["estimated_cost_usd"])
        for metadata_key in ("provider", "model", "cost_status", "cost_source"):
            if run[metadata_key] is not None:
                measurement[metadata_key] = str(run[metadata_key])
        return measurement

    def _new_recipe(
        self,
        run: sqlite3.Row,
        action: sqlite3.Row,
        measurement: Mapping[str, Any],
        final_response: str | None,
    ) -> VerifiedActionRecipe:
        request = json.loads(action["request_json"])
        descriptor = request["tool_descriptor"]
        tool_name = str(descriptor["name"])
        probe_material = self._probe_for(
            tool_name, str(descriptor.get("capability") or "")
        )
        evidence = json.loads(action["evidence_json"])
        recipe_id = "hermes:" + _hash(
            {
                "intent": str(run["task_intent"]),
                "tool": tool_name,
                "capability": str(descriptor["capability"]),
                "args_hash": str(request["args_hash"]),
                "probe_hash": _hash(
                    {"probe": redact(probe_material, self.config.redact_keys)}
                ),
            }
        )
        expected = probe_material.get("expected_state")
        expected_outcome = dict(expected) if isinstance(expected, Mapping) else {}
        replay_args = request.get("replay_args")
        replay = None
        parameterized_replay = None
        if (
            isinstance(replay_args, Mapping)
            and isinstance(final_response, str)
            and final_response.strip()
        ):
            safe_args = _safe_replay_args(replay_args, self.config.redact_keys)
            if safe_args is not None:
                replay = {
                    "tool": tool_name,
                    "args": safe_args,
                    "final_response": final_response,
                }
                parameterized_replay = _parameterized_recipe(
                    str(run["task_intent"]), safe_args
                )
        strategy: dict[str, Any] = {
            "tool": tool_name,
            "capability": str(descriptor["capability"]),
            "argument_keys": sorted(
                str(key) for key in request.get("argument_keys") or ()
            ),
            "baseline": dict(measurement),
        }
        if replay is not None:
            strategy["replay"] = replay
        if parameterized_replay is not None:
            strategy["parameterized_replay"] = parameterized_replay
        return VerifiedActionRecipe(
            recipe_id=recipe_id,
            normalized_task_intent=str(run["task_intent"]),
            tool_capability_sequence=(
                RecipeStep(
                    tool=tool_name,
                    capability=str(descriptor["capability"]),
                    side_effecting=descriptor.get("side_effecting") is True,
                ),
            ),
            relevant_inputs={},
            preconditions={
                "tool": tool_name,
                "capability": str(descriptor["capability"]),
                "tool_descriptor_hash": _hash({"descriptor": descriptor}),
                "args_hash": str(request["args_hash"]),
                **(
                    {"args_template_hash": parameterized_replay["args_template_hash"]}
                    if parameterized_replay is not None
                    else {}
                ),
                "probe_hash": _hash(
                    {"probe": redact(probe_material, self.config.redact_keys)}
                ),
            },
            execution_strategy=strategy,
            expected_outcome=expected_outcome,
            verification_evidence=(
                VerificationEvidence(
                    summary="Hermes action receipt and fresh runtime probe verified",
                    reference=str(evidence["checksum"]),
                ),
            ),
            recipe_version="hermes-v1",
            source_task_id=str(run["task_id"]),
            source_run_id=str(run["run_id"]),
            original_token_usage=int(measurement["total_tokens"]),
        )

    def _store_recipe(self, recipe: VerifiedActionRecipe) -> None:
        self._cache.store(recipe)
        with self._db() as db:
            db.execute(
                "INSERT OR REPLACE INTO hermes_verified_recipes("
                "recipe_id,recipe_json,stored_at) VALUES(?,?,?)",
                (
                    recipe.recipe_id,
                    _canonical(self._recipe_document(recipe)),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def _finalize_cache_run(
        self,
        run_id: str,
        *,
        assistant_response: Any = None,
    ) -> None:
        with self._lock, self._db() as db:
            run = db.execute(
                "SELECT * FROM hermes_cache_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            action = db.execute(
                "SELECT * FROM hermes_actions WHERE run_id=? "
                "ORDER BY rowid DESC LIMIT 1",
                (run_id,),
            ).fetchone()
        if (
            run is None
            or action is None
            or run["finalized"]
            or not run["usage_observed"]
            or action["verification_status"] != "verified"
            or not action["receipt_delivered"]
            or not action["confirmation_delivered"]
        ):
            return
        receipt = json.loads(action["receipt_json"])
        measurement = self._measurement(
            run, tool_duration_ms=receipt.get("duration_ms")
        )
        if measurement["total_tokens"] <= 0:
            # Zero is valid provider data but cannot prove a measured comparison.
            return

        cache_status = str(action["cache_status"] or "miss")
        recipe = (
            self._recipe_by_id(str(action["recipe_id"]))
            if action["recipe_id"]
            else None
        )
        validation = json.loads(action["validation_json"] or "{}")
        failed_checks = [
            item
            for item in validation.get("checks") or []
            if isinstance(item, Mapping) and item.get("passed") is not True
        ]
        new_recipe: VerifiedActionRecipe | None = None
        if cache_status == "miss" and recipe is None:
            new_recipe = self._new_recipe(
                run,
                action,
                measurement,
                assistant_response if isinstance(assistant_response, str) else None,
            )
            recipe = new_recipe
        if cache_status == "hit" and recipe is None:
            return

        baseline = measurement
        reused: Mapping[str, Any] | None = None
        if cache_status == "hit":
            source = recipe.execution_strategy.get("baseline") if recipe else None
            if not isinstance(source, Mapping) or source.get("kind") != "measured":
                return
            baseline = dict(source)
            reused = measurement

        payload: dict[str, Any] = {
            "message_id": f"hermes:{run_id}:verified-action-cache",
            "runtime_id": self.config.runtime_id,
            "run_id": run_id,
            "task_id": str(run["task_id"]),
            "decision_id": str(action["decision_id"]),
            "receipt_id": str(receipt["receipt_id"]),
            "cache_status": cache_status,
            "recipe_id": None if recipe is None else recipe.recipe_id,
            "match_type": (
                str(action["match_type"]) if action["match_type"] else "none"
            ),
            "match_confidence": (
                float(action["match_confidence"])
                if action["match_confidence"] is not None
                else None
            ),
            "validation_result": "failed" if failed_checks else "verified",
            "fallback_reason": (
                "verified recipe preconditions changed" if failed_checks else None
            ),
            "baseline": baseline,
            "reused": reused,
            "final_task_success": True,
            "verification_status": "verified",
            "human_intervention": action["approval_id"] is not None,
        }
        if cache_status == "hit" and recipe is not None:
            payload.update(
                {
                    "recipe_source_run_id": recipe.source_run_id,
                    "recipe_source_task_id": recipe.source_task_id,
                }
            )
        if not self._record_cache_telemetry(payload):
            return

        if new_recipe is not None:
            self._store_recipe(new_recipe)
            self._cache.metrics.fallback += 1
        elif cache_status == "hit" and recipe is not None:
            self._cache.metrics.successful_reuse += 1
            self._cache.metrics.tokens_avoided += max(
                recipe.original_token_usage - int(measurement["total_tokens"]), 0
            )
        with self._db() as db:
            db.execute(
                "UPDATE hermes_cache_runs SET finalized=1 WHERE run_id=?",
                (run_id,),
            )

    def _refresh_tools(self) -> bool:
        try:
            self.tool_inventory.refresh(self._tool_discovery)
            return True
        except ToolDiscoveryError:
            # Invocation remains fail-closed through classify_unknown().
            return False

    def _tool(self, name: str) -> ToolDescriptor:
        if self._refresh_tools():
            descriptor = self.tool_inventory.get(name)
            if descriptor is not None:
                return descriptor
        return self.tool_inventory.classify_unknown(
            name,
            provider="hermes",
            framework="hermes",
            discovery_source="hermes.pre_tool_call",
        )

    @staticmethod
    def _approval_rule(call_id: str) -> str:
        return f"cortexops:{call_id}"

    def _register_task(
        self,
        contract: TaskContract[dict[str, str], dict[str, bool]],
        session_id: str,
    ) -> None:
        request_id = (
            f"runtime:{self.config.runtime_id}:hermes-task:{contract.task_id}:register"
        )
        register_task = getattr(self.client, "register_task", None)
        if callable(register_task):
            register_task(
                contract,
                correlation_id=session_id,
                worker_id="hermes",
                request_id=request_id,
            )
            return
        # Compatibility for injected v1-style clients that expose only the
        # transport seam (including existing application test doubles).
        self.client.transport.request(
            "POST",
            "/api/runmantle/v1/tasks/register",
            {
                "request_id": request_id,
                "runtime_id": self.config.runtime_id,
                "task_id": contract.task_id,
                "contract_hash": _digest(task_contract_telemetry(contract)),
                "correlation_id": session_id,
                "worker_id": "hermes",
            },
        )

    def _register_runtime_for(
        self, tool: ToolDescriptor, *, force: bool = False
    ) -> None:
        """Ensure the control plane has the runtime's current capabilities.

        A CortexOps workspace reset intentionally removes runtime registrations.
        The Hermes process can outlive that reset, however, so its in-memory
        handshake is no longer evidence that the control plane still knows the
        runtime.  Registration is safe to refresh with the stable request ID.
        """

        if force:
            self.client._handshake = None
        if getattr(self.client, "_handshake", None):
            return
        capabilities = {
            descriptor.capability
            for descriptor in self.tool_inventory.snapshot()
            if descriptor.side_effecting
        }
        capabilities.add(tool.capability)
        capabilities.update({"govern.v2", "govern.receipt.v1"})
        if self.config.verified_action_cache_enabled:
            capabilities.add("verified_action_cache.telemetry.v1")
        self.client.register_runtime(capabilities)

    def _probe_for(self, tool_name: str, capability: str) -> Mapping[str, Any]:
        """Resolve a probe by exact tool name, capability, or safe default."""

        probes = self.config.post_action_probes or {}
        for key in (tool_name, f"capability:{capability}", "*"):
            probe = probes.get(key)
            if isinstance(probe, Mapping):
                return probe
        return {}

    @staticmethod
    def _filesystem_expected_state(
        probe: Mapping[str, Any], args: Mapping[str, Any]
    ) -> dict[str, Any]:
        path_key = str(probe.get("path_argument") or "path")
        content_key = str(probe.get("content_argument") or "content")
        path, content = args.get(path_key), args.get(content_key)
        if not isinstance(path, str) or not isinstance(content, str):
            raise ValueError(
                "filesystem probe requires string path and content arguments"
            )
        encoded = content.encode("utf-8")
        return {
            "file": {
                "path_hash": _hash({"path": path}),
                "content_sha256": hashlib.sha256(encoded).hexdigest(),
                "byte_length": len(encoded),
            }
        }

    def _expected_state_for_probe(
        self, probe: Mapping[str, Any], args: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if str(probe.get("kind") or "http") == "filesystem_content":
            return self._filesystem_expected_state(probe, args)
        expected = probe.get("expected_state")
        return dict(expected) if isinstance(expected, Mapping) else {}

    @staticmethod
    def _requires_runtime_reregistration(error: CortexOpsControlRejected) -> bool:
        """Return whether a rejected task registration proves a stale handshake."""

        return "runmantle runtime is not registered" in str(error).lower()

    def pre_tool_call(self, **kw: Any) -> dict[str, str] | None:
        tool_name = str(kw.get("tool_name") or "")
        if not tool_name:
            return {
                "action": "block",
                "message": "BLOCKED: missing Hermes tool identity",
            }
        try:
            tool = self._tool(tool_name)
        except (ToolDiscoveryError, TypeError, ValueError):
            return {
                "action": "block",
                "message": "BLOCKED: tool classification unavailable",
            }
        if tool.read_only and not self.config.govern_read_only_tools:
            return None
        raw_args = kw.get("args")
        args: Mapping[str, Any] = raw_args if isinstance(raw_args, Mapping) else {}
        call_id, task_id, session_id = (
            str(kw.get(k) or "") for k in ("tool_call_id", "task_id", "session_id")
        )
        if not call_id or not task_id or not session_id:
            return {
                "action": "block",
                "message": "BLOCKED: missing Hermes correlation identity",
            }
        with self._db() as db:
            existing = db.execute(
                "SELECT state,decision_json FROM hermes_actions WHERE tool_call_id=?",
                (call_id,),
            ).fetchone()
        if existing is not None:
            outcome = json.loads(existing["decision_json"])["outcome"]
            if outcome == "ALLOW" and existing["state"] == "dispatched":
                return None
            if outcome == "REQUIRE_APPROVAL" and existing["state"] in {
                "awaiting_approval",
                "dispatching",
            }:
                return {
                    "action": "approve",
                    "message": "CortexOps approval required",
                    "rule_key": self._approval_rule(call_id),
                }
            return {
                "action": "block",
                "message": "BLOCKED: CortexOps action is already final or unavailable",
            }
        args_hash = _hash(args)
        replay_args = _safe_replay_args(args, self.config.redact_keys)
        try:
            cache_status, cache_match, cache_validation = self._cache_decision_for_call(
                kw, tool, args_hash
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            # Cache availability never weakens the mandatory control path.
            cache_status, cache_match, cache_validation = "miss", None, ()
        action_id = _hash(
            {
                "task_id": task_id,
                "session_id": session_id,
                "tool_call_id": call_id,
                "tool_name": tool_name,
                "args_hash": args_hash,
            }
        )
        request = ActionRequest(
            action_id=action_id,
            task_id=task_id,
            name=str(
                self.config.controlled_tools.get(tool_name, {}).get("action_name")
                or tool_name
            ),
            required_capability=tool.capability,
            input=redact(args, self.config.redact_keys),
            idempotency_key=action_id,
            risk_level=tool.risk_level,
            requested_by="hermes",
            requested_at=datetime.now(UTC),
            timeout=timedelta(seconds=self.config.decision_timeout_seconds),
            metadata={
                "session_id": session_id,
                "tool_call_id": call_id,
                "args_hash": args_hash,
                "tool_descriptor": tool.as_dict(),
            },
        )
        probe = self._probe_for(tool.name, tool.capability)
        try:
            expected_state = self._expected_state_for_probe(probe, args)
        except (TypeError, ValueError):
            expected_state = {}
        contract = hermes_task_contract(
            task_id,
            session_id,
            capability=request.required_capability,
            risk_level=request.risk_level,
            expected_state=expected_state,
        )
        try:
            self._register_runtime_for(tool)
            try:
                self._register_task(contract, session_id)
            except CortexOpsControlRejected as error:
                if not self._requires_runtime_reregistration(error):
                    raise
                self._register_runtime_for(tool, force=True)
                self._register_task(contract, session_id)
            decision = self.client.evaluate_action(
                request, correlation_id=session_id, worker_id="hermes"
            )
            decision_id = str(decision["decision_id"])
            if not _same_hash(decision.get("action_hash"), request.action_hash):
                raise CortexOpsControlError("decision action hash mismatch")
            state = (
                "awaiting_approval"
                if decision["outcome"] == "REQUIRE_APPROVAL"
                else "evaluated"
            )
            with self._db() as db:
                db.execute(
                    "INSERT INTO hermes_actions("
                    "tool_call_id,action_id,action_hash,decision_id,"
                    "decision_json,request_json,state,run_id,cache_status,"
                    "recipe_id,match_type,match_confidence,validation_json"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        call_id,
                        action_id,
                        request.action_hash,
                        decision_id,
                        _canonical(decision),
                        _canonical(
                            {
                                "action_id": action_id,
                                "args_hash": args_hash,
                                "argument_keys": sorted(str(key) for key in args),
                                "tool_descriptor": tool.as_dict(),
                                **(
                                    {"replay_args": replay_args}
                                    if replay_args is not None
                                    else {}
                                ),
                            }
                        ),
                        state,
                        self._run_id(kw) or task_id,
                        cache_status,
                        None if cache_match is None else cache_match.recipe.recipe_id,
                        None if cache_match is None else cache_match.kind.value,
                        None if cache_match is None else cache_match.score,
                        _canonical(
                            {
                                "checks": [
                                    {
                                        "name": item.name,
                                        "passed": item.passed,
                                        "message": item.message,
                                    }
                                    for item in cache_validation
                                ]
                            }
                        ),
                    ),
                )
            if decision["outcome"] == "ALLOW":
                self.client.dispatch_action(
                    decision, action_hash=request.action_hash, attempt_id=call_id
                )
                with self._db() as db:
                    db.execute(
                        "UPDATE hermes_actions SET state='dispatched',"
                        "dispatch_attempt_id=? WHERE tool_call_id=?",
                        (call_id, call_id),
                    )
                return None
            if decision["outcome"] == "REQUIRE_APPROVAL":
                approval = self.client.transport.request(
                    "POST",
                    f"/api/runmantle/v1/actions/{decision_id}/approval",
                    {
                        "runtime_id": self.config.runtime_id,
                        "task_id": task_id,
                        "action_id": action_id,
                        "action_hash": request.action_hash,
                        "idempotency_key": f"hermes:{call_id}:approval",
                        "message_id": f"hermes:{call_id}:approval",
                        "expires_at": (
                            datetime.now(UTC)
                            + timedelta(seconds=self.config.approval_timeout_seconds)
                        ).isoformat(),
                    },
                )
                self._validate_approval(
                    approval, decision_id, action_id, request.action_hash
                )
                with self._db() as db:
                    db.execute(
                        "UPDATE hermes_actions SET approval_id=? WHERE tool_call_id=?",
                        (approval["approval_id"], call_id),
                    )
                if self.config.blocking_hook_approval:
                    request_id = f"hermes-blocking-hook:{call_id}"
                    pattern_key = f"plugin_rule:{self._approval_rule(call_id)}"
                    request_digest = _hash(
                        {
                            "call_id": call_id,
                            "action_hash": request.action_hash,
                            "request_id": request_id,
                        }
                    )

                    class BlockingHookRequest:
                        def __init__(self) -> None:
                            self.pattern_key = pattern_key
                            self.request_id = request_id
                            self.digest = request_digest

                        @staticmethod
                        def respond(choice: str) -> str:
                            return choice

                    choice = self.present_approval(BlockingHookRequest())
                    if choice == "once":
                        return None
                    return {
                        "action": "block",
                        "message": "BLOCKED: CortexOps did not approve this action",
                    }
                return {
                    "action": "approve",
                    "message": "CortexOps approval required",
                    "rule_key": self._approval_rule(call_id),
                }
            return {
                "action": "block",
                "message": "BLOCKED: CortexOps policy denied this action",
            }
        except (
            CortexOpsControlError,
            KeyError,
            TypeError,
            ValueError,
            OSError,
            sqlite3.Error,
        ):
            return {
                "action": "block",
                "message": "BLOCKED: CortexOps decision unavailable",
            }

    @staticmethod
    def _validate_approval(
        approval: Mapping[str, Any], decision_id: str, action_id: str, action_hash: str
    ) -> None:
        if (
            not str(approval.get("approval_id") or "")
            or approval.get("decision_id") != decision_id
            or approval.get("action_id") != action_id
            or not _same_hash(approval.get("action_hash"), action_hash)
        ):
            raise CortexOpsControlError("approval identity mismatch")

    def present_approval(self, request: Any) -> Any:
        """Only an exact CortexOps Approved permit yields Hermes ``once``."""
        key = str(getattr(request, "pattern_key", ""))
        if not key.startswith(self._RULE_PREFIX):
            return request.respond("deny")
        call_id = key.removeprefix(self._RULE_PREFIX)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM hermes_actions WHERE tool_call_id=?", (call_id,)
            ).fetchone()
            if (
                row is None
                or row["state"] != "awaiting_approval"
                or not row["approval_id"]
            ):
                return request.respond("deny")
            if row["hermes_request_id"] and (
                row["hermes_request_id"] != request.request_id
                or row["hermes_request_digest"] != request.digest
            ):
                return request.respond("deny")
            db.execute(
                "UPDATE hermes_actions SET hermes_request_id=?,"
                "hermes_request_digest=? WHERE tool_call_id=?",
                (request.request_id, request.digest, call_id),
            )
        deadline, delay = (
            time.monotonic() + self.config.approval_timeout_seconds,
            self.config.approval_poll_initial_seconds,
        )
        while time.monotonic() < deadline:
            try:
                approval = self.client.transport.request(
                    "GET",
                    "/api/runmantle/v1/approvals/"
                    f"{row['approval_id']}/status?runtime_id={self.config.runtime_id}",
                )
                self._validate_approval(
                    approval, row["decision_id"], row["action_id"], row["action_hash"]
                )
                status = approval.get("status")
                if (
                    status in {"Denied", "Expired"}
                    or approval.get("fail_closed") is True
                ):
                    return request.respond("deny")
                if status == "Approved" and approval.get("authorized") is True:
                    if not self._claim_dispatch(call_id, request.request_id):
                        return request.respond("deny")
                    decision = self.client.action_decision(
                        row["decision_id"], row["action_hash"]
                    )
                    bound = decision.get("approval")
                    if not isinstance(bound, Mapping) or bound.get(
                        "approval_id"
                    ) != approval.get("governance_approval_id"):
                        raise CortexOpsControlError(
                            "canonical permit approval mismatch"
                        )
                    self.client.dispatch_action(
                        decision,
                        action_hash=row["action_hash"],
                        attempt_id=request.request_id,
                    )
                    with self._db() as db:
                        db.execute(
                            "UPDATE hermes_actions SET state='dispatched' "
                            "WHERE tool_call_id=? AND state='dispatching'",
                            (call_id,),
                        )
                    return request.respond("once")
            except CortexOpsControlError:
                return request.respond("deny")
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
            delay = min(delay * 2, self.config.approval_poll_max_seconds)
        return request.respond("deny")

    def _claim_dispatch(self, call_id: str, request_id: str) -> bool:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            return (
                db.execute(
                    "UPDATE hermes_actions SET state='dispatching',"
                    "dispatch_attempt_id=? WHERE tool_call_id=? "
                    "AND state='awaiting_approval' AND hermes_request_id=?",
                    (request_id, call_id, request_id),
                ).rowcount
                == 1
            )

    def post_tool_call(self, **kw: Any) -> None:
        call_id = str(kw.get("tool_call_id") or "")
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM hermes_actions WHERE tool_call_id=?", (call_id,)
            ).fetchone()
            if row is None or row["state"] not in {"dispatched", "executed"}:
                return
            if row["receipt_json"] is None:
                now = datetime.now(UTC).isoformat()
                receipt = {
                    "runtime_id": self.config.runtime_id,
                    "receipt_id": f"hermes:{call_id}",
                    "attempt_id": row["dispatch_attempt_id"] or call_id,
                    "runtime_execution_id": call_id,
                    "outcome": "succeeded" if kw.get("status") == "ok" else "failed",
                    "occurred_at": now,
                    "started_at": now,
                    "ended_at": now,
                    "action_hash": row["action_hash"],
                    "duration_ms": kw.get("duration_ms"),
                    "side_effect_confirmation": False,
                    "result_hash": _hash(
                        {"value": redact(kw.get("result"), self.config.redact_keys)}
                    ),
                    "error_hash": _hash(
                        {
                            "value": redact(
                                kw.get("error_message"), self.config.redact_keys
                            )
                        }
                    ),
                }
                db.execute(
                    "UPDATE hermes_actions SET receipt_json=?,"
                    "state='executed' WHERE tool_call_id=?",
                    (_canonical(receipt), call_id),
                )
                row = db.execute(
                    "SELECT * FROM hermes_actions WHERE tool_call_id=?", (call_id,)
                ).fetchone()
        self._deliver_execution(row, kw)

    def _deliver_execution(self, row: sqlite3.Row, kw: Mapping[str, Any]) -> None:
        if not row["receipt_delivered"]:
            try:
                self.client.transport.request(
                    "POST",
                    f"/api/runmantle/v1/actions/{row['decision_id']}/receipts",
                    json.loads(row["receipt_json"]),
                )
                with self._db() as db:
                    db.execute(
                        "UPDATE hermes_actions SET receipt_delivered=1 "
                        "WHERE tool_call_id=?",
                        (row["tool_call_id"],),
                    )
            except CortexOpsControlError:
                return
        with self._db() as db:
            current = db.execute(
                "SELECT * FROM hermes_actions WHERE tool_call_id=?",
                (row["tool_call_id"],),
            ).fetchone()
        if current is None or kw.get("status") != "ok":
            return
        if (
            not current["confirmation_delivered"]
            or current["verification_status"] == "awaiting_task_sync"
        ):
            verification = self._send_probe(current, kw)
            if verification is None:
                return
            stored_status = (
                "awaiting_task_sync"
                if verification.result.status is VerificationStatus.VERIFIED
                else verification.result.status.value
            )
            with self._db() as db:
                db.execute(
                    "UPDATE hermes_actions SET confirmation_delivered=1,"
                    "verification_status=?,evidence_json=? WHERE tool_call_id=?",
                    (
                        stored_status,
                        _canonical(
                            {
                                "evidence_id": verification.evidence.evidence_id,
                                "checksum": verification.evidence.checksum,
                                "criteria": [
                                    {
                                        "name": item.name,
                                        "passed": item.passed,
                                        "conclusive": item.conclusive,
                                    }
                                    for item in verification.result.criteria
                                ],
                            }
                        ),
                        current["tool_call_id"],
                    ),
                )
            if verification.result.status is VerificationStatus.VERIFIED:
                self._sync_verified_task(current, kw, verification)

    def _send_probe(
        self, row: sqlite3.Row, kw: Mapping[str, Any]
    ) -> _HermesProbeVerification | None:
        request_data = json.loads(row["request_json"])
        descriptor = request_data.get("tool_descriptor") or {}
        probe = self._probe_for(
            str(kw.get("tool_name") or ""), str(descriptor.get("capability") or "")
        )
        if not probe:
            # An executor success without fresh outcome evidence is not verified.
            return None
        observed: dict[str, Any] = {}
        raw_args = kw.get("args")
        args = raw_args if isinstance(raw_args, Mapping) else {}
        try:
            expected = dict(self._expected_state_for_probe(probe, args))
        except (TypeError, ValueError):
            return None
        if not expected:
            return None
        kind = str(probe.get("kind") or "http")
        provider_id = "runmantle.hermes.http_probe"
        try:
            if kind == "filesystem_content":
                path_key = str(probe.get("path_argument") or "path")
                path = args.get(path_key)
                if not isinstance(path, str):
                    raise ValueError("filesystem probe requires a string path")
                content = Path(path).read_bytes()
                observed = {
                    "file": {
                        "path_hash": _hash({"path": path}),
                        "content_sha256": hashlib.sha256(content).hexdigest(),
                        "byte_length": len(content),
                    }
                }
                provider_id = "runmantle.hermes.filesystem_probe"
            elif kind == "http":
                for label in ("version_url", "health_url"):
                    url = probe.get(label)
                    if not isinstance(url, str) or not url:
                        raise ValueError(f"missing {label}")
                    with urlopen(
                        Request(url, headers={"Accept": "application/json"}),
                        timeout=self.config.decision_timeout_seconds,
                    ) as response:
                        observed[label.removesuffix("_url")] = json.loads(
                            response.read()
                        )
            else:
                return None
            status = "confirmed" if observed == expected else "failed"
        except Exception as error:  # noqa: BLE001 - probes are non-authoritative evidence
            status, observed = "inconclusive", {"probe_error": type(error).__name__}
        receipt = json.loads(row["receipt_json"]) if row["receipt_json"] else {}
        checked_at = str(
            receipt.get("ended_at")
            or receipt.get("occurred_at")
            or datetime.now(UTC).isoformat()
        )
        payload = {
            "message_id": f"hermes:{row['tool_call_id']}:probe",
            "runtime_id": self.config.runtime_id,
            "task_id": str(kw.get("task_id") or ""),
            "action_id": row["action_id"],
            "action_hash": row["action_hash"],
            "receipt_id": str(
                receipt.get("receipt_id") or f"hermes:{row['tool_call_id']}"
            ),
            "confirmation_id": f"hermes:{row['tool_call_id']}:probe",
            "status": status,
            "provider_id": provider_id,
            "observed_state": observed,
            "expected_state": expected,
            "evidence_ids": [
                str(receipt.get("receipt_id") or f"hermes:{row['tool_call_id']}"),
                f"hermes:{row['tool_call_id']}:version",
                f"hermes:{row['tool_call_id']}:health",
            ],
            "checked_at": checked_at,
            "actor": "runmantle.hermes_control",
        }
        try:
            contract = hermes_task_contract(
                str(kw.get("task_id") or ""),
                str(kw.get("session_id") or ""),
                capability=str(descriptor["capability"]),
                risk_level=RiskLevel(str(descriptor["risk_level"])),
                expected_state=expected,
            )
            evidence = _establish_evidence_origin(
                EvidenceItem(
                    evidence_id=f"hermes:{row['tool_call_id']}:runtime-probe",
                    type="hermes_tool_runtime",
                    source=provider_id,
                    collected_at=datetime.fromisoformat(checked_at),
                    payload=observed,
                ),
                boundary="runmantle.hermes_control.post_action_probe",
                provider_identity=f"{provider_id}:v1",
                provider_configuration={
                    "kind": kind,
                    "path_argument": str(probe.get("path_argument") or ""),
                    "content_argument": str(probe.get("content_argument") or ""),
                    "version_url": str(probe.get("version_url") or ""),
                    "health_url": str(probe.get("health_url") or ""),
                    "expected_state_hash": _hash({"expected": expected}),
                },
                trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
            )
            result = RuleBasedVerifier().verify(
                contract,
                {"executed": True},
                EvidenceCollection((evidence,)),
            )
        except (KeyError, TypeError, ValueError):
            return None
        try:
            self.client.transport.request(
                "POST",
                f"/api/runmantle/v1/actions/{row['decision_id']}/runtime-confirmations",
                payload,
            )
            return _HermesProbeVerification(result, evidence, contract)
        except CortexOpsControlError:
            return None

    def _sync_verified_task(
        self,
        row: sqlite3.Row,
        kw: Mapping[str, Any],
        verification: _HermesProbeVerification,
    ) -> None:
        material = {
            "status": verification.result.status.value,
            "criteria": [
                {
                    "name": item.name,
                    "passed": item.passed,
                    "conclusive": item.conclusive,
                }
                for item in verification.result.criteria
            ],
            "evidence_ids": [verification.evidence.evidence_id],
        }
        verification_hash = _digest(material)
        task_id = str(kw.get("task_id") or "")
        try:
            response = self.client.transport.request(
                "POST",
                "/api/runmantle/v1/tasks/status",
                {
                    "request_id": (
                        f"runtime:{self.config.runtime_id}:hermes-task:"
                        f"{task_id}:verified"
                    ),
                    "runtime_id": self.config.runtime_id,
                    "task_id": task_id,
                    "contract_hash": _digest(
                        task_contract_telemetry(verification.contract)
                    ),
                    "status": "verified",
                    "sequence": 1,
                    "verification_hash": verification_hash,
                },
            )
            if response.get("verified_status") != "verified":
                return
        except CortexOpsControlError:
            return
        with self._db() as db:
            db.execute(
                "UPDATE hermes_actions SET verification_status='verified',"
                "verification_hash=? WHERE tool_call_id=?",
                (verification_hash, row["tool_call_id"]),
            )


def register(ctx: Any) -> None:
    keys = (
        "cortexops_url",
        "authorization",
        "runtime_id",
        "controlled_tools",
        "classification_overrides",
        "post_action_probes",
        "state_path",
        "decision_timeout_seconds",
        "approval_timeout_seconds",
        "approval_poll_initial_seconds",
        "approval_poll_max_seconds",
        "blocking_hook_approval",
        "govern_read_only_tools",
        "verified_action_cache_enabled",
        "verified_action_cache_similarity_threshold",
        "redact_keys",
    )
    adapter = HermesControlAdapter(
        HermesControlConfig.from_settings({key: ctx.get_config(key) for key in keys})
    )
    ctx.register_hook("pre_llm_call", adapter.pre_llm_call)
    ctx.register_hook("pre_model_completion", adapter.pre_model_completion)
    ctx.register_hook("post_api_request", adapter.post_api_request)
    ctx.register_hook("pre_tool_call", adapter.pre_tool_call)
    ctx.register_hook("post_tool_call", adapter.post_tool_call)
    ctx.register_hook("post_llm_call", adapter.post_llm_call)
    ctx.register_approval_transport("cortexops", adapter.present_approval)


def install_plugin(hermes_home: str | Path) -> Path:
    source, target = (
        Path(__file__).resolve().parents[1] / "hermes_plugin",
        Path(hermes_home).expanduser() / "plugins" / "runmantle-cortexops-control",
    )
    if target.exists():
        raise FileExistsError(f"refusing to overwrite existing plugin: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)
    return target


def main() -> int:
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="Install the RunMantle Hermes control plugin"
    )
    parser.add_argument(
        "--hermes-home", default=os.environ.get("HERMES_HOME", "~/.hermes")
    )
    args = parser.parse_args()
    print(install_plugin(args.hermes_home))
    return 0


__all__ = [
    "HermesControlAdapter",
    "HermesControlConfig",
    "HermesToolDiscoveryAdapter",
    "hermes_task_contract",
    "install_plugin",
    "main",
    "redact",
    "register",
]
