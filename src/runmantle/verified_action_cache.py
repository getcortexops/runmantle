"""Small, framework-neutral cache for verified execution recipes.

The cache stores *how* a successful task was completed, never an authorization
to repeat its effects.  A caller must supply both a fresh precondition validator
and a governed executor for every reuse attempt.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, TypeAlias

from ._validation import require_non_empty
from .serialization import SafeJsonCodec


def normalize_task_intent(intent: str) -> str:
    """Return the conservative canonical form used for exact matching."""

    normalized = " ".join(intent.casefold().split())
    require_non_empty(normalized, "normalized task intent")
    return normalized


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    return value


def _fingerprint(intent: str, inputs: Mapping[str, Any]) -> str:
    encoded = SafeJsonCodec().dumps(
        {"normalized_intent": intent, "relevant_inputs": inputs}
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RecipeStep:
    """One declared tool/capability operation in a reusable strategy."""

    tool: str
    capability: str
    side_effecting: bool = False

    def __post_init__(self) -> None:
        require_non_empty(self.tool, "recipe step tool")
        require_non_empty(self.capability, "recipe step capability")


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    """Compact evidence that a recipe outcome was independently checked."""

    summary: str
    reference: str | None = None

    def __post_init__(self) -> None:
        require_non_empty(self.summary, "verification evidence summary")


@dataclass(frozen=True, slots=True)
class VerifiedActionRecipe:
    """A compact, auditable description of a verified execution path."""

    recipe_id: str
    normalized_task_intent: str
    tool_capability_sequence: tuple[RecipeStep, ...]
    relevant_inputs: Mapping[str, Any]
    preconditions: Mapping[str, Any]
    execution_strategy: Mapping[str, Any]
    expected_outcome: Mapping[str, Any]
    verification_evidence: tuple[VerificationEvidence, ...]
    recipe_version: str
    source_task_id: str
    source_run_id: str
    original_token_usage: int
    successful: bool = True
    verified: bool = True
    exact_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        for name in (
            "recipe_id",
            "normalized_task_intent",
            "recipe_version",
            "source_task_id",
            "source_run_id",
        ):
            require_non_empty(getattr(self, name), f"recipe {name}")
        if not self.tool_capability_sequence:
            raise ValueError("a recipe requires at least one tool/capability step")
        if not self.verification_evidence:
            raise ValueError("a recipe requires verification evidence")
        if self.original_token_usage < 0:
            raise ValueError("original_token_usage must not be negative")
        normalized_intent = normalize_task_intent(self.normalized_task_intent)
        inputs = _freeze(self.relevant_inputs)
        object.__setattr__(self, "normalized_task_intent", normalized_intent)
        object.__setattr__(
            self, "tool_capability_sequence", tuple(self.tool_capability_sequence)
        )
        object.__setattr__(self, "relevant_inputs", inputs)
        object.__setattr__(self, "preconditions", _freeze(self.preconditions))
        object.__setattr__(self, "execution_strategy", _freeze(self.execution_strategy))
        object.__setattr__(self, "expected_outcome", _freeze(self.expected_outcome))
        object.__setattr__(
            self, "verification_evidence", tuple(self.verification_evidence)
        )
        object.__setattr__(
            self, "exact_fingerprint", _fingerprint(normalized_intent, inputs)
        )


@dataclass(frozen=True, slots=True)
class ReuseRequest:
    """The current task presented to the recipe cache."""

    task_id: str
    run_id: str
    task_intent: str
    relevant_inputs: Mapping[str, Any]

    normalized_task_intent: str = field(init=False)
    exact_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        require_non_empty(self.task_id, "reuse task_id")
        require_non_empty(self.run_id, "reuse run_id")
        intent = normalize_task_intent(self.task_intent)
        inputs = _freeze(self.relevant_inputs)
        object.__setattr__(self, "normalized_task_intent", intent)
        object.__setattr__(self, "relevant_inputs", inputs)
        object.__setattr__(self, "exact_fingerprint", _fingerprint(intent, inputs))


@dataclass(frozen=True, slots=True)
class PreconditionResult:
    name: str
    passed: bool
    message: str

    def __post_init__(self) -> None:
        require_non_empty(self.name, "recipe precondition name")
        require_non_empty(self.message, "recipe precondition message")


class RecipePreconditionValidator(Protocol):
    """Application-owned fresh-state check required before any reuse."""

    def validate(
        self, recipe: VerifiedActionRecipe, request: ReuseRequest
    ) -> Sequence[PreconditionResult]: ...


class RecipeSimilarityMatcher(Protocol):
    """Extension point for future semantic matching; scores range from 0 to 1."""

    def score(self, request: ReuseRequest, recipe: VerifiedActionRecipe) -> float: ...


class NormalizedIntentSimilarityMatcher:
    """Conservative lexical matcher for wording changes with identical inputs."""

    def score(self, request: ReuseRequest, recipe: VerifiedActionRecipe) -> float:
        if request.relevant_inputs != recipe.relevant_inputs:
            return 0.0
        requested = set(request.normalized_task_intent.split())
        recorded = set(recipe.normalized_task_intent.split())
        if not requested or not recorded:
            return 0.0
        return len(requested & recorded) / len(requested | recorded)


class CacheMatchKind(StrEnum):
    EXACT = "exact"
    PARAMETERIZED = "parameterized"
    SIMILAR = "similar"


@dataclass(frozen=True, slots=True)
class CacheMatch:
    recipe: VerifiedActionRecipe
    kind: CacheMatchKind
    score: float


@dataclass(slots=True)
class CacheMetrics:
    cache_hit: int = 0
    cache_miss: int = 0
    validation_failure: int = 0
    fallback: int = 0
    successful_reuse: int = 0
    tokens_avoided: int = 0


@dataclass(frozen=True, slots=True)
class RecipeExecution:
    """The fresh result of either a governed reuse or normal agent execution."""

    output: Any
    token_usage: int = 0

    def __post_init__(self) -> None:
        if self.token_usage < 0:
            raise ValueError("token_usage must not be negative")


@dataclass(frozen=True, slots=True)
class RecipeVerification:
    verified: bool
    evidence: tuple[VerificationEvidence, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if self.verified and not self.evidence:
            raise ValueError(
                "a verified recipe execution requires verification evidence"
            )


@dataclass(frozen=True, slots=True)
class NormalExecution:
    """Normal agent execution, optionally yielding a new cacheable recipe."""

    result: RecipeExecution
    recipe: VerifiedActionRecipe | None = None


class CacheOutcome(StrEnum):
    REUSED = "reused"
    REUSE_UNVERIFIED = "reuse_unverified"
    FALLBACK = "fallback"


@dataclass(frozen=True, slots=True)
class CacheExecutionResult:
    outcome: CacheOutcome
    execution: RecipeExecution
    verification: RecipeVerification
    recipe: VerifiedActionRecipe | None
    match: CacheMatch | None
    validation: tuple[PreconditionResult, ...] = ()


GovernedRecipeExecutor: TypeAlias = Callable[
    [VerifiedActionRecipe, ReuseRequest], Awaitable[RecipeExecution] | RecipeExecution
]
NormalAgentExecutor: TypeAlias = Callable[
    [ReuseRequest], Awaitable[NormalExecution] | NormalExecution
]
RecipeVerifier: TypeAlias = Callable[
    [ReuseRequest, RecipeExecution, VerifiedActionRecipe | None],
    Awaitable[RecipeVerification] | RecipeVerification,
]


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class VerifiedActionCache:
    """In-memory verified recipe store with mandatory fresh-state validation.

    It intentionally has no handler registry and no direct side-effect API.
    Consequently, reuse cannot bypass a host application's policy, approvals,
    permissions, or runtime confirmation: those must occur in
    ``governed_executor`` on every invocation.
    """

    def __init__(
        self,
        *,
        similarity_matcher: RecipeSimilarityMatcher | None = None,
        similarity_threshold: float = 0.8,
    ) -> None:
        if not 0 <= similarity_threshold <= 1:
            raise ValueError("similarity_threshold must be between 0 and 1")
        self._recipes: dict[str, VerifiedActionRecipe] = {}
        self._similarity_matcher = (
            similarity_matcher or NormalizedIntentSimilarityMatcher()
        )
        self._similarity_threshold = similarity_threshold
        self.metrics = CacheMetrics()

    def store(self, recipe: VerifiedActionRecipe) -> None:
        """Store only recipes produced by successful, verified runs."""

        if not recipe.successful or not recipe.verified:
            raise ValueError("only successful, verified recipes may be cached")
        self._recipes[recipe.recipe_id] = recipe

    def discard(self, recipe_id: str) -> None:
        """Forget a recipe whose durable source is no longer available."""

        self._recipes.pop(recipe_id, None)

    def recipes(self) -> tuple[VerifiedActionRecipe, ...]:
        """Return verified recipes for a host-owned conservative matcher."""

        return tuple(
            recipe
            for recipe in self._recipes.values()
            if recipe.successful and recipe.verified
        )

    def lookup(self, request: ReuseRequest) -> CacheMatch | None:
        """Find an exact match before considering the pluggable similarity path."""

        verified = tuple(
            recipe
            for recipe in self._recipes.values()
            if recipe.successful and recipe.verified
        )
        for recipe in verified:
            if recipe.exact_fingerprint == request.exact_fingerprint:
                self.metrics.cache_hit += 1
                return CacheMatch(recipe, CacheMatchKind.EXACT, 1.0)

        candidates = (
            (self._similarity_matcher.score(request, recipe), recipe)
            for recipe in verified
        )
        best: tuple[float, VerifiedActionRecipe | None] = max(
            candidates,
            default=(0.0, None),
            key=lambda item: item[0],
        )
        score, candidate_recipe = best
        if candidate_recipe is not None and score >= self._similarity_threshold:
            self.metrics.cache_hit += 1
            return CacheMatch(candidate_recipe, CacheMatchKind.SIMILAR, score)
        self.metrics.cache_miss += 1
        return None

    async def execute_or_fallback(
        self,
        request: ReuseRequest,
        *,
        precondition_validator: RecipePreconditionValidator,
        governed_executor: GovernedRecipeExecutor,
        normal_executor: NormalAgentExecutor,
        verifier: RecipeVerifier,
    ) -> CacheExecutionResult:
        """Reuse safely, or fall back to ordinary execution and verification.

        The cache validates current state before reuse and calls the verifier
        after *every* execution.  A failed validation runs the normal agent
        path.  A governed action whose verification fails is returned as
        ``REUSE_UNVERIFIED`` rather than replaying another side effect.
        """

        match = self.lookup(request)
        if match is not None:
            validation = tuple(precondition_validator.validate(match.recipe, request))
            if validation and all(item.passed for item in validation):
                execution = await _resolve(governed_executor(match.recipe, request))
                verification = await _resolve(
                    verifier(request, execution, match.recipe)
                )
                if verification.verified:
                    self.metrics.successful_reuse += 1
                    self.metrics.tokens_avoided += max(
                        match.recipe.original_token_usage - execution.token_usage, 0
                    )
                    return CacheExecutionResult(
                        CacheOutcome.REUSED,
                        execution,
                        verification,
                        match.recipe,
                        match,
                        validation,
                    )
                return CacheExecutionResult(
                    CacheOutcome.REUSE_UNVERIFIED,
                    execution,
                    verification,
                    match.recipe,
                    match,
                    validation,
                )
            else:
                self.metrics.validation_failure += 1

        self.metrics.fallback += 1
        normal = await _resolve(normal_executor(request))
        verification = await _resolve(verifier(request, normal.result, normal.recipe))
        if normal.recipe is not None and verification.verified:
            recipe = replace(normal.recipe, verification_evidence=verification.evidence)
            self.store(recipe)
        else:
            recipe = normal.recipe
        return CacheExecutionResult(
            CacheOutcome.FALLBACK,
            normal.result,
            verification,
            recipe,
            match,
            () if match is None else validation,
        )
