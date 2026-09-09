"""A deliberately small file-write demo built on :mod:`verified_action_cache`.

``FileWriteCacheDemo`` never writes files itself.  Both the first execution and
a recipe reuse call the same application-supplied ``governed_writer``.  In a
RunMantle application that callback should invoke ``MediatedActionExecutor`` or
``SafeFunctionTool`` so policy, approvals, permissions, and postconditions are
evaluated again on every write.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias

from .verified_action_cache import (
    CacheExecutionResult,
    NormalExecution,
    PreconditionResult,
    RecipeExecution,
    RecipePreconditionValidator,
    RecipeStep,
    RecipeVerification,
    ReuseRequest,
    VerificationEvidence,
    VerifiedActionCache,
    VerifiedActionRecipe,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_digest(path: Path) -> str | None:
    return _sha256(path.read_bytes()) if path.is_file() else None


@dataclass(frozen=True, slots=True)
class FileWriteTask:
    task_id: str
    run_id: str
    intent: str
    path: Path
    content: bytes


class FileWriteStateValidator(RecipePreconditionValidator):
    """Checks the actual current target state; it never trusts cached state."""

    def validate(
        self, recipe: VerifiedActionRecipe, request: ReuseRequest
    ) -> Sequence[PreconditionResult]:
        del request
        condition = recipe.preconditions["file_state"]
        path = Path(condition["path"])
        actual = _file_digest(path)
        allowed = tuple(condition["allowed_digests"])
        return (
            PreconditionResult(
                "file-state",
                actual in allowed,
                "target file state is safe for the cached write"
                if actual in allowed
                else "target file changed since the verified recipe",
            ),
        )


GovernedFileWriter: TypeAlias = Callable[[FileWriteTask], Awaitable[Any] | Any]
AgentDiscovery: TypeAlias = Callable[[FileWriteTask], Awaitable[int] | int]


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class FileWriteCacheDemo:
    """Demo orchestration for a repeatable, idempotent file-write task.

    The source state's digest and desired-content digest are both allowed.  The
    latter permits a repeat request after the first verified write; any other
    intervening edit fails validation and invokes ordinary agent discovery.
    """

    def __init__(
        self,
        *,
        cache: VerifiedActionCache,
        governed_writer: GovernedFileWriter,
        agent_discovery: AgentDiscovery,
    ) -> None:
        self.cache = cache
        self.governed_writer = governed_writer
        self.agent_discovery = agent_discovery
        self.validator = FileWriteStateValidator()

    async def execute(self, task: FileWriteTask) -> CacheExecutionResult:
        request = ReuseRequest(
            task_id=task.task_id,
            run_id=task.run_id,
            task_intent=task.intent,
            relevant_inputs={"path": str(task.path), "content": task.content.hex()},
        )

        async def governed(
            recipe: VerifiedActionRecipe, current: ReuseRequest
        ) -> RecipeExecution:
            del recipe, current
            await _resolve(self.governed_writer(task))
            return RecipeExecution(output={"path": str(task.path)}, token_usage=0)

        async def normal(current: ReuseRequest) -> NormalExecution:
            del current
            before_digest = _file_digest(task.path)
            discovery_tokens = await _resolve(self.agent_discovery(task))
            await _resolve(self.governed_writer(task))
            recipe = self._recipe(task, before_digest, discovery_tokens)
            return NormalExecution(
                RecipeExecution(
                    output={"path": str(task.path)}, token_usage=discovery_tokens
                ),
                recipe,
            )

        async def verify(
            current: ReuseRequest,
            execution: RecipeExecution,
            recipe: VerifiedActionRecipe | None,
        ) -> RecipeVerification:
            del current, execution, recipe
            observed_digest = _file_digest(task.path)
            expected_digest = _sha256(task.content)
            return RecipeVerification(
                verified=observed_digest == expected_digest,
                evidence=(
                    VerificationEvidence(
                        summary="file content hash observed after governed write",
                        reference=f"sha256:{observed_digest}",
                    ),
                ),
            )

        return await self.cache.execute_or_fallback(
            request,
            precondition_validator=self.validator,
            governed_executor=governed,
            normal_executor=normal,
            verifier=verify,
        )

    @staticmethod
    def _recipe(
        task: FileWriteTask,
        before_digest: str | None,
        original_token_usage: int,
    ) -> VerifiedActionRecipe:
        desired_digest = _sha256(task.content)
        return VerifiedActionRecipe(
            recipe_id=f"file-write:{task.run_id}",
            normalized_task_intent=task.intent,
            tool_capability_sequence=(
                RecipeStep("write_file", "filesystem.write", side_effecting=True),
            ),
            relevant_inputs={"path": str(task.path), "content": task.content.hex()},
            preconditions={
                "file_state": {
                    "path": str(task.path),
                    "allowed_digests": (before_digest, desired_digest),
                }
            },
            execution_strategy={"operation": "write_bytes", "idempotent": True},
            expected_outcome={"sha256": desired_digest},
            verification_evidence=(
                VerificationEvidence(
                    "source run verified file content independently",
                    f"sha256:{desired_digest}",
                ),
            ),
            recipe_version="1",
            source_task_id=task.task_id,
            source_run_id=task.run_id,
            original_token_usage=original_token_usage,
        )
