from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from runmantle import (
    CacheOutcome,
    FileWriteCacheDemo,
    FileWriteTask,
    NormalExecution,
    PreconditionResult,
    RecipeExecution,
    RecipeStep,
    RecipeVerification,
    ReuseRequest,
    VerificationEvidence,
    VerifiedActionCache,
    VerifiedActionRecipe,
)


def recipe(*, intent: str = "write report") -> VerifiedActionRecipe:
    return VerifiedActionRecipe(
        recipe_id="recipe-1",
        normalized_task_intent=intent,
        tool_capability_sequence=(RecipeStep("write_file", "filesystem.write", True),),
        relevant_inputs={"path": "report.txt", "content": "done"},
        preconditions={"target": "checked at reuse time"},
        execution_strategy={"operation": "write"},
        expected_outcome={"content": "done"},
        verification_evidence=(VerificationEvidence("file hash matched"),),
        recipe_version="1",
        source_task_id="source-task",
        source_run_id="source-run",
        original_token_usage=100,
    )


class PassingValidator:
    def validate(
        self, cached: VerifiedActionRecipe, request: ReuseRequest
    ) -> tuple[PreconditionResult, ...]:
        del cached, request
        return (PreconditionResult("state", True, "state freshly checked"),)


class FailingValidator:
    def validate(
        self, cached: VerifiedActionRecipe, request: ReuseRequest
    ) -> tuple[PreconditionResult, ...]:
        del cached, request
        return (PreconditionResult("state", False, "state is stale"),)


def request(intent: str = "write report") -> ReuseRequest:
    return ReuseRequest(
        task_id="task-2",
        run_id="run-2",
        task_intent=intent,
        relevant_inputs={"path": "report.txt", "content": "done"},
    )


async def verified(*args: object) -> RecipeVerification:
    del args
    return RecipeVerification(True, (VerificationEvidence("fresh outcome check"),))


class VerifiedActionCacheTest(unittest.IsolatedAsyncioTestCase):
    async def test_exact_cache_hit(self) -> None:
        cache = VerifiedActionCache()
        cache.store(recipe())
        calls = 0

        async def governed(*args: object) -> RecipeExecution:
            nonlocal calls
            del args
            calls += 1
            return RecipeExecution({"written": True}, token_usage=5)

        async def normal(_: ReuseRequest) -> NormalExecution:
            self.fail("exact cache hit must not use normal agent execution")

        result = await cache.execute_or_fallback(
            request(),
            precondition_validator=PassingValidator(),
            governed_executor=governed,
            normal_executor=normal,
            verifier=verified,
        )

        self.assertEqual(result.outcome, CacheOutcome.REUSED)
        self.assertEqual(calls, 1)
        self.assertEqual(cache.metrics.cache_hit, 1)
        self.assertEqual(cache.metrics.tokens_avoided, 95)

    async def test_cache_miss_uses_normal_execution_and_stores_verified_recipe(
        self,
    ) -> None:
        cache = VerifiedActionCache()
        calls = 0

        async def normal(_: ReuseRequest) -> NormalExecution:
            nonlocal calls
            calls += 1
            return NormalExecution(RecipeExecution({"written": True}, 100), recipe())

        result = await cache.execute_or_fallback(
            request(),
            precondition_validator=PassingValidator(),
            governed_executor=lambda *_: self.fail("should not reuse on a miss"),
            normal_executor=normal,
            verifier=verified,
        )

        self.assertEqual(result.outcome, CacheOutcome.FALLBACK)
        self.assertEqual(calls, 1)
        self.assertEqual(cache.metrics.cache_miss, 1)
        self.assertEqual(cache.metrics.fallback, 1)
        self.assertIsNotNone(cache.lookup(request()))

    async def test_stale_precondition_falls_back_without_replaying_cached_action(
        self,
    ) -> None:
        cache = VerifiedActionCache()
        cache.store(recipe())
        normal_calls = 0

        async def unsafe_cached_action(*args: object) -> RecipeExecution:
            del args
            self.fail("stale cache entries must not replay side effects")

        async def normal(_: ReuseRequest) -> NormalExecution:
            nonlocal normal_calls
            normal_calls += 1
            return NormalExecution(RecipeExecution({"replanned": True}, 100), recipe())

        result = await cache.execute_or_fallback(
            request(),
            precondition_validator=FailingValidator(),
            governed_executor=unsafe_cached_action,
            normal_executor=normal,
            verifier=verified,
        )

        self.assertEqual(result.outcome, CacheOutcome.FALLBACK)
        self.assertEqual(normal_calls, 1)
        self.assertEqual(cache.metrics.validation_failure, 1)

    async def test_policy_and_approval_are_enforced_on_reuse(self) -> None:
        cache = VerifiedActionCache()
        cache.store(recipe())
        policy_checks = 0
        approved = False

        async def governed(*args: object) -> RecipeExecution:
            nonlocal policy_checks
            del args
            policy_checks += 1
            if not approved:
                raise PermissionError("approval is required for filesystem.write")
            return RecipeExecution({"written": True})

        async def normal(_: ReuseRequest) -> NormalExecution:
            self.fail("denied governed reuse must not switch to an ungoverned path")

        with self.assertRaises(PermissionError):
            await cache.execute_or_fallback(
                request(),
                precondition_validator=PassingValidator(),
                governed_executor=governed,
                normal_executor=normal,
                verifier=verified,
            )
        self.assertEqual(policy_checks, 1)

    async def test_file_write_demo_reuses_and_verifies_a_similar_task(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            agent_calls = 0
            governed_calls = 0

            async def discovery(_: FileWriteTask) -> int:
                nonlocal agent_calls
                agent_calls += 1
                return 120

            async def governed_write(task: FileWriteTask) -> None:
                nonlocal governed_calls
                governed_calls += 1
                path.write_bytes(task.content)

            cache = VerifiedActionCache()
            demo = FileWriteCacheDemo(
                cache=cache,
                governed_writer=governed_write,
                agent_discovery=discovery,
            )
            first = await demo.execute(
                FileWriteTask(
                    "first-task", "first-run", "write deployment report", path, b"done"
                )
            )
            second = await demo.execute(
                FileWriteTask(
                    "second-task",
                    "second-run",
                    "write report deployment",
                    path,
                    b"done",
                )
            )

            self.assertEqual(first.outcome, CacheOutcome.FALLBACK)
            self.assertEqual(second.outcome, CacheOutcome.REUSED)
            self.assertEqual(agent_calls, 1)
            self.assertEqual(governed_calls, 2)
            self.assertEqual(path.read_bytes(), b"done")
            self.assertEqual(cache.metrics.successful_reuse, 1)
            self.assertEqual(cache.metrics.tokens_avoided, 120)

    async def test_file_write_stale_state_falls_back_to_normal_agent_execution(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            agent_calls = 0

            async def discovery(_: FileWriteTask) -> int:
                nonlocal agent_calls
                agent_calls += 1
                return 80

            def governed_write(task: FileWriteTask) -> None:
                task.path.write_bytes(task.content)

            demo = FileWriteCacheDemo(
                cache=VerifiedActionCache(),
                governed_writer=governed_write,
                agent_discovery=discovery,
            )
            await demo.execute(
                FileWriteTask("one", "run-one", "write report", path, b"done")
            )
            path.write_bytes(b"intervening unverified change")
            result = await demo.execute(
                FileWriteTask("two", "run-two", "write report", path, b"done")
            )

            self.assertEqual(result.outcome, CacheOutcome.FALLBACK)
            self.assertEqual(agent_calls, 2)
            self.assertEqual(demo.cache.metrics.validation_failure, 1)
