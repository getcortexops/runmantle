from __future__ import annotations

import asyncio
import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Lock
from typing import Any

from runmantle import (
    ActionExecutionStatus,
    ActionPolicy,
    ActionPolicyDecision,
    ActionPostconditionStatus,
    ActionReceipt,
    ActionReceiptEvidenceProvider,
    ActionRequest,
    CallableEvidenceProvider,
    CapabilityDeclaration,
    CapabilityRegistry,
    ConcurrentUpdateError,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceIntegrityError,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FileEvidenceProvider,
    FunctionWorker,
    InvalidTransitionError,
    LifecycleEventType,
    MediatedActionExecutor,
    PersistenceStore,
    Postcondition,
    PreActionAuthorization,
    Precondition,
    RiskLevel,
    RuleBasedVerifier,
    SafeFunctionTool,
    SafeJsonCodec,
    SQLiteStore,
    TaskContext,
    TaskContract,
    TaskStatus,
    VerificationStatus,
    WorkerReport,
)

NOW = datetime(2026, 8, 29, 15, 0, tzinfo=UTC)
WRITE_CAPABILITY = "write_file"


def contract(
    task_id: str,
    *,
    allowed_capabilities: frozenset[str] = frozenset({WRITE_CAPABILITY}),
    required_evidence: tuple[EvidenceRequirement, ...] = (),
    criteria: tuple[Any, ...] | None = None,
) -> TaskContract[dict[str, Any], dict[str, Any]]:
    return TaskContract(
        task_id=task_id,
        objective="Execute one mediated write and verify its postcondition.",
        input={},
        acceptance_criteria=criteria
        or (
            FieldEqualsCriterion(
                name="output-acknowledged",
                description="The executor returned an acknowledgement.",
                field_path="acknowledged",
                expected=True,
            ),
        ),
        required_evidence=required_evidence,
        allowed_capabilities=allowed_capabilities,
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}-task-key",
        metadata={"contract_revision": 1},
    )


def placeholder_worker() -> FunctionWorker[dict[str, Any], dict[str, Any]]:
    async def execute(
        task: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del task, context
        return WorkerReport.completed({"acknowledged": True})

    return FunctionWorker(
        id="action-test-worker",
        name="Action test worker",
        role="test",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name=WRITE_CAPABILITY,
                description="Write through the mediated test boundary.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )


def start_running(
    path: Path,
    task_contract: TaskContract[Any, Any],
) -> DurableRuntime:
    runtime = DurableRuntime(database_path=path, clock=lambda: NOW)
    pending = runtime.start(
        placeholder_worker(),
        task_contract,
        correlation_id=f"{task_contract.task_id}-correlation",
    )
    runtime.store.transition(
        task_contract.task_id,
        expected_version=pending.version,
        next_status=TaskStatus.RUNNING,
        occurred_at=NOW,
    )
    return runtime


def action_executor(
    store: PersistenceStore,
    *,
    evidence_providers: EvidenceProviderRegistry | None = None,
) -> MediatedActionExecutor:
    return MediatedActionExecutor(
        store=store,
        capabilities=CapabilityRegistry(
            (
                CapabilityDeclaration(
                    name=WRITE_CAPABILITY,
                    description="Write through the mediated test boundary.",
                    requires_runtime_confirmation=False,
                ),
            )
        ),
        policy=ActionPolicy(
            allowed_capabilities=frozenset({WRITE_CAPABILITY}),
            maximum_risk_level=RiskLevel.LOW,
        ),
        evidence_providers=evidence_providers,
        clock=lambda: NOW,
        id_factory=lambda: "receipt-1",
    )


def action_request(task_id: str, *, action_id: str = "action-1") -> ActionRequest:
    return ActionRequest(
        action_id=action_id,
        task_id=task_id,
        name="write-file",
        required_capability=WRITE_CAPABILITY,
        input={"path": "artifact.txt", "content": "complete"},
        idempotency_key="write-artifact-once",
        risk_level=RiskLevel.LOW,
        requested_by="test-worker",
        requested_at=NOW,
        execution_handler_id="tests.write_artifact:v1",
    )


class MediatedActionExecutorTest(unittest.IsolatedAsyncioTestCase):
    def test_action_hash_binds_every_security_relevant_semantic(self) -> None:
        class Provider:
            async def acquire(self, request: Any, receipt: Any) -> tuple[Any, ...]:
                del request, receipt
                return ()

        def precondition(request: ActionRequest) -> bool:
            return bool(request.input)

        base = replace(
            action_request("manifest-task"),
            metadata={"tenant": "one"},
            preconditions=(
                Precondition("ready", "Repository is ready.", precondition),
            ),
            postconditions=(
                Postcondition(
                    "observed",
                    "Observe the result.",
                    Provider(),
                    evidence_type="state",
                    provider_identity="tests.Provider:v1",
                    provider_configuration={"endpoint": "primary"},
                ),
            ),
        )
        variants = (
            replace(base, name="delete-file"),
            replace(base, required_capability="delete_file"),
            replace(base, input={"path": "other.txt"}),
            replace(base, idempotency_key="different-key"),
            replace(base, risk_level=RiskLevel.HIGH),
            replace(base, requested_by="different-worker"),
            replace(base, execution_handler_id="tests.write_artifact:v2"),
            replace(base, timeout=timedelta(seconds=31)),
            replace(base, metadata={"tenant": "two"}),
            replace(
                base,
                preconditions=(
                    Precondition("ready", "Different condition.", precondition),
                ),
            ),
            replace(
                base,
                postconditions=(
                    Postcondition(
                        "observed",
                        "Observe the result.",
                        Provider(),
                        evidence_type="state",
                        provider_identity="tests.Provider:v2",
                        provider_configuration={"endpoint": "secondary"},
                    ),
                ),
            ),
        )

        self.assertEqual(
            len({base.action_hash, *(item.action_hash for item in variants)}), 12
        )
        self.assertNotIn("0x", SafeJsonCodec().dumps(base.approval_manifest))

    async def test_modified_handler_cannot_reuse_existing_approval(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("modified-approved-action")
            runtime = start_running(path, task_contract)
            executor = MediatedActionExecutor(
                store=runtime.store,
                capabilities=CapabilityRegistry(
                    (
                        CapabilityDeclaration(
                            name=WRITE_CAPABILITY,
                            description="Approved mediated write.",
                            requires_approval=True,
                        ),
                    )
                ),
                policy=ActionPolicy(allowed_capabilities=frozenset({WRITE_CAPABILITY})),
                clock=lambda: NOW,
            )
            request = action_request(task_contract.task_id)

            async def handler(arguments: Any, cancellation: Any) -> Any:
                del arguments, cancellation
                return {"acknowledged": True}

            await executor.execute(request, contract=task_contract, handler=handler)
            runtime.decide_approval(
                task_contract.task_id,
                approval_key=request.approval_key,
                approved=True,
                approved_by="release-owner",
                reason="Approved v1 only.",
                approval_id=request.approval_id,
            )

            modified = replace(request, execution_handler_id="tests.write_artifact:v2")
            self.assertNotEqual(request.approval_key, modified.approval_key)
            with self.assertRaises(ConcurrentUpdateError):
                await executor.execute(
                    modified,
                    contract=task_contract,
                    handler=handler,
                )

    async def test_missing_capability_blocks_without_invoking_handler(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract(
                "missing-capability",
                allowed_capabilities=frozenset(),
            )
            runtime = start_running(path, task_contract)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            result = await action_executor(runtime.store).execute(
                action_request(task_contract.task_id),
                contract=task_contract,
                handler=handler,
                granted_capabilities=frozenset(),
            )

            self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
            self.assertEqual(calls, 0)
            self.assertFalse(result.executor_succeeded)
            event_types = {
                event.event_type
                for event in runtime.event_history(task_contract.task_id)
            }
            self.assertIn(LifecycleEventType.ACTION_REQUESTED, event_types)
            self.assertIn(LifecycleEventType.ACTION_POLICY_DECIDED, event_types)
            self.assertIn(LifecycleEventType.ACTION_BLOCKED, event_types)

    async def test_duplicate_idempotency_key_does_not_repeat_action(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("duplicate-action")
            runtime = start_running(path, task_contract)
            executor = action_executor(runtime.store)
            request = action_request(task_contract.task_id)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                executing = runtime.store.load_action(request.action_id)
                self.assertEqual(
                    executing.status,
                    ActionExecutionStatus.EXECUTING,
                )
                return {"acknowledged": True}

            first = await executor.execute(
                request,
                contract=task_contract,
                handler=handler,
            )
            duplicate = await executor.execute(
                action_request(task_contract.task_id, action_id="another-request-id"),
                contract=task_contract,
                handler=handler,
            )

            self.assertEqual(calls, 1)
            self.assertEqual(
                first.action.status,
                ActionExecutionStatus.EXECUTOR_SUCCEEDED,
            )
            self.assertEqual(duplicate.action.action_id, request.action_id)
            self.assertTrue(duplicate.duplicate_prevented)

    async def test_exact_approval_continues_same_durable_action(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("action-approval")
            runtime = start_running(path, task_contract)
            executor = MediatedActionExecutor(
                store=runtime.store,
                capabilities=CapabilityRegistry(
                    (
                        CapabilityDeclaration(
                            name=WRITE_CAPABILITY,
                            description="Approved mediated write.",
                            requires_approval=True,
                            requires_runtime_confirmation=False,
                        ),
                    )
                ),
                policy=ActionPolicy(
                    allowed_capabilities=frozenset({WRITE_CAPABILITY}),
                ),
                clock=lambda: NOW,
                id_factory=lambda: "approval-receipt",
            )
            request = action_request(task_contract.task_id)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            waiting = await executor.execute(
                request,
                contract=task_contract,
                handler=handler,
            )
            self.assertEqual(
                waiting.action.status,
                ActionExecutionStatus.AWAITING_APPROVAL,
            )
            self.assertEqual(calls, 0)
            pending_approval = runtime.store.approvals(task_contract.task_id)[0]
            self.assertEqual(pending_approval.approval_id, request.approval_id)
            self.assertEqual(pending_approval.approval_key, request.approval_key)
            self.assertIsNone(pending_approval.approved)
            runtime.decide_approval(
                task_contract.task_id,
                approval_key=request.approval_key,
                approved=True,
                approved_by="release-owner",
                reason="Approved the exact action hash.",
                approval_id=request.approval_id,
            )

            completed = await executor.execute(
                request,
                contract=task_contract,
                handler=handler,
            )
            self.assertEqual(
                completed.action.status,
                ActionExecutionStatus.EXECUTOR_SUCCEEDED,
            )
            self.assertEqual(completed.action.action_id, waiting.action.action_id)
            self.assertEqual(calls, 1)

    async def test_stale_approval_cannot_execute_after_task_failed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("stale-failed-approval")
            runtime = start_running(path, task_contract)
            executor = MediatedActionExecutor(
                store=runtime.store,
                capabilities=CapabilityRegistry(
                    (
                        CapabilityDeclaration(
                            WRITE_CAPABILITY,
                            "Approved mediated write.",
                            requires_approval=True,
                            requires_runtime_confirmation=False,
                        ),
                    )
                ),
                policy=ActionPolicy(allowed_capabilities=frozenset({WRITE_CAPABILITY})),
                clock=lambda: NOW,
            )
            request = action_request(task_contract.task_id)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            waiting = await executor.execute(
                request,
                contract=task_contract,
                handler=handler,
            )
            task = runtime.store.load_task(task_contract.task_id)
            runtime.store.transition(
                task_contract.task_id,
                expected_version=task.version,
                next_status=TaskStatus.FAILED,
                occurred_at=NOW,
            )
            runtime.decide_approval(
                task_contract.task_id,
                approval_key=request.approval_key,
                approved=True,
                approved_by="release-owner",
                reason="Approval arrived after the task failed.",
                approval_id=request.approval_id,
            )

            with self.assertRaises(InvalidTransitionError):
                await executor.execute(
                    request,
                    contract=task_contract,
                    handler=handler,
                )

            self.assertEqual(
                waiting.action.status,
                ActionExecutionStatus.AWAITING_APPROVAL,
            )
            self.assertEqual(calls, 0)

    async def test_stale_approval_cannot_execute_after_context_version_change(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("stale-context-approval")
            runtime = start_running(path, task_contract)
            executor = MediatedActionExecutor(
                store=runtime.store,
                capabilities=CapabilityRegistry(
                    (
                        CapabilityDeclaration(
                            WRITE_CAPABILITY,
                            "Approved mediated write.",
                            requires_approval=True,
                            requires_runtime_confirmation=False,
                        ),
                    )
                ),
                policy=ActionPolicy(allowed_capabilities=frozenset({WRITE_CAPABILITY})),
                clock=lambda: NOW,
            )
            request = action_request(task_contract.task_id)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            await executor.execute(request, contract=task_contract, handler=handler)
            before = runtime.store.load_task(task_contract.task_id)
            runtime.store.record_evidence(
                task_contract.task_id,
                EvidenceItem(
                    "context-change",
                    "audit_context",
                    "application",
                    NOW,
                    payload={"revision": 2},
                ),
            )
            after = runtime.store.load_task(task_contract.task_id)
            self.assertGreater(
                after.execution_context_version,
                before.execution_context_version,
            )
            runtime.decide_approval(
                task_contract.task_id,
                approval_key=request.approval_key,
                approved=True,
                approved_by="release-owner",
                reason="Stale after context change.",
                approval_id=request.approval_id,
            )

            with self.assertRaises(InvalidTransitionError):
                await executor.execute(
                    request,
                    contract=task_contract,
                    handler=handler,
                )
            self.assertEqual(calls, 0)

    async def test_approved_action_rejects_changed_parameters_and_capability(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("changed-approved-action")
            runtime = start_running(path, task_contract)
            executor = MediatedActionExecutor(
                store=runtime.store,
                capabilities=CapabilityRegistry(
                    (
                        CapabilityDeclaration(
                            WRITE_CAPABILITY,
                            "Approved mediated write.",
                            requires_approval=True,
                            requires_runtime_confirmation=False,
                        ),
                    )
                ),
                policy=ActionPolicy(allowed_capabilities=frozenset({WRITE_CAPABILITY})),
                clock=lambda: NOW,
            )
            request = action_request(task_contract.task_id)

            async def handler(arguments: Any, cancellation: Any) -> Any:
                del arguments, cancellation
                raise AssertionError("changed approved action must not execute")

            await executor.execute(request, contract=task_contract, handler=handler)
            runtime.decide_approval(
                task_contract.task_id,
                approval_key=request.approval_key,
                approved=True,
                approved_by="release-owner",
                reason="Approve the original request only.",
                approval_id=request.approval_id,
            )

            for changed in (
                replace(request, input={"path": "different.txt"}),
                replace(request, required_capability="different_capability"),
            ):
                with self.subTest(action_hash=changed.action_hash):
                    with self.assertRaises(ConcurrentUpdateError):
                        await executor.execute(
                            changed,
                            contract=task_contract,
                            handler=handler,
                        )

    async def test_task_transition_and_approval_execution_are_atomically_ordered(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("concurrent-approval-context")
            runtime = start_running(path, task_contract)
            order: list[str] = []
            order_lock = Lock()

            class OrderingStore(SQLiteStore):
                def mark_action_executing(
                    self, *args: Any, **kwargs: Any
                ) -> tuple[Any, Any]:
                    result = super().mark_action_executing(*args, **kwargs)
                    with order_lock:
                        order.append("action-authority")
                    return result

            executor = MediatedActionExecutor(
                store=OrderingStore(path),
                capabilities=CapabilityRegistry(
                    (
                        CapabilityDeclaration(
                            WRITE_CAPABILITY,
                            "Approved mediated write.",
                            requires_approval=True,
                            requires_runtime_confirmation=False,
                        ),
                    )
                ),
                policy=ActionPolicy(allowed_capabilities=frozenset({WRITE_CAPABILITY})),
                clock=lambda: NOW,
            )
            request = action_request(task_contract.task_id)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            await executor.execute(request, contract=task_contract, handler=handler)
            runtime.decide_approval(
                task_contract.task_id,
                approval_key=request.approval_key,
                approved=True,
                approved_by="release-owner",
                reason="Approve before the concurrent transition.",
                approval_id=request.approval_id,
            )
            task = runtime.store.load_task(task_contract.task_id)
            barrier = Barrier(2)

            def execute_action() -> object:
                barrier.wait()
                try:
                    return asyncio.run(
                        executor.execute(
                            request,
                            contract=task_contract,
                            handler=handler,
                        )
                    )
                except InvalidTransitionError as error:
                    return error

            def fail_task() -> object:
                barrier.wait()
                try:
                    result = runtime.store.transition(
                        task_contract.task_id,
                        expected_version=task.version,
                        next_status=TaskStatus.FAILED,
                        occurred_at=NOW,
                    )
                    with order_lock:
                        order.append("task-transition")
                    return result
                except ConcurrentUpdateError as error:
                    return error

            with ThreadPoolExecutor(max_workers=2) as pool:
                action_future = pool.submit(execute_action)
                transition_future = pool.submit(fail_task)
                action_result = action_future.result()
                transition_result = transition_future.result()

            self.assertNotIsInstance(transition_result, InvalidTransitionError)
            if order[0] == "task-transition":
                self.assertIsInstance(action_result, InvalidTransitionError)
                self.assertEqual(calls, 0)
            else:
                self.assertEqual(order[0], "action-authority")
                self.assertEqual(calls, 1)

    async def test_same_executor_duplicate_does_not_mark_live_action_unknown(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("in-flight-duplicate")
            runtime = start_running(path, task_contract)
            executor = action_executor(runtime.store)
            request = action_request(task_contract.task_id)
            started = asyncio.Event()
            release = asyncio.Event()
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                started.set()
                await release.wait()
                return {"acknowledged": True}

            first_task = asyncio.create_task(
                executor.execute(
                    request,
                    contract=task_contract,
                    handler=handler,
                )
            )
            await started.wait()
            duplicate = await executor.execute(
                request,
                contract=task_contract,
                handler=handler,
            )
            self.assertEqual(
                duplicate.action.status,
                ActionExecutionStatus.EXECUTING,
            )
            self.assertTrue(duplicate.duplicate_prevented)
            self.assertEqual(calls, 1)
            release.set()
            first = await first_task
            self.assertEqual(
                first.action.status,
                ActionExecutionStatus.EXECUTOR_SUCCEEDED,
            )

    async def test_restart_during_execution_becomes_unknown_without_reexecution(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("interrupted-action")
            runtime = start_running(path, task_contract)
            request = action_request(task_contract.task_id)
            stored, _, _ = runtime.store.prepare_action(
                request,
                dry_run=False,
                occurred_at=NOW,
            )
            stored, _ = runtime.store.record_action_policy(
                request.action_id,
                expected_version=stored.version,
                decision=ActionPolicyDecision(
                    allowed=True,
                    reasons=("test authorization",),
                    requires_approval=False,
                    decided_at=NOW,
                ),
            )
            stored, _ = runtime.store.record_action_authorization(
                request.action_id,
                expected_version=stored.version,
                authorization=PreActionAuthorization(
                    authorized=True,
                    reason="test authorization",
                    evaluated_preconditions=(),
                    approved_by=None,
                    authorized_at=NOW,
                ),
            )
            stored, _ = runtime.store.mark_action_executing(
                request.action_id,
                expected_version=stored.version,
                occurred_at=NOW,
                owner_id="crashed-executor-instance",
            )
            self.assertEqual(stored.status, ActionExecutionStatus.EXECUTING)
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            reopened = SQLiteStore(path)
            result = await action_executor(reopened).execute(
                request,
                contract=task_contract,
                handler=handler,
            )

            self.assertEqual(calls, 0)
            self.assertEqual(result.action.status, ActionExecutionStatus.UNKNOWN)
            self.assertIsNone(result.action.receipt)
            self.assertFalse(result.executor_succeeded)
            self.assertFalse(result.verified_outcome)

    async def test_timeout_is_unknown_and_dry_run_never_invokes_handler(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("timeout-action")
            runtime = start_running(path, task_contract)
            executor = action_executor(runtime.store)
            timeout_request = replace(
                action_request(task_contract.task_id),
                timeout=timedelta(milliseconds=1),
            )

            async def slow_handler(arguments: Any, cancellation: Any) -> Any:
                del arguments, cancellation
                await asyncio.sleep(1)
                return {"acknowledged": True}

            timed_out = await executor.execute(
                timeout_request,
                contract=task_contract,
                handler=slow_handler,
            )
            self.assertEqual(timed_out.action.status, ActionExecutionStatus.UNKNOWN)

            dry_contract = contract("dry-run-action")
            dry_runtime = start_running(Path(directory) / "dry.db", dry_contract)
            calls = 0

            async def counted_handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"acknowledged": True}

            dry = await action_executor(dry_runtime.store).execute(
                action_request(dry_contract.task_id),
                contract=dry_contract,
                handler=counted_handler,
                dry_run=True,
            )
            self.assertEqual(dry.action.status, ActionExecutionStatus.DRY_RUN)
            self.assertEqual(calls, 0)


class ActionEvidenceFlowTest(unittest.IsolatedAsyncioTestCase):
    async def test_required_postcondition_returning_no_evidence_fails_task(
        self,
    ) -> None:
        class EmptyEvidenceProvider:
            async def acquire(
                self,
                request: Any,
                receipt: Any,
            ) -> tuple[EvidenceItem, ...]:
                del request, receipt
                return ()

        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("empty-required-postcondition")
            runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            tool = SafeFunctionTool(
                name="write-file",
                description="Return an executor acknowledgement.",
                required_capability=WRITE_CAPABILITY,
                function=lambda **arguments: {"acknowledged": bool(arguments)},
                executor=action_executor(runtime.store),
                postconditions=(
                    Postcondition(
                        name="required-empty",
                        description="A required provider must return evidence.",
                        provider=EmptyEvidenceProvider(),
                        evidence_type="external_state",
                        required=True,
                    ),
                ),
                id_factory=lambda: "empty-required-action",
            )

            async def execute(
                task: TaskContract[dict[str, Any], dict[str, Any]],
                context: TaskContext,
            ) -> WorkerReport[dict[str, Any]]:
                await tool.invoke(
                    contract=task,
                    context=context,
                    arguments={"path": "artifact.txt"},
                    idempotency_key="empty-required-once",
                )
                return WorkerReport.completed({"acknowledged": True})

            worker = FunctionWorker(
                id="empty-required-worker",
                name="Empty required evidence worker",
                role="test",
                version="1.0.0",
                capabilities=placeholder_worker().capabilities,
                handler=execute,
            )
            result = await runtime.execute(worker, task_contract)

            self.assertEqual(result.status, TaskStatus.FAILED)
            self.assertFalse(result.succeeded)
            self.assertTrue(
                any(
                    "required provider returned no outcome evidence" in error.message
                    for error in result.errors
                )
            )
            stored_action = runtime.store.load_action("empty-required-action")
            self.assertEqual(
                stored_action.status,
                ActionExecutionStatus.EXECUTOR_SUCCEEDED,
            )
            event_types = {
                event.event_type
                for event in runtime.event_history(task_contract.task_id)
            }
            self.assertIn(
                LifecycleEventType.ACTION_POSTCONDITION_FAILED,
                event_types,
            )

    async def test_executor_receipt_is_not_independent_verified_outcome(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract(
                "receipt-is-not-proof",
                required_evidence=(
                    EvidenceRequirement(
                        "action_receipt",
                        "An independently trusted postcondition is required.",
                        minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
                    ),
                ),
                criteria=(
                    FieldEqualsCriterion(
                        name="receipt-success",
                        description="Receipt claims executor success.",
                        field_path="status",
                        expected=ActionExecutionStatus.EXECUTOR_SUCCEEDED.value,
                        evidence_type="action_receipt",
                    ),
                ),
            )
            runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            executor = action_executor(runtime.store)
            tool = SafeFunctionTool(
                name="write-file",
                description="Return an executor acknowledgement.",
                required_capability=WRITE_CAPABILITY,
                function=lambda **arguments: {"acknowledged": bool(arguments)},
                executor=executor,
                postconditions=(
                    Postcondition(
                        name="receipt",
                        description="Capture the executor receipt.",
                        provider=ActionReceiptEvidenceProvider(),
                        evidence_type="action_receipt",
                    ),
                ),
            )

            async def execute(
                task: TaskContract[dict[str, Any], dict[str, Any]],
                context: TaskContext,
            ) -> WorkerReport[dict[str, Any]]:
                action = await tool.invoke(
                    contract=task,
                    context=context,
                    arguments={"path": "artifact.txt"},
                    idempotency_key="receipt-action",
                )
                self.assertTrue(action.executor_succeeded)
                self.assertFalse(action.verified_outcome)
                assert action.action.receipt is not None
                return WorkerReport.completed(action.action.receipt.output)

            worker = FunctionWorker(
                id="receipt-worker",
                name="Receipt worker",
                role="test",
                version="1.0.0",
                capabilities=placeholder_worker().capabilities,
                handler=execute,
            )
            result = await runtime.execute(worker, task_contract)

            self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
            self.assertFalse(result.succeeded)
            self.assertEqual(len(result.evidence), 1)
            self.assertEqual(
                result.evidence[0].trust_level,
                EvidenceTrustLevel.EXECUTOR_RECEIPT,
            )

    async def test_independent_postcondition_evidence_moves_task_to_verified(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract(
                "independent-postcondition",
                required_evidence=(
                    EvidenceRequirement(
                        "external_state",
                        "Independently observe the resulting external state.",
                        minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
                        max_age=timedelta(minutes=5),
                    ),
                ),
                criteria=(
                    FieldEqualsCriterion(
                        name="external-state",
                        description="External state must be complete.",
                        field_path="complete",
                        expected=True,
                        evidence_type="external_state",
                    ),
                ),
            )
            runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            provider = CallableEvidenceProvider(
                provider=lambda request, receipt: {
                    "complete": receipt.status
                    is ActionExecutionStatus.EXECUTOR_SUCCEEDED,
                    "observed_action": request.action_hash,
                },
                evidence_type="external_state",
                source="test.independent_observer",
                trust_level=EvidenceTrustLevel.INDEPENDENT,
                acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
                ttl=timedelta(minutes=5),
            )
            provider_configuration = {
                "evidence_type": "external_state",
                "source": "test.independent_observer",
                "ttl_seconds": 300,
            }
            provider_registry = EvidenceProviderRegistry(
                (
                    EvidenceProviderRegistration(
                        provider=provider,
                        provider_identity=(
                            "test_actions.independent_external_state_provider:v1"
                        ),
                        provider_configuration=provider_configuration,
                        trust_level=EvidenceTrustLevel.INDEPENDENT,
                        acquisition_method=(
                            EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER
                        ),
                    ),
                )
            )
            tool = SafeFunctionTool(
                name="write-file",
                description="Return an executor acknowledgement.",
                required_capability=WRITE_CAPABILITY,
                function=lambda **arguments: {"acknowledged": bool(arguments)},
                executor=action_executor(
                    runtime.store,
                    evidence_providers=provider_registry,
                ),
                postconditions=(
                    Postcondition(
                        name="observe-external-state",
                        description="Inspect state independently after the write.",
                        provider=provider,
                        evidence_type="external_state",
                        provider_identity=(
                            "test_actions.independent_external_state_provider:v1"
                        ),
                        provider_configuration=provider_configuration,
                    ),
                ),
            )

            async def execute(
                task: TaskContract[dict[str, Any], dict[str, Any]],
                context: TaskContext,
            ) -> WorkerReport[dict[str, Any]]:
                action = await tool.invoke(
                    contract=task,
                    context=context,
                    arguments={"path": "artifact.txt"},
                    idempotency_key="independent-action",
                )
                assert action.action.receipt is not None
                return WorkerReport.completed(action.action.receipt.output)

            worker = FunctionWorker(
                id="independent-worker",
                name="Independent evidence worker",
                role="test",
                version="1.0.0",
                capabilities=placeholder_worker().capabilities,
                handler=execute,
            )
            result = await runtime.execute(worker, task_contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            self.assertTrue(result.succeeded)
            self.assertEqual(result.evidence[0].type, "external_state")
            self.assertEqual(
                result.evidence[0].trust_level,
                EvidenceTrustLevel.INDEPENDENT,
            )

    async def test_restart_after_executor_success_resumes_postconditions_only(
        self,
    ) -> None:
        class SimulatedProcessStop(RuntimeError):
            pass

        class Provider:
            calls = 0

            async def acquire(self, request: Any, receipt: Any) -> EvidenceItem:
                del request, receipt
                self.calls += 1
                return EvidenceItem(
                    evidence_id="restart-observation",
                    type="external_state",
                    source="restart-provider",
                    collected_at=NOW,
                    payload={"complete": True},
                )

        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract(
                "postcondition-restart",
                required_evidence=(
                    EvidenceRequirement(
                        "external_state",
                        "Runtime-observed external state.",
                    ),
                ),
                criteria=(
                    FieldEqualsCriterion(
                        name="external-complete",
                        description="The external state must be complete.",
                        field_path="complete",
                        expected=True,
                        evidence_type="external_state",
                    ),
                ),
            )
            runtime = start_running(path, task_contract)
            provider = Provider()
            postcondition = Postcondition(
                "observe-external-state",
                "Observe the external result after execution.",
                provider,
                evidence_type="external_state",
            )
            request = replace(
                action_request(task_contract.task_id),
                postconditions=(postcondition,),
            )
            registry = EvidenceProviderRegistry(
                (
                    EvidenceProviderRegistration(
                        provider=provider,
                        provider_identity=str(postcondition.provider_identity),
                        provider_configuration=postcondition.provider_configuration,
                        trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                        acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                    ),
                )
            )
            first = action_executor(runtime.store, evidence_providers=registry)
            executor_calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal executor_calls
                del arguments, cancellation
                executor_calls += 1
                return {"acknowledged": True}

            async def stop_before_postconditions(*args: Any, **kwargs: Any) -> Any:
                del args, kwargs
                raise SimulatedProcessStop("process stopped after receipt commit")

            first._acquire_postconditions = stop_before_postconditions  # type: ignore[method-assign]
            with self.assertRaises(SimulatedProcessStop):
                await first.execute(request, contract=task_contract, handler=handler)

            persisted = SQLiteStore(path).load_action(request.action_id)
            self.assertEqual(
                persisted.postcondition_status,
                ActionPostconditionStatus.PENDING,
            )
            self.assertEqual(executor_calls, 1)
            self.assertEqual(provider.calls, 0)

            resumed = await action_executor(
                SQLiteStore(path),
                evidence_providers=registry,
            ).execute(request, contract=task_contract, handler=handler)

            self.assertEqual(executor_calls, 1)
            self.assertEqual(provider.calls, 1)
            self.assertEqual(
                resumed.action.postcondition_status,
                ActionPostconditionStatus.COMPLETED,
            )
            self.assertEqual(len(resumed.outcome_evidence), 1)
            self.assertEqual(
                RuleBasedVerifier(clock=lambda: NOW)
                .verify(
                    task_contract,
                    {"acknowledged": True},
                    resumed.outcome_evidence,
                )
                .status,
                VerificationStatus.VERIFIED,
            )

    async def test_restart_during_postconditions_skips_persisted_observations(
        self,
    ) -> None:
        class SimulatedProcessStop(BaseException):
            pass

        class Provider:
            def __init__(self, name: str, *, stop_once: bool = False) -> None:
                self.name = name
                self.stop_once = stop_once
                self.calls = 0

            async def acquire(self, request: Any, receipt: Any) -> EvidenceItem:
                del request, receipt
                self.calls += 1
                if self.stop_once and self.calls == 1:
                    raise SimulatedProcessStop("process stopped during observation")
                return EvidenceItem(
                    evidence_id=f"{self.name}-evidence",
                    type=f"{self.name}_state",
                    source=f"{self.name}-provider",
                    collected_at=NOW,
                    payload={"complete": True},
                )

        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("postcondition-midphase-restart")
            runtime = start_running(path, task_contract)
            first_provider = Provider("first")
            second_provider = Provider("second", stop_once=True)
            postconditions = tuple(
                Postcondition(
                    f"observe-{provider.name}",
                    f"Observe {provider.name} state.",
                    provider,
                    evidence_type=f"{provider.name}_state",
                )
                for provider in (first_provider, second_provider)
            )
            request = replace(
                action_request(task_contract.task_id),
                postconditions=postconditions,
            )
            registry = EvidenceProviderRegistry(
                tuple(
                    EvidenceProviderRegistration(
                        provider=postcondition.provider,
                        provider_identity=str(postcondition.provider_identity),
                        provider_configuration=postcondition.provider_configuration,
                        trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                        acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                    )
                    for postcondition in postconditions
                )
            )
            executor_calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal executor_calls
                del arguments, cancellation
                executor_calls += 1
                return {"acknowledged": True}

            with self.assertRaises(SimulatedProcessStop):
                await action_executor(
                    runtime.store,
                    evidence_providers=registry,
                ).execute(request, contract=task_contract, handler=handler)

            resumed = await action_executor(
                SQLiteStore(path),
                evidence_providers=registry,
            ).execute(request, contract=task_contract, handler=handler)

            self.assertEqual(executor_calls, 1)
            self.assertEqual(first_provider.calls, 1)
            self.assertEqual(second_provider.calls, 2)
            self.assertEqual(len(resumed.outcome_evidence), 2)
            self.assertEqual(
                resumed.action.postcondition_status,
                ActionPostconditionStatus.COMPLETED,
            )

    async def test_partial_multi_item_postcondition_resumes_from_explicit_marker(
        self,
    ) -> None:
        class SimulatedProcessStop(BaseException):
            pass

        for item_count in (2, 3):
            with self.subTest(item_count=item_count), TemporaryDirectory() as directory:
                path = Path(directory) / "runtime.db"
                task_contract = contract(
                    f"multi-item-{item_count}",
                    required_evidence=(
                        EvidenceRequirement(
                            "external_state",
                            "Every provider observation must survive restart.",
                            minimum_count=item_count,
                        ),
                    ),
                    criteria=(
                        FieldEqualsCriterion(
                            "all-complete",
                            "Every observation is complete.",
                            "complete",
                            True,
                            evidence_type="external_state",
                        ),
                    ),
                )
                runtime = start_running(path, task_contract)

                class Provider:
                    calls = 0
                    expected_count = item_count

                    async def acquire(
                        self, request: Any, receipt: Any
                    ) -> tuple[EvidenceItem, ...]:
                        del request, receipt
                        self.calls += 1
                        return tuple(
                            EvidenceItem(
                                f"multi-item-{index}",
                                "external_state",
                                "multi-item-provider",
                                NOW,
                                payload={"complete": True, "index": index},
                            )
                            for index in range(self.expected_count)
                        )

                provider = Provider()
                postcondition = Postcondition(
                    "observe-all",
                    "Acquire the complete multi-item observation.",
                    provider,
                    evidence_type="external_state",
                    provider_identity="tests.multi_item_provider:v1",
                    provider_configuration={"item_count": item_count},
                )
                request = replace(
                    action_request(task_contract.task_id),
                    postconditions=(postcondition,),
                )
                registry = EvidenceProviderRegistry(
                    (
                        EvidenceProviderRegistration(
                            provider,
                            "tests.multi_item_provider:v1",
                            {"item_count": item_count},
                            EvidenceTrustLevel.RUNTIME_OBSERVED,
                            EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                        ),
                    )
                )
                executor_calls = 0

                async def handler(arguments: Any, cancellation: Any) -> Any:
                    nonlocal executor_calls
                    del arguments, cancellation
                    executor_calls += 1
                    return {"acknowledged": True}

                first = action_executor(
                    runtime.store,
                    evidence_providers=registry,
                )

                async def stop_after_receipt(*args: Any, **kwargs: Any) -> Any:
                    del args, kwargs
                    raise SimulatedProcessStop("stop before atomic provider commit")

                first._acquire_postconditions = stop_after_receipt  # type: ignore[method-assign]
                with self.assertRaises(SimulatedProcessStop):
                    await first.execute(
                        request,
                        contract=task_contract,
                        handler=handler,
                    )

                receipt = runtime.store.load_action(request.action_id).receipt
                assert receipt is not None
                raw_items = await provider.acquire(request, receipt)
                first_item = registry._establish(
                    provider,
                    raw_items[0],
                    boundary="mediated_action_postcondition",
                    provider_identity="tests.multi_item_provider:v1",
                    provider_configuration={"item_count": item_count},
                )
                assert first_item is not None
                runtime.store.record_evidence(task_contract.task_id, first_item)
                runtime.store.link_action_evidence(
                    request.action_id,
                    first_item.evidence_id,
                    postcondition_name=postcondition.name,
                    occurred_at=NOW,
                )
                self.assertEqual(
                    runtime.store.completed_action_postconditions(request.action_id),
                    frozenset(),
                )

                resumed = await action_executor(
                    SQLiteStore(path),
                    evidence_providers=registry,
                ).execute(request, contract=task_contract, handler=handler)

                self.assertEqual(executor_calls, 1)
                self.assertEqual(provider.calls, 2)
                self.assertEqual(len(resumed.outcome_evidence), item_count)
                self.assertEqual(
                    resumed.action.postcondition_status,
                    ActionPostconditionStatus.COMPLETED,
                )
                self.assertEqual(
                    RuleBasedVerifier(clock=lambda: NOW)
                    .verify(
                        task_contract,
                        {"acknowledged": True},
                        resumed.outcome_evidence,
                    )
                    .status,
                    VerificationStatus.VERIFIED,
                )


class ProductionEvidenceTest(unittest.IsolatedAsyncioTestCase):
    def test_schema_five_executor_success_migrates_to_pending_postconditions(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("action-phase-migration")
            legacy = SQLiteStore(path, target_schema_version=5)
            legacy.create_task(
                task_contract,
                correlation_id="migration-correlation",
                worker_id="migration-worker",
                occurred_at=NOW,
            )
            request = action_request(task_contract.task_id)
            legacy.prepare_action(request, dry_run=False, occurred_at=NOW)
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "UPDATE actions SET status = ? WHERE action_id = ?",
                    (
                        ActionExecutionStatus.EXECUTOR_SUCCEEDED.value,
                        request.action_id,
                    ),
                )

            migrated = SQLiteStore(path)
            action = migrated.load_action(request.action_id)

            self.assertEqual(migrated.schema_version, 7)
            self.assertEqual(
                action.postcondition_status,
                ActionPostconditionStatus.PENDING,
            )

    def test_schema_six_migrates_context_and_explicit_postcondition_markers(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("schema-six-action")
            legacy = SQLiteStore(path, target_schema_version=6)
            legacy.create_task(
                task_contract,
                correlation_id="schema-six-correlation",
                worker_id="schema-six-worker",
                occurred_at=NOW,
            )
            request = action_request(task_contract.task_id)
            legacy.prepare_action(request, dry_run=False, occurred_at=NOW)

            migrated = SQLiteStore(path)

            self.assertEqual(migrated.schema_version, 7)
            self.assertEqual(
                migrated.load_task(task_contract.task_id).execution_context_version,
                1,
            )
            self.assertIsNone(
                migrated.load_action(request.action_id).policy_task_context_version
            )
            self.assertEqual(
                migrated.completed_action_postconditions(request.action_id),
                frozenset(),
            )

    def test_schema_two_evidence_migrates_to_calculated_immutable_records(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("evidence-migration")
            store = SQLiteStore(path, target_schema_version=2)
            store.create_task(
                task_contract,
                correlation_id="migration-correlation",
                worker_id="migration-worker",
                occurred_at=NOW,
            )
            store.record_evidence(
                task_contract.task_id,
                EvidenceItem(
                    evidence_id="legacy-evidence",
                    type="legacy",
                    source="legacy-worker",
                    collected_at=NOW,
                    payload={"value": 1},
                ),
            )
            with sqlite3.connect(path) as connection:
                encoded = connection.execute(
                    "SELECT item_json FROM evidence WHERE evidence_id = ?",
                    ("legacy-evidence",),
                ).fetchone()[0]
                legacy = json.loads(encoded)
                legacy["checksum"] = "sha256:caller-trusted-before-v3"
                legacy.pop("acquisition_method", None)
                legacy.pop("trust_level", None)
                legacy.pop("expires_at", None)
                connection.execute(
                    "UPDATE evidence SET item_json = ? WHERE evidence_id = ?",
                    (json.dumps(legacy), "legacy-evidence"),
                )

            migrated = SQLiteStore(path)
            item = migrated.evidence(task_contract.task_id)[0]
            self.assertEqual(migrated.schema_version, 7)
            self.assertNotEqual(item.checksum, "sha256:caller-trusted-before-v3")
            self.assertEqual(item.trust_level, EvidenceTrustLevel.AGENT_CLAIM)
            self.assertEqual(
                item.acquisition_method,
                EvidenceAcquisitionMethod.AGENT_REPORTED,
            )
            with sqlite3.connect(path) as connection:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        "DELETE FROM evidence WHERE evidence_id = ?",
                        ("legacy-evidence",),
                    )

    async def test_tampered_and_expired_evidence_do_not_verify(self) -> None:
        with self.assertRaises(EvidenceIntegrityError):
            EvidenceItem(
                evidence_id="tampered",
                type="external_state",
                source="test",
                collected_at=NOW,
                payload={"complete": True},
                checksum="sha256:not-the-content-hash",
            )

        expired = EvidenceItem(
            evidence_id="expired",
            type="external_state",
            source="test.independent_observer",
            collected_at=NOW - timedelta(hours=2),
            payload={"complete": True},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
            expires_at=NOW - timedelta(hours=1),
        )
        task_contract = contract(
            "expired-evidence",
            required_evidence=(
                EvidenceRequirement(
                    "external_state",
                    "Fresh independent state is required.",
                    minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
                    max_age=timedelta(minutes=30),
                ),
            ),
            criteria=(
                FieldEqualsCriterion(
                    name="external-state",
                    description="External state must be complete.",
                    field_path="complete",
                    expected=True,
                    evidence_type="external_state",
                ),
            ),
        )
        verification = RuleBasedVerifier(clock=lambda: NOW).verify(
            task_contract,
            {"acknowledged": True},
            EvidenceCollection((expired,)),
        )
        self.assertEqual(verification.status, VerificationStatus.AWAITING_EVIDENCE)

        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            runtime = start_running(path, contract("immutable-evidence"))
            item = EvidenceItem(
                evidence_id="immutable",
                type="external_state",
                source="test",
                collected_at=NOW,
                payload={"nested": {"value": 1}},
            )
            runtime.add_evidence("immutable-evidence", item)
            with self.assertRaises(TypeError):
                item.payload["nested"]["value"] = 2  # type: ignore[index]
            with sqlite3.connect(path) as connection:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        "UPDATE evidence SET item_json = '{}' WHERE evidence_id = ?",
                        (item.evidence_id,),
                    )

    async def test_file_provider_reports_existence_content_and_hash(self) -> None:
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.txt"
            artifact.write_text("verified content", encoding="utf-8")
            request = action_request("provider-task")
            receipt = ActionReceiptEvidenceProvider()
            executor_receipt = action_executor_receipt(request)
            receipt_evidence = await receipt.acquire(request, executor_receipt)
            self.assertEqual(
                receipt_evidence.trust_level,
                EvidenceTrustLevel.EXECUTOR_RECEIPT,
            )

            evidence = await FileEvidenceProvider(
                artifact,
                include_content=True,
            ).acquire(request, executor_receipt)
            self.assertTrue(evidence.payload and evidence.payload["exists"])
            self.assertEqual(evidence.content, b"verified content")
            self.assertTrue(
                evidence.payload
                and str(evidence.payload["sha256"]).startswith("sha256:")
            )


def action_executor_receipt(request: ActionRequest) -> ActionReceipt:
    return ActionReceipt(
        receipt_id="provider-receipt",
        action_id=request.action_id,
        executor_id="provider-test",
        status=ActionExecutionStatus.EXECUTOR_SUCCEEDED,
        action_hash=request.action_hash,
        input_hash=request.input_hash,
        idempotency_key=request.idempotency_key,
        started_at=NOW,
        finished_at=NOW,
        output={"acknowledged": True},
    )


if __name__ == "__main__":
    unittest.main()
