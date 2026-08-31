from __future__ import annotations

import json
import os
import sqlite3
import unittest
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

import pytest

from examples.cortexops_workspace import configure_cortexops_workspace
from runmantle import (
    ActionExecutionStatus,
    ActionPolicy,
    ActionRequest,
    CapabilityDeclaration,
    CapabilityRegistry,
    DurableRecoveryExecutor,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    MediatedActionExecutor,
    PostActionRuntimeConfirmation,
    PostActionRuntimeConfirmationStatus,
    PreActionCapabilityConfirmation,
    RecoveryAction,
    RecoveryExecutorResult,
    RecoveryHandlerRegistration,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryPostcondition,
    RecoveryPrecondition,
    RecoveryStatus,
    RiskLevel,
    RuleBasedVerifier,
    SQLiteStore,
    StandardCapability,
    TaskContext,
    TaskContract,
    TaskStatus,
    WorkerReport,
)
from runmantle.evidence import _establish_evidence_origin
from runmantle.integrations.cortexops_control import (
    CortexOpsControlClient,
    CortexOpsControlledActionExecutor,
    CortexOpsControlledRecoveryExecutor,
    CortexOpsControlRejected,
    CortexOpsControlUnavailable,
)

pytestmark = pytest.mark.cortexops_integration
try:
    configure_cortexops_workspace()
except RuntimeError as error:
    pytest.skip(str(error), allow_module_level=True)

FastAPI = import_module("fastapi").FastAPI
TestClient = import_module("fastapi.testclient").TestClient
create_openclaw_plugin_router = import_module(
    "cortexops.openclaw_plugin"
).create_openclaw_plugin_router
OpenClawPluginRepository = import_module(
    "cortexops.openclaw_plugin.repository"
).OpenClawPluginRepository
create_runmantle_control_router = import_module(
    "cortexops.runmantle_control"
).create_runmantle_control_router

WRITE_CAPABILITY = "write_file"
RUNTIME_HEADERS = {"Authorization": "Bearer runtime-token"}
OPERATOR_HEADERS = {"Authorization": "Bearer operator-token"}
OTHER_RUNTIME_HEADERS = {"Authorization": "Bearer other-runtime-token"}


class ControlTestTransport:
    def __init__(self, client: Any) -> None:
        self.client = client

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        response = self.client.request(
            method,
            path,
            json=None if payload is None else dict(payload),
            headers=RUNTIME_HEADERS,
        )
        if response.status_code >= 400:
            detail = response.json().get("detail", response.text)
            raise CortexOpsControlRejected(str(detail))
        value = response.json()
        if not isinstance(value, dict):
            raise CortexOpsControlRejected("control response was not an object")
        return value


class OfflineTransport:
    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        del method, path, payload
        raise CortexOpsControlUnavailable("simulated CortexOps outage")


class MutatingTransport:
    def __init__(
        self,
        delegate: ControlTestTransport,
        path_suffix: str,
        mutate: Callable[[dict[str, Any]], Any],
    ) -> None:
        self.delegate = delegate
        self.path_suffix = path_suffix
        self.mutate = mutate

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        response = self.delegate.request(method, path, payload)
        if path.endswith(self.path_suffix):
            return self.mutate(dict(response))
        return response


def policy(effect: str = "allow") -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    if effect != "allow":
        rules.append(
            {
                "id": f"{effect}-write-file",
                "effect": effect,
                "reason": f"test {effect} rule",
                "match": {"tool_name": "write-file"},
            }
        )
    return {
        "defaults": {"tools": "allow", "models": "deny"},
        "tool_rules": rules,
        "model_allowlist": [],
        "budgets": {
            "run": {"max_tokens": None, "max_cost_usd": None},
            "session": {"max_tokens": None, "max_cost_usd": None},
            "agent_daily_utc": {
                "max_tokens": None,
                "max_cost_usd": None,
            },
        },
    }


def control_harness(
    directory: str,
    *,
    effect: str = "allow",
    capabilities: tuple[str, ...] = (WRITE_CAPABILITY, StandardCapability.RETRY),
    mode: str = "control",
    data_mode: str = "live",
) -> tuple[Any, CortexOpsControlClient, Any, Path]:
    db_path = Path(directory) / "cortexops.db"
    plugin = OpenClawPluginRepository(db_path)
    plugin.save_policy(policy(effect))
    identities = json.dumps(
        [
            {
                "token": "runtime-token",
                "principal_id": "runmantle-runtime",
                "roles": ["runtime"],
            },
            {
                "token": "operator-token",
                "principal_id": "incident-commander",
                "roles": ["operator"],
            },
            {
                "token": "other-runtime-token",
                "principal_id": "other-runtime",
                "roles": ["runtime"],
            },
        ]
    )
    with patch.dict(
        os.environ,
        {"CORTEXOPS_GOVERNANCE_IDENTITIES_JSON": identities},
    ):
        app = FastAPI()
        app.include_router(create_openclaw_plugin_router(db_path))
        app.include_router(create_runmantle_control_router(db_path))
    http = TestClient(app)
    control = CortexOpsControlClient(
        ControlTestTransport(http),
        runtime_id="runmantle-test-runtime",
        runtime_version="0.10.0",
        mode=mode,
        data_mode=data_mode,
    )
    control.register_runtime(capabilities)
    return http, control, plugin, db_path


def action_contract(
    task_id: str,
    *,
    capability: str = WRITE_CAPABILITY,
) -> TaskContract[dict[str, Any], dict[str, Any]]:
    return TaskContract(
        task_id=task_id,
        objective="Run one capability-mediated action.",
        input={},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="worker-output",
                description="The worker output must be acknowledged.",
                field_path="acknowledged",
                expected=True,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type="control_verification",
                description="Runtime-established control test evidence.",
            ),
        ),
        allowed_capabilities=frozenset({capability}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}-key",
    )


def worker(
    capability: str = WRITE_CAPABILITY,
) -> FunctionWorker[dict[str, Any], dict[str, Any]]:
    async def execute(
        contract: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del contract, context
        return WorkerReport.completed({"acknowledged": True})

    return FunctionWorker(
        id="control-worker",
        name="Control worker",
        role="test",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name=capability,
                description="Capability exercised by the control-loop test.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )


def running_action_task(
    path: Path,
    control: CortexOpsControlClient,
    task_id: str,
    *,
    capability: str = WRITE_CAPABILITY,
) -> tuple[TaskContract[Any, Any], MediatedActionExecutor]:
    contract = action_contract(task_id, capability=capability)
    runtime = DurableRuntime(database_path=path)
    pending = runtime.start(
        worker(capability),
        contract,
        correlation_id=f"{task_id}-session",
    )
    runtime.store.transition(
        task_id,
        expected_version=pending.version,
        next_status=TaskStatus.RUNNING,
        occurred_at=datetime.now(UTC),
    )
    control.register_task(
        contract,
        correlation_id=f"{task_id}-session",
        worker_id="control-worker",
    )
    registry = CapabilityRegistry(
        (
            CapabilityDeclaration(
                name=capability,
                description="Locally installed mediated capability.",
                requires_runtime_confirmation=False,
            ),
        )
    )
    return contract, MediatedActionExecutor(
        store=runtime.store,
        capabilities=registry,
        policy=ActionPolicy(
            allowed_capabilities=frozenset({capability}),
            maximum_risk_level=RiskLevel.LOW,
        ),
    )


def action_request(
    task_id: str,
    *,
    capability: str = WRITE_CAPABILITY,
) -> ActionRequest:
    return ActionRequest(
        action_id=f"{task_id}-action",
        task_id=task_id,
        name="write-file",
        required_capability=capability,
        input={"path": "artifact.txt", "content": "done"},
        idempotency_key=f"{task_id}-action-once",
        risk_level=RiskLevel.LOW,
        requested_by="control-worker",
        requested_at=datetime.now(UTC),
        execution_handler_id="tests.control.write_file:v1",
    )


class HealthEvidenceProvider:
    async def acquire(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: Any,
    ) -> EvidenceItem:
        del action, receipt
        return EvidenceItem(
            evidence_id=f"{plan.plan_id}-health",
            type="service_health",
            source="independent-health-api",
            collected_at=datetime.now(UTC),
            payload={"healthy": True},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        )


class PostDeployRuntimeProvider:
    """Fixture adapter representing an independent /version + /health probe."""

    async def confirm(
        self,
        request: ActionRequest,
        receipt: Any,
    ) -> PostActionRuntimeConfirmation:
        evidence = EvidenceItem(
            evidence_id=f"{request.action_id}-runtime-health",
            type="runtime_health",
            source="fixture-independent-health-endpoint",
            collected_at=datetime.now(UTC),
            payload={"version": "1.2.3", "healthy": True},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        )
        return PostActionRuntimeConfirmation(
            confirmation_id=f"{request.action_id}-post-action",
            task_id=request.task_id,
            action_id=request.action_id,
            action_hash=request.action_hash,
            receipt_id=receipt.receipt_id,
            status=PostActionRuntimeConfirmationStatus.CONFIRMED,
            provider_id="fixture.health-and-version:v1",
            observed_state={"version": "1.2.3", "healthy": True},
            expected_state={"version": "1.2.3", "healthy": True},
            evidence=EvidenceCollection((evidence,)),
            checked_at=datetime.now(UTC),
            actor="fixture-independent-runtime-provider",
        )


async def recovery_fixture(
    path: Path,
    control: CortexOpsControlClient,
    task_id: str,
    *,
    handler_succeeds: bool = True,
) -> tuple[
    TaskContract[Any, Any],
    RecoveryPlan,
    CortexOpsControlledRecoveryExecutor,
    list[str],
]:
    contract: TaskContract[dict[str, Any], dict[str, Any]] = TaskContract(
        task_id=task_id,
        objective="Recover and verify independent service health.",
        input={},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="original-output",
                description="The original worker output must be acknowledged.",
                field_path="acknowledged",
                expected=True,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type="service_health",
                description="Independent service health evidence is required.",
                minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
            ),
        ),
        allowed_capabilities=frozenset({StandardCapability.RETRY}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}-retry-once",
    )
    result = await DurableRuntime(
        database_path=path,
        verifier=RuleBasedVerifier(),
    ).execute(
        worker(StandardCapability.RETRY),
        contract,
        correlation_id=f"{task_id}-session",
    )
    if result.status is not TaskStatus.AWAITING_EVIDENCE:
        raise AssertionError("recovery fixture did not await evidence")
    control.register_task(
        contract,
        correlation_id=result.correlation_id,
        worker_id="control-worker",
    )
    action = RecoveryAction(
        action_id=f"{task_id}-retry-action",
        capability=StandardCapability.RETRY,
        idempotency_key=contract.idempotency_key,
        reason="Retry the missing health observation.",
        parameters={"attempt": 2},
        handler_identity="tests.control.retry:v1",
        handler_configuration={"mode": "fixture"},
    )
    health_provider = HealthEvidenceProvider()
    health_postcondition = RecoveryPostcondition(
        name="service-health",
        description="Acquire service health after the retry.",
        provider=health_provider,
        evidence_type="service_health",
    )
    plan = RecoveryPlan(
        plan_id=f"{task_id}-recovery",
        task_id=task_id,
        actions=(action,),
        proposed_by="runtime-recovery-coordinator",
        failure_diagnosis="Independent health evidence was missing.",
        context_reference=f"task:{task_id}:checkpoint:reported-output",
        risk_level=RiskLevel.LOW,
        approval_required=True,
        preconditions=(
            RecoveryPrecondition(
                name="same-task-and-idempotency-boundary",
                description="The recovery remains bound to the original task.",
                evaluator=lambda supplied_plan, supplied_action, supplied_contract: (
                    supplied_plan.task_id == supplied_contract.task_id
                    and supplied_action.idempotency_key
                    == supplied_contract.idempotency_key
                ),
            ),
        ),
        postconditions=(health_postcondition,),
        created_at=datetime.now(UTC),
    )
    calls: list[str] = []

    async def handler(
        recovery_action: RecoveryAction,
        task_contract: TaskContract[Any, Any],
    ) -> RecoveryExecutorResult:
        calls.append(f"{task_contract.task_id}:{recovery_action.action_id}")
        return RecoveryExecutorResult(
            succeeded=handler_succeeds,
            output={"retry_started": handler_succeeds},
            message="retry accepted" if handler_succeeds else "retry rejected",
        )

    local = DurableRecoveryExecutor(
        store=SQLiteStore(path),
        registry=CapabilityRegistry.with_standard_recovery_capabilities(),
        policy=RecoveryPolicy(
            allowed_capabilities=frozenset({StandardCapability.RETRY}),
            allowed_task_states=frozenset(
                {TaskStatus.AWAITING_EVIDENCE, TaskStatus.FAILED}
            ),
            maximum_risk_level=RiskLevel.MEDIUM,
            require_runtime_confirmation=False,
        ),
        handlers={
            StandardCapability.RETRY: RecoveryHandlerRegistration(
                handler=handler,
                handler_identity="tests.control.retry:v1",
                handler_configuration={"mode": "fixture"},
            )
        },
        evidence_providers=EvidenceProviderRegistry(
            (
                EvidenceProviderRegistration(
                    provider=health_provider,
                    provider_identity=str(health_postcondition.provider_identity),
                    provider_configuration=(
                        health_postcondition.provider_configuration
                    ),
                    trust_level=EvidenceTrustLevel.INDEPENDENT,
                    acquisition_method=(EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER),
                ),
            )
        ),
        verifier=RuleBasedVerifier(),
    )
    return contract, plan, CortexOpsControlledRecoveryExecutor(local, control), calls


def recovery_confirmation(plan: RecoveryPlan) -> PreActionCapabilityConfirmation:
    action = plan.actions[0]
    return PreActionCapabilityConfirmation(
        confirmation_id=f"{plan.plan_id}-local-preflight",
        action_id=action.action_id,
        capability=action.capability,
        idempotency_key=action.idempotency_key,
        supported=True,
        safe=True,
        confirmed_at=datetime.now(UTC),
        confirmed_by="runmantle-local-handler-registry",
        reason="The exact idempotent recovery handler is installed locally.",
        target_hash=action.action_hash,
    )


class CortexOpsControlLoopIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_post_action_runtime_confirmation_is_independent_and_audited(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            _, control, _, cortex_path = control_harness(directory)
            contract, local = running_action_task(
                Path(directory) / "runtime.db", control, "post-action-confirmation"
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> dict[str, bool]:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"written": True}

            result = await CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="post-action-confirmation-session",
                worker_id="control-worker",
                post_action_confirmation_provider=PostDeployRuntimeProvider(),
            ).execute(
                action_request(contract.task_id), contract=contract, handler=handler
            )

            self.assertEqual(calls, 1)
            self.assertIsNotNone(result.action.receipt)
            self.assertIsNotNone(result.post_action_confirmation)
            self.assertFalse(result.verified_outcome)
            with __import__("sqlite3").connect(cortex_path) as database:
                row = database.execute(
                    "SELECT status, receipt_id, evidence_ids_json "
                    "FROM runmantle_action_runtime_confirmations"
                ).fetchone()
            self.assertEqual(row[0], "confirmed")
            self.assertEqual(
                row[1], f"{control.runtime_id}:{result.action.receipt.receipt_id}"
            )
            self.assertIn("runtime-health", row[2])

    async def test_recognized_block_never_invokes_handler(self) -> None:
        with TemporaryDirectory() as directory:
            _, control, _, _ = control_harness(directory, effect="deny")
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "recognized-block",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1

            result = await CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="recognized-block-session",
                worker_id="control-worker",
            ).execute(
                action_request(contract.task_id),
                contract=contract,
                handler=handler,
            )

            self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
            self.assertEqual(calls, 0)

    async def test_invalid_policy_responses_never_invoke_handler(self) -> None:
        def without_outcome(value: dict[str, Any]) -> dict[str, Any]:
            value.pop("outcome", None)
            return value

        def unknown_outcome(value: dict[str, Any]) -> dict[str, Any]:
            value["outcome"] = "UNRECOGNIZED"
            return value

        def invalid_outcome_type(value: dict[str, Any]) -> dict[str, Any]:
            value["outcome"] = 1
            return value

        def future_outcome(value: dict[str, Any]) -> dict[str, Any]:
            value["outcome"] = "ALLOW_V2"
            return value

        def malformed_response(value: dict[str, Any]) -> list[Any]:
            del value
            return []

        def incomplete_approval(value: dict[str, Any]) -> dict[str, Any]:
            value["outcome"] = "REQUIRE_APPROVAL"
            value["approval"] = {"approval_id": "incomplete"}
            return value

        cases = (
            ("missing-outcome", without_outcome),
            ("unknown-outcome", unknown_outcome),
            ("invalid-outcome-type", invalid_outcome_type),
            ("forward-compatible-unknown", future_outcome),
            ("malformed-response", malformed_response),
            ("incomplete-approval", incomplete_approval),
        )
        for name, mutation in cases:
            with self.subTest(name=name), TemporaryDirectory() as directory:
                http, control, _, _ = control_harness(directory)
                control.transport = MutatingTransport(
                    ControlTestTransport(http),
                    "/actions/evaluate",
                    mutation,
                )
                contract, local = running_action_task(
                    Path(directory) / "runtime.db",
                    control,
                    name,
                )
                calls = 0

                async def handler(arguments: Any, cancellation: Any) -> Any:
                    nonlocal calls
                    del arguments, cancellation
                    calls += 1

                result = await CortexOpsControlledActionExecutor(
                    local,
                    control,
                    correlation_id=f"{name}-session",
                    worker_id="control-worker",
                ).execute(
                    action_request(contract.task_id),
                    contract=contract,
                    handler=handler,
                )

                self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
                self.assertEqual(calls, 0)

    async def test_invalid_dispatch_responses_never_invoke_handler(self) -> None:
        def without_state(value: dict[str, Any]) -> dict[str, Any]:
            value.pop("state", None)
            return value

        def invalid_state(value: dict[str, Any]) -> dict[str, Any]:
            value["state"] = "FORWARD_COMPATIBLE_DISPATCH"
            return value

        def incomplete(value: dict[str, Any]) -> dict[str, Any]:
            return {"decision_id": value.get("decision_id")}

        def malformed(value: dict[str, Any]) -> str:
            del value
            return "DISPATCHED"

        for name, mutation in (
            ("missing-dispatch-state", without_state),
            ("invalid-dispatch-state", invalid_state),
            ("incomplete-dispatch", incomplete),
            ("malformed-dispatch", malformed),
        ):
            with self.subTest(name=name), TemporaryDirectory() as directory:
                http, control, _, _ = control_harness(directory)
                control.transport = MutatingTransport(
                    ControlTestTransport(http),
                    "/dispatch",
                    mutation,
                )
                contract, local = running_action_task(
                    Path(directory) / "runtime.db",
                    control,
                    name,
                )
                calls = 0

                async def handler(arguments: Any, cancellation: Any) -> Any:
                    nonlocal calls
                    del arguments, cancellation
                    calls += 1

                result = await CortexOpsControlledActionExecutor(
                    local,
                    control,
                    correlation_id=f"{name}-session",
                    worker_id="control-worker",
                ).execute(
                    action_request(contract.task_id),
                    contract=contract,
                    handler=handler,
                )

                self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
                self.assertEqual(calls, 0)

    async def test_happy_path_and_verified_status_sync(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, _, _ = control_harness(directory)
            hijack = http.post(
                "/api/runmantle/v1/runtimes/register",
                headers=OTHER_RUNTIME_HEADERS,
                json={
                    "request_id": "runtime:runmantle-test-runtime:register",
                    "protocol_version": 1,
                    "runtime_id": "runmantle-test-runtime",
                    "runtime_version": "0.10.0",
                    "mode": "control",
                    "data_mode": "live",
                    "capabilities": [StandardCapability.RETRY, WRITE_CAPABILITY],
                },
            )
            self.assertEqual(hijack.status_code, 403)
            local_path = Path(directory) / "runmantle.db"
            contract, local = running_action_task(
                local_path,
                control,
                "happy-action",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"executor": "accepted"}

            result = await CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="happy-action-session",
                worker_id="control-worker",
            ).execute(
                action_request(contract.task_id),
                contract=contract,
                handler=handler,
            )
            self.assertEqual(
                result.action.status, ActionExecutionStatus.EXECUTOR_SUCCEEDED
            )
            self.assertEqual(calls, 1)
            self.assertEqual(
                SQLiteStore(local_path).load_task(contract.task_id).status,
                TaskStatus.RUNNING,
            )

            verified_contract = action_contract("verified-sync")
            verified_runtime = DurableRuntime(
                database_path=Path(directory) / "verified.db",
                verifier=RuleBasedVerifier(),
            )
            awaiting = await verified_runtime.execute(
                worker(),
                verified_contract,
                correlation_id="verified-sync-session",
            )
            self.assertEqual(awaiting.status, TaskStatus.AWAITING_EVIDENCE)
            verified_runtime.store.record_evidence(
                verified_contract.task_id,
                _establish_evidence_origin(
                    EvidenceItem(
                        evidence_id="verified-sync-observation",
                        type="control_verification",
                        source="control-test-runtime",
                        collected_at=datetime.now(UTC),
                        payload={"observed": True},
                    ),
                    boundary="control_test_runtime",
                    provider_identity="tests.control_verification:v1",
                    provider_configuration={"fixture": True},
                    trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                    acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                ),
            )
            verified = await verified_runtime.resume(
                verified_contract.task_id,
                contract=verified_contract,
            )
            self.assertEqual(verified.status, TaskStatus.VERIFIED)
            control.register_task(
                verified_contract,
                correlation_id=verified.correlation_id,
                worker_id="control-worker",
            )
            synchronized = control.sync_task_result(
                verified_contract,
                verified,
                sequence=1,
            )
            self.assertEqual(synchronized["verified_status"], "verified")
            observed = http.get(
                "/api/runmantle/v1/tasks/runmantle-test-runtime/verified-sync",
                headers=OPERATOR_HEADERS,
            )
            self.assertEqual(observed.status_code, 200)
            self.assertEqual(observed.json()["reported_status"], "verified")

    async def test_offline_control_plane_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            _, control, _, _ = control_harness(directory)
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "offline-action",
            )
            control.transport = OfflineTransport()
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1

            result = await CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="offline-action-session",
                worker_id="control-worker",
            ).execute(
                action_request(contract.task_id),
                contract=contract,
                handler=handler,
            )
            self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
            self.assertEqual(calls, 0)

    async def test_demo_observation_cannot_gain_control_authority(self) -> None:
        with TemporaryDirectory() as directory:
            _, control, _, _ = control_harness(
                directory,
                mode="observe",
                data_mode="demo",
            )
            self.assertFalse(control.handshake["control_authority"])
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "demo-observe-only",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1

            result = await CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="demo-observe-only-session",
                worker_id="control-worker",
            ).execute(
                action_request(contract.task_id),
                contract=contract,
                handler=handler,
            )
            self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
            self.assertEqual(calls, 0)

    async def test_duplicate_messages_and_resume_execute_once(self) -> None:
        with TemporaryDirectory() as directory:
            _, control, _, _ = control_harness(directory)
            first = control.register_runtime(
                (WRITE_CAPABILITY, StandardCapability.RETRY)
            )
            duplicate = control.register_runtime(
                (WRITE_CAPABILITY, StandardCapability.RETRY)
            )
            self.assertEqual(first, duplicate)
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "duplicate-action",
            )
            controlled = CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="duplicate-action-session",
                worker_id="control-worker",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"ok": True}

            first_result = await controlled.execute(
                action_request(contract.task_id),
                contract=contract,
                handler=handler,
            )
            duplicate_result = await controlled.execute(
                action_request(contract.task_id),
                contract=contract,
                handler=handler,
            )
            self.assertEqual(calls, 1)
            self.assertEqual(
                first_result.action.action_id, duplicate_result.action.action_id
            )
            self.assertTrue(duplicate_result.duplicate_prevented)

    async def test_expired_exact_hash_approval_never_dispatches(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, _, cortex_db = control_harness(
                directory,
                effect="approval",
            )
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "expired-approval",
            )
            request = action_request(contract.task_id)
            controlled = CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="expired-approval-session",
                worker_id="control-worker",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1

            waiting = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            self.assertEqual(
                waiting.action.status, ActionExecutionStatus.AWAITING_APPROVAL
            )
            decision = control.evaluate_action(
                request,
                correlation_id="expired-approval-session",
                worker_id="control-worker",
            )
            approval_id = decision["approval"]["approval_id"]
            approved = http.post(
                f"/api/govern/approvals/{approval_id}/approve",
                headers=OPERATOR_HEADERS,
                json={"reason": "Reviewed the exact action hash."},
            )
            self.assertEqual(approved.status_code, 200)
            exact_decision = control.action_decision(
                str(decision["decision_id"]),
                request.action_hash,
            )
            with self.assertRaises(CortexOpsControlRejected):
                control.dispatch_action(
                    exact_decision,
                    action_hash=f"sha256:{'0' * 64}",
                    attempt_id="mismatched-action-attempt",
                )
            with sqlite3.connect(cortex_db) as connection:
                connection.execute(
                    """UPDATE govern_approval_requests
                       SET permit_expires_at=? WHERE id=?""",
                    (
                        (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                        approval_id,
                    ),
                )
            still_waiting = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            self.assertEqual(
                still_waiting.action.status,
                ActionExecutionStatus.AWAITING_APPROVAL,
            )
            self.assertEqual(calls, 0)
            local_approval = local.store.load_approval(request.approval_id)
            self.assertIsNone(local_approval.decision)

    async def test_exact_hash_approval_resumes_once(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, _, _ = control_harness(
                directory,
                effect="approval",
            )
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "approved-action",
            )
            request = action_request(contract.task_id)
            controlled = CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="approved-action-session",
                worker_id="control-worker",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"accepted": True}

            waiting = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            self.assertEqual(
                waiting.action.status,
                ActionExecutionStatus.AWAITING_APPROVAL,
            )
            decision = control.evaluate_action(
                request,
                correlation_id="approved-action-session",
                worker_id="control-worker",
            )
            approved = http.post(
                f"/api/govern/approvals/{decision['approval']['approval_id']}/approve",
                headers=OPERATOR_HEADERS,
                json={"reason": "Approved the exact immutable action."},
            )
            self.assertEqual(approved.status_code, 200)
            completed = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            duplicate = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            self.assertEqual(
                completed.action.status,
                ActionExecutionStatus.EXECUTOR_SUCCEEDED,
            )
            self.assertTrue(duplicate.duplicate_prevented)
            self.assertEqual(calls, 1)
            local_approval = local.store.load_approval(request.approval_id)
            self.assertIsNotNone(local_approval.decision)
            assert local_approval.decision is not None
            self.assertEqual(
                local_approval.decision.metadata["action_hash"],
                request.action_hash,
            )

    async def test_rejected_approval_blocks_the_local_action(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, _, _ = control_harness(directory, effect="approval")
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "rejected-action",
            )
            request = action_request(contract.task_id)
            controlled = CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="rejected-action-session",
                worker_id="control-worker",
            )

            async def handler(arguments: Any, cancellation: Any) -> Any:
                raise AssertionError("rejected action handler must not run")

            waiting = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            self.assertEqual(
                waiting.action.status,
                ActionExecutionStatus.AWAITING_APPROVAL,
            )
            decision = control.evaluate_action(
                request,
                correlation_id="rejected-action-session",
                worker_id="control-worker",
            )
            rejected = http.post(
                f"/api/govern/approvals/{decision['approval']['approval_id']}/deny",
                headers=OPERATOR_HEADERS,
                json={"reason": "The exact action was not authorized."},
            )
            self.assertEqual(rejected.status_code, 200)
            blocked = await controlled.execute(
                request,
                contract=contract,
                handler=handler,
            )
            self.assertEqual(blocked.action.status, ActionExecutionStatus.BLOCKED)

    async def test_unsupported_capability_is_rejected_before_execution(self) -> None:
        with TemporaryDirectory() as directory:
            _, control, _, _ = control_harness(
                directory,
                capabilities=(WRITE_CAPABILITY,),
            )
            contract, local = running_action_task(
                Path(directory) / "runtime.db",
                control,
                "unsupported-capability",
                capability="delete_file",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> Any:
                nonlocal calls
                del arguments, cancellation
                calls += 1

            result = await CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="unsupported-capability-session",
                worker_id="control-worker",
            ).execute(
                action_request(contract.task_id, capability="delete_file"),
                contract=contract,
                handler=handler,
            )
            self.assertEqual(result.action.status, ActionExecutionStatus.BLOCKED)
            self.assertEqual(calls, 0)

    async def test_stale_recovery_instruction_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, plugin, _ = control_harness(directory)
            contract, plan, controlled, calls = await recovery_fixture(
                Path(directory) / "runtime.db",
                control,
                "stale-recovery",
            )
            pending = await controlled.execute(plan, contract=contract)
            self.assertIsNone(pending.recovery)
            authorized = http.post(
                f"/api/runmantle/v1/recovery/reviews/{pending.review['review_id']}/authorize",
                headers=OPERATOR_HEADERS,
                json={"plan_hash": plan.plan_hash},
            )
            self.assertEqual(authorized.status_code, 200)
            plugin.save_policy(policy("deny"))
            stale = await controlled.execute(plan, contract=contract)
            self.assertIsNone(stale.recovery)
            self.assertEqual(stale.review["status"], "rejected")
            self.assertEqual(calls, [])

    async def test_recovery_failure_is_reported_without_task_success(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, _, _ = control_harness(directory)
            path = Path(directory) / "runtime.db"
            contract, plan, controlled, calls = await recovery_fixture(
                path,
                control,
                "failed-recovery",
                handler_succeeds=False,
            )
            pending = await controlled.execute(plan, contract=contract)
            http.post(
                f"/api/runmantle/v1/recovery/reviews/{pending.review['review_id']}/authorize",
                headers=OPERATOR_HEADERS,
                json={"plan_hash": plan.plan_hash},
            ).raise_for_status()
            completed = await controlled.execute(
                plan,
                contract=contract,
                preflight_confirmation=recovery_confirmation(plan),
            )
            self.assertIsNotNone(completed.recovery)
            assert completed.recovery is not None
            self.assertEqual(completed.recovery.status, RecoveryStatus.FAILED)
            self.assertEqual(len(calls), 1)
            self.assertNotEqual(
                SQLiteStore(path).load_task(plan.task_id).status, TaskStatus.VERIFIED
            )
            review = control.recovery_instruction(str(pending.review["review_id"]))
            self.assertEqual(review["status"], "verification_failed")

    async def test_authorized_recovery_verifies_only_after_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            http, control, _, _ = control_harness(directory)
            path = Path(directory) / "runtime.db"
            contract, plan, controlled, calls = await recovery_fixture(
                path,
                control,
                "verified-recovery",
            )
            pending = await controlled.execute(plan, contract=contract)
            http.post(
                f"/api/runmantle/v1/recovery/reviews/{pending.review['review_id']}/authorize",
                headers=OPERATOR_HEADERS,
                json={"plan_hash": plan.plan_hash},
            ).raise_for_status()
            completed = await controlled.execute(
                plan,
                contract=contract,
                preflight_confirmation=recovery_confirmation(plan),
            )
            self.assertIsNotNone(completed.recovery)
            assert completed.recovery is not None
            self.assertEqual(completed.recovery.status, RecoveryStatus.VERIFIED)
            self.assertEqual(len(calls), 1)
            self.assertEqual(
                SQLiteStore(path).load_task(plan.task_id).status, TaskStatus.VERIFIED
            )
            review = control.recovery_instruction(str(pending.review["review_id"]))
            self.assertEqual(review["status"], "verified")
            self.assertEqual(
                review["verification"]["evidence_ids"],
                [f"{plan.plan_id}-health"],
            )


if __name__ == "__main__":
    unittest.main()
