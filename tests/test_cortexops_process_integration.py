from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from examples.cortexops_workspace import configure_cortexops_workspace
from runmantle import (
    ActionExecutionStatus,
    ActionPolicy,
    ActionRequest,
    CapabilityDeclaration,
    CapabilityRegistry,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    MediatedActionExecutor,
    PostActionRuntimeConfirmation,
    PostActionRuntimeConfirmationStatus,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    TaskStatus,
    WorkerReport,
)
from runmantle.evidence import _establish_evidence_origin
from runmantle.integrations.cortexops_control import (
    CortexOpsControlClient,
    CortexOpsControlledActionExecutor,
    CortexOpsControlUnavailable,
    UrllibCortexOpsControlTransport,
)

pytestmark = pytest.mark.cortexops_process_integration
WRITE = "write_file"
RUNTIME_TOKEN = "process-runtime-token"
OPERATOR_TOKEN = "process-operator-token"


class _ProcessRuntimeProbe:
    """Independent fixture probe used through the actual HTTP control server."""

    async def confirm(
        self, request: ActionRequest, receipt: Any
    ) -> PostActionRuntimeConfirmation:
        item = EvidenceItem(
            evidence_id="process-runtime-health",
            type="runtime_health",
            source="process-fixture-health-endpoint",
            collected_at=datetime.now(UTC),
            payload={"health": "ok", "version": "1.0.0"},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        )
        return PostActionRuntimeConfirmation(
            confirmation_id="process-post-action-confirmation",
            task_id=request.task_id,
            action_id=request.action_id,
            action_hash=request.action_hash,
            receipt_id=receipt.receipt_id,
            status=PostActionRuntimeConfirmationStatus.CONFIRMED,
            provider_id="tests.process.runtime_probe:v1",
            observed_state={"health": "ok", "version": "1.0.0"},
            expected_state={"health": "ok", "version": "1.0.0"},
            evidence=EvidenceCollection((item,)),
            checked_at=datetime.now(UTC),
            actor="process-fixture-runtime-probe",
        )


def _contract(task_id: str) -> TaskContract[dict[str, Any], dict[str, Any]]:
    return TaskContract(
        task_id=task_id,
        objective="Exercise the real CortexOps HTTP control path.",
        input={},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="acknowledged",
                description="The worker output is acknowledged.",
                field_path="acknowledged",
                expected=True,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                "process_verification",
                "Runtime-established process integration evidence.",
            ),
        ),
        allowed_capabilities=frozenset({WRITE}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}:once",
    )


def _worker() -> FunctionWorker[dict[str, Any], dict[str, Any]]:
    async def execute(
        contract: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del contract, context
        return WorkerReport.completed({"acknowledged": True})

    return FunctionWorker(
        id="process-integration-worker",
        name="Process integration worker",
        role="test",
        version="1",
        capabilities=(
            CapabilityDeclaration(
                name=WRITE,
                description="Process integration controlled action.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _operator_post(base_url: str, path: str, payload: dict[str, Any]) -> None:
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPERATOR_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        assert response.status == 200


@contextmanager
def _cortexops_process(root: Path) -> Iterator[str]:
    try:
        cortexops = configure_cortexops_workspace()
        __import__("fastapi")
        __import__("uvicorn")
    except (ImportError, RuntimeError) as error:
        pytest.skip(f"CortexOps process environment unavailable: {error}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    identities = json.dumps(
        [
            {
                "token": RUNTIME_TOKEN,
                "principal_id": "runmantle-process-runtime",
                "roles": ["runtime"],
            },
            {
                "token": OPERATOR_TOKEN,
                "principal_id": "process-operator",
                "roles": ["operator"],
            },
        ]
    )
    env = os.environ.copy()
    env["CORTEXOPS_GOVERNANCE_IDENTITIES_JSON"] = identities
    python_path = [str(cortexops), str(cortexops / "packages" / "python-sdk")]
    if env.get("PYTHONPATH"):
        python_path.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_path)
    log_path = root / "cortexops-process.log"
    with log_path.open("w+", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).parent / "fixtures" / "cortexops_process_server.py"),
                "--database",
                str(root / "cortexops.db"),
                "--port",
                str(port),
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            started = False
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                        started = True
                        break
                except (OSError, TimeoutError):
                    time.sleep(0.05)
            if not started:
                log.flush()
                log.seek(0)
                detail = log.read()[-2000:]
                pytest.skip(
                    "CortexOps separate process could not be started locally: "
                    f"{detail or 'no diagnostic output'}"
                )
            with pytest.raises(HTTPError) as unauthorized:
                urlopen(
                    f"{base_url}/api/runmantle/v1/tasks/missing/missing",
                    timeout=2,
                )
            assert unauthorized.value.code == 401
            yield base_url
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


async def _exercise_process_integration() -> None:
    if os.environ.get("RUNMANTLE_CORTEXOPS_PROCESS_TEST") != "1":
        pytest.skip(
            "set RUNMANTLE_CORTEXOPS_PROCESS_TEST=1 to start the local "
            "CortexOps process"
        )
    with TemporaryDirectory() as directory:
        root = Path(directory)
        with _cortexops_process(root) as base_url:
            transport = UrllibCortexOpsControlTransport(
                base_url,
                authorization_provider=lambda: f"Bearer {RUNTIME_TOKEN}",
            )
            control = CortexOpsControlClient(
                transport,
                runtime_id="runmantle-process-test",
                runtime_version="1.0.1",
            )
            handshake = control.register_runtime((WRITE,))
            assert handshake["runtime_id"] == "runmantle-process-test"

            action_contract = _contract("process-action")
            action_runtime = DurableRuntime(database_path=root / "action.db")
            pending = action_runtime.start(
                _worker(),
                action_contract,
                correlation_id="process-action-session",
            )
            action_runtime.store.transition(
                action_contract.task_id,
                expected_version=pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=datetime.now(UTC),
            )
            control.register_task(
                action_contract,
                correlation_id="process-action-session",
                worker_id="process-integration-worker",
            )
            local = MediatedActionExecutor(
                store=action_runtime.store,
                capabilities=CapabilityRegistry((_worker().capabilities[0],)),
                policy=ActionPolicy(
                    allowed_capabilities=frozenset({WRITE}),
                    maximum_risk_level=RiskLevel.LOW,
                ),
            )
            controlled = CortexOpsControlledActionExecutor(
                local,
                control,
                correlation_id="process-action-session",
                worker_id="process-integration-worker",
                post_action_confirmation_provider=_ProcessRuntimeProbe(),
            )
            request = ActionRequest(
                action_id="process-controlled-action",
                task_id=action_contract.task_id,
                name="write-file",
                required_capability=WRITE,
                input={"path": "artifact.txt"},
                idempotency_key="process-controlled-action:once",
                risk_level=RiskLevel.LOW,
                requested_by="process-integration-worker",
                requested_at=datetime.now(UTC),
                execution_handler_id="tests.process.write_file:v1",
            )
            calls = 0

            async def handler(arguments: Any, cancellation: Any) -> dict[str, bool]:
                nonlocal calls
                del arguments, cancellation
                calls += 1
                return {"written": True}

            waiting = await controlled.execute(
                request,
                contract=action_contract,
                handler=handler,
            )
            assert waiting.action.status is ActionExecutionStatus.AWAITING_APPROVAL
            decision = control.evaluate_action(
                request,
                correlation_id="process-action-session",
                worker_id="process-integration-worker",
            )
            assert decision["outcome"] == "REQUIRE_APPROVAL"
            _operator_post(
                base_url,
                f"/api/govern/approvals/{decision['approval']['approval_id']}/approve",
                {"reason": "Approved through the real operator auth path."},
            )
            completed = await controlled.execute(
                request,
                contract=action_contract,
                handler=handler,
            )
            assert completed.action.status is ActionExecutionStatus.EXECUTOR_SUCCEEDED
            assert completed.post_action_confirmation is not None
            assert (
                completed.post_action_confirmation.status
                is PostActionRuntimeConfirmationStatus.CONFIRMED
            )
            assert calls == 1

            verified_contract = _contract("process-verified-sync")
            verified_runtime = DurableRuntime(
                database_path=root / "verified.db",
                verifier=RuleBasedVerifier(),
            )
            awaiting = await verified_runtime.execute(
                _worker(),
                verified_contract,
                correlation_id="process-verified-session",
            )
            assert awaiting.status is TaskStatus.AWAITING_EVIDENCE
            verified_runtime.store.record_evidence(
                verified_contract.task_id,
                _establish_evidence_origin(
                    EvidenceItem(
                        evidence_id="process-verification",
                        type="process_verification",
                        source="process-test-runtime",
                        collected_at=datetime.now(UTC),
                        payload={"observed": True},
                    ),
                    boundary="cortexops_process_test_runtime",
                    provider_identity="tests.process_verification:v1",
                    provider_configuration={"fixture": True},
                    trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                    acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                ),
            )
            verified = await verified_runtime.resume(
                verified_contract.task_id,
                contract=verified_contract,
            )
            assert verified.status is TaskStatus.VERIFIED
            control.register_task(
                verified_contract,
                correlation_id=verified.correlation_id,
                worker_id="process-integration-worker",
            )
            synchronized = control.sync_task_result(
                verified_contract,
                verified,
                sequence=1,
            )
            assert synchronized["verified_status"] == "verified"
            operator_transport = UrllibCortexOpsControlTransport(
                base_url,
                authorization_provider=lambda: f"Bearer {OPERATOR_TOKEN}",
            )
            remote = operator_transport.request(
                "GET",
                "/api/runmantle/v1/tasks/runmantle-process-test/process-verified-sync",
            )
            assert remote["reported_status"] == "verified"


def test_real_cortexops_process_http_control_round_trip() -> None:
    try:
        asyncio.run(_exercise_process_integration())
    except CortexOpsControlUnavailable as error:
        pytest.skip(f"CortexOps process environment became unavailable: {error}")
