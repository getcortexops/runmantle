"""Packaged, restart-safe Verified Release Guard reference workflow."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from .actions import (
    ActionPolicy,
    ActionRequest,
    ExecutorResult,
    MediatedActionExecutor,
    Postcondition,
    Precondition,
)
from .adapters import (
    AgentAdapterContract,
    AgentAdapterWorker,
    AgentHealth,
    AgentHealthStatus,
    AgentIdentity,
)
from .approvals import ApprovalDecision, ApproverIdentity
from .capabilities import CapabilityDeclaration, CapabilityRegistry
from .contracts import RiskLevel, TaskContract, TaskStatus
from .core import TaskContext, WorkerReport
from .durable import DurableRuntime
from .durable_recovery import DurableRecoveryExecutor, RecoveryHandlerRegistration
from .evidence import (
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    new_id,
    utc_now,
)
from .project import RunmantleProject
from .recovery import (
    PreActionCapabilityConfirmation,
    RecoveryAction,
    RecoveryExecutorResult,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryPostcondition,
    RecoveryPrecondition,
    RecoveryResult,
)
from .telemetry import CompositeEventSink, EventSink, JsonlEventSink
from .verification import FieldEqualsCriterion, PredicateCriterion, RuleBasedVerifier

INSPECT_CAPABILITY = "repository.inspect"
RECOVERY_CAPABILITY = "repository.release_fix"


class RepositoryBoundaryError(RuntimeError):
    """A reference-workflow path escaped or weakened its repository boundary."""


@dataclass(frozen=True, slots=True)
class ExistingReleaseAgentAdapter:
    """Minimal adapter around an existing agent-like submit function.

    The fixture intentionally reports completion without modifying the repository.
    A normal adapter can replace this class without changing the runtime contract.
    """

    adapter_contract: AgentAdapterContract = field(
        default_factory=lambda: AgentAdapterContract(
            identity=AgentIdentity(
                agent_id="existing-release-agent",
                name="Existing release agent",
                role="release-preparer",
                version="1.0",
            ),
            capabilities=(
                CapabilityDeclaration(
                    name=INSPECT_CAPABILITY,
                    description="Request mediated repository inspection.",
                    requires_runtime_confirmation=False,
                ),
                CapabilityDeclaration(
                    name=RECOVERY_CAPABILITY,
                    description="Apply the reference release correction.",
                    recovery_supported=True,
                    requires_idempotency=True,
                    requires_approval=True,
                ),
            ),
            emits_evidence=False,
        )
    )
    recovery_hooks: None = None

    async def submit(
        self,
        task: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del task
        context.cancellation.raise_if_cancelled()
        context.event_emitter.emit(
            "existing_agent.claimed_release_complete",
            {"claim_is_verification": False},
        )
        return WorkerReport.completed({"release_ready": True, "agent_claim": True})

    async def health(self) -> AgentHealth:
        return AgentHealth(AgentHealthStatus.HEALTHY, "local deterministic adapter")


def release_contract(
    project: RunmantleProject,
) -> TaskContract[dict[str, Any], dict[str, Any]]:
    """Reconstruct the executable contract; callables are never loaded from SQLite."""

    return TaskContract(
        task_id=project.task_id,
        objective=(
            "Prepare a clean repository whose release artifact matches its manifest."
        ),
        input={"repository": "repository"},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="agent-reported-completion",
                description="The wrapped agent reported completion.",
                field_path="release_ready",
                expected=True,
            ),
            PredicateCriterion(
                name="latest-acceptance-checks-pass",
                description="The latest runtime-observed repository checks all pass.",
                predicate=_latest_release_evidence_passes,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type="release_guard",
                description=(
                    "Fresh acceptance results acquired from the local repository."
                ),
                minimum_trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                max_age=timedelta(minutes=10),
            ),
        ),
        allowed_capabilities=frozenset({INSPECT_CAPABILITY, RECOVERY_CAPABILITY}),
        risk_level=RiskLevel.MEDIUM,
        timeout=timedelta(seconds=30),
        idempotency_key=f"{project.task_id}:release-fix:v1",
        metadata={"workflow": "verified_release_guard", "checkpoint_boundary": "task"},
    )


def release_worker() -> AgentAdapterWorker[dict[str, Any], dict[str, Any]]:
    return AgentAdapterWorker(ExistingReleaseAgentAdapter())


def runtime(project: RunmantleProject) -> DurableRuntime:
    project.state_directory.mkdir(parents=True, exist_ok=True)
    return DurableRuntime(
        database_path=project.database_path,
        verifier=RuleBasedVerifier(),
        event_sink=_event_sink(project),
    )


async def run_agent(project: RunmantleProject) -> Any:
    return await runtime(project).execute(
        release_worker(),
        release_contract(project),
        correlation_id=project.correlation_id,
    )


async def verify_repository(project: RunmantleProject) -> Any:
    """Run real checks through the mediated action boundary, then verify the task."""

    active_runtime = runtime(project)
    contract = release_contract(project)
    request = ActionRequest(
        action_id=f"{project.task_id}:acceptance:v1",
        task_id=project.task_id,
        name="inspect release repository",
        required_capability=INSPECT_CAPABILITY,
        input={"repository": "repository"},
        idempotency_key=f"{project.task_id}:acceptance:v1",
        risk_level=RiskLevel.LOW,
        requested_by="runmantle.release_guard",
        requested_at=project.created_at,
        execution_handler_id="runmantle.release_guard.inspect_repository:v1",
        preconditions=(
            Precondition(
                name="repository-contained",
                description="Repository was resolved within the project root.",
                evaluator=lambda request: (
                    request.input.get("repository") == "repository"
                ),
            ),
        ),
        postconditions=(
            Postcondition(
                name="reacquire-repository-state",
                description="Inspect repository after the executor receipt.",
                provider=_ActionReleaseEvidence(project.repository),
                evidence_type="release_guard",
                provider_identity="runmantle.release_guard.action_evidence:v1",
                provider_configuration={
                    "repository": "project-relative:repository",
                    "inspection_schema": 1,
                },
            ),
        ),
    )
    action_postcondition = request.postconditions[0]
    assert action_postcondition.provider_identity is not None
    evidence_providers = EvidenceProviderRegistry(
        (
            EvidenceProviderRegistration(
                provider=action_postcondition.provider,
                provider_identity=action_postcondition.provider_identity,
                provider_configuration=action_postcondition.provider_configuration,
                trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                acquisition_method=EvidenceAcquisitionMethod.FILESYSTEM_INSPECTION,
            ),
        )
    )
    executor = MediatedActionExecutor(
        store=active_runtime.store,
        capabilities=CapabilityRegistry((_inspect_declaration(),)),
        policy=ActionPolicy(
            allowed_capabilities=frozenset({INSPECT_CAPABILITY}),
            allowed_task_states=frozenset(
                {TaskStatus.AWAITING_EVIDENCE, TaskStatus.FAILED}
            ),
            maximum_risk_level=RiskLevel.LOW,
        ),
        evidence_providers=evidence_providers,
        event_sink=_event_sink(project),
    )

    async def inspect_handler(input: Any, cancellation: Any) -> ExecutorResult:
        del input
        cancellation.raise_if_cancelled()
        checks = await asyncio.to_thread(inspect_repository, project.repository)
        return ExecutorResult(succeeded=True, output={"checks_ran": len(checks)})

    await executor.execute(
        request,
        contract=contract,
        handler=inspect_handler,
        granted_capabilities=frozenset({INSPECT_CAPABILITY}),
    )
    return await active_runtime.resume(project.task_id, contract=contract)


def recovery_plan(project: RunmantleProject) -> RecoveryPlan:
    action = RecoveryAction(
        action_id=f"{project.task_id}:release-fix:v1",
        capability=RECOVERY_CAPABILITY,
        idempotency_key=f"{project.task_id}:release-fix:v1",
        reason="Bring the local release fixture into conformance with the contract.",
        parameters={"repository": "repository", "artifact": "dist/release.txt"},
        handler_identity="runmantle.release_guard.apply_release_fix:v1",
        handler_configuration={"artifact": "dist/release.txt"},
    )
    return RecoveryPlan(
        plan_id=f"{project.task_id}:recovery:v1",
        task_id=project.task_id,
        actions=(action,),
        proposed_by="runmantle.release_guard",
        failure_diagnosis="Runtime acceptance evidence shows the agent claim is false.",
        context_reference=f"task:{project.task_id}:reported-output",
        declared_recovery_capability=RECOVERY_CAPABILITY,
        risk_level=RiskLevel.MEDIUM,
        approval_required=True,
        preconditions=(
            RecoveryPrecondition(
                name="exact-local-fixture",
                description="Recovery remains bound to the initialized fixture.",
                evaluator=_recovery_precondition,
            ),
        ),
        postconditions=(
            RecoveryPostcondition(
                name="repository-satisfies-contract",
                description="Reinspect the repository after the recovery receipt.",
                provider=_RecoveryReleaseEvidence(project.repository),
                evidence_type="release_guard",
                provider_identity="runmantle.release_guard.repository_inspector:v1",
                provider_configuration={"repository": "project-relative:repository"},
            ),
        ),
        created_at=project.created_at,
    )


async def resume_recovery(
    project: RunmantleProject,
    *,
    approve_current: bool = False,
    fault_after_write: bool = False,
) -> RecoveryResult:
    """Resume the exact durable recovery plan from a new process boundary."""

    active_runtime = runtime(project)
    plan = recovery_plan(project)
    contract = release_contract(project)
    executor = _recovery_executor(project, active_runtime, plan, fault_after_write)
    confirmation = PreActionCapabilityConfirmation(
        confirmation_id=f"{plan.plan_id}:preflight",
        action_id=plan.actions[0].action_id,
        capability=RECOVERY_CAPABILITY,
        idempotency_key=plan.actions[0].idempotency_key,
        supported=True,
        safe=True,
        confirmed_at=project.created_at,
        confirmed_by="runmantle.local_capability_registry",
        reason="The packaged, path-bounded recovery handler is installed.",
        target_hash=plan.actions[0].action_hash,
    )
    result = await executor.execute(
        plan,
        contract=contract,
        preflight_confirmation=confirmation,
    )
    if not approve_current or result.status.value != "awaiting_approval":
        return result
    approval = active_runtime.store.load_approval(f"recovery:{plan.plan_id}:approval")
    now = utc_now()
    active_runtime.record_approval_decision(
        ApprovalDecision(
            decision_id=new_id(),
            approval_id=approval.request.approval_id,
            request_hash=approval.request.request_hash,
            approved=True,
            approver=ApproverIdentity(
                subject="local-cli-user",
                issuer="runmantle.local_cli",
                authenticated_at=now,
                authentication_method="local-process-assertion",
                claims={"not_remote_identity_proof": True},
            ),
            decided_at=now,
            reason="Operator explicitly approved the current exact recovery plan.",
        )
    )
    return await _recovery_executor(
        project,
        active_runtime,
        plan,
        fault_after_write,
    ).execute(
        plan,
        contract=contract,
        preflight_confirmation=confirmation,
    )


def inspect_repository(repository: Path) -> dict[str, Any]:
    """Acquire deterministic local evidence without executing repository code."""

    repository = _validated_repository_root(repository)
    manifest: dict[str, Any] = {}
    try:
        manifest_content = _read_repository_file(repository, "release.json")
        loaded = json.loads(
            manifest_content.decode("utf-8") if manifest_content is not None else ""
        )
        if isinstance(loaded, dict):
            manifest = loaded
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    artifact = _read_repository_file(repository, "dist/release.txt") or b""
    actual_hash = f"sha256:{hashlib.sha256(artifact).hexdigest()}" if artifact else None
    git = _run_git(
        repository,
        "status",
        "--porcelain",
        "--untracked-files=all",
        check=False,
    )
    checks = {
        "manifest_ready": manifest.get("ready") is True,
        "artifact_exists": bool(artifact),
        "artifact_hash_matches": manifest.get("artifact_sha256") == actual_hash,
        "git_repository": git.returncode == 0,
        "repository_clean": git.returncode == 0 and not git.stdout.strip(),
    }
    return {
        **checks,
        "all_passed": all(checks.values()),
        "artifact_sha256": actual_hash,
    }


def apply_release_fix(
    repository: Path, *, fault_after_write: bool = False
) -> dict[str, Any]:
    """Apply the one narrowly scoped reference recovery action."""

    repository = _validated_repository_root(repository)
    artifact = b"runmantle verified release\n"
    _write_repository_file(
        repository,
        "dist/release.txt",
        artifact,
        create_parent=True,
    )
    digest = f"sha256:{hashlib.sha256(artifact).hexdigest()}"
    _write_repository_file(
        repository,
        "release.json",
        (
            json.dumps({"ready": True, "artifact_sha256": digest}, sort_keys=True)
            + "\n"
        ).encode("utf-8"),
    )
    if fault_after_write:
        raise RuntimeError("injected crash after filesystem effects")
    for relative in (".git", "release.json", "dist", "dist/release.txt"):
        _validate_existing_repository_path(repository, relative)
    _recovery_git(
        repository,
        "--literal-pathspecs",
        "add",
        "--",
        "release.json",
        "dist/release.txt",
    )
    _recovery_git(
        repository,
        "-c",
        "user.name=Runmantle",
        "-c",
        "user.email=local@runmantle.dev",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "--no-verify",
        "--only",
        "-m",
        "Prepare verified release",
        "--",
        "release.json",
        "dist/release.txt",
    )
    return {"artifact_sha256": digest, "mutated": True}


def _validated_repository_root(repository: Path) -> Path:
    """Resolve an authorized real directory while rejecting a symlink root."""

    if repository.is_symlink():
        raise RepositoryBoundaryError("repository root must not be a symlink")
    try:
        resolved = repository.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RepositoryBoundaryError("repository root is unavailable") from error
    if not resolved.is_dir():
        raise RepositoryBoundaryError("repository root must be a directory")
    return resolved


def _repository_parts(relative: str) -> tuple[str, ...]:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise RepositoryBoundaryError(
            "repository paths must be non-empty relative paths without '..'"
        )
    if any(part in {"", "."} for part in candidate.parts):
        raise RepositoryBoundaryError("repository paths must be normalized")
    return candidate.parts


def _open_repository_directory(
    repository: Path,
    parts: tuple[str, ...],
    *,
    create: bool = False,
) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(repository, flags)
    try:
        for part in parts:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o755, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise RepositoryBoundaryError(
                "repository path contains a symlink or non-directory component"
            ) from error
        raise


def _read_repository_file(repository: Path, relative: str) -> bytes | None:
    parts = _repository_parts(relative)
    try:
        parent = _open_repository_directory(repository, parts[:-1])
    except FileNotFoundError:
        return None
    try:
        try:
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise RepositoryBoundaryError(
                    "repository read target is a symlink or invalid path"
                ) from error
            raise
        with os.fdopen(descriptor, "rb") as stream:
            return stream.read()
    finally:
        os.close(parent)


def _write_repository_file(
    repository: Path,
    relative: str,
    content: bytes,
    *,
    create_parent: bool = False,
) -> None:
    parts = _repository_parts(relative)
    try:
        parent = _open_repository_directory(
            repository,
            parts[:-1],
            create=create_parent,
        )
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise RepositoryBoundaryError(
                "repository mutation path contains a symlink"
            ) from error
        raise
    try:
        try:
            descriptor = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o644,
                dir_fd=parent,
            )
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise RepositoryBoundaryError(
                    "repository mutation target is a symlink or invalid path"
                ) from error
            raise
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(parent)


def _validate_existing_repository_path(repository: Path, relative: str) -> None:
    parts = _repository_parts(relative)
    descriptor = _open_repository_directory(repository, parts[:-1])
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if relative in {".git", "dist"}:
            flags |= os.O_DIRECTORY
        try:
            target = os.open(parts[-1], flags, dir_fd=descriptor)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise RepositoryBoundaryError(
                    "Git input contains a symlink or invalid component"
                ) from error
            raise
        os.close(target)
    finally:
        os.close(descriptor)


def _run_git(
    repository: Path,
    *arguments: str,
    check: bool,
) -> subprocess.CompletedProcess[str]:
    """Run Git with the repository's own hooks and configuration disabled.

    A checkout under evaluation must not be able to influence the guard that
    inspects it, so hooks, fsmonitor and both system and global config are
    neutralised on every invocation.
    """

    return subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            *arguments,
        ],
        cwd=repository,
        check=check,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
    )


def _recovery_git(repository: Path, *arguments: str) -> None:
    """Run a framework-managed Git command with repository hooks disabled."""

    _validate_existing_repository_path(repository, ".git")
    _run_git(repository, *arguments, check=True)


def _latest_release_evidence_passes(
    output: dict[str, Any], evidence: EvidenceCollection
) -> bool | None:
    del output
    items = tuple(evidence.of_type("release_guard"))
    if not items:
        return None
    latest = max(items, key=lambda item: (item.collected_at, item.evidence_id))
    return latest.payload is not None and latest.payload.get("all_passed") is True


def _recovery_precondition(
    plan: RecoveryPlan,
    action: RecoveryAction,
    contract: TaskContract[Any, Any],
) -> bool:
    return (
        plan.task_id == contract.task_id
        and action.idempotency_key == contract.idempotency_key
        and action.parameters.get("repository") == "repository"
    )


def _inspect_declaration() -> CapabilityDeclaration:
    return CapabilityDeclaration(
        name=INSPECT_CAPABILITY,
        description="Read bounded local release state and git status.",
        supported_task_states=frozenset(
            {TaskStatus.AWAITING_EVIDENCE, TaskStatus.FAILED}
        ),
        maximum_risk_level=RiskLevel.LOW,
        requires_runtime_confirmation=False,
    )


def _recovery_declaration() -> CapabilityDeclaration:
    return CapabilityDeclaration(
        name=RECOVERY_CAPABILITY,
        description="Write and commit the reference release artifact.",
        recovery_supported=True,
        supported_task_states=frozenset(
            {TaskStatus.FAILED, TaskStatus.AWAITING_EVIDENCE}
        ),
        requires_idempotency=True,
        maximum_risk_level=RiskLevel.MEDIUM,
        requires_approval=True,
        requires_runtime_confirmation=True,
    )


def _recovery_executor(
    project: RunmantleProject,
    active_runtime: DurableRuntime,
    plan: RecoveryPlan,
    fault_after_write: bool,
) -> DurableRecoveryExecutor:
    async def handler(action: RecoveryAction, contract: TaskContract[Any, Any]) -> Any:
        del action, contract
        value = await asyncio.to_thread(
            apply_release_fix,
            project.repository,
            fault_after_write=fault_after_write,
        )
        return RecoveryExecutorResult(succeeded=True, output=value)

    postcondition = plan.postconditions[0]
    assert postcondition.provider_identity is not None
    evidence_providers = EvidenceProviderRegistry(
        (
            EvidenceProviderRegistration(
                provider=postcondition.provider,
                provider_identity=postcondition.provider_identity,
                provider_configuration=postcondition.provider_configuration,
                trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                acquisition_method=EvidenceAcquisitionMethod.FILESYSTEM_INSPECTION,
            ),
        )
    )
    return DurableRecoveryExecutor(
        store=active_runtime.store,
        registry=CapabilityRegistry((_recovery_declaration(),)),
        policy=RecoveryPolicy(
            allowed_capabilities=frozenset({RECOVERY_CAPABILITY}),
            allowed_task_states=frozenset(
                {TaskStatus.FAILED, TaskStatus.AWAITING_EVIDENCE}
            ),
            maximum_risk_level=RiskLevel.MEDIUM,
            approval_required_capabilities=frozenset({RECOVERY_CAPABILITY}),
            require_runtime_confirmation=True,
        ),
        handlers={
            RECOVERY_CAPABILITY: RecoveryHandlerRegistration(
                handler=handler,
                handler_identity="runmantle.release_guard.apply_release_fix:v1",
                handler_configuration={"artifact": "dist/release.txt"},
            )
        },
        evidence_providers=evidence_providers,
        verifier=RuleBasedVerifier(),
        event_sink=_event_sink(project),
    )


def _event_sink(project: RunmantleProject) -> EventSink:
    local = JsonlEventSink(project.event_path)
    if not project.cortexops_enabled:
        return local
    from .integrations.cortexops import (
        CortexOpsIntegrationConfig,
        create_cortexops_event_sink,
    )

    cortexops = create_cortexops_event_sink(
        CortexOpsIntegrationConfig(
            enabled=True,
            export_path=project.state_directory / "cortexops-events.jsonl",
            outbox_path=project.state_directory / "cortexops-outbox.sqlite3",
        )
    )
    return CompositeEventSink((local, cortexops))


class _ActionReleaseEvidence:
    def __init__(self, repository: Path) -> None:
        self.repository = repository

    async def acquire(self, request: Any, receipt: Any) -> EvidenceItem:
        return _release_evidence(
            self.repository,
            source="runmantle.release_guard.action_postcondition",
            provenance={
                "action_id": request.action_id,
                "receipt_id": receipt.receipt_id,
            },
        )


class _RecoveryReleaseEvidence:
    def __init__(self, repository: Path) -> None:
        self.repository = repository

    async def acquire(self, plan: Any, action: Any, receipt: Any) -> EvidenceItem:
        return _release_evidence(
            self.repository,
            source="runmantle.release_guard.recovery_postcondition",
            provenance={
                "plan_id": plan.plan_id,
                "action_id": action.action_id,
                "receipt_id": receipt.receipt_id,
            },
        )


def _release_evidence(
    repository: Path, *, source: str, provenance: dict[str, Any]
) -> EvidenceItem:
    now = utc_now()
    return EvidenceItem(
        evidence_id=new_id(),
        type="release_guard",
        source=source,
        collected_at=now,
        payload=inspect_repository(repository),
        provenance={**provenance, "repository": "project-relative:repository"},
        acquisition_method=EvidenceAcquisitionMethod.FILESYSTEM_INSPECTION,
        trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
        expires_at=now + timedelta(minutes=10),
    )
