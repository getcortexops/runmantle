from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest

pytest.importorskip("agents")

from agents import Agent, RunContextWrapper, WebSearchTool, function_tool, handoff
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from runmantle import (
    ActionPolicy,
    AgentAdapterContract,
    AgentAdapterWorker,
    AgentIdentity,
    CallableEvidenceProvider,
    CancellationToken,
    CapabilityDeclaration,
    CapabilityRegistry,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    InMemoryRuntime,
    MediatedActionExecutor,
    Postcondition,
    RiskLevel,
    RuleBasedVerifier,
    TaskContract,
    TaskStatus,
)
from runmantle.evidence import utc_now
from runmantle.integrations.openai_agents import (
    OpenAIAgentsAdapter,
    OpenAIAgentsEnforcementMode,
    OpenAIAgentsRunContext,
    inspect_openai_agent_surface,
    mediate_openai_function_tool,
)

DEPLOY = "deploy"


def output_message(text: str = "done") -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id="message-1",
        role="assistant",
        status="completed",
        type="message",
        content=[
            ResponseOutputText(
                annotations=[],
                text=text,
                type="output_text",
                logprobs=[],
            )
        ],
    )


def function_call() -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        arguments='{"service":"api"}',
        call_id="call-1",
        name="deploy_service",
        type="function_call",
        id="function-call-1",
    )


class ScriptedModel(Model):
    def __init__(self, *turns: list[Any]) -> None:
        self.turns = list(turns)
        self.calls = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        del args, kwargs
        self.calls += 1
        return ModelResponse(
            output=self.turns.pop(0),
            usage=Usage(),
            response_id=None,
        )

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        del args, kwargs

        async def empty() -> AsyncIterator[Any]:
            if False:
                yield None

        return empty()


class SlowModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        del args, kwargs
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        del args, kwargs

        async def empty() -> AsyncIterator[Any]:
            if False:
                yield None

        return empty()


def capability() -> CapabilityDeclaration:
    return CapabilityDeclaration(
        name=DEPLOY,
        description="Deploy through the mediated OpenAI function tool.",
        requires_runtime_confirmation=False,
    )


def adapter_contract() -> AgentAdapterContract:
    return AgentAdapterContract(
        identity=AgentIdentity(
            agent_id="openai-deployer",
            name="OpenAI deployer",
            role="deployment",
            version="1.0.0",
        ),
        capabilities=(capability(),),
        emits_evidence=True,
    )


def task_contract(
    task_id: str,
    *,
    capabilities: frozenset[str] = frozenset({DEPLOY}),
    require_evidence: bool = True,
    timeout: timedelta = timedelta(seconds=2),
    session_id: str | None = None,
) -> TaskContract[dict[str, str], dict[str, str]]:
    evidence = (
        (
            EvidenceRequirement(
                "external_state",
                "Independently observe the deployed state.",
                minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
            ),
        )
        if require_evidence
        else ()
    )
    criteria: list[Any] = [
        FieldEqualsCriterion(
            name="agent-output",
            description="The mapped agent output says done.",
            field_path="status",
            expected="done",
        )
    ]
    if require_evidence:
        criteria.append(
            FieldEqualsCriterion(
                name="external-state",
                description="The external state is independently complete.",
                field_path="complete",
                expected=True,
                evidence_type="external_state",
            )
        )
    return TaskContract(
        task_id=task_id,
        objective="Deploy the API service.",
        input={"service": "api"},
        acceptance_criteria=tuple(criteria),
        required_evidence=evidence,
        allowed_capabilities=capabilities,
        risk_level=RiskLevel.LOW,
        timeout=timeout,
        idempotency_key=f"{task_id}-once",
        metadata={} if session_id is None else {"session_id": session_id},
    )


def adapter_for(
    agent: Agent[Any],
    *,
    enforcement: OpenAIAgentsEnforcementMode = (
        OpenAIAgentsEnforcementMode.FAIL_CLOSED
    ),
) -> OpenAIAgentsAdapter[dict[str, str], dict[str, str]]:
    return OpenAIAgentsAdapter(
        agent=agent,
        adapter_contract=adapter_contract(),
        output_mapper=lambda output, result: {"status": str(output)},
        enforcement_mode=enforcement,
        run_config={"tracing_disabled": True},
    )


async def _runner_return_is_only_claim_without_required_evidence() -> None:
    model = ScriptedModel([output_message()])
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        AgentAdapterWorker(adapter_for(Agent(name="deployer", model=model))),
        task_contract("claim-only"),
        correlation_id="session-claim-only",
    )

    assert model.calls == 1
    assert result.reported_status is not None
    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert not result.succeeded


async def _agent_evidence_mapper_cannot_self_assign_independent_trust() -> None:
    model = ScriptedModel([output_message()])
    adapter = adapter_for(Agent(name="deployer", model=model))
    adapter = OpenAIAgentsAdapter(
        agent=adapter.agent,
        adapter_contract=adapter.adapter_contract,
        output_mapper=adapter.output_mapper,
        evidence_mapper=lambda result, output: EvidenceItem(
            evidence_id="external-observation-1",
            type="external_state",
            source="test.independent-read-client",
            collected_at=utc_now(),
            payload={"complete": True},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        ),
        run_config={"tracing_disabled": True},
    )
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        AgentAdapterWorker(adapter),
        task_contract("mapped-evidence"),
    )

    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert result.evidence[0].source == "test.independent-read-client"
    assert result.evidence[0].trust_level is EvidenceTrustLevel.AGENT_CLAIM
    assert not result.evidence[0].trust_established


async def _fail_closed_rejects_unmediated_tools_before_model_call() -> None:
    calls = 0

    @function_tool(failure_error_function=None)
    async def deploy_service(service: str) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"service": service}

    model = ScriptedModel([function_call()], [output_message()])
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        AgentAdapterWorker(
            adapter_for(Agent(name="deployer", model=model, tools=[deploy_service]))
        ),
        task_contract("unmediated", require_evidence=False),
    )

    assert result.status is TaskStatus.FAILED
    assert model.calls == 0
    assert calls == 0


async def _observe_only_explicitly_allows_unmediated_function_tool() -> None:
    @function_tool(failure_error_function=None)
    async def deploy_service(service: str) -> dict[str, str]:
        return {"service": service}

    model = ScriptedModel([function_call()], [output_message()])
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        AgentAdapterWorker(
            adapter_for(
                Agent(name="deployer", model=model, tools=[deploy_service]),
                enforcement=OpenAIAgentsEnforcementMode.OBSERVE_ONLY,
            )
        ),
        task_contract("observe-only", require_evidence=False),
    )

    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert not result.succeeded
    assert model.calls == 2


async def _missing_capability_blocks_mediated_tool_without_side_effect() -> None:
    with TemporaryDirectory() as directory:
        runtime = DurableRuntime(
            database_path=Path(directory) / "runtime.db",
            verifier=RuleBasedVerifier(),
        )
        executor = MediatedActionExecutor(
            store=runtime.store,
            capabilities=CapabilityRegistry((capability(),)),
            policy=ActionPolicy(
                allowed_capabilities=frozenset({DEPLOY}),
                maximum_risk_level=RiskLevel.LOW,
            ),
        )
        calls = 0

        @function_tool(failure_error_function=None)
        async def deploy_service(service: str) -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"service": service}

        mediated = mediate_openai_function_tool(
            deploy_service,
            executor=executor,
            required_capability=DEPLOY,
        )
        model = ScriptedModel([function_call()], [output_message()])
        result = await runtime.execute(
            AgentAdapterWorker(
                adapter_for(Agent(name="deployer", model=model, tools=[mediated]))
            ),
            task_contract(
                "blocked-tool",
                capabilities=frozenset(),
                require_evidence=False,
            ),
        )

        assert result.status is TaskStatus.FAILED
        assert calls == 0
        action = runtime.store.load_action("openai:blocked-tool:deploy_service:call-1")
        assert action.status.value == "blocked"


async def _mediated_tool_propagates_context_and_verifies_postcondition() -> None:
    with TemporaryDirectory() as directory:
        runtime = DurableRuntime(
            database_path=Path(directory) / "runtime.db",
            verifier=RuleBasedVerifier(),
        )
        observed_context: list[OpenAIAgentsRunContext] = []

        @function_tool(failure_error_function=None)
        async def deploy_service(
            context: RunContextWrapper[OpenAIAgentsRunContext],
            service: str,
        ) -> dict[str, str]:
            observed_context.append(context.context)
            return {"service": service, "receipt": "executor-return"}

        provider = CallableEvidenceProvider(
            provider=lambda request, receipt: {
                "complete": receipt.output["service"] == "api",
            },
            evidence_type="external_state",
            source="test.external-observer",
            trust_level=EvidenceTrustLevel.INDEPENDENT,
            acquisition_method=(EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER),
        )
        provider_configuration = {
            "evidence_type": "external_state",
            "source": "test.external-observer",
        }
        provider_registry = EvidenceProviderRegistry(
            (
                EvidenceProviderRegistration(
                    provider=provider,
                    provider_identity="tests.openai.external_observer:v1",
                    provider_configuration=provider_configuration,
                    trust_level=EvidenceTrustLevel.INDEPENDENT,
                    acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
                ),
            )
        )
        executor = MediatedActionExecutor(
            store=runtime.store,
            capabilities=CapabilityRegistry((capability(),)),
            policy=ActionPolicy(
                allowed_capabilities=frozenset({DEPLOY}),
                maximum_risk_level=RiskLevel.LOW,
            ),
            evidence_providers=provider_registry,
        )
        postcondition = Postcondition(
            name="observe-deployment",
            description="Read the independently observed deployment state.",
            provider=provider,
            evidence_type="external_state",
            provider_identity="tests.openai.external_observer:v1",
            provider_configuration=provider_configuration,
        )
        mediated = mediate_openai_function_tool(
            deploy_service,
            executor=executor,
            required_capability=DEPLOY,
            postconditions=(postcondition,),
        )
        model = ScriptedModel([function_call()], [output_message()])
        result = await runtime.execute(
            AgentAdapterWorker(
                adapter_for(Agent(name="deployer", model=model, tools=[mediated]))
            ),
            task_contract("verified-tool", session_id="application-session-7"),
            correlation_id="openai-session-42",
        )

        assert result.status is TaskStatus.VERIFIED
        assert len(result.evidence) == 1
        metadata = observed_context[0].runmantle
        assert metadata.task_id == "verified-tool"
        assert metadata.correlation_id == "openai-session-42"
        assert metadata.session_id == "application-session-7"
        assert metadata.worker_id == "openai-deployer"
        assert metadata.capabilities == frozenset({DEPLOY})
        assert metadata.idempotency_key == "verified-tool-once"
        event_names = {event.name for event in runtime.event_history("verified-tool")}
        assert "openai.tool.started" in event_names
        assert "action.executor_succeeded" in event_names
        assert "openai.agent.reported_output" in event_names


def test_surface_report_marks_sdk_owned_paths_as_unenforced() -> None:
    nested = Agent(name="nested")
    agent = Agent(
        name="outer",
        tools=[
            WebSearchTool(),
            nested.as_tool(
                tool_name="nested_agent",
                tool_description="Run the nested agent.",
            ),
        ],
        handoffs=[handoff(nested)],
        mcp_servers=[object()],  # type: ignore[list-item]
    )

    kinds = {item.kind for item in inspect_openai_agent_surface(agent).issues}

    assert "sdk_websearch_tool" in kinds
    assert "agent_as_tool" in kinds
    assert "handoff" in kinds
    assert "local_mcp_tools" in kinds


async def _timeout_cancels_openai_run_and_never_reports_success() -> None:
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        AgentAdapterWorker(adapter_for(Agent(name="slow", model=SlowModel()))),
        task_contract(
            "timed-out",
            require_evidence=False,
            timeout=timedelta(milliseconds=20),
        ),
    )

    assert result.status is TaskStatus.FAILED
    assert not result.succeeded


async def _cancellation_reaches_openai_run_and_never_reports_success() -> None:
    cancellation = CancellationToken()

    async def cancel_soon() -> None:
        await asyncio.sleep(0.01)
        cancellation.cancel()

    cancellation_task = asyncio.create_task(cancel_soon())
    try:
        result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
            AgentAdapterWorker(adapter_for(Agent(name="slow", model=SlowModel()))),
            task_contract("cancelled", require_evidence=False),
            cancellation=cancellation,
        )
    finally:
        await cancellation_task

    assert result.status is TaskStatus.FAILED
    assert not result.succeeded


def test_runner_return_is_only_claim_without_required_evidence() -> None:
    asyncio.run(_runner_return_is_only_claim_without_required_evidence())


def test_fail_closed_rejects_unmediated_tools_before_model_call() -> None:
    asyncio.run(_fail_closed_rejects_unmediated_tools_before_model_call())


def test_agent_evidence_mapper_cannot_self_assign_independent_trust() -> None:
    asyncio.run(_agent_evidence_mapper_cannot_self_assign_independent_trust())


def test_observe_only_explicitly_allows_unmediated_function_tool() -> None:
    asyncio.run(_observe_only_explicitly_allows_unmediated_function_tool())


def test_missing_capability_blocks_mediated_tool_without_side_effect() -> None:
    asyncio.run(_missing_capability_blocks_mediated_tool_without_side_effect())


def test_mediated_tool_propagates_context_and_verifies_postcondition() -> None:
    asyncio.run(_mediated_tool_propagates_context_and_verifies_postcondition())


def test_timeout_cancels_openai_run_and_never_reports_success() -> None:
    asyncio.run(_timeout_cancels_openai_run_and_never_reports_success())


def test_cancellation_reaches_openai_run_and_never_reports_success() -> None:
    asyncio.run(_cancellation_reaches_openai_run_and_never_reports_success())
