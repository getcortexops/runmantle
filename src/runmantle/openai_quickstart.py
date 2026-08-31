"""Runnable, network-free OpenAI Agents SDK adapter quickstart."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from agents import Agent, function_tool
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from .actions import (
    ActionPolicy,
    ActionRequest,
    MediatedActionExecutor,
    Postcondition,
)
from .adapters import AgentAdapterContract, AgentAdapterWorker, AgentIdentity
from .capabilities import CapabilityDeclaration, CapabilityRegistry
from .contracts import RiskLevel, TaskContract, TaskStatus
from .durable import DurableRuntime
from .evidence import (
    EvidenceAcquisitionMethod,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
)
from .evidence_providers import CallableEvidenceProvider
from .integrations.openai_agents import (
    OpenAIAgentsAdapter,
    mediate_openai_function_tool,
)
from .verification import FieldEqualsCriterion, RuleBasedVerifier

CAPABILITY = "deploy"


class ScriptedModel(Model):
    """SDK model implementation that returns fixed local responses."""

    def __init__(self, *turns: list[Any]) -> None:
        self.turns = list(turns)

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        del args, kwargs
        return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        del args, kwargs

        async def empty() -> AsyncIterator[Any]:
            if False:
                yield None

        return empty()


def output_message() -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id="message-1",
        role="assistant",
        status="completed",
        type="message",
        content=[
            ResponseOutputText(
                annotations=[], text="done", type="output_text", logprobs=[]
            )
        ],
    )


def _tool_call() -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        arguments='{"service":"api"}',
        call_id="call-1",
        name="deploy_service",
        type="function_call",
        id="function-call-1",
    )


def _boundary() -> AgentAdapterContract:
    return AgentAdapterContract(
        identity=AgentIdentity("openai-agent", "Existing agent", "deployment", "1.0.0"),
        capabilities=(CapabilityDeclaration(CAPABILITY, "Deploy a service."),),
        emits_evidence=False,
    )


def _contract(task_id: str, *, capabilities: frozenset[str]) -> TaskContract[Any, Any]:
    return TaskContract(
        task_id=task_id,
        objective="Deploy the API and prove its observed state.",
        input={"service": "api"},
        acceptance_criteria=(
            FieldEqualsCriterion("claim", "Agent must report done.", "status", "done"),
            FieldEqualsCriterion(
                "state",
                "Observed state must be ready.",
                "ready",
                True,
                evidence_type="deployment_state",
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                "deployment_state",
                "Independent deployment observation.",
                minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
            ),
        ),
        allowed_capabilities=capabilities,
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=5),
        idempotency_key=f"{task_id}-once",
    )


def _adapter(agent: Agent[Any]) -> AgentAdapterWorker[Any, Any]:
    return AgentAdapterWorker(
        OpenAIAgentsAdapter(
            agent=agent,
            adapter_contract=_boundary(),
            output_mapper=lambda output, result: {"status": str(output)},
            run_config={"tracing_disabled": True},
        )
    )


async def run_quickstart() -> dict[str, Any]:
    with TemporaryDirectory() as directory:
        runtime = DurableRuntime(
            database_path=Path(directory) / "runtime.db", verifier=RuleBasedVerifier()
        )
        claim = await runtime.execute(
            _adapter(
                Agent(name="existing-agent", model=ScriptedModel([output_message()]))
            ),
            _contract("claim", capabilities=frozenset({CAPABILITY})),
        )

        calls = 0

        @function_tool(failure_error_function=None)
        async def deploy_service(service: str) -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"service": service}

        executor = MediatedActionExecutor(
            store=runtime.store,
            capabilities=CapabilityRegistry(
                (CapabilityDeclaration(CAPABILITY, "Deploy."),)
            ),
            policy=ActionPolicy(allowed_capabilities=frozenset({CAPABILITY})),
        )
        mediated = mediate_openai_function_tool(
            deploy_service, executor=executor, required_capability=CAPABILITY
        )
        blocked = await runtime.execute(
            _adapter(
                Agent(
                    name="existing-agent",
                    model=ScriptedModel([_tool_call()]),
                    tools=[mediated],
                )
            ),
            _contract("blocked", capabilities=frozenset()),
        )
        observer = CallableEvidenceProvider(
            provider=lambda request, receipt: {"ready": receipt.output["deployed"]},
            evidence_type="deployment_state",
            source="quickstart.independent_observer",
        )
        observer_identity = "quickstart.independent_observer:v1"
        observer_configuration = {
            "evidence_type": "deployment_state",
            "source": "quickstart.independent_observer",
        }
        claim_executor = MediatedActionExecutor(
            store=runtime.store,
            capabilities=CapabilityRegistry(
                (
                    CapabilityDeclaration(
                        CAPABILITY,
                        "Deploy.",
                        requires_runtime_confirmation=False,
                    ),
                )
            ),
            policy=ActionPolicy(
                allowed_capabilities=frozenset({CAPABILITY}),
                allowed_task_states=frozenset({TaskStatus.AWAITING_EVIDENCE}),
            ),
            evidence_providers=EvidenceProviderRegistry(
                (
                    EvidenceProviderRegistration(
                        provider=observer,
                        provider_identity=observer_identity,
                        provider_configuration=observer_configuration,
                        trust_level=EvidenceTrustLevel.INDEPENDENT,
                        acquisition_method=(
                            EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER
                        ),
                    ),
                )
            ),
        )

        async def deploy(arguments: Any, cancellation: Any) -> dict[str, bool]:
            del arguments, cancellation
            return {"deployed": True}

        claim_contract = _contract("claim", capabilities=frozenset({CAPABILITY}))
        await claim_executor.execute(
            ActionRequest(
                action_id="claim-deploy",
                task_id="claim",
                name="deploy",
                required_capability=CAPABILITY,
                input={"service": "api"},
                idempotency_key="claim-deploy-once",
                risk_level=RiskLevel.LOW,
                requested_by="quickstart",
                requested_at=claim.timestamps.pending_at,
                execution_handler_id="quickstart.deploy:v1",
                postconditions=(
                    Postcondition(
                        name="observe-deployment",
                        description="Read deployment state independently.",
                        provider=observer,
                        evidence_type="deployment_state",
                        provider_identity=observer_identity,
                        provider_configuration=observer_configuration,
                    ),
                ),
            ),
            contract=claim_contract,
            handler=deploy,
            granted_capabilities=frozenset({CAPABILITY}),
        )
        verified = await runtime.resume("claim", contract=claim_contract)
        return {
            "claim_status": claim.status.value,
            "blocked_status": blocked.status.value,
            "blocked_tool_calls": calls,
            "final_status": verified.status.value,
            "verified": verified.succeeded,
        }


def main() -> None:
    print(json.dumps(asyncio.run(run_quickstart()), sort_keys=True))


if __name__ == "__main__":
    main()
