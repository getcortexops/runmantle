"""Optional OpenAI Agents SDK adapter with explicit enforcement boundaries.

Install with ``runmantle[openai-agents]``. Importing the Runmantle core does not
import this module or require the OpenAI package.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import timedelta
from enum import StrEnum
from typing import Any, Generic, TypeVar, cast

try:
    from agents import Agent, FunctionTool, RunConfig, RunHooks, Runner
    from agents.exceptions import AgentsException
    from agents.items import (
        HandoffCallItem,
        HandoffOutputItem,
        ToolCallItem,
        ToolCallOutputItem,
    )
    from agents.result import RunResult
    from agents.run_context import AgentHookContext, RunContextWrapper
    from agents.tool import set_function_tool_failure_error_function
    from agents.tool_context import ToolContext
except ModuleNotFoundError as error:  # pragma: no cover - exercised without extra
    raise ModuleNotFoundError(
        "OpenAI Agents integration requires the optional dependency; install "
        "with `pip install 'runmantle[openai-agents]'`"
    ) from error

from runmantle.actions import (
    ActionExecutionStatus,
    ActionExecutor,
    ActionRequest,
    Postcondition,
    Precondition,
    callable_semantic_identity,
)
from runmantle.adapters import (
    AgentAdapterContract,
    AgentHealth,
    AgentHealthStatus,
    AgentIdentity,
)
from runmantle.contracts import RiskLevel, TaskContract
from runmantle.core import (
    TaskCancelledError,
    TaskContext,
    TaskError,
    TaskErrorCode,
    WorkerReport,
)
from runmantle.evidence import EvidenceCollection, EvidenceItem, new_id, utc_now
from runmantle.serialization import SafeJsonCodec
from runmantle.telemetry import LifecycleEventType

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")

OpenAIInput = str | list[Any]
InputMapper = Callable[[TaskContract[Any, Any]], OpenAIInput]
OutputMapper = Callable[[Any, RunResult], Any]
EvidenceMapper = Callable[
    [RunResult, Any],
    EvidenceItem | EvidenceCollection | Sequence[EvidenceItem],
]
ContextFactory = Callable[["OpenAIAgentsRunMetadata"], Any]
SessionFactory = Callable[["OpenAIAgentsRunMetadata"], Any]

_MEDIATED_MARKER = "__runmantle_mediated_function_tool__"


class OpenAIAgentsEnforcementMode(StrEnum):
    """How unsupported OpenAI execution surfaces are handled."""

    FAIL_CLOSED = "fail_closed"
    OBSERVE_ONLY = "observe_only"


class UnsupportedOpenAIAgentsSurfaceError(RuntimeError):
    """Raised before a run whose tools cannot meet fail-closed enforcement."""


class OpenAIMediatedToolError(RuntimeError):
    """Raised when a mediated tool does not reach executor-reported success."""


@dataclass(frozen=True, slots=True)
class OpenAIAgentSurfaceIssue:
    """One SDK path Runmantle cannot enforce through the action executor."""

    path: str
    kind: str
    reason: str


@dataclass(frozen=True, slots=True)
class OpenAIAgentSurfaceReport:
    """Static inspection result for the supplied starting agent."""

    issues: tuple[OpenAIAgentSurfaceIssue, ...] = ()

    @property
    def fully_mediated(self) -> bool:
        return not self.issues


@dataclass(frozen=True, slots=True)
class OpenAIAgentsRunMetadata:
    """Runmantle identifiers propagated into local SDK context and tracing."""

    task_id: str
    correlation_id: str
    session_id: str
    worker_id: str
    worker_name: str
    capabilities: frozenset[str]
    idempotency_key: str
    timeout: timedelta
    task_metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class OpenAIAgentsRunContext:
    """Default local context passed to ``Runner.run``.

    Existing applications may supply ``context_factory`` to keep their own
    context type. Mediated tools use a task-local ContextVar and do not require
    this wrapper type.
    """

    runmantle: OpenAIAgentsRunMetadata
    application: Any = None


@dataclass(frozen=True, slots=True)
class _ActiveRun:
    contract: TaskContract[Any, Any]
    context: TaskContext
    identity: AgentIdentity
    metadata: OpenAIAgentsRunMetadata


_ACTIVE_RUN: ContextVar[_ActiveRun | None] = ContextVar(
    "runmantle_openai_agents_active_run",
    default=None,
)


@dataclass(frozen=True, slots=True)
class OpenAIAgentsAdapter(Generic[InputT, OutcomeT]):
    """Expose an existing OpenAI ``Agent`` and ``Runner`` as a Runmantle adapter.

    A normal ``Runner.run`` return becomes only ``WorkerReport.completed``.
    Runmantle evidence requirements and verification remain authoritative.
    """

    agent: Agent[Any] = field(compare=False, repr=False)
    adapter_contract: AgentAdapterContract
    input_mapper: InputMapper = field(
        default=lambda task: _default_input(task),
        compare=False,
        repr=False,
    )
    output_mapper: OutputMapper = field(
        default=lambda output, result: output,
        compare=False,
        repr=False,
    )
    evidence_mapper: EvidenceMapper | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    context_factory: ContextFactory = field(
        default=lambda metadata: OpenAIAgentsRunContext(metadata),
        compare=False,
        repr=False,
    )
    session_factory: SessionFactory | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    run_config: RunConfig | Mapping[str, Any] | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    max_turns: int | None = 10
    enforcement_mode: OpenAIAgentsEnforcementMode = (
        OpenAIAgentsEnforcementMode.FAIL_CLOSED
    )
    runner: Any = field(
        default=Runner,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.adapter_contract.supports_recovery_hooks:
            raise ValueError(
                "OpenAIAgentsAdapter does not implement recovery proposal hooks"
            )
        if self.max_turns is not None and self.max_turns < 1:
            raise ValueError("OpenAI max_turns must be positive or None")
        object.__setattr__(
            self,
            "enforcement_mode",
            OpenAIAgentsEnforcementMode(self.enforcement_mode),
        )

    @property
    def recovery_hooks(self) -> None:
        return None

    async def health(self) -> AgentHealth:
        return AgentHealth(
            AgentHealthStatus.UNKNOWN,
            "adapter construction does not probe the model provider or API key",
        )

    def inspect_surface(self) -> OpenAIAgentSurfaceReport:
        return inspect_openai_agent_surface(self.agent)

    async def submit(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        surface = self.inspect_surface()
        if (
            self.enforcement_mode is OpenAIAgentsEnforcementMode.FAIL_CLOSED
            and not surface.fully_mediated
        ):
            summary = "; ".join(f"{item.path}: {item.kind}" for item in surface.issues)
            raise UnsupportedOpenAIAgentsSurfaceError(
                f"OpenAI agent has non-mediated execution paths: {summary}"
            )
        for issue in surface.issues:
            context.event_emitter.emit(
                "openai.enforcement.observe_only",
                {
                    "path": issue.path,
                    "kind": issue.kind,
                    "reason": issue.reason,
                    "enforcement": "observe_only",
                },
            )

        identity = self.adapter_contract.identity
        configured_session_id = context.task_metadata.get("session_id")
        if configured_session_id is not None and (
            not isinstance(configured_session_id, str)
            or not configured_session_id.strip()
        ):
            raise ValueError("task metadata session_id must be a non-empty string")
        metadata = OpenAIAgentsRunMetadata(
            task_id=task.task_id,
            correlation_id=context.correlation_id,
            session_id=configured_session_id or context.correlation_id,
            worker_id=identity.agent_id,
            worker_name=identity.name,
            capabilities=context.allowed_capabilities,
            idempotency_key=task.idempotency_key,
            timeout=task.timeout,
            task_metadata=dict(context.task_metadata),
        )
        active = _ActiveRun(
            contract=cast(TaskContract[Any, Any], task),
            context=context,
            identity=identity,
            metadata=metadata,
        )
        token = _ACTIVE_RUN.set(active)
        try:
            result = await self._run(task, context, metadata)
            if result.interruptions:
                return WorkerReport.failed(
                    TaskError(
                        code=TaskErrorCode.WORKER_FAILURE,
                        message=(
                            "OpenAI run paused for SDK approval; RunState approval "
                            "resume is not a Runmantle durable checkpoint"
                        ),
                        error_type="OpenAIAgentsRunInterrupted",
                    )
                )
            self._emit_result_items(result, context)
            output = cast(
                OutcomeT,
                self.output_mapper(result.final_output, result),
            )
            if self.evidence_mapper is not None:
                for item in _evidence_items(self.evidence_mapper(result, output)):
                    _record_evidence(context, item)
            return WorkerReport.completed(output)
        except TaskCancelledError:
            raise
        except asyncio.CancelledError:
            raise
        except TimeoutError as error:
            return WorkerReport.failed(
                TaskError(
                    code=TaskErrorCode.TIMEOUT,
                    message=str(error),
                    error_type=type(error).__name__,
                )
            )
        except (AgentsException, OpenAIMediatedToolError) as error:
            return WorkerReport.failed(
                TaskError(
                    code=TaskErrorCode.WORKER_FAILURE,
                    message=str(error),
                    error_type=type(error).__name__,
                )
            )
        except Exception as error:  # noqa: BLE001 - external SDK/tool boundary
            return WorkerReport.failed(
                TaskError(
                    code=TaskErrorCode.WORKER_FAILURE,
                    message=str(error),
                    error_type=type(error).__name__,
                )
            )
        finally:
            _ACTIVE_RUN.reset(token)

    async def _run(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
        metadata: OpenAIAgentsRunMetadata,
    ) -> RunResult:
        run_task = asyncio.create_task(
            self.runner.run(
                self.agent,
                self.input_mapper(task),
                context=self.context_factory(metadata),
                max_turns=self.max_turns,
                hooks=_RunmantleOpenAIHooks(context),
                run_config=_merged_run_config(self.run_config, metadata),
                session=(
                    None
                    if self.session_factory is None
                    else self.session_factory(metadata)
                ),
            )
        )
        cancellation_waiter = asyncio.create_task(context.cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {run_task, cancellation_waiter},
                timeout=task.timeout.total_seconds(),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if run_task in done:
                return cast(RunResult, await run_task)
            run_task.cancel()
            await _suppress_cancelled(run_task)
            if cancellation_waiter in done:
                raise TaskCancelledError("OpenAI agent run was cancelled")
            raise TimeoutError(
                f"OpenAI agent run exceeded task timeout of {task.timeout}"
            )
        except asyncio.CancelledError:
            run_task.cancel()
            await _suppress_cancelled(run_task)
            raise
        finally:
            cancellation_waiter.cancel()
            await _suppress_cancelled(cancellation_waiter)

    @staticmethod
    def _emit_result_items(result: RunResult, context: TaskContext) -> None:
        for item in result.new_items:
            if isinstance(item, ToolCallItem):
                context.event_emitter.emit(
                    "openai.tool.call_observed",
                    {
                        "tool_name": item.tool_name,
                        "call_id": item.call_id,
                        "item_type": item.type,
                        "observation_only": True,
                        "note": (
                            "result-item origin does not prove that execution "
                            "passed through Runmantle"
                        ),
                    },
                    event_type=LifecycleEventType.TOOL_ACTION_REQUESTED,
                )
            elif isinstance(item, ToolCallOutputItem):
                context.event_emitter.emit(
                    "openai.tool.output_observed",
                    {
                        "call_id": item.call_id,
                        "item_type": item.type,
                        "proves_external_outcome": False,
                    },
                )
            elif isinstance(item, HandoffCallItem):
                context.event_emitter.emit(
                    "openai.handoff.call_observed",
                    {"item_type": item.type, "enforcement": "observe_only"},
                )
            elif isinstance(item, HandoffOutputItem):
                context.event_emitter.emit(
                    "openai.handoff.completed",
                    {
                        "item_type": item.type,
                        "source_agent": item.source_agent.name,
                        "target_agent": item.target_agent.name,
                        "enforcement": "observe_only",
                    },
                )


class _RunmantleOpenAIHooks(RunHooks[Any]):
    def __init__(self, context: TaskContext) -> None:
        self._context = context

    async def on_agent_start(
        self,
        context: AgentHookContext[Any],
        agent: Agent[Any],
    ) -> None:
        del context
        self._context.event_emitter.emit(
            "openai.agent.started",
            {"agent_name": agent.name},
        )

    async def on_agent_end(
        self,
        context: AgentHookContext[Any],
        agent: Agent[Any],
        output: Any,
    ) -> None:
        del output
        self._context.event_emitter.emit(
            "openai.agent.reported_output",
            {
                "agent_name": agent.name,
                "model_requests": context.usage.requests,
                "proves_task_success": False,
            },
        )

    async def on_handoff(
        self,
        context: RunContextWrapper[Any],
        from_agent: Agent[Any],
        to_agent: Agent[Any],
    ) -> None:
        del context
        self._context.event_emitter.emit(
            "openai.handoff.observed",
            {
                "source_agent": from_agent.name,
                "target_agent": to_agent.name,
                "enforcement": "observe_only",
            },
        )

    async def on_tool_start(
        self,
        context: RunContextWrapper[Any],
        agent: Agent[Any],
        tool: Any,
    ) -> None:
        self._context.event_emitter.emit(
            "openai.tool.started",
            {
                "agent_name": agent.name,
                "tool_name": getattr(tool, "name", type(tool).__name__),
                "call_id": getattr(context, "tool_call_id", None),
                "mediated": is_mediated_openai_function_tool(tool),
            },
            event_type=LifecycleEventType.TOOL_ACTION_REQUESTED,
        )

    async def on_tool_end(
        self,
        context: RunContextWrapper[Any],
        agent: Agent[Any],
        tool: Any,
        result: object,
    ) -> None:
        del result
        self._context.event_emitter.emit(
            "openai.tool.completed",
            {
                "agent_name": agent.name,
                "tool_name": getattr(tool, "name", type(tool).__name__),
                "call_id": getattr(context, "tool_call_id", None),
                "executor_receipt_is_verification": False,
            },
        )


@dataclass(frozen=True, slots=True)
class OpenAIMediatedFunctionTool:
    """Wrap one SDK ``FunctionTool`` around a Runmantle ``ActionExecutor``."""

    source: FunctionTool = field(compare=False, repr=False)
    executor: ActionExecutor = field(compare=False, repr=False)
    required_capability: str
    risk_level: RiskLevel = RiskLevel.LOW
    timeout: timedelta = timedelta(seconds=30)
    preconditions: tuple[Precondition, ...] = ()
    postconditions: tuple[Postcondition, ...] = ()
    dry_run: bool = False
    clock: Callable[[], Any] = field(default=utc_now, compare=False, repr=False)
    id_factory: Callable[[], str] = field(default=new_id, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.required_capability.strip():
            raise ValueError("mediated OpenAI tool capability must not be empty")
        if self.timeout.total_seconds() <= 0:
            raise ValueError("mediated OpenAI tool timeout must be positive")
        if getattr(self.source, "_is_agent_tool", False):
            raise UnsupportedOpenAIAgentsSurfaceError(
                "Agent.as_tool cannot be converted into a mediated function tool"
            )
        if is_mediated_openai_function_tool(self.source):
            raise ValueError("OpenAI function tool is already mediated")

    def as_tool(self) -> FunctionTool:
        source = copy.copy(self.source)
        set_function_tool_failure_error_function(source, None)
        wrapped = copy.copy(self.source)

        async def invoke(tool_context: ToolContext[Any], raw_arguments: str) -> Any:
            active = _ACTIVE_RUN.get()
            if active is None:
                raise OpenAIMediatedToolError(
                    "mediated OpenAI tool must run inside OpenAIAgentsAdapter"
                )
            arguments = json.loads(raw_arguments)
            if not isinstance(arguments, Mapping) or any(
                not isinstance(key, str) for key in arguments
            ):
                raise OpenAIMediatedToolError(
                    "OpenAI function tool arguments must be a JSON object"
                )
            call_id = tool_context.tool_call_id
            if not call_id:
                raise OpenAIMediatedToolError(
                    "OpenAI function tool call is missing its required call ID"
                )
            action_id = f"openai:{active.contract.task_id}:{self.source.name}:{call_id}"
            request = ActionRequest(
                action_id=action_id,
                task_id=active.contract.task_id,
                name=self.source.name,
                required_capability=self.required_capability,
                input=dict(arguments),
                idempotency_key=(
                    f"{active.contract.idempotency_key}:openai:"
                    f"{self.source.name}:{call_id}"
                ),
                risk_level=self.risk_level,
                requested_by=active.identity.agent_id,
                requested_at=self.clock(),
                execution_handler_id=_openai_tool_handler_identity(source),
                timeout=self.timeout,
                preconditions=self.preconditions,
                postconditions=self.postconditions,
                metadata={
                    "openai_call_id": call_id,
                    "correlation_id": active.metadata.correlation_id,
                    "session_id": active.metadata.session_id,
                    "worker_id": active.metadata.worker_id,
                },
            )

            async def handler(
                action_input: Mapping[str, Any],
                cancellation: Any,
            ) -> Any:
                del action_input
                cancellation.raise_if_cancelled()
                return await source.on_invoke_tool(tool_context, raw_arguments)

            result = await self.executor.execute(
                request,
                contract=active.contract,
                handler=handler,
                granted_capabilities=active.context.allowed_capabilities,
                cancellation=active.context.cancellation,
                dry_run=self.dry_run,
            )
            receipt = result.action.receipt
            if (
                result.action.status is not ActionExecutionStatus.EXECUTOR_SUCCEEDED
                or receipt is None
            ):
                raise OpenAIMediatedToolError(
                    "Runmantle blocked or could not confirm the mediated tool call "
                    f"(status={result.action.status.value})"
                )
            return receipt.output

        wrapped.on_invoke_tool = invoke
        wrapped.needs_approval = False
        wrapped.timeout_seconds = None
        set_function_tool_failure_error_function(wrapped, None)
        setattr(wrapped, _MEDIATED_MARKER, True)
        wrapped.__dict__["__runmantle_required_capability__"] = self.required_capability
        return wrapped


def mediate_openai_function_tool(
    tool: FunctionTool,
    *,
    executor: ActionExecutor,
    required_capability: str,
    risk_level: RiskLevel = RiskLevel.LOW,
    timeout: timedelta = timedelta(seconds=30),
    preconditions: tuple[Precondition, ...] = (),
    postconditions: tuple[Postcondition, ...] = (),
    dry_run: bool = False,
) -> FunctionTool:
    """Return a schema-compatible SDK tool whose invocation is mediated."""

    return OpenAIMediatedFunctionTool(
        source=tool,
        executor=executor,
        required_capability=required_capability,
        risk_level=risk_level,
        timeout=timeout,
        preconditions=preconditions,
        postconditions=postconditions,
        dry_run=dry_run,
    ).as_tool()


def _openai_tool_handler_identity(tool: FunctionTool) -> str:
    manifest = SafeJsonCodec().dumps(
        {
            "name": tool.name,
            "params_json_schema": tool.params_json_schema,
            "strict_json_schema": tool.strict_json_schema,
            "invoke": callable_semantic_identity(tool.on_invoke_tool),
        }
    )
    digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    return f"openai.function_tool:sha256:{digest}"


def is_mediated_openai_function_tool(tool: Any) -> bool:
    return isinstance(tool, FunctionTool) and bool(
        getattr(tool, _MEDIATED_MARKER, False)
    )


def inspect_openai_agent_surface(agent: Agent[Any]) -> OpenAIAgentSurfaceReport:
    """Classify execution paths visible on one starting agent.

    Dynamic tools loaded later and agents reached via handoff are intentionally
    not claimed as statically inspectable.
    """

    issues: list[OpenAIAgentSurfaceIssue] = []
    for index, tool in enumerate(agent.tools):
        path = f"tools[{index}]"
        if isinstance(tool, FunctionTool):
            if getattr(tool, "_is_agent_tool", False):
                issues.append(
                    OpenAIAgentSurfaceIssue(
                        path,
                        "agent_as_tool",
                        "the nested agent and its tools are controlled by the SDK",
                    )
                )
            elif not is_mediated_openai_function_tool(tool):
                issues.append(
                    OpenAIAgentSurfaceIssue(
                        path,
                        "unmediated_function_tool",
                        "the local function can execute without ActionExecutor",
                    )
                )
        else:
            issues.append(
                OpenAIAgentSurfaceIssue(
                    path,
                    _tool_kind(tool),
                    "this SDK tool family does not invoke a Runmantle wrapper",
                )
            )
    if agent.mcp_servers:
        issues.append(
            OpenAIAgentSurfaceIssue(
                "mcp_servers",
                "local_mcp_tools",
                "MCP tool discovery and invocation are owned by the SDK server path",
            )
        )
    if agent.handoffs:
        issues.append(
            OpenAIAgentSurfaceIssue(
                "handoffs",
                "handoff",
                "the destination agent may expose execution paths not mediated here",
            )
        )
    return OpenAIAgentSurfaceReport(tuple(issues))


def _default_input(task: TaskContract[Any, Any]) -> OpenAIInput:
    if isinstance(task.input, str):
        return task.input
    return SafeJsonCodec().dumps(
        {
            "task_id": task.task_id,
            "objective": task.objective,
            "input": task.input,
        }
    )


def _merged_run_config(
    configured: RunConfig | Mapping[str, Any] | None,
    metadata: OpenAIAgentsRunMetadata,
) -> RunConfig:
    if configured is None:
        base = RunConfig()
    elif isinstance(configured, RunConfig):
        base = configured
    else:
        base = RunConfig(**dict(configured))
    trace_metadata = dict(base.trace_metadata or {})
    trace_metadata.update(
        {
            "runmantle.task_id": metadata.task_id,
            "runmantle.correlation_id": metadata.correlation_id,
            "runmantle.session_id": metadata.session_id,
            "runmantle.worker_id": metadata.worker_id,
            "runmantle.capabilities": sorted(metadata.capabilities),
            "runmantle.idempotency_key": metadata.idempotency_key,
        }
    )
    return replace(
        base,
        group_id=metadata.correlation_id,
        trace_metadata=trace_metadata,
    )


def _evidence_items(
    value: EvidenceItem | EvidenceCollection | Sequence[EvidenceItem],
) -> tuple[EvidenceItem, ...]:
    if isinstance(value, EvidenceItem):
        return (value,)
    if isinstance(value, EvidenceCollection):
        return value.items
    items = tuple(value)
    if not all(isinstance(item, EvidenceItem) for item in items):
        raise TypeError("OpenAI evidence mapper returned a non-evidence value")
    return items


def _record_evidence(context: TaskContext, item: EvidenceItem) -> None:
    context.evidence.record(
        item.type,
        item.payload,
        content=item.content,
        source=item.source,
        provenance=item.provenance,
        artifact_reference=item.artifact_reference,
        checksum=item.checksum,
        metadata=item.metadata,
        acquisition_method=item.acquisition_method,
        trust_level=item.trust_level,
        expires_at=item.expires_at,
        evidence_id=item.evidence_id,
    )


def _tool_kind(tool: Any) -> str:
    name = type(tool).__name__
    if name == "HostedMCPTool":
        return "hosted_mcp_tool"
    if name.endswith("Tool"):
        return f"sdk_{name.removesuffix('Tool').lower()}_tool"
    return "unknown_sdk_tool"


async def _suppress_cancelled(task: asyncio.Future[Any]) -> None:
    try:
        await task
    except asyncio.CancelledError:
        pass


__all__ = [
    "OpenAIAgentSurfaceIssue",
    "OpenAIAgentSurfaceReport",
    "OpenAIAgentsAdapter",
    "OpenAIAgentsEnforcementMode",
    "OpenAIAgentsRunContext",
    "OpenAIAgentsRunMetadata",
    "OpenAIMediatedFunctionTool",
    "OpenAIMediatedToolError",
    "UnsupportedOpenAIAgentsSurfaceError",
    "inspect_openai_agent_surface",
    "is_mediated_openai_function_tool",
    "mediate_openai_function_tool",
]
