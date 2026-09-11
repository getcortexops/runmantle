"""Opt-in real HTTP CortexOps coverage for the Hermes control plugin."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from runmantle.integrations.cortexops_control import UrllibCortexOpsControlTransport
from runmantle.integrations.hermes_control import (
    HermesControlAdapter,
    HermesControlConfig,
    register,
)

pytestmark = pytest.mark.cortexops_process_integration


class _ApprovalRequest:
    def __init__(self, call_id: str) -> None:
        self.pattern_key = f"plugin_rule:cortexops:{call_id}"
        self.request_id = "hermes-host-request"
        self.digest = "host-created-redacted-request-digest"

    def respond(self, choice: str) -> str:
        return choice


class _Context:
    def __init__(self) -> None:
        self.hooks: dict[str, object] = {}
        self.transport: object | None = None
        self.settings: dict[str, Any] = {}

    def get_config(self, key: str) -> Any:
        return self.settings.get(key)

    def register_hook(self, name: str, callback: object) -> None:
        self.hooks[name] = callback

    def register_approval_transport(self, _name: str, callback: object) -> None:
        self.transport = callback


def _adapter(
    base_url: str,
    state_path: Path,
    *,
    probe_base_url: str | None = None,
) -> HermesControlAdapter:
    probes: dict[str, Any] = {}
    if probe_base_url is not None:
        probes = {
            "terminal": {
                "version_url": f"{probe_base_url}/version",
                "health_url": f"{probe_base_url}/health",
                "expected_state": {
                    "version": {"version": "v2"},
                    "health": {"status": "healthy"},
                },
            }
        }
    return HermesControlAdapter(
        HermesControlConfig.from_settings(
            {
                "cortexops_url": base_url,
                "authorization": "Bearer process-runtime-token",
                "runtime_id": "hermes-e2e-runtime",
                "state_path": str(state_path),
                "approval_timeout_seconds": 2,
                "approval_poll_initial_seconds": 0.01,
                "approval_poll_max_seconds": 0.05,
                "post_action_probes": probes,
                "controlled_tools": {
                    "terminal": {
                        "action_name": "write-file",
                        "capability": "write_file",
                        "risk_level": "high",
                    }
                },
            }
        )
    )


@contextmanager
def _runtime_probe() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = (
                {"version": "v2"} if self.path == "/version" else {"status": "healthy"}
            )
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_hermes_hook_to_cortexops_approve_then_deny(tmp_path: Path) -> None:
    # Reuse the checked-in Uvicorn fixture; neither CortexOps nor Hermes core changes.
    from tests.test_cortexops_process_integration import (
        _cortexops_process,
        _operator_post,
    )

    with _cortexops_process(tmp_path) as base_url:
        adapter = _adapter(base_url, tmp_path / "adapter.sqlite")
        transport = adapter.client.transport
        assert isinstance(transport, UrllibCortexOpsControlTransport)
        assert transport.base_url == base_url
        call = {
            "tool_name": "terminal",
            "args": {"path": "/tmp/a"},
            "task_id": "task-1",
            "session_id": "session-1",
            "tool_call_id": "call-1",
        }
        result = adapter.pre_tool_call(**call)
        assert result and result["action"] == "approve", result
        with adapter._db() as db:
            row = db.execute(
                "SELECT approval_id,action_hash FROM hermes_actions"
            ).fetchone()
        _operator_post(
            base_url,
            f"/api/runmantle/v1/approvals/{row['approval_id']}/approve",
            {
                "action_hash": row["action_hash"],
                "idempotency_key": "operator-approve",
                "reason": "reviewed",
            },
        )
        assert adapter.present_approval(_ApprovalRequest("call-1")) == "once"
        adapter.post_tool_call(**call, status="ok", result="executed", duration_ms=1)
        # A second action has an independent projection and a Deny never invokes it.
        call["tool_call_id"] = "call-2"
        result = adapter.pre_tool_call(**call)
        assert result is not None
        assert result["action"] == "approve"
        with adapter._db() as db:
            row = db.execute(
                "SELECT approval_id,action_hash FROM hermes_actions "
                "WHERE tool_call_id='call-2'"
            ).fetchone()
        _operator_post(
            base_url,
            f"/api/runmantle/v1/approvals/{row['approval_id']}/deny",
            {
                "action_hash": row["action_hash"],
                "idempotency_key": "operator-deny",
                "reason": "operator denied this action",
            },
        )
        assert adapter.present_approval(_ApprovalRequest("call-2")) == "deny"


def test_plugin_registers_the_actual_hermes_hook_and_transport() -> None:
    context = _Context()
    context.settings = {
        "cortexops_url": "http://127.0.0.1:9",
        "controlled_tools": {"terminal": {}},
    }
    register(context)
    assert set(context.hooks) == {
        "pre_llm_call",
        "post_api_request",
        "pre_tool_call",
        "post_tool_call",
        "post_llm_call",
    }
    assert callable(context.transport)


def test_hermes_first_run_is_measured_baseline_and_second_is_cache_reuse(
    tmp_path: Path,
) -> None:
    from tests.test_cortexops_process_integration import (
        OPERATOR_TOKEN,
        _cortexops_process,
        _operator_post,
    )

    with _cortexops_process(tmp_path) as base_url, _runtime_probe() as probe_url:
        adapter = _adapter(
            base_url,
            tmp_path / "cache-adapter.sqlite",
            probe_base_url=probe_url,
        )

        def run_turn(
            *, task_id: str, run_id: str, call_id: str, tokens: tuple[int, int]
        ) -> dict[str, str] | None:
            common = {
                "task_id": task_id,
                "session_id": f"session-{task_id}",
                "turn_id": run_id,
            }
            context = adapter.pre_llm_call(
                **common,
                user_message="Deploy version two to the local service",
            )
            adapter.post_api_request(
                **common,
                api_request_id=f"api-{run_id}",
                usage={"prompt_tokens": tokens[0], "output_tokens": tokens[1]},
                api_duration=0.01,
            )
            call = {
                **common,
                "tool_name": "terminal",
                "args": {"command": "deploy-v2"},
                "tool_call_id": call_id,
            }
            directive = adapter.pre_tool_call(**call)
            assert directive and directive["action"] == "approve"
            with adapter._db() as db:
                approval = db.execute(
                    "SELECT approval_id,action_hash FROM hermes_actions "
                    "WHERE tool_call_id=?",
                    (call_id,),
                ).fetchone()
            _operator_post(
                base_url,
                f"/api/runmantle/v1/approvals/{approval['approval_id']}/approve",
                {
                    "action_hash": approval["action_hash"],
                    "idempotency_key": f"operator-{call_id}",
                    "reason": "reviewed",
                },
            )
            assert adapter.present_approval(_ApprovalRequest(call_id)) == "once"
            adapter.post_tool_call(
                **call, status="ok", result="deployed", duration_ms=2
            )
            adapter.post_llm_call(
                **common,
                user_message="Deploy version two to the local service",
                assistant_response="Deployment complete.",
            )
            return context

        assert (
            run_turn(
                task_id="task-cache-baseline",
                run_id="run-cache-baseline",
                call_id="call-cache-baseline",
                tokens=(80, 20),
            )
            is None
        )
        # A later Hermes process gets a fresh adapter and hydrates only the
        # persisted successful, verified recipe from the shared plugin DB.
        adapter = _adapter(
            base_url,
            tmp_path / "cache-adapter.sqlite",
            probe_base_url=probe_url,
        )
        reused_context = run_turn(
            task_id="task-cache-reuse",
            run_id="run-cache-reuse",
            call_id="call-cache-reuse",
            tokens=(25, 10),
        )
        assert reused_context is not None

        operator = UrllibCortexOpsControlTransport(
            base_url,
            authorization_provider=lambda: f"Bearer {OPERATOR_TOKEN}",
        )
        result = operator.request(
            "GET", "/api/runmantle/v1/verified-action-cache/metrics"
        )
        assert result["summary"]["runs"] == 2
        assert result["summary"]["cache_hit_rate"] == 0.5
        assert result["summary"]["measured_tokens_saved"] == 65
        assert result["summary"]["verified_reuse_success_rate"] == 1
        runs = {item["run_id"]: item for item in result["runs"]}
        assert runs["run-cache-baseline"]["cache_status"] == "miss"
        assert runs["run-cache-baseline"]["baseline"]["kind"] == "measured"
        assert runs["run-cache-reuse"]["cache_status"] == "hit"
        assert runs["run-cache-reuse"]["reused"]["kind"] == "measured"
