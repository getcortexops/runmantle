"""Opt-in real HTTP CortexOps coverage for the Hermes control plugin."""

from __future__ import annotations

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


def _adapter(base_url: str, state_path: Path) -> HermesControlAdapter:
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
    assert set(context.hooks) == {"pre_tool_call", "post_tool_call"}
    assert callable(context.transport)
