from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from runmantle.actions import ActionRequest
from runmantle.integrations.cortexops_control import CortexOpsControlError
from runmantle.integrations.hermes_control import (
    HermesControlAdapter,
    HermesControlConfig,
)


class _Transport:
    def __init__(
        self,
        status: str = "Approved",
        mismatch: bool = False,
        fails: bool = False,
    ) -> None:
        self.status = status
        self.mismatch = mismatch
        self.fails = fails
        self.calls: list[tuple[str, str]] = []
        self.action_id = ""
        self.action_hash = ""

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((method, path))
        if self.fails and path.startswith("/api/runmantle/v1/approvals/"):
            raise CortexOpsControlError("offline")
        if path.startswith("/api/runmantle/v1/actions/d1/approval"):
            assert payload is not None
            return {
                "approval_id": "a1",
                "governance_approval_id": "g1",
                "decision_id": "d1",
                "action_id": payload["action_id"],
                "action_hash": payload["action_hash"],
                "status": "Pending",
            }
        if path.startswith("/api/runmantle/v1/approvals/a1/status"):
            value = {
                "approval_id": "a1",
                "governance_approval_id": "g1",
                "decision_id": "d1",
                "action_id": self.action_id,
                "action_hash": self.action_hash,
                "status": self.status,
                "authorized": self.status == "Approved",
                "fail_closed": self.status in {"Denied", "Expired"},
            }
            if self.mismatch:
                value["action_hash"] = "0" * 64
            return value
        return {"ok": True}


class _Client:
    def __init__(self, outcome: str = "REQUIRE_APPROVAL", **options: Any) -> None:
        self.outcome = outcome
        self._handshake: dict[str, Any] = {"policy": {}}
        self.dispatched: list[str] = []
        self.transport = _Transport(**options)

    def register_runtime(self, *_: Any) -> dict[str, Any]:
        return self._handshake

    def evaluate_action(self, request: ActionRequest, **_: Any) -> dict[str, Any]:
        self.transport.action_id, self.transport.action_hash = (
            request.action_id,
            request.action_hash,
        )
        return {
            "decision_id": "d1",
            "outcome": self.outcome,
            "action_hash": request.action_hash,
        }

    def action_decision(self, _id: str, action_hash: str) -> dict[str, Any]:
        return {
            "decision_id": "d1",
            "outcome": "REQUIRE_APPROVAL",
            "action_hash": action_hash,
            "approval": {"approval_id": "g1", "permit_id": "p", "permit_hash": "h"},
        }

    def dispatch_action(
        self,
        _decision: Mapping[str, Any],
        *,
        action_hash: str,
        attempt_id: str,
    ) -> dict[str, Any]:
        self.dispatched.append(attempt_id)
        return {
            "state": "DISPATCHED",
            "action_hash": action_hash,
            "permit_consumed": True,
        }


class _Request:
    def __init__(
        self, call_id: str = "c", request_id: str = "r1", digest: str = "digest"
    ) -> None:
        self.pattern_key, self.request_id, self.digest = (
            f"plugin_rule:cortexops:{call_id}",
            request_id,
            digest,
        )

    def respond(self, choice: str) -> str:
        return choice


def _adapter(
    tmp_path: Path, outcome: str = "REQUIRE_APPROVAL", **options: Any
) -> tuple[HermesControlAdapter, _Client]:
    config = HermesControlConfig.from_settings(
        {
            "cortexops_url": "http://127.0.0.1:9",
            "state_path": str(tmp_path / "a.sqlite"),
            "controlled_tools": {"terminal": {"capability": "terminal.deploy"}},
            "approval_timeout_seconds": options.pop("approval_timeout_seconds", 0.02),
            "approval_poll_initial_seconds": 0.001,
            "approval_poll_max_seconds": 0.002,
        }
    )
    adapter = HermesControlAdapter(config)
    client = _Client(outcome, **options)
    adapter.client = cast(Any, client)
    return adapter, client


def _call() -> dict[str, Any]:
    return {
        "tool_name": "terminal",
        "args": {"command": "deploy", "token": "secret"},
        "task_id": "t",
        "session_id": "s",
        "tool_call_id": "c",
    }


def _assert_approval(adapter: HermesControlAdapter) -> None:
    result = adapter.pre_tool_call(**_call())
    assert result is not None
    assert result["action"] == "approve"


def test_approved_dispatches_once_and_is_request_bound(tmp_path: Path) -> None:
    adapter, client = _adapter(tmp_path)
    _assert_approval(adapter)
    assert adapter.present_approval(_Request()) == "once"
    assert client.dispatched == ["r1"]
    assert adapter.present_approval(_Request()) == "deny"
    assert client.dispatched == ["r1"]


def test_denied_expired_timeout_and_api_failure_fail_closed(tmp_path: Path) -> None:
    cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("Denied", {"status": "Denied"}),
        ("Expired", {"status": "Expired"}),
        ("Pending", {"status": "Pending", "approval_timeout_seconds": 0.003}),
        ("Failed", {"fails": True}),
    )
    for name, options in cases:
        adapter, client = _adapter(tmp_path / name, **options)
        _assert_approval(adapter)
        assert adapter.present_approval(_Request()) == "deny"
        assert client.dispatched == []


def test_hash_mismatch_and_stale_request_are_blocked(tmp_path: Path) -> None:
    adapter, client = _adapter(tmp_path, mismatch=True)
    _assert_approval(adapter)
    assert adapter.present_approval(_Request()) == "deny"
    assert client.dispatched == []
    adapter, client = _adapter(tmp_path / "stale")
    _assert_approval(adapter)
    assert adapter.present_approval(_Request(request_id="first")) == "once"
    assert adapter.present_approval(_Request(request_id="second")) == "deny"
    assert client.dispatched == ["first"]


def test_delivery_retry_never_reexecutes_and_receipt_is_post_execution(
    tmp_path: Path,
) -> None:
    adapter, client = _adapter(tmp_path)
    _assert_approval(adapter)
    assert adapter.present_approval(_Request()) == "once"
    assert not any("/receipts" in path for _, path in client.transport.calls)
    adapter.post_tool_call(**_call(), status="ok", result="done", duration_ms=1)
    adapter.post_tool_call(**_call(), status="ok", result="done", duration_ms=1)
    assert len([path for _, path in client.transport.calls if "/receipts" in path]) == 1
    assert client.dispatched == ["r1"]


def test_allow_dispatches_once_and_persists_redacted_identity(tmp_path: Path) -> None:
    adapter, client = _adapter(tmp_path, "ALLOW")
    assert adapter.pre_tool_call(**_call()) is None
    assert adapter.pre_tool_call(**_call()) is None
    assert client.dispatched == ["c"]
    with adapter._db() as db:
        stored = db.execute("SELECT request_json FROM hermes_actions").fetchone()[0]
    assert "secret" not in stored
