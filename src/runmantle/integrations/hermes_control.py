"""Fail-closed CortexOps approval transport for the Hermes plugin API.

Hermes owns execution and its approval gate.  This module only maps a single,
persisted Hermes gate request to an exact CortexOps approval and dispatch permit.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from runmantle.actions import ActionRequest
from runmantle.contracts import RiskLevel
from runmantle.integrations.cortexops_control import (
    CortexOpsControlClient,
    CortexOpsControlError,
    UrllibCortexOpsControlTransport,
)


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _same_hash(left: Any, right: Any) -> bool:
    return str(left).lower().removeprefix("sha256:") == str(right).lower().removeprefix(
        "sha256:"
    )


def redact(value: Any, keys: frozenset[str]) -> Any:
    if isinstance(value, Mapping):
        return {
            str(k): (
                {"redacted_sha256": _hash({"value": str(v)})}
                if str(k).lower() in keys
                else redact(v, keys)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(item, keys) for item in value]
    return value


@dataclass(frozen=True)
class HermesControlConfig:
    cortexops_url: str
    authorization: str | None
    runtime_id: str
    controlled_tools: Mapping[str, Mapping[str, Any]]
    state_path: Path
    post_action_probes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    decision_timeout_seconds: float = 5
    approval_timeout_seconds: float = 300
    approval_poll_initial_seconds: float = 0.25
    approval_poll_max_seconds: float = 2
    redact_keys: frozenset[str] = frozenset(
        {"authorization", "token", "secret", "password", "api_key"}
    )

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> HermesControlConfig:
        url = str(settings.get("cortexops_url") or "").rstrip("/")
        tools, probes = (
            settings.get("controlled_tools"),
            settings.get("post_action_probes"),
        )
        if not url:
            raise ValueError("cortexops_url is required")
        if not isinstance(tools, Mapping) or not tools:
            raise ValueError("controlled_tools must explicitly name at least one tool")
        initial, maximum = (
            float(settings.get("approval_poll_initial_seconds") or 0.25),
            float(settings.get("approval_poll_max_seconds") or 2),
        )
        if initial <= 0 or maximum < initial:
            raise ValueError("approval polling intervals must be positive and ordered")
        return cls(
            url,
            settings.get("authorization"),
            str(settings.get("runtime_id") or "hermes"),
            tools,
            Path(
                str(
                    settings.get("state_path") or "~/.hermes/runmantle-cortexops.sqlite"
                )
            ).expanduser(),
            probes if isinstance(probes, Mapping) else {},
            float(settings.get("decision_timeout_seconds") or 5),
            float(settings.get("approval_timeout_seconds") or 300),
            initial,
            maximum,
            frozenset(str(v).lower() for v in (settings.get("redact_keys") or []))
            or cls.redact_keys,
        )


class HermesControlAdapter:
    """Durable, one-decision-per-Hermes-call CortexOps mediator."""

    _RULE_PREFIX = "plugin_rule:cortexops:"

    def __init__(self, config: HermesControlConfig) -> None:
        self.config = config
        self.client = CortexOpsControlClient(
            UrllibCortexOpsControlTransport(
                config.cortexops_url,
                lambda: config.authorization,
                config.decision_timeout_seconds,
            ),
            config.runtime_id,
            "hermes-plugin-v1",
        )
        self._lock = threading.RLock()
        config.state_path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS hermes_actions (
                tool_call_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL, action_hash TEXT NOT NULL,
                decision_id TEXT NOT NULL, decision_json TEXT NOT NULL,
                request_json TEXT NOT NULL, approval_id TEXT,
                hermes_request_id TEXT, hermes_request_digest TEXT,
                state TEXT NOT NULL DEFAULT 'evaluated', dispatch_attempt_id TEXT,
                receipt_json TEXT, receipt_delivered INTEGER NOT NULL DEFAULT 0,
                confirmation_delivered INTEGER NOT NULL DEFAULT 0)""")

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.config.state_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def _tool(self, name: str) -> Mapping[str, Any] | None:
        value = self.config.controlled_tools.get(name)
        return value if isinstance(value, Mapping) else None

    @staticmethod
    def _approval_rule(call_id: str) -> str:
        return f"cortexops:{call_id}"

    def _register_task(self, task_id: str, session_id: str) -> None:
        self.client.transport.request(
            "POST",
            "/api/runmantle/v1/tasks/register",
            {
                "request_id": (
                    f"runtime:{self.config.runtime_id}:hermes-task:{task_id}:register"
                ),
                "runtime_id": self.config.runtime_id,
                "task_id": task_id,
                "contract_hash": _hash({"task_id": task_id, "session_id": session_id}),
                "correlation_id": session_id,
                "worker_id": "hermes",
            },
        )

    def pre_tool_call(self, **kw: Any) -> dict[str, str] | None:
        tool_name = str(kw.get("tool_name") or "")
        tool = self._tool(tool_name)
        if tool is None:
            return None
        args = kw.get("args") if isinstance(kw.get("args"), Mapping) else {}
        call_id, task_id, session_id = (
            str(kw.get(k) or "") for k in ("tool_call_id", "task_id", "session_id")
        )
        if not call_id or not task_id or not session_id:
            return {
                "action": "block",
                "message": "BLOCKED: missing Hermes correlation identity",
            }
        with self._db() as db:
            existing = db.execute(
                "SELECT state,decision_json FROM hermes_actions WHERE tool_call_id=?",
                (call_id,),
            ).fetchone()
        if existing is not None:
            outcome = json.loads(existing["decision_json"])["outcome"]
            if outcome == "ALLOW" and existing["state"] == "dispatched":
                return None
            if outcome == "REQUIRE_APPROVAL" and existing["state"] in {
                "awaiting_approval",
                "dispatching",
            }:
                return {
                    "action": "approve",
                    "message": "CortexOps approval required",
                    "rule_key": self._approval_rule(call_id),
                }
            return {
                "action": "block",
                "message": "BLOCKED: CortexOps action is already final or unavailable",
            }
        args_hash = _hash(args)
        action_id = _hash(
            {
                "task_id": task_id,
                "session_id": session_id,
                "tool_call_id": call_id,
                "tool_name": tool_name,
                "args_hash": args_hash,
            }
        )
        request = ActionRequest(
            action_id=action_id,
            task_id=task_id,
            name=str(tool.get("action_name") or tool_name),
            required_capability=str(tool.get("capability") or "terminal.deploy"),
            input=redact(args, self.config.redact_keys),
            idempotency_key=action_id,
            risk_level=RiskLevel(str(tool.get("risk_level") or "high")),
            requested_by="hermes",
            requested_at=datetime.now(UTC),
            timeout=timedelta(seconds=self.config.decision_timeout_seconds),
            metadata={
                "session_id": session_id,
                "tool_call_id": call_id,
                "args_hash": args_hash,
            },
        )
        try:
            if not getattr(self.client, "_handshake", None):
                capabilities = {
                    str(spec.get("capability") or "terminal.deploy")
                    for spec in self.config.controlled_tools.values()
                    if isinstance(spec, Mapping)
                }
                capabilities.update({"govern.v2", "govern.receipt.v1"})
                self.client.register_runtime(capabilities)
            self._register_task(task_id, session_id)
            decision = self.client.evaluate_action(
                request, correlation_id=session_id, worker_id="hermes"
            )
            decision_id = str(decision["decision_id"])
            if not _same_hash(decision.get("action_hash"), request.action_hash):
                raise CortexOpsControlError("decision action hash mismatch")
            state = (
                "awaiting_approval"
                if decision["outcome"] == "REQUIRE_APPROVAL"
                else "evaluated"
            )
            with self._db() as db:
                db.execute(
                    "INSERT INTO hermes_actions("
                    "tool_call_id,action_id,action_hash,decision_id,"
                    "decision_json,request_json,state) VALUES(?,?,?,?,?,?,?)",
                    (
                        call_id,
                        action_id,
                        request.action_hash,
                        decision_id,
                        _canonical(decision),
                        _canonical({"action_id": action_id, "args_hash": args_hash}),
                        state,
                    ),
                )
            if decision["outcome"] == "ALLOW":
                self.client.dispatch_action(
                    decision, action_hash=request.action_hash, attempt_id=call_id
                )
                with self._db() as db:
                    db.execute(
                        "UPDATE hermes_actions SET state='dispatched',"
                        "dispatch_attempt_id=? WHERE tool_call_id=?",
                        (call_id, call_id),
                    )
                return None
            if decision["outcome"] == "REQUIRE_APPROVAL":
                approval = self.client.transport.request(
                    "POST",
                    f"/api/runmantle/v1/actions/{decision_id}/approval",
                    {
                        "runtime_id": self.config.runtime_id,
                        "task_id": task_id,
                        "action_id": action_id,
                        "action_hash": request.action_hash,
                        "idempotency_key": f"hermes:{call_id}:approval",
                        "message_id": f"hermes:{call_id}:approval",
                        "expires_at": (
                            datetime.now(UTC)
                            + timedelta(seconds=self.config.approval_timeout_seconds)
                        ).isoformat(),
                    },
                )
                self._validate_approval(
                    approval, decision_id, action_id, request.action_hash
                )
                with self._db() as db:
                    db.execute(
                        "UPDATE hermes_actions SET approval_id=? WHERE tool_call_id=?",
                        (approval["approval_id"], call_id),
                    )
                return {
                    "action": "approve",
                    "message": "CortexOps approval required",
                    "rule_key": self._approval_rule(call_id),
                }
            return {
                "action": "block",
                "message": "BLOCKED: CortexOps policy denied this action",
            }
        except (
            CortexOpsControlError,
            KeyError,
            TypeError,
            ValueError,
            OSError,
        ):
            return {
                "action": "block",
                "message": "BLOCKED: CortexOps decision unavailable",
            }

    @staticmethod
    def _validate_approval(
        approval: Mapping[str, Any], decision_id: str, action_id: str, action_hash: str
    ) -> None:
        if (
            not str(approval.get("approval_id") or "")
            or approval.get("decision_id") != decision_id
            or approval.get("action_id") != action_id
            or not _same_hash(approval.get("action_hash"), action_hash)
        ):
            raise CortexOpsControlError("approval identity mismatch")

    def present_approval(self, request: Any) -> Any:
        """Only an exact CortexOps Approved permit yields Hermes ``once``."""
        key = str(getattr(request, "pattern_key", ""))
        if not key.startswith(self._RULE_PREFIX):
            return request.respond("deny")
        call_id = key.removeprefix(self._RULE_PREFIX)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM hermes_actions WHERE tool_call_id=?", (call_id,)
            ).fetchone()
            if (
                row is None
                or row["state"] != "awaiting_approval"
                or not row["approval_id"]
            ):
                return request.respond("deny")
            if row["hermes_request_id"] and (
                row["hermes_request_id"] != request.request_id
                or row["hermes_request_digest"] != request.digest
            ):
                return request.respond("deny")
            db.execute(
                "UPDATE hermes_actions SET hermes_request_id=?,"
                "hermes_request_digest=? WHERE tool_call_id=?",
                (request.request_id, request.digest, call_id),
            )
        deadline, delay = (
            time.monotonic() + self.config.approval_timeout_seconds,
            self.config.approval_poll_initial_seconds,
        )
        while time.monotonic() < deadline:
            try:
                approval = self.client.transport.request(
                    "GET",
                    "/api/runmantle/v1/approvals/"
                    f"{row['approval_id']}/status?runtime_id={self.config.runtime_id}",
                )
                self._validate_approval(
                    approval, row["decision_id"], row["action_id"], row["action_hash"]
                )
                status = approval.get("status")
                if (
                    status in {"Denied", "Expired"}
                    or approval.get("fail_closed") is True
                ):
                    return request.respond("deny")
                if status == "Approved" and approval.get("authorized") is True:
                    if not self._claim_dispatch(call_id, request.request_id):
                        return request.respond("deny")
                    decision = self.client.action_decision(
                        row["decision_id"], row["action_hash"]
                    )
                    bound = decision.get("approval")
                    if not isinstance(bound, Mapping) or bound.get(
                        "approval_id"
                    ) != approval.get("governance_approval_id"):
                        raise CortexOpsControlError(
                            "canonical permit approval mismatch"
                        )
                    self.client.dispatch_action(
                        decision,
                        action_hash=row["action_hash"],
                        attempt_id=request.request_id,
                    )
                    with self._db() as db:
                        db.execute(
                            "UPDATE hermes_actions SET state='dispatched' "
                            "WHERE tool_call_id=? AND state='dispatching'",
                            (call_id,),
                        )
                    return request.respond("once")
            except CortexOpsControlError:
                return request.respond("deny")
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
            delay = min(delay * 2, self.config.approval_poll_max_seconds)
        return request.respond("deny")

    def _claim_dispatch(self, call_id: str, request_id: str) -> bool:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            return (
                db.execute(
                    "UPDATE hermes_actions SET state='dispatching',"
                    "dispatch_attempt_id=? WHERE tool_call_id=? "
                    "AND state='awaiting_approval' AND hermes_request_id=?",
                    (request_id, call_id, request_id),
                ).rowcount
                == 1
            )

    def post_tool_call(self, **kw: Any) -> None:
        call_id = str(kw.get("tool_call_id") or "")
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM hermes_actions WHERE tool_call_id=?", (call_id,)
            ).fetchone()
            if row is None or row["state"] not in {"dispatched", "executed"}:
                return
            if row["receipt_json"] is None:
                now = datetime.now(UTC).isoformat()
                receipt = {
                    "runtime_id": self.config.runtime_id,
                    "receipt_id": f"hermes:{call_id}",
                    "attempt_id": row["dispatch_attempt_id"] or call_id,
                    "runtime_execution_id": call_id,
                    "outcome": "succeeded" if kw.get("status") == "ok" else "failed",
                    "occurred_at": now,
                    "started_at": now,
                    "ended_at": now,
                    "action_hash": row["action_hash"],
                    "duration_ms": kw.get("duration_ms"),
                    "side_effect_confirmation": False,
                    "result_hash": _hash(
                        {"value": redact(kw.get("result"), self.config.redact_keys)}
                    ),
                    "error_hash": _hash(
                        {
                            "value": redact(
                                kw.get("error_message"), self.config.redact_keys
                            )
                        }
                    ),
                }
                db.execute(
                    "UPDATE hermes_actions SET receipt_json=?,"
                    "state='executed' WHERE tool_call_id=?",
                    (_canonical(receipt), call_id),
                )
                row = db.execute(
                    "SELECT * FROM hermes_actions WHERE tool_call_id=?", (call_id,)
                ).fetchone()
        self._deliver_execution(row, kw)

    def _deliver_execution(self, row: sqlite3.Row, kw: Mapping[str, Any]) -> None:
        if not row["receipt_delivered"]:
            try:
                self.client.transport.request(
                    "POST",
                    f"/api/runmantle/v1/actions/{row['decision_id']}/receipts",
                    json.loads(row["receipt_json"]),
                )
                with self._db() as db:
                    db.execute(
                        "UPDATE hermes_actions SET receipt_delivered=1 "
                        "WHERE tool_call_id=?",
                        (row["tool_call_id"],),
                    )
            except CortexOpsControlError:
                return
        if (
            kw.get("status") == "ok"
            and not row["confirmation_delivered"]
            and self._send_probe(row, kw)
        ):
            with self._db() as db:
                db.execute(
                    "UPDATE hermes_actions SET confirmation_delivered=1 "
                    "WHERE tool_call_id=?",
                    (row["tool_call_id"],),
                )

    def _send_probe(self, row: Mapping[str, Any], kw: Mapping[str, Any]) -> bool:
        probe = (self.config.post_action_probes or {}).get(
            str(kw.get("tool_name") or "")
        )
        if not isinstance(probe, Mapping):
            return True
        observed: dict[str, Any] = {}
        status = "confirmed"
        try:
            for label in ("version_url", "health_url"):
                url = probe.get(label)
                if not isinstance(url, str) or not url:
                    raise ValueError(f"missing {label}")
                with urlopen(
                    Request(url, headers={"Accept": "application/json"}),
                    timeout=self.config.decision_timeout_seconds,
                ) as response:
                    observed[label.removesuffix("_url")] = json.loads(response.read())
        except Exception as error:  # noqa: BLE001 - probes are non-authoritative evidence
            status, observed = "inconclusive", {"probe_error": type(error).__name__}
        payload = {
            "message_id": f"hermes:{row['tool_call_id']}:probe",
            "runtime_id": self.config.runtime_id,
            "task_id": str(kw.get("task_id") or ""),
            "action_id": row["action_id"],
            "action_hash": row["action_hash"],
            "receipt_id": f"{self.config.runtime_id}:hermes:{row['tool_call_id']}",
            "confirmation_id": f"hermes:{row['tool_call_id']}:probe",
            "status": status,
            "provider_id": "runmantle.hermes.http_probe",
            "observed_state": observed,
            "expected_state": dict(probe.get("expected_state") or {}),
            "evidence_ids": [],
            "checked_at": datetime.now(UTC).isoformat(),
            "actor": "runmantle.hermes_control",
        }
        try:
            self.client.transport.request(
                "POST",
                f"/api/runmantle/v1/actions/{row['decision_id']}/runtime-confirmations",
                payload,
            )
            return True
        except CortexOpsControlError:
            return False


def register(ctx: Any) -> None:
    keys = (
        "cortexops_url",
        "authorization",
        "runtime_id",
        "controlled_tools",
        "post_action_probes",
        "state_path",
        "decision_timeout_seconds",
        "approval_timeout_seconds",
        "approval_poll_initial_seconds",
        "approval_poll_max_seconds",
        "redact_keys",
    )
    adapter = HermesControlAdapter(
        HermesControlConfig.from_settings({key: ctx.get_config(key) for key in keys})
    )
    ctx.register_hook("pre_tool_call", adapter.pre_tool_call)
    ctx.register_hook("post_tool_call", adapter.post_tool_call)
    ctx.register_approval_transport("cortexops", adapter.present_approval)


def install_plugin(hermes_home: str | Path) -> Path:
    source, target = (
        Path(__file__).resolve().parents[1] / "hermes_plugin",
        Path(hermes_home).expanduser() / "plugins" / "runmantle-cortexops-control",
    )
    if target.exists():
        raise FileExistsError(f"refusing to overwrite existing plugin: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)
    return target


def main() -> int:
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="Install the RunMantle Hermes control plugin"
    )
    parser.add_argument(
        "--hermes-home", default=os.environ.get("HERMES_HOME", "~/.hermes")
    )
    args = parser.parse_args()
    print(install_plugin(args.hermes_home))
    return 0
