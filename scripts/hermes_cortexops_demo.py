#!/usr/bin/env python3
"""Run a real local Hermes -> RunMantle -> CortexOps approval demo."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pty
import shlex
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tty
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_TOKEN = "runmantle-hermes-demo-runtime-token"
OPERATOR_TOKEN = "runmantle-hermes-demo-operator-token"
MODEL_NAME = "runmantle-hermes-demo-model"


def _json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[Any], log_path: Path) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            raise RuntimeError(f"process exited before port {port} opened:\n{detail}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not open")


def _post_json(url: str, payload: dict[str, Any], token: str) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _get_json(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=10) as response:
        return json.loads(response.read())


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _rows(path: Path, query: str, values: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with _connect(path) as connection:
        return [dict(row) for row in connection.execute(query, values).fetchall()]


def _approval_policy() -> dict[str, Any]:
    return {
        "defaults": {"tools": "allow", "models": "deny"},
        "tool_rules": [
            {
                "id": "hermes-local-deployment-approval",
                "effect": "approval",
                "reason": (
                    "The local deployment requires authenticated operator approval."
                ),
                "match": {"tool_name": "local-deployment"},
            }
        ],
        "model_allowlist": [],
        "budgets": {
            "run": {"max_tokens": None, "max_cost_usd": None},
            "session": {"max_tokens": None, "max_cost_usd": None},
            "agent_daily_utc": {"max_tokens": None, "max_cost_usd": None},
        },
    }


def _serve_cortexops(database: Path, port: int) -> None:
    import uvicorn
    from cortexops.openclaw_plugin import create_openclaw_plugin_router
    from cortexops.openclaw_plugin.repository import OpenClawPluginRepository
    from cortexops.runmantle_control import create_runmantle_control_router
    from cortexops.storage import initialize_storage
    from fastapi import FastAPI

    initialize_storage(database)
    OpenClawPluginRepository(database).save_policy(_approval_policy())
    app = FastAPI(title="CortexOps RunMantle local control demo")
    app.include_router(create_openclaw_plugin_router(database))
    app.include_router(create_runmantle_control_router(database))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def _serve_deployment(state_path: Path, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if self.path.rstrip("/") == "/version":
                self._reply({"version": state["version"]})
            elif self.path.rstrip("/") == "/health":
                self._reply({"status": state["health"]})
            else:
                self.send_error(404)

        def _reply(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def _deploy_once(state_path: Path) -> None:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["execution_count"] = int(state.get("execution_count", 0)) + 1
    state["version"] = "v2"
    state["last_executed_at"] = datetime.now(UTC).isoformat()
    _json_dump(state_path, state)
    print(json.dumps({"deployed": "v2", "execution_count": state["execution_count"]}))


def _serve_model(command: str, call_id: str, request_log: Path, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            if self.path.rstrip("/") != "/v1/models":
                self.send_error(404)
                return
            self._write_json(
                {
                    "object": "list",
                    "data": [
                        {
                            "id": MODEL_NAME,
                            "object": "model",
                            "created": 0,
                            "owned_by": "local-demo",
                        }
                    ],
                }
            )

        def do_POST(self) -> None:
            if self.path.rstrip("/") != "/v1/chat/completions":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            with request_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, sort_keys=True) + "\n")
            tools = payload.get("tools") or []
            terminal_available = any(
                isinstance(tool, dict)
                and isinstance(tool.get("function"), dict)
                and tool["function"].get("name") == "terminal"
                for tool in tools
            )
            has_tool_result = any(
                isinstance(message, dict) and message.get("role") == "tool"
                for message in payload.get("messages") or []
            )
            request_tool = terminal_available and not has_tool_result
            if payload.get("stream"):
                self._write_stream(request_tool)
            else:
                self._write_json(self._completion(request_tool))

        def _completion(self, request_tool: bool) -> dict[str, Any]:
            message: dict[str, Any] = {
                "role": "assistant",
                "content": "Deployment request completed through the governed path."
                if not request_tool
                else "",
            }
            if request_tool:
                message["tool_calls"] = [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": json.dumps(
                                {"command": command, "timeout": 30},
                                separators=(",", ":"),
                            ),
                        },
                    }
                ]
            return {
                "id": f"chatcmpl-{call_id}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": MODEL_NAME,
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if request_tool else "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 3,
                    "total_tokens": 13,
                },
            }

        def _write_stream(self, request_tool: bool) -> None:
            completion = self._completion(request_tool)
            message = completion["choices"][0]["message"]
            chunks = [
                {
                    "id": completion["id"],
                    "object": "chat.completion.chunk",
                    "created": completion["created"],
                    "model": MODEL_NAME,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": ""},
                            "finish_reason": None,
                        }
                    ],
                }
            ]
            delta: dict[str, Any]
            if request_tool:
                tool = message["tool_calls"][0]
                delta = {"tool_calls": [{"index": 0, **tool}]}
            else:
                delta = {"content": message["content"]}
            chunks.append(
                {
                    "id": completion["id"],
                    "object": "chat.completion.chunk",
                    "created": completion["created"],
                    "model": MODEL_NAME,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                }
            )
            chunks.append(
                {
                    "id": completion["id"],
                    "object": "chat.completion.chunk",
                    "created": completion["created"],
                    "model": MODEL_NAME,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {},
                            "finish_reason": "tool_calls" if request_tool else "stop",
                        }
                    ],
                }
            )
            chunks.append(
                {
                    "id": completion["id"],
                    "object": "chat.completion.chunk",
                    "created": completion["created"],
                    "model": MODEL_NAME,
                    "choices": [],
                    "usage": completion["usage"],
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True

        def _write_json(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def _run_checked(
    command: list[str], *, log_path: Path, env: dict[str, str] | None = None
) -> None:
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"$ {shlex.join(command)}\n")
        log.flush()
        completed = subprocess.run(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
    if completed.returncode:
        detail = log_path.read_text(encoding="utf-8", errors="replace")[-6000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {shlex.join(command)}\n{detail}"
        )


def _write_hermes_config(
    home: Path,
    *,
    model_port: int,
    cortexops_port: int,
    deployment_port: int,
    adapter_db: Path,
    runtime_id: str,
) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / ".env").write_text("OPENAI_API_KEY=local-demo-key\n", encoding="utf-8")
    (home / "config.yaml").write_text(
        f"""model:
  default: {MODEL_NAME}
  provider: custom
  base_url: http://127.0.0.1:{model_port}/v1
  api_mode: chat_completions
  context_length: 64000
agent:
  reasoning_effort: none
approvals:
  timeout: 60
security:
  tirith_enabled: false
  approval:
    transport: cortexops
plugins:
  enabled: [runmantle-cortexops-control]
  entries:
    runmantle-cortexops-control:
      settings:
        cortexops_url: http://127.0.0.1:{cortexops_port}
        authorization: "Bearer {RUNTIME_TOKEN}"
        runtime_id: {runtime_id}
        state_path: {adapter_db}
        decision_timeout_seconds: 5
        approval_timeout_seconds: 60
        approval_poll_initial_seconds: 0.05
        approval_poll_max_seconds: 0.25
        # Hermes owns the user-facing approval wait. The RunMantle pre-tool
        # hook must return immediately with the approval directive.
        blocking_hook_approval: false
        classification_overrides:
          terminal:
            action_name: local-deployment
            capability: terminal.deploy
            risk_level: high
        post_action_probes:
          terminal:
            version_url: http://127.0.0.1:{deployment_port}/version
            health_url: http://127.0.0.1:{deployment_port}/health
            expected_state:
              version:
                version: v2
              health:
                status: healthy
""",
        encoding="utf-8",
    )


def _wait_for_pending(database: Path, hermes: subprocess.Popen[Any]) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if database.exists():
            try:
                rows = _rows(
                    database,
                    "SELECT * FROM runmantle_action_approvals "
                    "WHERE status='Pending' ORDER BY created_at",
                )
                if rows:
                    return rows[-1]
            except sqlite3.OperationalError:
                pass
        if hermes.poll() is not None:
            raise RuntimeError(
                "Hermes exited before CortexOps created Pending approval"
            )
        time.sleep(0.05)
    raise TimeoutError("CortexOps did not create Pending approval")


def _wait_for_model_tool_result(
    request_log: Path, hermes: subprocess.Popen[Any]
) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if request_log.exists():
            for line in request_log.read_text(encoding="utf-8").splitlines():
                payload = json.loads(line)
                if any(
                    isinstance(message, dict) and message.get("role") == "tool"
                    for message in payload.get("messages") or []
                ):
                    return
        if hermes.poll() is not None:
            raise RuntimeError("Hermes exited before it consumed the tool result")
        time.sleep(0.05)
    raise TimeoutError("Hermes did not consume the tool result")


async def _verify_approved_outcome(
    scenario_dir: Path,
    *,
    adapter_db: Path,
    cortexops_url: str,
    deployment_url: str,
    runtime_id: str,
) -> dict[str, Any]:
    from runmantle import (
        CapabilityDeclaration,
        DurableRuntime,
        EvidenceAcquisitionMethod,
        EvidenceItem,
        EvidenceTrustLevel,
        FunctionWorker,
        JsonlEventSink,
        RiskLevel,
        RuleBasedVerifier,
        TaskContext,
        TaskStatus,
        WorkerReport,
    )
    from runmantle.evidence import _establish_evidence_origin
    from runmantle.integrations.cortexops_control import (
        CortexOpsControlClient,
        UrllibCortexOpsControlTransport,
    )
    from runmantle.integrations.hermes_control import hermes_task_contract

    action = _rows(adapter_db, "SELECT * FROM hermes_actions")[0]
    remote_task = _rows(
        scenario_dir / "cortexops.db",
        "SELECT * FROM runmantle_tasks WHERE runtime_id=?",
        (runtime_id,),
    )[0]
    task_id = str(remote_task["task_id"])
    session_id = str(remote_task["correlation_id"])
    expected = {
        "version": {"version": "v2"},
        "health": {"status": "healthy"},
    }
    contract = hermes_task_contract(
        task_id,
        session_id,
        capability="terminal.deploy",
        risk_level=RiskLevel.HIGH,
        expected_state=expected,
    )

    async def report(
        _contract: Any, _context: TaskContext
    ) -> WorkerReport[dict[str, bool]]:
        return WorkerReport.completed({"executed": True})

    worker = FunctionWorker(
        id="hermes",
        name="Hermes CLI",
        role="governed deployment agent",
        version="local-demo",
        capabilities=(
            CapabilityDeclaration(
                name="terminal.deploy",
                description="Deploy the isolated local version service.",
            ),
        ),
        handler=report,
    )
    events_path = scenario_dir / "runmantle-events.jsonl"
    runtime = DurableRuntime(
        database_path=scenario_dir / "runmantle-runtime.db",
        verifier=RuleBasedVerifier(),
        event_sink=JsonlEventSink(events_path),
    )
    awaiting = await runtime.execute(worker, contract, correlation_id=session_id)
    if awaiting.status is not TaskStatus.AWAITING_EVIDENCE:
        raise AssertionError(f"expected AWAITING_EVIDENCE, got {awaiting.status}")
    observed = {
        "version": _get_json(f"{deployment_url}/version"),
        "health": _get_json(f"{deployment_url}/health"),
    }
    evidence = _establish_evidence_origin(
        EvidenceItem(
            evidence_id=f"runtime-probe:{action['tool_call_id']}",
            type="hermes_deployment_runtime",
            source=deployment_url,
            collected_at=datetime.now(UTC),
            payload=observed,
        ),
        boundary="hermes_cortexops_local_demo_http_probe",
        provider_identity="scripts.hermes_cortexops_demo:http-probe:v1",
        provider_configuration={"version_url": "/version", "health_url": "/health"},
        trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
        acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
    )
    runtime.store.record_evidence(task_id, evidence)
    verified = await runtime.resume(task_id, contract=contract)
    if verified.status is not TaskStatus.VERIFIED:
        raise AssertionError(f"RunMantle did not verify the outcome: {verified.status}")

    control = CortexOpsControlClient(
        UrllibCortexOpsControlTransport(
            cortexops_url,
            authorization_provider=lambda: f"Bearer {RUNTIME_TOKEN}",
        ),
        runtime_id=runtime_id,
        runtime_version="hermes-plugin-v1",
    )
    control.register_runtime({"terminal.deploy", "govern.v2", "govern.receipt.v1"})
    synchronized = control.sync_task_result(contract, verified, sequence=1)
    if synchronized.get("verified_status") != "verified":
        raise AssertionError(f"CortexOps did not retain VERIFIED: {synchronized}")
    return {
        "task_id": task_id,
        "session_id": session_id,
        "evidence_id": evidence.evidence_id,
        "evidence_checksum": evidence.checksum,
        "verification_status": verified.status.value,
        "verification_hash": synchronized.get("verification_hash"),
        "observed": observed,
    }


def _scenario(
    scenario: str,
    *,
    python: Path,
    hermes: Path,
    hermes_repo: Path,
    scratch: Path,
    artifacts: Path,
) -> dict[str, Any]:
    scenario_dir = artifacts / scenario
    scenario_dir.mkdir(parents=True)
    home = scratch / f"hermes-{scenario}"
    database = scenario_dir / "cortexops.db"
    adapter_db = scenario_dir / "hermes-control.db"
    deployment_state = scenario_dir / "deployment-state.json"
    _json_dump(
        deployment_state,
        {"version": "v1", "health": "healthy", "execution_count": 0},
    )
    ports = {
        "cortexops": _free_port(),
        "deployment": _free_port(),
        "model": _free_port(),
    }
    runtime_id = f"hermes-local-demo-{scenario}"
    home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for variable in ("HERMES_CONFIG", "HERMES_ENV", "HERMES_PROFILE"):
        env.pop(variable, None)
    env["HERMES_HOME"] = str(home)
    env["HERMES_CONFIG"] = str(home / "config.yaml")
    env["HERMES_ENV"] = str(home / ".env")
    env["PYTHONUNBUFFERED"] = "1"
    env["CORTEXOPS_GOVERNANCE_IDENTITIES_JSON"] = json.dumps(
        [
            {"token": RUNTIME_TOKEN, "principal_id": runtime_id, "roles": ["runtime"]},
            {
                "token": OPERATOR_TOKEN,
                "principal_id": "local-demo-operator",
                "roles": ["operator"],
            },
        ]
    )

    install_log = scenario_dir / "hermes-plugin-install.log"
    _run_checked(
        [
            str(python.parent / "runmantle-hermes-control-install"),
            "--hermes-home",
            str(home),
        ],
        log_path=install_log,
        env=env,
    )
    _run_checked(
        [
            str(hermes),
            "plugins",
            "enable",
            "--no-allow-tool-override",
            "runmantle-cortexops-control",
        ],
        log_path=install_log,
        env=env,
    )
    # The supported enable command may normalize config.yaml. Write the
    # isolated demo settings afterwards so its explicit transport selection
    # cannot be replaced by a default value during that normalization.
    _write_hermes_config(
        home,
        model_port=ports["model"],
        cortexops_port=ports["cortexops"],
        deployment_port=ports["deployment"],
        adapter_db=adapter_db,
        runtime_id=runtime_id,
    )
    shutil.copy2(home / "config.yaml", scenario_dir / "hermes-config.yaml")

    deploy_command = shlex.join(
        [
            str(python),
            str(Path(__file__).resolve()),
            "--deploy-once",
            str(deployment_state),
        ]
    )
    call_id = f"hermes-tool-{scenario}"
    children: list[tuple[subprocess.Popen[Any], Any]] = []

    def start(args: list[str], log_name: str) -> subprocess.Popen[Any]:
        log = (scenario_dir / log_name).open("w", encoding="utf-8")
        process = subprocess.Popen(
            args, stdout=log, stderr=subprocess.STDOUT, env=env, text=True
        )
        children.append((process, log))
        return process

    cortexops = start(
        [
            str(python),
            str(Path(__file__).resolve()),
            "--serve-cortexops",
            str(database),
            str(ports["cortexops"]),
        ],
        "cortexops.log",
    )
    deployment = start(
        [
            str(python),
            str(Path(__file__).resolve()),
            "--serve-deployment",
            str(deployment_state),
            str(ports["deployment"]),
        ],
        "deployment.log",
    )
    model = start(
        [
            str(python),
            str(Path(__file__).resolve()),
            "--serve-model",
            deploy_command,
            call_id,
            str(scenario_dir / "model-requests.jsonl"),
            str(ports["model"]),
        ],
        "model.log",
    )
    hermes_process: subprocess.Popen[Any] | None = None
    hermes_log_handle: Any = None
    hermes_terminal: int | None = None
    hermes_log_thread: threading.Thread | None = None
    try:
        _wait_for_port(ports["cortexops"], cortexops, scenario_dir / "cortexops.log")
        _wait_for_port(ports["deployment"], deployment, scenario_dir / "deployment.log")
        _wait_for_port(ports["model"], model, scenario_dir / "model.log")
        hermes_command = [
            str(hermes),
            "chat",
            "--cli",
            "--provider",
            "custom",
            "--model",
            MODEL_NAME,
            "--toolsets",
            "terminal",
            "--ignore-rules",
            "--max-turns",
            "3",
        ]
        (scenario_dir / "hermes-command.txt").write_text(
            " ".join(
                [
                    f"HERMES_HOME={shlex.quote(str(home))}",
                    f"HERMES_CONFIG={shlex.quote(str(home / 'config.yaml'))}",
                    f"HERMES_ENV={shlex.quote(str(home / '.env'))}",
                    shlex.join(hermes_command),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        hermes_terminal, hermes_slave = pty.openpty()
        tty.setraw(hermes_slave)
        import fcntl
        import termios

        fcntl.ioctl(
            hermes_terminal,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 40, 120, 0, 0),
        )
        hermes_log_handle = (scenario_dir / "hermes.log").open("wb")
        hermes_process = subprocess.Popen(
            hermes_command,
            stdin=hermes_slave,
            stdout=hermes_slave,
            stderr=hermes_slave,
            env=env,
            cwd=scenario_dir,
            close_fds=True,
        )
        os.close(hermes_slave)

        def copy_hermes_output() -> None:
            assert hermes_terminal is not None
            while True:
                try:
                    chunk = os.read(hermes_terminal, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                hermes_log_handle.write(chunk)
                hermes_log_handle.flush()

        hermes_log_thread = threading.Thread(target=copy_hermes_output, daemon=True)
        hermes_log_thread.start()
        prompt_deadline = time.monotonic() + 30
        while time.monotonic() < prompt_deadline:
            if (
                b"Welcome to Hermes Agent!"
                in (scenario_dir / "hermes.log").read_bytes()
            ):
                break
            if hermes_process.poll() is not None:
                raise RuntimeError("Hermes exited before its interactive prompt opened")
            time.sleep(0.05)
        else:
            raise TimeoutError("Hermes interactive prompt did not open")
        time.sleep(0.5)
        os.write(
            hermes_terminal,
            b"Deploy the isolated local service to v2 using the terminal tool "
            b"exactly once.\r",
        )
        pending = _wait_for_pending(database, hermes_process)
        pending_snapshot = {
            "observed_status": pending["status"],
            "approval_id": pending["approval_id"],
            "decision_id": pending["decision_id"],
            "action_id": pending["action_id"],
            "action_hash": pending["action_hash"],
        }
        _json_dump(scenario_dir / "pending-approval.json", pending_snapshot)
        decision = "approve" if scenario == "approve" else "deny"
        resolution = _post_json(
            f"http://127.0.0.1:{ports['cortexops']}/api/runmantle/v1/approvals/"
            f"{pending['approval_id']}/{decision}",
            {
                "action_hash": pending["action_hash"],
                "idempotency_key": f"operator-{scenario}-{pending['approval_id']}",
                "reason": f"Authenticated local operator chose {scenario}.",
            },
            OPERATOR_TOKEN,
        )
        _wait_for_model_tool_result(
            scenario_dir / "model-requests.jsonl", hermes_process
        )
        os.write(hermes_terminal, b"/quit\r")
        return_code = hermes_process.wait(timeout=90)
        hermes_log_handle.flush()
        if return_code:
            detail = (scenario_dir / "hermes.log").read_text(
                encoding="utf-8", errors="replace"
            )[-6000:]
            raise RuntimeError(f"Hermes failed in {scenario}:\n{detail}")
        state = json.loads(deployment_state.read_text(encoding="utf-8"))
        action = _rows(adapter_db, "SELECT * FROM hermes_actions")[0]
        if scenario == "approve":
            if state["version"] != "v2" or state["execution_count"] != 1:
                raise AssertionError(f"approve did not execute exactly once: {state}")
            verification = asyncio.run(
                _verify_approved_outcome(
                    scenario_dir,
                    adapter_db=adapter_db,
                    cortexops_url=f"http://127.0.0.1:{ports['cortexops']}",
                    deployment_url=f"http://127.0.0.1:{ports['deployment']}",
                    runtime_id=runtime_id,
                )
            )
        else:
            if state["version"] != "v1" or state["execution_count"] != 0:
                raise AssertionError(f"deny unexpectedly executed: {state}")
            verification = {"verification_status": "not_run_after_deny"}
        task = _rows(
            database, "SELECT * FROM runmantle_tasks WHERE runtime_id=?", (runtime_id,)
        )[0]
        approvals = _rows(
            database,
            "SELECT * FROM runmantle_action_approval_audit WHERE approval_id=? "
            "ORDER BY occurred_at,event_id",
            (pending["approval_id"],),
        )
        receipts = _rows(
            database,
            "SELECT * FROM governance_runtime_receipts WHERE decision_id=? "
            "ORDER BY received_at",
            (pending["decision_id"],),
        )
        confirmations = _rows(
            database,
            "SELECT * FROM runmantle_action_runtime_confirmations "
            "WHERE decision_id=? ORDER BY checked_at",
            (pending["decision_id"],),
        )
        transitions = _rows(
            database,
            "SELECT transition_id,sequence,from_state,to_state,accepted,"
            "reason_code,occurred_at "
            "FROM governance_transitions WHERE decision_id=? ORDER BY sequence",
            (pending["decision_id"],),
        )
        result = {
            "scenario": scenario,
            "passed": True,
            "cortexops_url": f"http://127.0.0.1:{ports['cortexops']}",
            "hermes_command": (scenario_dir / "hermes-command.txt")
            .read_text(encoding="utf-8")
            .strip(),
            "pending": pending_snapshot,
            "resolution": resolution,
            "deployment": state,
            "version_probe": _get_json(
                f"http://127.0.0.1:{ports['deployment']}/version"
            ),
            "health_probe": _get_json(f"http://127.0.0.1:{ports['deployment']}/health"),
            "task": task,
            "action": action,
            "approval_audit": approvals,
            "governance_transitions": transitions,
            "receipts": receipts,
            "runtime_confirmations": confirmations,
            "verification": verification,
        }
        if scenario == "approve":
            assert action["receipt_delivered"] == 1
            assert action["confirmation_delivered"] == 1
            assert len(receipts) == 1
            assert len(confirmations) == 1 and confirmations[0]["status"] == "confirmed"
            assert confirmations[0]["receipt_id"] == receipts[0]["receipt_id"]
            assert task["verified_status"] == "verified"
        else:
            assert action["state"] == "awaiting_approval"
            assert not receipts and not confirmations
            assert any(event["event_type"] == "DENIED" for event in approvals)
            assert task["verified_status"] is None
        _json_dump(scenario_dir / "audit-trace.json", result)
        return result
    finally:
        if hermes_process is not None and hermes_process.poll() is None:
            hermes_process.terminate()
            try:
                hermes_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                hermes_process.kill()
        if hermes_terminal is not None:
            os.close(hermes_terminal)
        if hermes_log_thread is not None:
            hermes_log_thread.join(timeout=2)
        if hermes_log_handle is not None:
            hermes_log_handle.close()
        for process, log in reversed(children):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.close()


def _render_trace(artifacts: Path, results: list[dict[str, Any]]) -> None:
    lines = ["Hermes -> RunMantle -> CortexOps local audit trace", ""]
    for result in results:
        pending = result["pending"]
        receipt_id = result["receipts"][0]["receipt_id"] if result["receipts"] else "-"
        confirmation_id = (
            result["runtime_confirmations"][0]["confirmation_id"]
            if result["runtime_confirmations"]
            else "-"
        )
        lines.extend(
            [
                f"[{result['scenario'].upper()}] PASS",
                f"cortexops={result['cortexops_url']}",
                f"task={result['task']['task_id']}",
                f"decision={pending['decision_id']}",
                f"approval={pending['approval_id']}",
                f"action={pending['action_id']}",
                f"action_hash={pending['action_hash']}",
                f"receipt={receipt_id}",
                f"confirmation={confirmation_id}",
                f"outcome={result['verification']['verification_status']}",
                "verification_hash="
                + str(result["task"].get("verification_hash") or "-"),
                "evidence=" + str(result["verification"].get("evidence_id") or "-"),
                f"version={result['version_probe']['version']}",
                f"health={result['health_probe']['status']}",
                f"execution_count={result['deployment']['execution_count']}",
                "approval_audit="
                + " -> ".join(
                    event["event_type"] for event in result["approval_audit"]
                ),
                "governance="
                + " -> ".join(
                    event["to_state"] for event in result["governance_transitions"]
                ),
                "",
            ]
        )
    (artifacts / "audit-trace.txt").write_text("\n".join(lines), encoding="utf-8")


def _orchestrate(args: argparse.Namespace) -> int:
    hermes_repo = args.hermes_repo.resolve()
    cortexops_repo = args.cortexops_repo.resolve()
    bootstrap_python = Path(sys.executable)
    if sys.version_info >= (3, 14):
        compatible = shutil.which("python3.13")
        hermes_python = (
            Path(compatible) if compatible else hermes_repo / ".venv" / "bin" / "python"
        )
        if not hermes_python.is_file():
            raise RuntimeError(
                "Hermes requires Python <3.14; provide a Hermes checkout with "
                ".venv/bin/python or python3.13."
            )
        bootstrap_python = hermes_python
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    artifacts = (
        args.artifacts_dir or ROOT / "artifacts" / "hermes-cortexops-demo" / stamp
    ).resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    install_log = artifacts / "environment-install.log"
    with tempfile.TemporaryDirectory(prefix="runmantle-hermes-cortexops-") as directory:
        scratch = Path(directory)
        venv = scratch / "venv"
        _run_checked(
            [str(bootstrap_python), "-m", "venv", str(venv)],
            log_path=install_log,
        )
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        pip = [str(python), "-m", "pip"]
        _run_checked([*pip, "install", "build"], log_path=install_log)
        _run_checked(
            [
                str(python),
                "-m",
                "build",
                "--wheel",
                "--outdir",
                str(artifacts / "wheels"),
                str(ROOT),
            ],
            log_path=install_log,
        )
        wheels = sorted((artifacts / "wheels").glob("runmantle-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected one RunMantle wheel, found {wheels}")
        _run_checked(
            [*pip, "install", str(cortexops_repo), str(wheels[0])],
            log_path=install_log,
        )
        # Hermes intentionally refuses wheel builds; its documented development
        # installation path is editable, still inside this newly-created venv.
        _run_checked(
            [*pip, "install", "-e", str(hermes_repo)],
            log_path=install_log,
        )
        hermes = python.parent / ("hermes.exe" if os.name == "nt" else "hermes")
        results = [
            _scenario(
                name,
                python=python,
                hermes=hermes,
                hermes_repo=hermes_repo,
                scratch=scratch,
                artifacts=artifacts,
            )
            for name in ("approve", "deny")
        ]
    combined = {
        "created_at": datetime.now(UTC).isoformat(),
        "runmantle_wheel": str(wheels[0]),
        "hermes_repository": str(hermes_repo),
        "cortexops_repository": str(cortexops_repo),
        "results": results,
    }
    _json_dump(artifacts / "audit-trace.json", combined)
    _render_trace(artifacts, results)
    trace_text = (artifacts / "audit-trace.txt").read_text(encoding="utf-8")
    print(f"PASS approve + deny\nArtifacts: {artifacts}\n{trace_text}")
    return 0


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hermes-repo",
        type=Path,
        default=Path(
            os.environ.get("HERMES_REPOSITORY", ROOT.parents[1] / "hermes-agent")
        ),
    )
    parser.add_argument(
        "--cortexops-repo",
        type=Path,
        default=Path(
            os.environ.get("CORTEXOPS_REPOSITORY", ROOT.parents[1] / "cortexops")
        ),
    )
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--serve-cortexops", nargs=2, metavar=("DATABASE", "PORT"))
    parser.add_argument("--serve-deployment", nargs=2, metavar=("STATE", "PORT"))
    parser.add_argument(
        "--serve-model", nargs=4, metavar=("COMMAND", "CALL_ID", "REQUEST_LOG", "PORT")
    )
    parser.add_argument("--deploy-once", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    if args.serve_cortexops:
        _serve_cortexops(Path(args.serve_cortexops[0]), int(args.serve_cortexops[1]))
        return 0
    if args.serve_deployment:
        _serve_deployment(Path(args.serve_deployment[0]), int(args.serve_deployment[1]))
        return 0
    if args.serve_model:
        _serve_model(
            args.serve_model[0],
            args.serve_model[1],
            Path(args.serve_model[2]),
            int(args.serve_model[3]),
        )
        return 0
    if args.deploy_once:
        _deploy_once(args.deploy_once)
        return 0
    return _orchestrate(args)


if __name__ == "__main__":
    raise SystemExit(main())
