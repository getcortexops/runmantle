from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from runmantle.contracts import RiskLevel
from runmantle.integrations.hermes_control import (
    HermesControlAdapter,
    HermesControlConfig,
    HermesToolDiscoveryAdapter,
)
from runmantle.tool_discovery import (
    DiscoveredTool,
    ToolClassifier,
    ToolInventory,
)

from .test_hermes_control import _Client


@dataclass
class _Entry:
    name: str
    toolset: str
    description: str

    def __post_init__(self) -> None:
        self.schema = {"name": self.name, "description": self.description}
        self.handler = lambda _: None


class _HermesRegistry:
    def __init__(self, entries: list[_Entry]) -> None:
        self.entries = entries

    def get_all_entries(self) -> list[_Entry]:
        return list(self.entries)

    def get_definitions(
        self, names: set[str], quiet: bool = False
    ) -> list[dict[str, Any]]:
        del quiet
        return [
            {"type": "function", "function": entry.schema}
            for entry in self.entries
            if entry.name in names
        ]


class _Discovery:
    def discover_tools(self) -> tuple[DiscoveredTool, ...]:
        return (
            DiscoveredTool(
                "read_file",
                "example",
                "test-framework",
                "test.registry",
                "Read a file without modifying it.",
            ),
            DiscoveredTool(
                "send_email",
                "example",
                "test-framework",
                "test.registry",
                "Send an email to a recipient.",
            ),
        )


def test_automatic_discovery_normalizes_tools() -> None:
    inventory = ToolInventory()
    descriptors = inventory.refresh(_Discovery())

    assert [item.name for item in descriptors] == ["read_file", "send_email"]
    assert descriptors[0].framework == "test-framework"
    assert descriptors[0].discovery_source == "test.registry"
    assert descriptors[0].classification_confidence > 0


def test_read_only_known_side_effect_and_unknown_fail_closed() -> None:
    classifier = ToolClassifier()
    read = classifier.classify(
        DiscoveredTool(
            "read_file",
            "p",
            "f",
            "registry",
            "Read a file; use this instead of cat in the terminal.",
        )
    )
    write = classifier.classify(
        DiscoveredTool("send_email", "p", "f", "registry", "Send email")
    )
    unknown = classifier.classify(
        DiscoveredTool("teleport", "p", "f", "registry", "Do something custom")
    )

    assert read.read_only and read.capability == "filesystem.read"
    assert write.side_effecting and write.capability == "email.send"
    assert unknown.side_effecting
    assert unknown.risk_level == RiskLevel.HIGH
    assert unknown.classification_confidence == 0


def test_explicit_classification_override() -> None:
    classifier = ToolClassifier(
        {
            "lookup_widget": {
                "capability": "database.read",
                "risk_level": "low",
                "read_only": True,
            }
        }
    )
    descriptor = classifier.classify(
        DiscoveredTool("lookup_widget", "p", "f", "registry")
    )

    assert descriptor.read_only
    assert descriptor.capability == "database.read"
    assert descriptor.classification_confidence == 1


def _adapter(
    tmp_path: Path,
    entries: list[_Entry],
    *,
    overrides: dict[str, dict[str, Any]] | None = None,
    outcome: str = "REQUIRE_APPROVAL",
    govern_read_only: bool = False,
) -> tuple[HermesControlAdapter, _Client]:
    config = HermesControlConfig.from_settings(
        {
            "cortexops_url": "http://127.0.0.1:9",
            "state_path": str(tmp_path / "tools.sqlite"),
            "classification_overrides": overrides or {},
            "govern_read_only_tools": govern_read_only,
            "approval_timeout_seconds": 0.02,
            "approval_poll_initial_seconds": 0.001,
            "approval_poll_max_seconds": 0.002,
        }
    )
    adapter = HermesControlAdapter(
        config, HermesToolDiscoveryAdapter(_HermesRegistry(entries))
    )
    client = _Client(outcome)
    adapter.client = cast(Any, client)
    return adapter, client


def _call(name: str, call_id: str = "call") -> dict[str, Any]:
    return {
        "tool_name": name,
        "args": {},
        "task_id": "task",
        "session_id": "session",
        "tool_call_id": call_id,
    }


def test_hermes_reads_actual_registry_without_manual_list(tmp_path: Path) -> None:
    adapter, client = _adapter(
        tmp_path,
        [
            _Entry("read_file", "file", "Read a file"),
            _Entry("write_file", "file", "Write a file"),
        ],
    )

    assert adapter.pre_tool_call(**_call("read_file", "read")) is None
    assert client.dispatched == []
    result = adapter.pre_tool_call(**_call("write_file", "write"))
    assert result and result["action"] == "approve"


def test_policy_can_govern_read_only_tool(tmp_path: Path) -> None:
    adapter, client = _adapter(
        tmp_path,
        [_Entry("read_file", "file", "Read a file")],
        outcome="ALLOW",
        govern_read_only=True,
    )

    assert adapter.pre_tool_call(**_call("read_file", "read")) is None
    assert client.dispatched == ["read"]


def test_alternate_tool_cannot_bypass_configured_tool_scope(tmp_path: Path) -> None:
    adapter, client = _adapter(
        tmp_path,
        [
            _Entry("terminal", "terminal", "Execute a shell command"),
            _Entry("publish_release", "custom", "Publish a release"),
        ],
        overrides={"terminal": {"capability": "shell.execute"}},
        outcome="ALLOW",
    )

    assert adapter.pre_tool_call(**_call("publish_release", "alternate")) is None
    assert client.dispatched == ["alternate"]
    with adapter._db() as db:
        stored = db.execute(
            "SELECT request_json FROM hermes_actions WHERE tool_call_id='alternate'"
        ).fetchone()[0]
    assert "external_api.mutate" in stored


def test_registry_gap_is_governed_and_dispatches_exactly_once(tmp_path: Path) -> None:
    adapter, client = _adapter(tmp_path, [], outcome="ALLOW")

    assert adapter.pre_tool_call(**_call("unregistered_mutator")) is None
    assert adapter.pre_tool_call(**_call("unregistered_mutator")) is None
    assert client.dispatched == ["call"]
