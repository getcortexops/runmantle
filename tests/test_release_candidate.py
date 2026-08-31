from __future__ import annotations

import json
import subprocess
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from runmantle import (
    BackpressurePolicy,
    BufferedEventSink,
    EventBackpressureError,
    LifecycleEvent,
    LifecycleEventType,
    SafeJsonCodec,
    SerializationError,
    TaskStatus,
)
from runmantle.cli import _init
from runmantle.project import ProjectConfigurationError, load_project
from runmantle.release_guard import (
    RepositoryBoundaryError,
    _write_repository_file,
    apply_release_fix,
    resume_recovery,
    run_agent,
    runtime,
    verify_repository,
)


class ReleaseGuardTest(unittest.IsolatedAsyncioTestCase):
    async def test_restart_safe_false_claim_recovery_and_duplicate_prevention(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            _init(Path(directory), cortexops=False)
            project = load_project(Path(directory) / "runmantle.json")

            claimed = await run_agent(project)
            self.assertEqual(claimed.status, TaskStatus.AWAITING_EVIDENCE)
            self.assertFalse(claimed.succeeded)

            # Each helper constructs a new runtime/store, modeling a process restart.
            checked = await verify_repository(project)
            self.assertEqual(checked.status, TaskStatus.FAILED)
            self.assertFalse(checked.succeeded)
            first_history = runtime(project).event_history(project.task_id)

            waiting = await resume_recovery(project)
            self.assertEqual(waiting.status.value, "awaiting_approval")
            self.assertFalse(waiting.executed)

            recovered = await resume_recovery(project, approve_current=True)
            self.assertTrue(recovered.succeeded)
            self.assertEqual(
                runtime(project).load(project.task_id).status, TaskStatus.VERIFIED
            )
            after_recovery = runtime(project).event_history(project.task_id)
            self.assertGreater(len(after_recovery), len(first_history))

            duplicate = await resume_recovery(project, approve_current=True)
            self.assertEqual(duplicate.status.value, "duplicate_prevented")
            self.assertFalse(duplicate.executed)
            log = subprocess.run(
                ["git", "log", "--format=%s"],
                cwd=project.repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertEqual(log.count("Prepare verified release"), 1)

    async def test_fault_after_effect_is_unknown_and_never_retried(self) -> None:
        with TemporaryDirectory() as directory:
            _init(Path(directory), cortexops=False)
            project = load_project(Path(directory) / "runmantle.json")
            await run_agent(project)
            await verify_repository(project)
            await resume_recovery(project)

            interrupted = await resume_recovery(
                project, approve_current=True, fault_after_write=True
            )
            self.assertEqual(interrupted.status.value, "unknown")
            self.assertEqual(
                runtime(project).load(project.task_id).status, TaskStatus.FAILED
            )
            second = await resume_recovery(project)
            self.assertEqual(second.status.value, "unknown")
            self.assertFalse(second.succeeded)

    async def test_optional_cortexops_path_is_explicit_and_redacted(self) -> None:
        with TemporaryDirectory() as directory:
            _init(Path(directory), cortexops=True)
            project = load_project(Path(directory) / "runmantle.json")
            await run_agent(project)
            export = project.state_directory / "cortexops-events.jsonl"
            self.assertTrue(export.is_file())
            text = export.read_text(encoding="utf-8")
            self.assertIn("observation_only", text)
            self.assertNotIn("release_ready", text)


class ProjectSecurityTest(unittest.TestCase):
    def test_manifest_path_traversal_and_symlink_escape_are_rejected(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            _init(Path(directory), cortexops=False)
            manifest = Path(directory) / "runmantle.json"
            value = SafeJsonCodec().loads(manifest.read_text(encoding="utf-8"))
            assert isinstance(value, dict)
            value["repository"] = "../outside"
            manifest.write_text(SafeJsonCodec().dumps(value), encoding="utf-8")
            with self.assertRaises(ProjectConfigurationError):
                load_project(manifest)

            value["repository"] = "escape"
            (Path(directory) / "escape").symlink_to(
                Path(outside), target_is_directory=True
            )
            manifest.write_text(SafeJsonCodec().dumps(value), encoding="utf-8")
            with self.assertRaises(ProjectConfigurationError):
                load_project(manifest)

    def test_bounded_safe_deserialization_rejects_oversize_and_depth(self) -> None:
        codec = SafeJsonCodec(max_bytes=32, max_depth=3, max_collection_items=4)
        with self.assertRaises(SerializationError):
            codec.loads(json.dumps({"value": "x" * 64}))
        with self.assertRaises(SerializationError):
            codec.loads('[[[["too-deep"]]]]')
        with self.assertRaises(SerializationError):
            codec.loads("[1,2,3,4,5]")
        with self.assertRaises(SerializationError):
            codec.loads('{"$runmantle_type":"pickle","value":"boom"}')

    def test_recovery_rejects_dist_symlink_without_outside_write(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            _init(Path(directory), cortexops=False)
            project = load_project(Path(directory) / "runmantle.json")
            outside_path = Path(outside)
            (project.repository / "dist").symlink_to(
                outside_path,
                target_is_directory=True,
            )

            with self.assertRaises(RepositoryBoundaryError):
                apply_release_fix(project.repository)

            self.assertEqual(tuple(outside_path.iterdir()), ())

    def test_recovery_rejects_nested_symlink_and_parent_traversal(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            _init(Path(directory), cortexops=False)
            project = load_project(Path(directory) / "runmantle.json")
            outside_path = Path(outside)
            (project.repository / "dist").mkdir()
            (project.repository / "dist" / "nested").symlink_to(
                outside_path,
                target_is_directory=True,
            )

            with self.assertRaises(RepositoryBoundaryError):
                _write_repository_file(
                    project.repository,
                    "dist/nested/release.txt",
                    b"must-not-escape",
                )
            with self.assertRaises(RepositoryBoundaryError):
                _write_repository_file(
                    project.repository,
                    "../outside.txt",
                    b"must-not-traverse",
                )

            self.assertEqual(tuple(outside_path.iterdir()), ())
            self.assertFalse(Path(directory).joinpath("outside.txt").exists())

    def test_recovery_rejects_repository_root_symlink(self) -> None:
        with TemporaryDirectory() as directory:
            _init(Path(directory), cortexops=False)
            project = load_project(Path(directory) / "runmantle.json")
            linked_root = Path(directory) / "repository-link"
            linked_root.symlink_to(project.repository, target_is_directory=True)

            with self.assertRaises(RepositoryBoundaryError):
                apply_release_fix(linked_root)

            self.assertFalse((project.repository / "dist" / "release.txt").exists())

    def test_recovery_disables_repository_controlled_git_hooks(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            _init(Path(directory), cortexops=False)
            project = load_project(Path(directory) / "runmantle.json")
            marker = Path(outside) / "hook-ran"
            hook = project.repository / ".git" / "hooks" / "pre-commit"
            hook.write_text(
                f"#!/bin/sh\nprintf hook-ran > '{marker}'\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)

            result = apply_release_fix(project.repository)

            self.assertTrue(result["mutated"])
            self.assertFalse(marker.exists())
            self.assertTrue((project.repository / "dist" / "release.txt").is_file())


class BufferedEventSinkTest(unittest.TestCase):
    def test_flush_cleanup_and_backpressure_are_observable(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class SlowSink:
            def emit(self, event: LifecycleEvent) -> None:
                del event
                entered.set()
                release.wait(2)

        sink = BufferedEventSink(
            SlowSink(), max_queue_size=1, policy=BackpressurePolicy.RAISE
        )
        event = _event(1)
        sink.emit(event)
        self.assertTrue(entered.wait(1))
        sink.emit(_event(2))
        with self.assertRaises(EventBackpressureError):
            sink.emit(_event(3))
        release.set()
        sink.flush(timeout_seconds=2)
        sink.close()
        with self.assertRaises(EventBackpressureError):
            sink.emit(_event(4))

    def test_drop_policy_counts_non_authoritative_export_loss(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class SlowSink:
            def emit(self, event: LifecycleEvent) -> None:
                del event
                entered.set()
                release.wait(2)

        sink = BufferedEventSink(
            SlowSink(), max_queue_size=1, policy=BackpressurePolicy.DROP
        )
        sink.emit(_event(1))
        self.assertTrue(entered.wait(1))
        sink.emit(_event(2))
        sink.emit(_event(3))
        self.assertEqual(sink.dropped_events, 1)
        release.set()
        sink.close(timeout_seconds=2)


def _event(sequence: int) -> LifecycleEvent:
    return LifecycleEvent(
        event_type=LifecycleEventType.TASK_PROGRESS,
        task_id="task",
        correlation_id="correlation",
        worker_id="worker",
        occurred_at=datetime.now(UTC),
        sequence=sequence,
        state=TaskStatus.RUNNING,
    )


if __name__ == "__main__":
    unittest.main()
