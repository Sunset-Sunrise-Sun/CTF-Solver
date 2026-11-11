"""v0.1.1 installation-hardening regression tests.

Covers:
- package-resource privacy patch (source == installed package location);
- explicit ACP-unavailable failure instead of silently queued Tasks;
- ACP crash after Task creation reflected in durable state;
- preserved two-Worker FIFO behaviour.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import AcpUnavailableError, ConfigError
from ctf_solver.core.types import TaskStatus, WorkerStatus
from ctf_solver.manager.service import ManagerService
from ctf_solver.manager.store import ManagerStore
from tests.support.fakes import FakeAcp, FakeCapturer, FakeDeliverables, FakeEvidence, FakePipeline
from tests.support.proc import PROJECT_ROOT, child_env
from tests.test_round2_completion_faults import _build


def _service_with_failing_acp(tmp_path, exc: Exception | None = None):
    config = SolverConfig(root=tmp_path, capture_mode="fake")
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))

    def factory():
        raise exc or ConfigError("synthetic ACP startup failure")

    service = ManagerService(
        config=config,
        store=store,
        acp_factory=factory,
        evidence=FakeEvidence(),
        pipeline=FakePipeline(),
        deliverables=FakeDeliverables(tmp_path),
        capturer=FakeCapturer("ok"),
    )
    return service, store


def test_package_resource_is_the_single_privacy_patch(tmp_path) -> None:
    resource = PROJECT_ROOT / "ctf_solver" / "resources" / "acp" / "cordis.patch.yml"
    assert resource.is_file()
    config = SolverConfig(root=tmp_path)
    assert config.privacy_patch_path.resolve() == resource.resolve()
    text = config.privacy_patch_path.read_text(encoding="utf-8")
    assert "session-log-deepseek" in text
    assert "enabled: false" in text
    # The old duplicate project-level copy must not remain.
    assert not (PROJECT_ROOT / "config" / "acp" / "cordis.patch.yml").exists()


def test_acp_startup_failure_blocks_task_creation_before_persistence(tmp_path) -> None:
    service, store = _service_with_failing_acp(tmp_path)
    try:
        status = service.start()
        assert status["acp"]["ready"] is False
        assert status["acp"]["error"]
        with pytest.raises(AcpUnavailableError) as info:
            service.create_task(title="must not queue", category="misc", conversation_id="conv")
        assert info.value.reason_code == "acp_unavailable"
        assert info.value.details.get("acp_ready") is False
        assert store.list_tasks() == []
    finally:
        service.shutdown()
        store.close()


def test_create_task_before_start_fails_closed(tmp_path) -> None:
    service, store = _service_with_failing_acp(tmp_path)
    try:
        with pytest.raises(AcpUnavailableError):
            service.create_task(title="not started", category="misc", conversation_id="conv")
        assert store.list_tasks() == []
    finally:
        store.close()


def test_acp_crash_after_task_creation_is_durable_and_visible(tmp_path) -> None:
    service, store, _evidence = _build(tmp_path)
    try:
        task = service.create_task(title="crash", category="misc", conversation_id="conv")
        assert store.require_task(task.task_id).status is TaskStatus.RUNNING
        assert service._acp is not None  # noqa: SLF001 - test double
        service._acp.alive = False  # noqa: SLF001
        status = service.runtime_status()
        assert status["acp"]["ready"] is False
        stored = store.require_task(task.task_id)
        assert stored.status is TaskStatus.INTERRUPTED
        worker = store.get_worker_for_task(task.task_id)
        assert worker is not None and worker.status is WorkerStatus.CRASHED
        with pytest.raises(AcpUnavailableError):
            service.create_task(title="after crash", category="misc", conversation_id="conv")
    finally:
        service.shutdown()
        store.close()


def test_two_worker_fifo_queue_is_preserved(tmp_path) -> None:
    service, store, _evidence = _build(tmp_path)
    try:
        first = service.create_task(title="f1", category="misc", conversation_id="conv")
        second = service.create_task(title="f2", category="misc", conversation_id="conv")
        third = service.create_task(title="f3", category="misc", conversation_id="conv")
        assert store.require_task(first.task_id).status is TaskStatus.RUNNING
        assert store.require_task(second.task_id).status is TaskStatus.RUNNING
        assert store.require_task(third.task_id).status is TaskStatus.QUEUED
        assert store.get_worker_for_task(third.task_id) is None
        assert store.count_active_slots() == 2
    finally:
        service.shutdown()
        store.close()


def test_cli_task_create_reports_acp_startup_failure(tmp_path) -> None:
    root = tmp_path / "cli-root"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ctf_solver",
            "task",
            "create",
            "--root",
            str(root),
            "--title",
            "cli-fail",
            "--category",
            "misc",
            "--conversation-id",
            "conv-cli",
        ],
        cwd=str(PROJECT_ROOT),
        env=child_env(CTF_SOLVER_ACP_COMMAND="definitely-not-a-real-acp-command-xyz"),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    assert "startup failed" in combined.lower() or "acp unavailable" in combined.lower()
    assert "queued" not in proc.stdout.lower()
