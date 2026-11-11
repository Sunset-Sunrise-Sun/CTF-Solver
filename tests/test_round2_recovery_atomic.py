"""Final follow-up-2: atomic restart recovery for Task + Worker state.

All tests use the real SQLite ManagerStore/EvidenceStore. SQLite triggers abort
specific UPDATE statements to inject failures; the transaction must roll back
both Task and Worker, keeping the Worker slot occupied.
"""

from __future__ import annotations

import pytest

from ctf_solver.core.types import TaskStatus, WorkerStatus
from tests.test_round2_completion_faults import (
    _FlakyEvidence,
    _build_persistent,
    _complete,
    _install_trigger,
    _drop_trigger,
)


def _restart(tmp_path):
    return _build_persistent(tmp_path, start=False)


def test_generic_recovery_task_failure_rolls_back_worker(tmp_path) -> None:
    service, store, _evidence = _build_persistent(tmp_path)
    task_id = worker_id = None
    try:
        task = service.create_task(title="atomic-r1", category="misc", conversation_id="c")
        task_id = task.task_id
        worker_id = store.get_worker_for_task(task_id).worker_id
        _install_trigger(
            store,
            "block_recovery_task",
            "CREATE TRIGGER block_recovery_task BEFORE UPDATE ON tasks"
            " WHEN NEW.status = 'interrupted' BEGIN"
            " SELECT RAISE(ABORT, 'synthetic interrupted update failure'); END",
        )
    finally:
        service.close()
        store.close()

    service2, store2, _ev2 = _restart(tmp_path)
    try:
        service2.start()
        # Failed recovery must not fake success and must not release the slot.
        assert store2.require_task(task_id).status is TaskStatus.RUNNING
        assert store2.require_worker(worker_id).status is not WorkerStatus.STOPPED
        assert store2.count_active_slots() == 1
        result = service2.recover()
        assert result["interrupted"][0]["status"] == "running"
        assert result["interrupted"][0].get("error")
        _drop_trigger(store2, "block_recovery_task")
        result = service2.recover()
        assert result["interrupted"][0]["status"] == "interrupted"
        assert store2.require_task(task_id).status is TaskStatus.INTERRUPTED
        assert store2.require_worker(worker_id).status is WorkerStatus.STOPPED
        assert store2.count_active_slots() == 0
    finally:
        service2.close()
        store2.close()


def test_generic_recovery_worker_failure_rolls_back_task(tmp_path) -> None:
    service, store, _evidence = _build_persistent(tmp_path)
    task_id = worker_id = None
    try:
        task = service.create_task(title="atomic-r2", category="misc", conversation_id="c")
        task_id = task.task_id
        worker_id = store.get_worker_for_task(task_id).worker_id
        _install_trigger(
            store,
            "block_recovery_worker",
            "CREATE TRIGGER block_recovery_worker BEFORE UPDATE ON workers"
            " WHEN NEW.status = 'stopped' BEGIN"
            " SELECT RAISE(ABORT, 'synthetic worker stop failure'); END",
        )
    finally:
        service.close()
        store.close()

    service2, store2, _ev2 = _restart(tmp_path)
    try:
        service2.start()
        assert store2.require_task(task_id).status is TaskStatus.RUNNING
        assert store2.require_worker(worker_id).status is not WorkerStatus.STOPPED
        assert store2.count_active_slots() == 1
        _drop_trigger(store2, "block_recovery_worker")
        service2.recover()
        assert store2.require_task(task_id).status is TaskStatus.INTERRUPTED
        assert store2.require_worker(worker_id).status is WorkerStatus.STOPPED
        assert store2.count_active_slots() == 0
    finally:
        service2.close()
        store2.close()


def test_completion_pending_without_evidence_recovery_failure_keeps_slot(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    task_id = worker_id = None
    try:
        task = service.create_task(title="atomic-pending", category="misc", conversation_id="c")
        task_id = task.task_id
        worker_id = store.get_worker_for_task(task_id).worker_id
        service.evidence = _FlakyEvidence(evidence, fail_append_for={"task_completed"})
        with pytest.raises(Exception):
            _complete(service, task_id)
        assert store.require_task(task_id).status is TaskStatus.COMPLETION_PENDING
        _install_trigger(
            store,
            "block_pending_recovery",
            "CREATE TRIGGER block_pending_recovery BEFORE UPDATE ON tasks"
            " WHEN NEW.status = 'interrupted' BEGIN"
            " SELECT RAISE(ABORT, 'synthetic pending interrupt failure'); END",
        )
    finally:
        service.close()
        store.close()

    service2, store2, _ev2 = _restart(tmp_path)
    try:
        service2.start()
        assert store2.require_task(task_id).status is TaskStatus.COMPLETION_PENDING
        assert store2.require_worker(worker_id).status is not WorkerStatus.STOPPED
        assert store2.count_active_slots() == 1
        _drop_trigger(store2, "block_pending_recovery")
        service2.recover()
        assert store2.require_task(task_id).status is TaskStatus.INTERRUPTED
        assert store2.require_worker(worker_id).status is WorkerStatus.STOPPED
        assert store2.count_active_slots() == 0
    finally:
        service2.close()
        store2.close()


def test_recovery_failure_does_not_admit_fifo_task(tmp_path) -> None:
    service, store, _evidence = _build_persistent(tmp_path)
    task_ids: list[str] = []
    try:
        first = service.create_task(title="fifo-r1", category="misc", conversation_id="c")
        second = service.create_task(title="fifo-r2", category="misc", conversation_id="c")
        third = service.create_task(title="fifo-queued", category="misc", conversation_id="c")
        task_ids = [first.task_id, second.task_id, third.task_id]
        _install_trigger(
            store,
            "block_fifo_recovery_task",
            "CREATE TRIGGER block_fifo_recovery_task BEFORE UPDATE ON tasks"
            " WHEN NEW.status = 'interrupted' AND task_id IN ('"
            + first.task_id
            + "', '"
            + second.task_id
            + "') BEGIN"
            " SELECT RAISE(ABORT, 'synthetic fifo recovery failure'); END",
        )
    finally:
        service.close()
        store.close()

    service2, store2, _ev2 = _restart(tmp_path)
    try:
        service2.start()
        assert store2.require_task(task_ids[0]).status is TaskStatus.RUNNING
        assert store2.require_task(task_ids[2]).status is TaskStatus.QUEUED
        assert store2.get_worker_for_task(task_ids[2]) is None
        assert store2.count_active_slots() == 2
        assert len(service2._acp.new_session_calls) == 0  # noqa: SLF001 - no duplicate sessions
        _drop_trigger(store2, "block_fifo_recovery_task")
        service2.recover()
        assert store2.require_task(task_ids[0]).status is TaskStatus.INTERRUPTED
        service2.pump()
        assert store2.require_task(task_ids[2]).status is TaskStatus.RUNNING
        assert len([w for w in store2.list_workers() if w.task_id == task_ids[2]]) == 1
        assert len(service2._acp.new_session_calls) == 1  # noqa: SLF001
        # Repeated pump does not create another Worker/Session.
        service2.pump()
        assert len(service2._acp.new_session_calls) == 1  # noqa: SLF001
    finally:
        service2.close()
        store2.close()


def test_recovery_without_worker_interrupts_task_only(tmp_path) -> None:
    service, store, _evidence = _build_persistent(tmp_path, start=False)
    task_id = None
    try:
        from ctf_solver.core.types import Category, TaskRecord

        task_id = "t-recover-noworker"
        store.create_task(
            TaskRecord(
                task_id=task_id,
                conversation_id="c",
                title="no worker",
                category=Category.MISC,
                workspace_path=str(store.workspace_for_worker("x") or tmp_path / "work"),
                status=TaskStatus.RUNNING,
                created_at=store.clock.now_ms(),
                updated_at=store.clock.now_ms(),
            )
        )
    finally:
        pass
    service2, store2, _ev2 = _build_persistent(tmp_path, start=False)
    try:
        result = service2.recover()
        entry = next(item for item in result["interrupted"] if item["task_id"] == task_id)
        assert entry["status"] == "interrupted"
        assert store2.require_task(task_id).status is TaskStatus.INTERRUPTED
        assert store2.get_worker_for_task(task_id) is None
    finally:
        service2.close()
        store2.close()
        service.close()
        store.close()
