"""Scheduler and ManagerStore unit tests."""

from __future__ import annotations

import pytest

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import NotFoundError, StateError
from ctf_solver.core.types import (
    ApprovalRecord,
    ApprovalStatus,
    Category,
    GrantRecord,
    GrantStatus,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.manager.scheduler import Scheduler, SchedulerConfig
from ctf_solver.manager.store import ManagerStore


def _task(task_id: str, created_at: int, status: TaskStatus = TaskStatus.QUEUED) -> TaskRecord:
    return TaskRecord(
        task_id=task_id,
        conversation_id="conv",
        title=f"task {task_id}",
        category=Category.MISC,
        workspace_path=f"D:/tmp/{task_id}/work",
        status=status,
        created_at=created_at,
        updated_at=created_at,
    )


def test_scheduler_capacity_validation() -> None:
    Scheduler(1)
    Scheduler(2)
    with pytest.raises(Exception):
        Scheduler(3)
    with pytest.raises(Exception):
        SchedulerConfig(capacity=0)


def test_scheduler_admits_fifo_and_respects_capacity() -> None:
    scheduler = Scheduler(2)
    tasks = [_task("t-a", 1), _task("t-b", 2), _task("t-c", 3)]
    admitted = scheduler.admit(0, tasks)
    assert [task.task_id for task in admitted] == ["t-a", "t-b"]
    assert scheduler.admit(1, tasks) == [tasks[0]]
    assert scheduler.admit(2, tasks) == []
    assert scheduler.admit(0, []) == []
    with pytest.raises(ValueError):
        scheduler.admit(-1, tasks)


def test_scheduler_queue_positions() -> None:
    scheduler = Scheduler(2)
    tasks = [_task("t-b", 2), _task("t-a", 1), _task("t-c", 3)]
    assert scheduler.queue_position("t-a", tasks) == 1
    assert scheduler.queue_position("t-c", tasks) == 3
    assert scheduler.queue_position("t-zz", tasks) is None
    assert [task.task_id for task in scheduler.order(tasks)] == ["t-a", "t-b", "t-c"]


def _store(tmp_path) -> ManagerStore:
    config = SolverConfig(root=tmp_path)
    paths = config.ensure_layout()
    return ManagerStore(str(paths.db_path))


def test_store_task_lifecycle_and_queue(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        store.create_task(_task("t-2", 20, TaskStatus.CREATED))
        assert [task.task_id for task in store.list_tasks(status="created")] == ["t-1", "t-2"]
        store.set_task_status("t-1", TaskStatus.QUEUED)
        store.set_task_status("t-2", TaskStatus.QUEUED)
        assert [task.task_id for task in store.list_queued()] == ["t-1", "t-2"]
        with pytest.raises(StateError):
            store.set_task_status("t-1", TaskStatus.RUNNING)  # must go through STARTING
        with pytest.raises(NotFoundError):
            store.require_task("t-missing")
    finally:
        store.close()


def test_store_activate_task_persists_worker_and_session(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        store.set_task_status("t-1", TaskStatus.QUEUED)
        store.set_task_status("t-1", TaskStatus.STARTING)
        worker = WorkerRecord(
            worker_id="w-1",
            task_id="t-1",
            acp_session_id="session-1",
            workspace_path="D:/tmp/t-1/work",
            status=WorkerStatus.READY,
            worker_token="token-1",
        )
        task, stored_worker = store.activate_task("t-1", worker=worker)
        assert task.status is TaskStatus.RUNNING
        assert task.acp_session_id == "session-1"
        assert task.worker_id == "w-1"
        assert stored_worker.worker_token == "token-1"
        assert store.get_worker_by_token("token-1").worker_id == "w-1"
        assert store.count_active_slots() == 1
        store.set_worker_status("w-1", WorkerStatus.STOPPED)
        assert store.count_active_slots() == 0
    finally:
        store.close()


def _human_confirmation(digest: str):
    from ctf_solver.security.confirmation import HumanConfirmation

    return HumanConfirmation(
        channel="local_console",
        os_user="human-test",
        confirmed_at=1_700_000_000_000,
        confirmation_id="conf-test",
        approval_digest=digest,
    )


def test_store_approval_consume_is_one_shot(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        far_future = store.clock.now_ms() + 600_000
        approval = ApprovalRecord(
            approval_id="apr-1",
            task_id="t-1",
            action_kind="remote_target",
            action_digest="a" * 64,
            requested_at=store.clock.now_ms(),
            expires_at=far_future,
        )
        store.create_approval(approval)
        # A caller-supplied approver string is not a confirmation.
        with pytest.raises(StateError):
            store.record_approval_confirmation(
                "apr-1", approved=True, confirmation={"approver": "agent", "channel": "local_console"}
            )
        store.record_approval_confirmation(
            "apr-1", approved=True, confirmation=_human_confirmation("a" * 64)
        )
        assert store.consume_approval("apr-1", store.clock.now_ms()) is True
        assert store.consume_approval("apr-1", store.clock.now_ms()) is False
        assert store.consume_approval("apr-unknown", store.clock.now_ms()) is False
    finally:
        store.close()


def test_store_rejects_expired_approval(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        store.create_approval(
            ApprovalRecord(
                approval_id="apr-exp",
                task_id="t-1",
                action_kind="remote_target",
                action_digest="a" * 64,
                requested_at=1000,
                expires_at=1500,
            )
        )
        with pytest.raises(StateError):
            store.record_approval_confirmation(
                "apr-exp",
                approved=True,
                confirmation=_human_confirmation("a" * 64),
                decided_at=2000,
            )
    finally:
        store.close()


def test_store_grant_call_consumption(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        grant = GrantRecord(
            grant_id="grant-1",
            task_id="t-1",
            competition_profile="synthetic",
            host="127.0.0.1",
            port=31337,
            protocol="tcp",
            method="GET",
            path_prefix="/",
            expires_at=10_000,
            max_calls=2,
            approver="human",
            created_at=1000,
        )
        store.create_grant(grant)
        assert store.consume_grant_call("grant-1", 2000) is True
        assert store.consume_grant_call("grant-1", 2000) is True
        assert store.consume_grant_call("grant-1", 2000) is False
        assert store.get_grant("grant-1").status is GrantStatus.EXHAUSTED
    finally:
        store.close()


def test_store_grant_expiry(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        store.create_grant(
            GrantRecord(
                grant_id="grant-exp",
                task_id="t-1",
                competition_profile="synthetic",
                host="example.test",
                port=80,
                protocol="tcp",
                method="GET",
                path_prefix="/",
                expires_at=1000,
                max_calls=1,
                approver="human",
                created_at=500,
            )
        )
        assert store.consume_grant_call("grant-exp", 2000) is False
        assert store.get_grant("grant-exp").status is GrantStatus.EXPIRED
    finally:
        store.close()


def test_store_execution_rows_and_screenshots(tmp_path) -> None:
    store = _store(tmp_path)
    try:
        store.create_task(_task("t-1", 10, TaskStatus.CREATED))
        store.record_execution(
            {
                "execution_id": "exec-1",
                "task_id": "t-1",
                "worker_id": "w-1",
                "step_id": "s1",
                "tool_name": "internal.file_hash",
                "argv": ["x"],
                "cwd": "D:/tmp/t-1/work",
                "tier": 0,
                "status": "completed",
                "started_at": 100,
                "result": {},
            }
        )
        store.update_execution("exec-1", {"status": "failed", "exit_code": 3})
        rows = store.list_executions("t-1")
        assert rows[0]["status"] == "failed"
        assert rows[0]["exit_code"] == 3
    finally:
        store.close()
