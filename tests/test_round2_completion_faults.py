"""Final acceptance hardening: completion fault injection and recovery.

Every failure path must leave the Task unfinished and the Worker slot held (or a
clearly recoverable ``completion_pending`` state), and must never return success
without durable ``task_completed`` evidence.
"""

from __future__ import annotations

import pytest

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import AcpError, StateError, StorageError
from ctf_solver.core.types import TaskStatus, WorkerStatus
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.manager.service import ManagerService
from ctf_solver.manager.store import ManagerStore
from tests.support.fakes import (
    FakeAcp,
    FakeCapturer,
    FakeDeliverables,
    FakeEvidence,
    FakePipeline,
)


def _build(tmp_path, *, acp=None, evidence=None):
    config = SolverConfig(root=tmp_path)
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = evidence or FakeEvidence()
    service = ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: acp or FakeAcp(),
        evidence=evidence,
        pipeline=FakePipeline(),
        deliverables=FakeDeliverables(tmp_path),
        capturer=FakeCapturer("ok"),
    )
    service.start()
    return service, store, evidence


def _build_persistent(tmp_path, *, acp=None, start=True):
    config = SolverConfig(root=tmp_path)
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = EvidenceStore(
        str(paths.db_path), str(paths.cas_dir), clock=None
    )
    service = ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: acp or FakeAcp(),
        evidence=evidence,
        pipeline=FakePipeline(),
        deliverables=FakeDeliverables(tmp_path),
        capturer=FakeCapturer("ok"),
    )
    if start:
        service.start()
    return service, store, evidence


def _complete(service, task_id: str):
    return service.complete_task(
        task_id,
        result_state="solved_flag_candidate",
        note="fault-injection completion",
        allow_missing_session_log=True,
    )


class _FlakyEvidence:
    def __init__(self, inner, *, fail_append_for=(), chain_fail_at=None):
        self._inner = inner
        self.fail_append_for = set(fail_append_for)
        self.chain_fail_at = chain_fail_at
        self.chain_calls = 0

    def append_event(self, **kwargs):
        if kwargs.get("event_type") in self.fail_append_for:
            raise OSError("synthetic append_event failure")
        return self._inner.append_event(**kwargs)

    def chain_status(self):
        self.chain_calls += 1
        if self.chain_fail_at is not None and self.chain_calls >= self.chain_fail_at:
            raise OSError("synthetic chain_status failure")
        return self._inner.chain_status()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_session_close_failure_keeps_task_and_slot(tmp_path) -> None:
    acp = FakeAcp()
    acp.close_should_fail = True
    service, store, _evidence = _build(tmp_path, acp=acp)
    try:
        task = service.create_task(title="close", category="misc", conversation_id="c")
        worker = store.get_worker_for_task(task.task_id)
        with pytest.raises(AcpError):
            _complete(service, task.task_id)
        stored = store.require_task(task.task_id)
        assert stored.status is TaskStatus.RUNNING
        assert stored.ended_at is None
        assert store.require_worker(worker.worker_id).status is not WorkerStatus.STOPPED
        assert store.count_active_slots() == 1
        assert service._completion_events(task.task_id) == []  # noqa: SLF001
    finally:
        service.close()
        store.close()


def test_completion_event_failure_prevents_completion_and_is_retryable(tmp_path) -> None:
    inner = FakeEvidence()
    service, store, evidence = _build(tmp_path, evidence=inner)
    flaky = _FlakyEvidence(inner, fail_append_for={"task_completed"})
    service.evidence = flaky
    try:
        task = service.create_task(title="event-fail", category="misc", conversation_id="c")
        worker = store.get_worker_for_task(task.task_id)
        with pytest.raises(StorageError):
            _complete(service, task.task_id)
        pending = store.require_task(task.task_id)
        assert pending.status is TaskStatus.COMPLETION_PENDING
        assert pending.ended_at is None
        assert store.require_worker(worker.worker_id).status is not WorkerStatus.STOPPED
        assert store.count_active_slots() == 1
        assert service._completion_events(task.task_id) == []  # noqa: SLF001
        # Retry with evidence writing restored succeeds exactly once.
        service.evidence = inner
        result = _complete(service, task.task_id)
        assert result["status"] == "completed"
        assert len(service._completion_events(task.task_id)) == 1  # noqa: SLF001
        assert store.require_task(task.task_id).status is TaskStatus.COMPLETED
        assert store.count_active_slots() == 0
    finally:
        service.close()
        store.close()


def test_evidence_head_failure_prevents_completion_and_is_retryable(tmp_path) -> None:
    service, store, _evidence = _build(tmp_path)
    try:
        task = service.create_task(title="head-fail", category="misc", conversation_id="c")
        worker = store.get_worker_for_task(task.task_id)
        original = store.update_task_fields

        def flaky_update(task_id, **fields):
            if "evidence_head" in fields and store.require_task(task_id).status is TaskStatus.COMPLETION_PENDING:
                raise OSError("synthetic evidence_head failure")
            return original(task_id, **fields)

        store.update_task_fields = flaky_update  # type: ignore[method-assign]
        with pytest.raises(StorageError):
            _complete(service, task.task_id)
        pending = store.require_task(task.task_id)
        assert pending.status is TaskStatus.COMPLETION_PENDING
        assert store.require_worker(worker.worker_id).status is not WorkerStatus.STOPPED
        assert store.count_active_slots() == 1
        assert pending.ended_at is None
        store.update_task_fields = original  # type: ignore[method-assign]
        assert _complete(service, task.task_id)["status"] == "completed"
        assert store.require_task(task.task_id).status is TaskStatus.COMPLETED
    finally:
        service.close()
        store.close()


def test_chain_status_failure_after_event_keeps_pending_and_retry_finishes(tmp_path) -> None:
    inner = FakeEvidence()
    service, store, _evidence = _build(tmp_path, evidence=inner)
    flaky = _FlakyEvidence(inner, chain_fail_at=2)
    service.evidence = flaky
    try:
        task = service.create_task(title="chain-fail", category="misc", conversation_id="c")
        worker = store.get_worker_for_task(task.task_id)
        with pytest.raises((StorageError, StateError)):
            _complete(service, task.task_id)
        pending = store.require_task(task.task_id)
        assert pending.status is TaskStatus.COMPLETION_PENDING
        assert len(service._completion_events(task.task_id)) == 1  # noqa: SLF001
        assert store.require_worker(worker.worker_id).status is not WorkerStatus.STOPPED
        assert store.count_active_slots() == 1
        service.evidence = inner
        assert _complete(service, task.task_id)["status"] == "completed"
        assert len(service._completion_events(task.task_id)) == 1  # noqa: SLF001
    finally:
        service.close()
        store.close()


def test_worker_stop_failure_prevents_completion(tmp_path) -> None:
    service, store, _evidence = _build(tmp_path)
    try:
        task = service.create_task(title="worker-fail", category="misc", conversation_id="c")
        worker = store.get_worker_for_task(task.task_id)
        original = store.set_worker_status

        def flaky_worker(worker_id, status):
            if status is WorkerStatus.STOPPED:
                raise OSError("synthetic worker stop failure")
            return original(worker_id, status)

        store.set_worker_status = flaky_worker  # type: ignore[method-assign]
        with pytest.raises(StorageError):
            _complete(service, task.task_id)
        pending = store.require_task(task.task_id)
        assert pending.status is TaskStatus.COMPLETION_PENDING
        assert store.require_worker(worker.worker_id).status is not WorkerStatus.STOPPED
        assert store.count_active_slots() == 1
        store.set_worker_status = original  # type: ignore[method-assign]
        assert _complete(service, task.task_id)["status"] == "completed"
    finally:
        service.close()
        store.close()


def test_task_status_persistence_failure_does_not_report_success(tmp_path) -> None:
    service, store, _evidence = _build(tmp_path)
    try:
        task = service.create_task(title="status-fail", category="misc", conversation_id="c")
        original = store.set_task_status

        def flaky_status(task_id, target, **kwargs):
            if target is TaskStatus.COMPLETED:
                raise OSError("synthetic completed status failure")
            return original(task_id, target, **kwargs)

        store.set_task_status = flaky_status  # type: ignore[method-assign]
        with pytest.raises(StorageError):
            _complete(service, task.task_id)
        pending = store.require_task(task.task_id)
        assert pending.status is TaskStatus.COMPLETION_PENDING
        store.set_task_status = original  # type: ignore[method-assign]
        result = _complete(service, task.task_id)
        assert result["status"] == "completed"
        assert len(service._completion_events(task.task_id)) == 1  # noqa: SLF001
    finally:
        service.close()
        store.close()


def test_fifo_pump_failure_does_not_duplicate_workers(tmp_path) -> None:
    service, store, _evidence = _build(tmp_path)
    try:
        first = service.create_task(title="fifo-1", category="misc", conversation_id="c")
        second = service.create_task(title="fifo-2", category="misc", conversation_id="c")
        third = service.create_task(title="fifo-3", category="misc", conversation_id="c")
        original_pump = service.pump

        def failing_pump():
            raise OSError("synthetic FIFO pump failure")

        service.pump = failing_pump  # type: ignore[method-assign]
        result = _complete(service, first.task_id)
        assert result["status"] == "completed"
        assert store.require_task(first.task_id).status is TaskStatus.COMPLETED
        assert store.require_task(third.task_id).status is TaskStatus.QUEUED
        # No duplicate Worker/Session for the queued Task.
        assert store.get_worker_for_task(third.task_id) is None
        service.pump = original_pump  # type: ignore[method-assign]
        service.pump()
        assert store.require_task(third.task_id).status is TaskStatus.RUNNING
        assert store.get_worker_for_task(third.task_id) is not None
        assert len([w for w in store.list_workers() if w.task_id == third.task_id]) == 1
    finally:
        service.close()
        store.close()


def test_restart_pending_without_completion_evidence_is_interrupted(tmp_path) -> None:
    acp = FakeAcp()
    service, store, evidence = _build_persistent(tmp_path, acp=acp)
    task_id = None
    try:
        task = service.create_task(title="crash-no-evidence", category="misc", conversation_id="c")
        task_id = task.task_id
        inner = evidence
        service.evidence = _FlakyEvidence(inner, fail_append_for={"task_completed"})
        with pytest.raises(StorageError):
            _complete(service, task_id)
        assert store.require_task(task_id).status is TaskStatus.COMPLETION_PENDING
    finally:
        service.close()
        store.close()

    service2, store2, evidence2 = _build_persistent(tmp_path, start=False)
    try:
        service2.start()
        recovered = store2.require_task(task_id)
        assert recovered.status is TaskStatus.INTERRUPTED
        assert recovered.result_state == "completion_interrupted"
        assert store2.count_active_slots() == 0
        assert service2._completion_events(task_id) == []  # noqa: SLF001
        assert recovered.status is not TaskStatus.COMPLETED
    finally:
        service2.close()
        store2.close()


def test_restart_pending_with_valid_completion_evidence_finalizes_completed(tmp_path) -> None:
    acp = FakeAcp()
    service, store, _evidence = _build_persistent(tmp_path, acp=acp)
    task_id = None
    first_worker = None
    try:
        task = service.create_task(title="crash-with-evidence", category="misc", conversation_id="c")
        task_id = task.task_id
        first_worker = store.get_worker_for_task(task_id)
        original = store.set_task_status

        def flaky_status(task_id, target, **kwargs):
            if target is TaskStatus.COMPLETED:
                raise OSError("synthetic crash before final status")
            return original(task_id, target, **kwargs)

        store.set_task_status = flaky_status  # type: ignore[method-assign]
        with pytest.raises(StorageError):
            _complete(service, task_id)
        assert store.require_task(task_id).status is TaskStatus.COMPLETION_PENDING
        assert len(service._completion_events(task_id)) == 1  # noqa: SLF001
        assert store.require_worker(first_worker.worker_id).status is WorkerStatus.STOPPED
    finally:
        service.close()
        store.close()

    service2, store2, _evidence2 = _build_persistent(tmp_path, start=False)
    try:
        service2.start()
        recovered = store2.require_task(task_id)
        assert recovered.status is TaskStatus.COMPLETED
        assert recovered.result_state == "solved_flag_candidate"
        assert recovered.ended_at and recovered.ended_at > 0
        assert store2.count_active_slots() == 0
        events = service2._completion_events(task_id)  # noqa: SLF001
        assert len(events) == 1
        assert events[0]["payload"]["result_state"] == recovered.result_state
        # Idempotent after recovery.
        snapshot = service2.complete_task(
            task_id,
            result_state="solved_flag_candidate",
            allow_missing_session_log=True,
        )
        assert snapshot["already_completed"] is True
    finally:
        service2.close()
        store2.close()
