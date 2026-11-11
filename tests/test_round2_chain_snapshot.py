"""Final acceptance follow-up: historical evidence-head snapshots.

The global evidence chain is append-only and advances when other Tasks write
evidence. A completed Task must remain verifiable via its own historical
completion-event anchor, not via the current global head. All tests use the real
SQLite ManagerStore and real EvidenceStore.
"""

from __future__ import annotations

import pytest

from ctf_solver.core.errors import StateError, StorageError
from ctf_solver.core.types import TaskStatus
from tests.test_round2_completion_faults import _build_persistent


def _complete(service, task_id: str):
    return service.complete_task(
        task_id,
        result_state="solved_flag_candidate",
        note="historical snapshot test",
        allow_missing_session_log=True,
    )


def _drop_append_only_triggers(evidence) -> None:
    evidence.connection.execute("DROP TRIGGER IF EXISTS events_no_update")
    evidence.connection.execute("DROP TRIGGER IF EXISTS events_no_delete")
    evidence.connection.commit()


def test_cross_task_appends_do_not_break_completed_task_idempotence(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        task_a = service.create_task(title="A", category="misc", conversation_id="c")
        _complete(service, task_a.task_id)
        completed_a = store.require_task(task_a.task_id)
        head_a = completed_a.evidence_head
        global_head_a = evidence.chain_head()[1]
        assert head_a == global_head_a
        events_a = service._completion_events(task_a.task_id)  # noqa: SLF001
        assert len(events_a) == 1

        # Task B starts, adding its own events and advancing the global head.
        task_b = service.create_task(title="B", category="misc", conversation_id="c")
        evidence.append_event(
            task_id=task_b.task_id,
            source="test",
            source_id="test:cross-task-append",
            event_type="cross_task_probe",
            payload={"probe": True},
            timestamp=store.clock.now_ms(),
        )
        global_head_later = evidence.chain_head()[1]
        assert global_head_later != head_a

        snapshot = _complete(service, task_a.task_id)
        assert snapshot["already_completed"] is True
        reloaded = store.require_task(task_a.task_id)
        assert reloaded.status is TaskStatus.COMPLETED
        assert reloaded.evidence_head == head_a  # snapshot unchanged
        assert evidence.chain_head()[1] == global_head_later
        assert len(service._completion_events(task_a.task_id)) == 1  # noqa: SLF001
        # Task B unaffected.
        assert store.require_task(task_b.task_id).status is TaskStatus.RUNNING
    finally:
        service.close()
        store.close()


def test_tampered_historical_anchor_fails_closed(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        task = service.create_task(title="tamper-anchor", category="misc", conversation_id="c")
        _complete(service, task.task_id)
        store.update_task_fields(task.task_id, evidence_head="a" * 64)
        with pytest.raises((StateError, StorageError)):
            _complete(service, task.task_id)
        # No second completion event was written.
        assert len(service._completion_events(task.task_id)) == 1  # noqa: SLF001
    finally:
        service.close()
        store.close()


def test_global_chain_damage_rejects_historical_snapshot(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        task_a = service.create_task(title="A", category="misc", conversation_id="c")
        _complete(service, task_a.task_id)
        task_b = service.create_task(title="B", category="misc", conversation_id="c")
        evidence.append_event(
            task_id=task_b.task_id,
            source="test",
            source_id="test:damage",
            event_type="cross_task_probe",
            payload={"probe": True},
            timestamp=store.clock.now_ms(),
        )
        _drop_append_only_triggers(evidence)
        row = evidence.connection.execute(
            "SELECT record_id, payload_json FROM events WHERE event_type = 'cross_task_probe'"
        ).fetchone()
        assert row is not None
        evidence.connection.execute(
            "UPDATE events SET payload_json = ? WHERE record_id = ?",
            ('{"probe": false}', row["record_id"]),
        )
        evidence.connection.commit()
        assert evidence.chain_status().ok is False
        with pytest.raises((StateError, StorageError)):
            _complete(service, task_a.task_id)
        assert store.require_task(task_a.task_id).status is TaskStatus.COMPLETED
        assert len(service._completion_events(task_a.task_id)) == 1  # noqa: SLF001
    finally:
        service.close()
        store.close()


def test_three_completed_tasks_remain_independently_idempotent(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        tasks = [
            service.create_task(title=f"task-{index}", category="misc", conversation_id="c")
            for index in range(3)
        ]
        heads: dict[str, str] = {}
        for index, task in enumerate(tasks):
            _complete(service, task.task_id)
            heads[task.task_id] = store.require_task(task.task_id).evidence_head
            if index == 0:
                evidence.append_event(
                    task_id=tasks[1].task_id,
                    source="test",
                    source_id=f"test:interleave-{index}",
                    event_type="interleaved_probe",
                    payload={"index": index},
                    timestamp=store.clock.now_ms(),
                )
        assert len(set(heads.values())) == 3
        for task in tasks:
            snapshot = _complete(service, task.task_id)
            assert snapshot["already_completed"] is True
            assert store.require_task(task.task_id).evidence_head == heads[task.task_id]
            assert len(service._completion_events(task.task_id)) == 1  # noqa: SLF001
        assert evidence.chain_status().ok is True
    finally:
        service.close()
        store.close()
