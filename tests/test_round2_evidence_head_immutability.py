"""Final follow-up-2: completed Task evidence_head is an immutable snapshot.

Uses the real SQLite ManagerStore and real EvidenceStore. Ordinary query,
Writeup and evidence-ZIP operations must not overwrite the historical
``task_completed`` anchor with the advancing global chain head.
"""

from __future__ import annotations

import pytest

from ctf_solver.core.errors import StateError, StorageError
from ctf_solver.core.types import TaskStatus
from tests.test_round2_completion_faults import _build_persistent, _complete


def _append_global_probe(service, store, evidence, task_id: str) -> str:
    evidence.append_event(
        task_id=task_id,
        source="test",
        source_id=f"test:global-probe:{len(evidence.list_events(task_id=task_id))}",
        event_type="global_probe",
        payload={"probe": True},
        timestamp=store.clock.now_ms(),
    )
    return evidence.chain_head()[1]


def test_ordinary_operations_do_not_overwrite_completed_anchor(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        task_a = service.create_task(title="A", category="misc", conversation_id="c")
        _complete(service, task_a.task_id)
        anchor = store.require_task(task_a.task_id).evidence_head
        assert anchor
        task_b = service.create_task(title="B", category="misc", conversation_id="c")
        global_head_1 = _append_global_probe(service, store, evidence, task_b.task_id)
        assert global_head_1 != anchor

        # 1. ordinary status query
        service.get_task_status(task_a.task_id)
        assert store.require_task(task_a.task_id).evidence_head == anchor
        # 2. Writeup generation
        writeup = service.build_writeup(task_a.task_id)
        assert writeup.path
        assert store.require_task(task_a.task_id).evidence_head == anchor
        # 3. Evidence ZIP export
        zipped = service.export_evidence_zip(task_a.task_id)
        assert zipped.path
        assert store.require_task(task_a.task_id).evidence_head == anchor

        global_head_2 = _append_global_probe(service, store, evidence, task_b.task_id)
        assert global_head_2 not in {anchor, global_head_1}
        service.get_task_status(task_a.task_id)
        service.build_writeup(task_a.task_id)
        service.export_evidence_zip(task_a.task_id)
        completed = store.require_task(task_a.task_id)
        assert completed.status is TaskStatus.COMPLETED
        assert completed.evidence_head == anchor
        assert evidence.chain_status().ok is True
        assert len(service._completion_events(task_a.task_id)) == 1  # noqa: SLF001
        snapshot = _complete(service, task_a.task_id)
        assert snapshot["already_completed"] is True
        assert store.require_task(task_a.task_id).evidence_head == anchor
    finally:
        service.close()
        store.close()


def test_conditional_refresh_never_writes_completed_task(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        running = service.create_task(title="running", category="misc", conversation_id="c")
        assert store.update_evidence_head_if_not_completed(running.task_id, "b" * 64) is True
        assert store.require_task(running.task_id).evidence_head == "b" * 64

        completed = service.create_task(title="completed", category="misc", conversation_id="c")
        _complete(service, completed.task_id)
        anchor = store.require_task(completed.task_id).evidence_head
        assert store.update_evidence_head_if_not_completed(completed.task_id, "c" * 64) is False
        assert store.require_task(completed.task_id).evidence_head == anchor
        global_head = evidence.chain_head()[1]
        assert global_head != "c" * 64
    finally:
        service.close()
        store.close()


def test_tampered_anchor_still_fails_after_operations(tmp_path) -> None:
    service, store, evidence = _build_persistent(tmp_path)
    try:
        task = service.create_task(title="tamper", category="misc", conversation_id="c")
        _complete(service, task.task_id)
        original = store.require_task(task.task_id).evidence_head
        store.update_evidence_head_if_not_completed(task.task_id, "d" * 64)  # no-op: completed
        assert store.require_task(task.task_id).evidence_head == original
        # Direct tamper must still be detected (do not weaken verification).
        store.update_task_fields(task.task_id, evidence_head="d" * 64)
        with pytest.raises((StateError, StorageError)):
            _complete(service, task.task_id)
    finally:
        service.close()
        store.close()
