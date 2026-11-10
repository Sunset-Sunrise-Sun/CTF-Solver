"""Round 2 P0-4: normal Task completion lifecycle tests."""

from __future__ import annotations

import json

import pytest

from ctf_solver.core.errors import AcpError, StateError
from ctf_solver.core.types import TaskStatus, WorkerStatus
from ctf_solver.mcp.manager_server import build_manager_tools
from tests.support.manager_stub import StubManager
from tests.test_manager_service import build_service


def _scripted_completion_service(tmp_path, **kwargs):
    service, acp, evidence, pipeline, deliverables, store = build_service(tmp_path, **kwargs)
    service.start()
    return service, acp, evidence, pipeline, deliverables, store


def _complete(service, task_id: str, *, result_state: str = "solved_flag_candidate"):
    return service.complete_task(
        task_id, result_state=result_state, note="synthetic completion", allow_missing_session_log=True
    )


def test_complete_task_releases_slot_and_records_terminal_state(tmp_path) -> None:
    service, acp, evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="complete me", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        assert worker is not None
        result = _complete(service, task.task_id)
        assert result["status"] == "completed"
        assert result["result_state"] == "solved_flag_candidate"
        assert result["session_closed"] is True
        assert result["slot_released"] is True
        stored = store.require_task(task.task_id)
        assert stored.status is TaskStatus.COMPLETED
        assert stored.ended_at and stored.ended_at >= stored.started_at
        assert stored.result_state == "solved_flag_candidate"
        reloaded_worker = store.require_worker(worker.worker_id)
        assert reloaded_worker.status is WorkerStatus.STOPPED
        assert store.count_active_slots() == 0
        assert acp.close_calls == [worker.acp_session_id]
        events = evidence.list_events(task_id=task.task_id, event_type="task_completed")
        assert len(events) == 1
        payload = events[0]["payload"]
        assert payload["session_closed"] is True
        assert payload["worker_stopped"] is True
        assert payload["result_state"] == "solved_flag_candidate"
        assert payload["ended_at"] == stored.ended_at
        assert stored.evidence_head
        assert service.get_task_status(task.task_id)["task"]["status"] == "completed"
    finally:
        service.shutdown()
        store.close()


def test_completion_promotes_next_fifo_task(tmp_path) -> None:
    service, acp, _evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        first = service.create_task(title="first", category="misc", conversation_id="conv")
        second = service.create_task(title="second", category="misc", conversation_id="conv")
        third = service.create_task(title="third", category="misc", conversation_id="conv")
        assert [first.status, second.status, third.status] == [
            TaskStatus.RUNNING,
            TaskStatus.RUNNING,
            TaskStatus.QUEUED,
        ]
        _complete(service, first.task_id)
        promoted = store.require_task(third.task_id)
        assert promoted.status is TaskStatus.RUNNING
        assert promoted.acp_session_id
        assert store.count_active_slots() == 2
        assert len(acp.new_session_calls) == 3
    finally:
        service.shutdown()
        store.close()


def test_completion_rejects_unfinished_execution(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="busy", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        store.record_execution(
            {
                "execution_id": "exec-unfinished-1",
                "task_id": task.task_id,
                "worker_id": worker.worker_id,
                "step_id": "step-1",
                "tool_name": "internal.file_hash",
                "argv": ["x"],
                "cwd": task.workspace_path,
                "tier": 0,
                "status": "running",
                "started_at": 1,
            }
        )
        with pytest.raises(StateError):
            _complete(service, task.task_id)
        assert store.require_task(task.task_id).status is TaskStatus.RUNNING
        assert store.count_active_slots() == 1
        store.update_execution(
            "exec-unfinished-1", {"status": "completed", "ended_at": 2}
        )
        result = _complete(service, task.task_id)
        assert result["status"] == "completed"
    finally:
        service.shutdown()
        store.close()


def test_completion_rejects_pending_approval(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="approval", category="misc", conversation_id="conv")
        approval = service.request_approval(
            task.task_id,
            action_kind="tool_action",
            details={"tool": "internal.file_hash"},
        )
        with pytest.raises(StateError):
            _complete(service, task.task_id)
        assert store.require_task(task.task_id).status is TaskStatus.RUNNING
        assert store.count_pending_approvals(task.task_id) == 1
        assert service.list_approvals(task_id=task.task_id)[0].approval_id == approval.approval_id
    finally:
        service.shutdown()
        store.close()


def test_completion_requires_session_log_ingestion_without_override(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="log", category="misc", conversation_id="conv")
        with pytest.raises(StateError):
            service.complete_task(task.task_id, result_state="solved")
        assert store.require_task(task.task_id).status is TaskStatus.RUNNING
        # The explicit test-only override permits fake-ACP fixtures without logs;
        # the MCP tool never exposes this override.
        assert _complete(service, task.task_id)["status"] == "completed"
    finally:
        service.shutdown()
        store.close()


def test_session_close_failure_keeps_task_and_slot(tmp_path) -> None:
    service, acp, evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="close fails", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        acp.close_should_fail = True
        with pytest.raises(AcpError) as info:
            _complete(service, task.task_id)
        assert info.value.details.get("reason_code") == "session_close_failed"
        assert info.value.details.get("slot_released") is False
        stored = store.require_task(task.task_id)
        assert stored.status is TaskStatus.RUNNING
        assert stored.ended_at is None
        assert store.require_worker(worker.worker_id).status is not WorkerStatus.STOPPED
        assert store.count_active_slots() == 1
        assert evidence.list_events(task_id=task.task_id, event_type="task_completed") == []
        assert service.runtime_status()["diagnostics"][-1]["code"] == "task_completion_session_close_failed"
        # After the transient failure clears, completion succeeds exactly once.
        acp.close_should_fail = False
        result = _complete(service, task.task_id)
        assert result["status"] == "completed"
        assert len(evidence.list_events(task_id=task.task_id, event_type="task_completed")) == 1
    finally:
        service.shutdown()
        store.close()


def test_repeat_completion_is_idempotent_and_execution_is_refused(tmp_path) -> None:
    service, _acp, evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="idempotent", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        first = _complete(service, task.task_id)
        assert first["already_completed"] is False
        second = service.complete_task(
            task.task_id, result_state="solved", allow_missing_session_log=True
        )
        assert second["already_completed"] is True
        assert second["result_state"] == "solved_flag_candidate"
        assert len(evidence.list_events(task_id=task.task_id, event_type="task_completed")) == 1
        with pytest.raises(StateError):
            service.record_candidate_flag(task.task_id, flag="flag{x}", source="late")
        # A Worker token cannot execute after completion.
        params = {
            "task_id": task.task_id,
            "worker_id": worker.worker_id,
            "step_id": "step-late",
            "tool_name": "internal.file_hash",
            "argv": ["x"],
            "cwd": task.workspace_path,
        }
        from ctf_solver.core.errors import IpcError

        with pytest.raises(IpcError) as info:
            service.ipc_exec(worker.worker_token, params)
        assert info.value.reason_code == "task_terminal"
    finally:
        service.shutdown()
        store.close()


def test_completed_task_survives_restart_as_completed(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = _scripted_completion_service(tmp_path)
    try:
        task = service.create_task(title="restart", category="misc", conversation_id="conv")
        _complete(service, task.task_id)
        task_id = task.task_id
    finally:
        service.shutdown()
        store.close()
    service2, _acp2, _evidence2, _pipeline2, _deliverables2, store2 = build_service(tmp_path)
    try:
        service2.start()
        reloaded = store2.require_task(task_id)
        assert reloaded.status is TaskStatus.COMPLETED
        assert reloaded.result_state == "solved_flag_candidate"
        assert store2.count_active_slots() == 0
        assert service2.get_task_status(task_id)["task"]["status"] == "completed"
    finally:
        service2.shutdown()
        store2.close()


def test_manager_mcp_complete_tool_contract() -> None:
    tools = {tool.name: tool for tool in build_manager_tools(StubManager())}
    assert "ctf_task_complete" in tools
    tool = tools["ctf_task_complete"]
    assert set(tool.input_schema["required"]) == {"task_id", "result_state"}
    assert tool.input_schema["properties"]["result_state"]["type"] == "string"
    result = tool.handler({"task_id": "t-stub0001", "result_state": "solved"})
    assert result["status"] == "completed"
    assert result["result_state"] == "solved"
    # Missing result_state is rejected by schema validation at the MCP layer.
    from ctf_solver.mcp.protocol import McpServer
    from ctf_solver.mcp.schema import validate_schema
    from tests.test_mcp_manager_server import EXPECTED_TOOLS

    assert "ctf_task_complete" in EXPECTED_TOOLS
    assert validate_schema(tool.input_schema, {"task_id": "t-stub0001"})
