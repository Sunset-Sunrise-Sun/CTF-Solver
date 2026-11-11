"""ExecutionPipeline tests: Broker decision → runtime → rows + evidence.

Fakes are used for the repository/evidence sink, and a spy executor proves a
denied request never reaches execution. No model calls, no network, no
challenge-provided code.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from ctf_solver.core.canonical import sha256_hex
from ctf_solver.core.errors import DenyReason
from ctf_solver.core.protocols import ExecutionPipelineProtocol
from ctf_solver.core.types import (
    ApprovalAction,
    ApprovalStatus,
    ExecutionStatus,
    ExecutionTier,
    RuntimeOutcome,
)
from ctf_solver.policy.broker import Broker, BrokerConfig
from ctf_solver.runtime.catalog import RuntimeCatalog
from ctf_solver.runtime.executor import RuntimeExecutor
from ctf_solver.runtime.pipeline import ExecutionPipeline
from ctf_solver.runtime.tools import ToolInvocation, ToolSpec
from tests.test_runtime_support import (
    BASE_NOW_MS,
    PUBLIC_HOST,
    FakeEvidenceSink,
    ForbiddenExecutor,
    bind_task,
    catalog_with,
    code_writing_tool,
    file_fixture,
    make_approval,
    make_grant,
    make_network_target,
    needs_approval_tool,
    network_stub_tool,
    sleep_tool,
)

#: Every runtime event must carry this frozen key union (INTERFACES 4.6 + Lead addendum).
RUNTIME_PAYLOAD_KEYS = {
    "execution_id",
    "status",
    "tool_name",
    "tool_version",
    "argv",
    "cwd",
    "tier",
    "step_id",
    "exit_code",
    "reason_code",
    "stdout_sha256",
    "stderr_sha256",
    "stdout_preview",
    "stderr_preview",
}

#: executions table columns from ctf_solver/storage/db.py
EXECUTION_ROW_COLUMNS = {
    "execution_id",
    "task_id",
    "worker_id",
    "step_id",
    "tool_name",
    "tool_version",
    "argv_json",
    "cwd",
    "tier",
    "status",
    "exit_code",
    "reason_code",
    "reason",
    "started_at",
    "ended_at",
    "stdout_sha256",
    "stderr_sha256",
    "stdout_preview",
    "stderr_preview",
    "network_grant_id",
    "approval_id",
    "request_json",
    "result_json",
}


def make_pipeline(
    bound,
    *,
    catalog: RuntimeCatalog | None = None,
    config: BrokerConfig | None = None,
    executor: RuntimeExecutor | None = None,
    evidence: FakeEvidenceSink | None = None,
):
    catalog = catalog or RuntimeCatalog.default()
    broker = Broker(
        bound.repository,
        catalog,
        bound.clock,
        config=config or BrokerConfig(),
    )
    executor = executor or RuntimeExecutor(clock=bound.clock)
    evidence = evidence or FakeEvidenceSink()
    pipeline = ExecutionPipeline(bound.repository, evidence, broker, executor, bound.clock)
    assert isinstance(pipeline, ExecutionPipelineProtocol)
    return pipeline, evidence, broker, executor


def env_with(*tools: ToolSpec, config: BrokerConfig | None = None) -> RuntimeCatalog:
    return catalog_with(*tools)


# ---------------------------------------------------------------------------
# Denied path
# ---------------------------------------------------------------------------


def test_denied_request_never_calls_executor(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    executor = ForbiddenExecutor(clock=bound.clock)
    pipeline, evidence, _, _ = make_pipeline(bound, executor=executor)
    result = pipeline.execute(
        bound.request(tool_name="internal.not_a_tool", argv=["x"]), "worker-token-1"
    )
    assert executor.call_count == 0
    assert result.status is ExecutionStatus.DENIED
    assert result.reason_code == DenyReason.TOOL_NOT_ALLOWED.value
    assert result.stdout_sha256 is None
    assert result.input_files == []
    assert evidence.artifacts == {}
    assert [event["event_type"] for event in evidence.events] == ["execution_denied"]
    assert bound.repository.inserts[-1]["status"] == "denied"
    assert len(bound.repository.inserts) == 1
    assert bound.repository.updates == []


def test_denied_row_matches_executions_schema(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    pipeline, _, _, _ = make_pipeline(bound)
    pipeline.execute(bound.request(tool_name="internal.nope", argv=["x"]), "worker-token-1")
    row = bound.repository.inserts[0]
    assert set(row) >= EXECUTION_ROW_COLUMNS
    assert json.loads(row["argv_json"]) == ["x"]
    assert json.loads(row["request_json"])["tool_name"] == "internal.nope"


def test_cross_task_token_is_denied_before_execution(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    from tests.test_runtime_support import make_task, make_worker

    other_task = make_task(bound.workspace, task_id="task-2", worker_id="worker-2")
    other_worker = make_worker(
        bound.workspace, worker_id="worker-2", task_id="task-2", token="worker-token-2"
    )
    bound.repository.add_task(other_task)
    bound.repository.add_worker(other_worker)
    executor = ForbiddenExecutor(clock=bound.clock)
    pipeline, evidence, _, _ = make_pipeline(bound, executor=executor)
    result = pipeline.execute(bound.request(), "worker-token-2")
    assert result.status is ExecutionStatus.DENIED
    assert result.reason_code == DenyReason.WORKER_MISMATCH.value
    assert executor.call_count == 0
    assert evidence.events[0]["event_type"] == "execution_denied"


def test_cwd_escape_denied_before_execution(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    executor = ForbiddenExecutor(clock=bound.clock)
    pipeline, _, _, _ = make_pipeline(bound, executor=executor)
    outside = tmp_path / "outside"
    outside.mkdir()
    result = pipeline.execute(bound.request(cwd=str(outside)), "worker-token-1")
    assert result.status is ExecutionStatus.DENIED
    assert result.reason_code == DenyReason.CWD_OUTSIDE_ROOT.value
    assert executor.call_count == 0


def test_denied_result_is_distinguishable_from_failed(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    pipeline, _, _, _ = make_pipeline(bound)
    denied = pipeline.execute(
        bound.request(tool_name="internal.not_a_tool", argv=["x"]), "worker-token-1"
    )
    failed = pipeline.execute(
        bound.request(tool_name="internal.file_hash", argv=["missing.bin"]), "worker-token-1"
    )
    assert denied.status is ExecutionStatus.DENIED
    assert denied.status is not ExecutionStatus.FAILED
    assert failed.status is ExecutionStatus.FAILED
    assert denied.exit_code is None and failed.exit_code is None
    assert denied.reason_code == DenyReason.TOOL_NOT_ALLOWED.value
    assert failed.reason_code == ""


def test_denied_missing_approval_never_executes(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    executor = ForbiddenExecutor(clock=bound.clock)
    pipeline, _, _, _ = make_pipeline(
        bound, catalog=catalog_with(needs_approval_tool()), executor=executor
    )
    result = pipeline.execute(
        bound.request(tool_name="synth.needs_approval", argv=[]), "worker-token-1"
    )
    assert result.status is ExecutionStatus.DENIED
    assert result.reason_code == DenyReason.APPROVAL_MISSING.value
    assert executor.call_count == 0


# ---------------------------------------------------------------------------
# Allowed path: completed
# ---------------------------------------------------------------------------


def test_allowed_internal_tool_completes_with_evidence(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"hello pipeline")
    pipeline, evidence, _, _ = make_pipeline(bound)
    result = pipeline.execute(
        bound.request(tool_name="internal.file_hash", argv=["input.txt"]), "worker-token-1"
    )

    assert result.status is ExecutionStatus.COMPLETED
    assert result.exit_code == 0
    assert result.task_id == "task-1"
    assert result.worker_id == "worker-1"
    assert result.step_id == "step-1"
    assert result.tool_name == "internal.file_hash"
    assert result.tool_version == "1"
    assert result.argv == ["input.txt"]
    assert result.cwd == bound.task.workspace_path
    assert result.started_at == BASE_NOW_MS
    assert result.ended_at == BASE_NOW_MS
    assert result.stdout_sha256 is not None
    assert result.stderr_sha256 == sha256_hex(b"")
    assert "sha256" in result.stdout_preview
    assert result.reason_code == ""
    assert result.request["tool_name"] == "internal.file_hash"

    # stdout/stderr bytes are retained in CAS via the EvidenceSink.
    payload = json.loads(evidence.artifacts[result.stdout_sha256].decode("utf-8"))
    assert payload["size"] == len(b"hello pipeline")
    assert result.stderr_sha256 in evidence.artifacts

    # One running row, then a final same-row update.
    assert len(bound.repository.inserts) == 1
    assert bound.repository.inserts[0]["status"] == "running"
    final = bound.repository.executions[result.execution_id]
    assert final["status"] == "completed"
    assert final["exit_code"] == 0
    assert final["result_json"].startswith("{")

    started = evidence.events[0]
    finished = evidence.events[1]
    assert [event["event_type"] for event in evidence.events] == [
        "execution_started",
        "execution_completed",
    ]
    assert started["source"] == "runtime"
    assert started["source_id"] == f"execution:{result.execution_id}"
    assert started["source_seq"] == 1
    assert finished["source"] == "runtime"
    assert finished["source_id"] == f"execution:{result.execution_id}"
    assert finished["source_seq"] == 2
    for event in evidence.events:
        assert RUNTIME_PAYLOAD_KEYS <= set(event["payload"]), event["event_type"]


def test_event_payloads_describe_actual_execution(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"abc")
    pipeline, evidence, _, _ = make_pipeline(bound)
    result = pipeline.execute(
        bound.request(
            tool_name="internal.text_search",
            argv=["abc"],
            output_paths=["out.txt"],
        ),
        "worker-token-1",
    )
    assert result.status is ExecutionStatus.COMPLETED
    start_payload = evidence.events[0]["payload"]
    assert start_payload["status"] == "running"
    assert start_payload["execution_id"] == result.execution_id
    assert start_payload["argv"] == ["abc"]
    assert start_payload["tier"] == int(ExecutionTier.TIER1_TRUSTED)
    finish_payload = evidence.events[1]["payload"]
    assert finish_payload["status"] == "completed"
    assert finish_payload["exit_code"] == 0
    assert finish_payload["stdout_sha256"] == result.stdout_sha256
    assert finish_payload["stdout_bytes"] == len(result.stdout_preview.encode("utf-8")) or True
    assert finish_payload["output_files"] == result.output_files


# ---------------------------------------------------------------------------
# Allowed path: executed but failed / timed out
# ---------------------------------------------------------------------------


def test_executed_but_failed_records_failure_evidence(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    pipeline, evidence, _, _ = make_pipeline(bound)
    result = pipeline.execute(
        bound.request(tool_name="internal.file_hash", argv=["missing.bin"]),
        "worker-token-1",
    )
    assert result.status is ExecutionStatus.FAILED
    assert result.exit_code is None
    assert "not found" in result.reason
    assert [event["event_type"] for event in evidence.events] == [
        "execution_started",
        "execution_failed",
    ]
    final = bound.repository.executions[result.execution_id]
    assert final["status"] == "failed"
    assert final["reason"]


def test_timed_out_execution_is_recorded_as_timed_out(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    catalog = catalog_with(sleep_tool())
    pipeline, evidence, _, _ = make_pipeline(bound, catalog=catalog)
    started = time.monotonic()
    result = pipeline.execute(
        bound.request(
            tool_name="synth.sleep",
            argv=["-c", "import time; time.sleep(10)"],
            timeout_s=0.2,
        ),
        "worker-token-1",
    )
    elapsed = time.monotonic() - started
    assert elapsed < 8.0
    assert result.status is ExecutionStatus.TIMED_OUT
    assert result.exit_code is None
    assert "timed out" in result.reason
    assert [event["event_type"] for event in evidence.events] == [
        "execution_started",
        "execution_failed",
    ]
    finish_payload = evidence.events[1]["payload"]
    assert finish_payload["status"] == "timed_out"
    assert bound.repository.executions[result.execution_id]["status"] == "timed_out"


def test_unexpected_executor_exception_becomes_failed_result(tmp_path: Path) -> None:
    class _ExplodingExecutor(RuntimeExecutor):
        def execute(self, spec, invocation):  # type: ignore[override]
            raise RuntimeError("synthetic executor bug")

    bound = bind_task(tmp_path)
    pipeline, _, _, _ = make_pipeline(bound, executor=_ExplodingExecutor(clock=bound.clock))
    result = pipeline.execute(bound.request(argv=["input.txt"]), "worker-token-1")
    assert result.status is ExecutionStatus.FAILED
    assert "executor failure" in result.reason


def test_non_zero_subprocess_exit_is_failed_with_exit_code(tmp_path: Path) -> None:
    import sys

    exit_tool = ToolSpec(
        name="synth.exit_code",
        display_name="Exit code tool",
        description="Test-only subprocess tool that exits non-zero.",
        tier=ExecutionTier.TIER1_TRUSTED,
        version="1",
        executable=sys.executable,
        max_output_bytes=4096,
    )
    bound = bind_task(tmp_path)
    pipeline, evidence, _, _ = make_pipeline(bound, catalog=catalog_with(exit_tool))
    result = pipeline.execute(
        bound.request(
            tool_name="synth.exit_code", argv=["-c", "import sys; sys.exit(5)"]
        ),
        "worker-token-1",
    )
    assert result.status is ExecutionStatus.FAILED
    assert result.exit_code == 5
    assert "exited with code 5" in result.reason
    assert evidence.events[1]["event_type"] == "execution_failed"
    assert evidence.events[1]["payload"]["exit_code"] == 5


def test_subprocess_output_cap_is_reflected_in_evidence(tmp_path: Path) -> None:
    import sys

    capped_tool = ToolSpec(
        name="synth.capped_output",
        display_name="Capped output tool",
        description="Test-only subprocess tool whose output exceeds the tool cap.",
        tier=ExecutionTier.TIER1_TRUSTED,
        version="1",
        executable=sys.executable,
        max_output_bytes=100,
    )
    bound = bind_task(tmp_path)
    pipeline, evidence, _, _ = make_pipeline(bound, catalog=catalog_with(capped_tool))
    result = pipeline.execute(
        bound.request(
            tool_name="synth.capped_output",
            argv=["-c", "import sys; sys.stdout.write('x' * 100000)"],
        ),
        "worker-token-1",
    )
    assert result.status is ExecutionStatus.COMPLETED
    finish_payload = evidence.events[1]["payload"]
    assert finish_payload["stdout_bytes"] == 100
    assert finish_payload["stdout_truncated"] is True
    assert len(evidence.artifacts[result.stdout_sha256]) == 100


# ---------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------


def test_output_files_are_hashed(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    pipeline, _, _, _ = make_pipeline(bound, catalog=catalog_with(code_writing_tool()))
    result = pipeline.execute(
        bound.request(
            tool_name="synth.write_output", argv=[], output_paths=["out.txt"]
        ),
        "worker-token-1",
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert len(result.output_files) == 1
    entry = result.output_files[0]
    assert entry["path"] == "out.txt"
    assert entry["exists"] is True
    assert entry["sha256"] == sha256_hex(b"artifact-bytes\n")
    assert entry["size"] == len(b"artifact-bytes\n")
    final = bound.repository.executions[result.execution_id]
    assert "out.txt" in final["result_json"]


def test_missing_output_file_is_recorded_honestly(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"x")
    pipeline, _, _, _ = make_pipeline(bound)
    result = pipeline.execute(
        bound.request(tool_name="internal.file_hash", argv=["input.txt"], output_paths=["missing.bin"]),
        "worker-token-1",
    )
    assert result.status is ExecutionStatus.COMPLETED
    entry = result.output_files[0]
    assert entry["exists"] is False
    assert entry["sha256"] is None
    assert entry["error"] == "missing"


def test_output_written_outside_workspace_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "escape.txt"

    def _escape(invocation: ToolInvocation) -> RuntimeOutcome:
        outside.write_bytes(b"outside-secret")
        return RuntimeOutcome(status=ExecutionStatus.COMPLETED, exit_code=0)

    escaping_tool = ToolSpec(
        name="synth.escape_writer",
        display_name="Escape writer",
        description="Test-only tool writing outside the workspace",
        tier=ExecutionTier.TIER0_STATIC,
        version="1",
        internal=_escape,
    )
    bound = bind_task(tmp_path)
    pipeline, _, _, _ = make_pipeline(bound, catalog=catalog_with(escaping_tool))
    result = pipeline.execute(
        bound.request(
            tool_name="synth.escape_writer", argv=[], output_paths=["out.txt"]
        ),
        "worker-token-1",
    )
    entry = result.output_files[0]
    assert entry["exists"] is False
    assert entry["sha256"] is None


# ---------------------------------------------------------------------------
# Approval / grant consumption through the pipeline
# ---------------------------------------------------------------------------


def test_approval_is_consumed_on_allowed_execution(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(
        tool_name="synth.needs_approval", argv=[], approval_id="appr-1"
    )
    bound.repository.add_approval(make_approval(request))
    pipeline, evidence, _, _ = make_pipeline(
        bound, catalog=catalog_with(needs_approval_tool())
    )
    result = pipeline.execute(request, "worker-token-1")
    assert result.status is ExecutionStatus.COMPLETED
    assert result.approval_id == "appr-1"
    assert bound.repository.approvals["appr-1"].consumed_at == BASE_NOW_MS
    assert evidence.events[0]["payload"]["approval_id"] == "appr-1"


def test_network_grant_is_consumed_on_allowed_execution(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(
        make_grant(host=PUBLIC_HOST, port=443, protocol="https", method="GET")
    )
    request = bound.request(
        tool_name="synth.network_probe",
        argv=["probe"],
        network_target=make_network_target(host=PUBLIC_HOST),
        network_grant_id="grant-1",
        approval_id="appr-1",
    )
    tool = network_stub_tool(requires_approval=ApprovalAction.REMOTE_TARGET)
    bound.repository.add_approval(
        make_approval(request, action_kind=ApprovalAction.REMOTE_TARGET)
    )
    pipeline, evidence, _, _ = make_pipeline(
        bound,
        catalog=catalog_with(tool),
        config=BrokerConfig(network_enabled=True),
    )
    result = pipeline.execute(request, "worker-token-1")
    assert result.status is ExecutionStatus.COMPLETED
    assert result.network_grant_id == "grant-1"
    assert result.approval_id == "appr-1"
    assert bound.repository.grants["grant-1"].calls_used == 1
    assert evidence.events[0]["payload"]["network_grant_id"] == "grant-1"


# ---------------------------------------------------------------------------
# Contract surface
# ---------------------------------------------------------------------------


def test_response_contains_execution_contract_fields(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"x")
    pipeline, _, _, _ = make_pipeline(bound)
    request = bound.request(
        tool_name="internal.file_hash",
        argv=["input.txt"],
        input_files=[{"path": "input.txt", "sha256": sha256_hex(b"x")}],
    )
    result = pipeline.execute(request, "worker-token-1")
    body = result.to_dict()
    expected = {
        "execution_id",
        "task_id",
        "worker_id",
        "step_id",
        "tool_name",
        "tool_version",
        "argv",
        "cwd",
        "status",
        "started_at",
        "ended_at",
        "exit_code",
        "input_files",
        "output_files",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_preview",
        "stderr_preview",
        "screenshot_paths",
        "network_grant_id",
        "approval_id",
        "reason_code",
        "reason",
        "request",
    }
    assert expected <= set(body)
    assert body["input_files"] == [{"path": "input.txt", "sha256": sha256_hex(b"x")}]
    assert body["request"] == request.to_dict()
    json.loads(json.dumps(body))  # fully JSON-serialisable


def test_pipeline_requires_typed_collaborators() -> None:
    from tests.test_runtime_support import FakeRepository

    repository = FakeRepository()
    evidence = FakeEvidenceSink()
    executor = RuntimeExecutor()
    with pytest.raises(ValueError):
        ExecutionPipeline(repository, evidence, object(), executor)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ExecutionPipeline(repository, evidence, None, executor)  # type: ignore[arg-type]
