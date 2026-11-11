"""Broker structural, identity, tool, tier, path and approval policy tests.

The Broker is the trusted policy enforcement point: every expected failure must
produce a stable ``DenyReason`` and nothing may execute or be consumed when a
check fails.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_solver.core.errors import DenyReason, StorageError
from ctf_solver.core.paths import resolve_path
from ctf_solver.core.protocols import EvidenceSink, PolicyRepository
from ctf_solver.core.types import (
    ApprovalAction,
    ApprovalStatus,
    BrokerDecision,
    ExecutionTier,
    TaskStatus,
    WorkerStatus,
)
from ctf_solver.policy.broker import Broker, BrokerConfig
from ctf_solver.policy.models import (
    action_digest,
    approval_action_digest,
    approval_details,
    target_digest,
)
from ctf_solver.runtime.catalog import RuntimeCatalog
from tests.test_runtime_support import (
    BASE_NOW_MS,
    SESSION_ID,
    TASK_ID,
    WORKER_ID,
    WORKER_TOKEN,
    BoundTask,
    FakeEvidenceSink,
    FakeRepository,
    bind_task,
    catalog_with,
    custom_catalog,
    file_fixture,
    file_input,
    make_approval,
    make_network_target,
    make_request,
    make_task,
    make_worker,
    make_workspace,
    needs_approval_tool,
    untrusted_code_tool,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def broker_for(
    bound: BoundTask,
    *,
    catalog: RuntimeCatalog | None = None,
    config: BrokerConfig | None = None,
) -> Broker:
    return Broker(
        bound.repository,
        catalog or RuntimeCatalog.default(),
        bound.clock,
        config=config or BrokerConfig(),
    )


def assert_denied(decision: BrokerDecision, reason: DenyReason) -> None:
    assert decision.allowed is False
    assert decision.reason_code == reason.value, (
        f"expected {reason.value!r}, got {decision.reason_code!r}: {decision.reason}"
    )
    assert decision.reason, "denials must carry a human-readable reason"


def network_config(**overrides: object) -> BrokerConfig:
    values = {"network_enabled": True}
    values.update(overrides)
    return BrokerConfig(**values)


# ---------------------------------------------------------------------------
# Fakes satisfy the frozen protocols
# ---------------------------------------------------------------------------


def test_fakes_satisfy_frozen_protocols() -> None:
    repository = FakeRepository()
    evidence = FakeEvidenceSink()
    assert isinstance(repository, PolicyRepository)
    assert isinstance(evidence, EvidenceSink)


def test_broker_rejects_non_catalog(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    with pytest.raises(ValueError):
        Broker(bound.repository, object(), bound.clock)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Allow path
# ---------------------------------------------------------------------------


def test_allow_internal_tool_happy_path(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"hello")
    broker = broker_for(bound)
    decision = broker.authorize(
        bound.request(tool_name="internal.file_hash", argv=["input.txt"]), WORKER_TOKEN
    )
    assert decision.allowed is True
    assert decision.reason_code == "allowed"
    assert decision.tool is not None
    assert decision.tool["name"] == "internal.file_hash"
    assert decision.tool["version"] == "1"
    assert decision.effective_tier == ExecutionTier.TIER1_TRUSTED
    assert decision.approval_id is None
    assert decision.network_grant_id is None
    assert decision.grant_call_consumed is False


@pytest.mark.parametrize(
    "status", [TaskStatus.RUNNING, TaskStatus.PAUSED, TaskStatus.AWAITING_APPROVAL]
)
def test_allow_runnable_task_statuses(tmp_path: Path, status: TaskStatus) -> None:
    bound = bind_task(tmp_path, task_status=status)
    broker = broker_for(bound)
    decision = broker.authorize(bound.request(), WORKER_TOKEN)
    assert decision.allowed is True


@pytest.mark.parametrize(
    "status",
    [
        TaskStatus.CREATED,
        TaskStatus.QUEUED,
        TaskStatus.STARTING,
        TaskStatus.BLOCKED,
        TaskStatus.CANCEL_REQUESTED,
        TaskStatus.CANCELLED,
        TaskStatus.COMPLETED,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.INTERRUPTED,
    ],
)
def test_deny_non_runnable_task_statuses(tmp_path: Path, status: TaskStatus) -> None:
    bound = bind_task(tmp_path, task_status=status)
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.TASK_NOT_RUNNABLE)


# ---------------------------------------------------------------------------
# Step 1: structural sanity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "bad id!"),
        ("worker_id", "bad id!"),
        ("step_id", "step/1"),
        ("step_id", "x" * 65),
        ("tool_name", "Bad Tool"),
        ("tool_name", "x" * 200),
    ],
)
def test_deny_invalid_identifiers(tmp_path: Path, field: str, value: str) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request()
    setattr(request, field, value)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


def test_deny_argv_not_a_list(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request()
    request.argv = ("input.txt",)  # type: ignore[assignment]
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


def test_deny_argv_too_many_arguments(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(argv=["a"] * 65), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


def test_deny_argv_argument_too_long(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(argv=["a" * 8193]), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


def test_deny_argv_control_character(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(argv=["bad\x00arg"]), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


@pytest.mark.parametrize("payload", ["a;b", "a|b", "a&b", "$(id)", "`id`", "x>y", "x<y"])
def test_deny_shell_metacharacters_in_argv0(tmp_path: Path, payload: str) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(argv=[payload]), WORKER_TOKEN),
        DenyReason.SHELL_EXPANSION_REJECTED,
    )


def test_deny_relative_cwd(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request()
    request.cwd = "relative/work"
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


@pytest.mark.parametrize("timeout_s", [0.0, 0.01, 601.0, 10000.0])
def test_deny_timeout_outside_policy(tmp_path: Path, timeout_s: float) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(timeout_s=timeout_s), WORKER_TOKEN),
        DenyReason.RESOURCE_LIMIT,
    )


@pytest.mark.parametrize("max_output", [0, -1, 64 * 1024 * 1024 + 1])
def test_deny_invalid_max_output_bytes(tmp_path: Path, max_output: int) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(max_output_bytes=max_output), WORKER_TOKEN),
        DenyReason.RESOURCE_LIMIT,
    )


def test_deny_invalid_tier_value(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request()
    request.tier = 7  # type: ignore[assignment]
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


def test_deny_invalid_input_digest_shape(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "a.txt", b"a")
    broker = broker_for(bound)
    request = bound.request(input_files=[{"path": "a.txt", "sha256": "not-a-digest"}])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


def test_deny_control_character_in_output_path(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(output_paths=["bad\nout"]), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


def test_deny_control_character_in_approval_id(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(approval_id="bad\tid"), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


def test_deny_invalid_network_target_port(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(network_target=make_network_target(port=0))
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


@pytest.mark.parametrize("protocol", ["gopher", "ftp", "", "TCP!"])
def test_deny_invalid_network_target_protocol(tmp_path: Path, protocol: str) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(
        network_target=make_network_target(protocol=protocol),
        network_grant_id="grant-1",
    )
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


def test_deny_http_target_without_method(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(
        network_target=make_network_target(protocol="https", method=""),
        network_grant_id="grant-1",
    )
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


# ---------------------------------------------------------------------------
# Step 2: worker identity
# ---------------------------------------------------------------------------


def test_deny_unknown_worker_token(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), "not-a-real-token"), DenyReason.UNKNOWN_WORKER)


@pytest.mark.parametrize("token", ["", "   "])
def test_deny_empty_worker_token(tmp_path: Path, token: str) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), token), DenyReason.UNKNOWN_WORKER)


def test_deny_worker_id_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request()
    request.worker_id = "worker-2"
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.WORKER_MISMATCH)


def test_deny_cross_task_token_denial(tmp_path: Path) -> None:
    """A token issued for Task A must never authorize Task B."""

    bound = bind_task(tmp_path)
    other_task = make_task(bound.workspace, task_id="task-2", worker_id="worker-2")
    other_worker = make_worker(
        bound.workspace, worker_id="worker-2", task_id="task-2", token="worker-token-2"
    )
    bound.repository.add_task(other_task)
    bound.repository.add_worker(other_worker)
    broker = broker_for(bound)
    forged = make_request(other_task, other_worker)
    assert_denied(broker.authorize(forged, WORKER_TOKEN), DenyReason.WORKER_MISMATCH)


def test_deny_cross_task_token_with_matching_worker_id(tmp_path: Path) -> None:
    """Even a token of the right worker_id cannot act on another Task."""

    bound = bind_task(tmp_path)
    other_task = make_task(bound.workspace, task_id="task-2")
    bound.repository.add_task(other_task)
    broker = broker_for(bound)
    request = bound.request()
    request.task_id = "task-2"
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.WORKER_MISMATCH)


@pytest.mark.parametrize(
    "status",
    [WorkerStatus.STARTING, WorkerStatus.STOPPING, WorkerStatus.STOPPED, WorkerStatus.FAILED, WorkerStatus.CRASHED],
)
def test_deny_worker_not_running(tmp_path: Path, status: WorkerStatus) -> None:
    bound = bind_task(tmp_path, worker_status=status)
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.WORKER_NOT_RUNNING)


@pytest.mark.parametrize("status", [WorkerStatus.READY, WorkerStatus.RUNNING])
def test_allow_ready_or_running_worker(tmp_path: Path, status: WorkerStatus) -> None:
    bound = bind_task(tmp_path, worker_status=status)
    broker = broker_for(bound)
    assert broker.authorize(bound.request(), WORKER_TOKEN).allowed is True


# ---------------------------------------------------------------------------
# Step 3: task binding
# ---------------------------------------------------------------------------


def test_deny_unknown_task(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.tasks.clear()
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.UNKNOWN_TASK)


def test_deny_task_worker_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.task.worker_id = "worker-2"
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.WORKER_MISMATCH)


def test_deny_task_without_bound_worker(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.task.worker_id = None
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.WORKER_MISMATCH)


def test_deny_session_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.task.acp_session_id = "different-session"
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.SESSION_MISMATCH)


def test_deny_task_without_session(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.task.acp_session_id = None
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.SESSION_MISMATCH)


def test_deny_workspace_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    other = make_workspace(tmp_path, name="other-work")
    bound.worker.workspace_path = str(other)
    broker = broker_for(bound)
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.WORKER_MISMATCH)


# ---------------------------------------------------------------------------
# Step 4: tool allowlist and version
# ---------------------------------------------------------------------------


def test_deny_unknown_tool(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(tool_name="internal.not_a_tool", argv=["x"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.TOOL_NOT_ALLOWED)


def test_deny_tool_not_installed(tmp_path: Path) -> None:
    from ctf_solver.runtime.tools import ToolSpec

    bound = bind_task(tmp_path)
    missing = ToolSpec(
        name="tool.missing_probe",
        display_name="Missing probe",
        description="Executable that does not exist",
        tier=ExecutionTier.TIER1_TRUSTED,
        version_probe=["--version"],
        executable="ctf-solver-definitely-missing-binary",
        arg_validator=lambda argv: None if argv == ["--version"] else "fixed argv required",
    )
    broker = broker_for(bound, catalog=catalog_with(missing))
    request = bound.request(tool_name="tool.missing_probe", argv=["--version"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.TOOL_NOT_INSTALLED)


def test_deny_tool_version_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"hello")
    broker = broker_for(bound)
    request = bound.request(tool_version="2.0")
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.TOOL_VERSION_MISMATCH)


def test_allow_matching_tool_version(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"hello")
    broker = broker_for(bound)
    decision = broker.authorize(bound.request(tool_version=" 1 "), WORKER_TOKEN)
    assert decision.allowed is True
    assert decision.tool is not None and decision.tool["version"] == "1"


# ---------------------------------------------------------------------------
# Step 5: execution tier
# ---------------------------------------------------------------------------


def test_deny_tier2_network_stub(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(tool_name="tool.remote_probe", argv=["--version"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.TIER_NOT_AVAILABLE)


def test_deny_tier2_synthetic_tool(tmp_path: Path) -> None:
    from ctf_solver.core.types import RuntimeOutcome, ExecutionStatus
    from ctf_solver.runtime.tools import ToolSpec

    tier2 = ToolSpec(
        name="synth.tier2",
        display_name="Tier 2 tool",
        description="Static Tier 2 tool",
        tier=ExecutionTier.TIER2_ISOLATED,
        version="1",
        internal=lambda invocation: RuntimeOutcome(
            status=ExecutionStatus.COMPLETED, exit_code=0
        ),
    )
    bound = bind_task(tmp_path)
    broker = broker_for(bound, catalog=catalog_with(tier2))
    request = bound.request(tool_name="synth.tier2", argv=[], tier=ExecutionTier.TIER2_ISOLATED)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.TIER_NOT_AVAILABLE)


def test_deny_untrusted_challenge_code(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound, catalog=catalog_with(untrusted_code_tool()))
    request = bound.request(tool_name="synth.untrusted", argv=[])
    assert_denied(
        broker.authorize(request, WORKER_TOKEN), DenyReason.UNTRUSTED_CODE_REQUIRES_TIER2
    )


def test_untrusted_code_with_tier2_available_requires_approval(tmp_path: Path) -> None:
    """When Tier 2 were available, untrusted code still needs an approval."""

    all_tiers = frozenset(
        {ExecutionTier.TIER0_STATIC, ExecutionTier.TIER1_TRUSTED, ExecutionTier.TIER2_ISOLATED}
    )
    bound = bind_task(tmp_path)
    catalog = catalog_with(untrusted_code_tool(), available_tiers=all_tiers)
    broker = broker_for(bound, catalog=catalog)
    request = bound.request(
        tool_name="synth.untrusted", argv=[], tier=ExecutionTier.TIER2_ISOLATED
    )
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_MISSING)


# ---------------------------------------------------------------------------
# Step 6: argv schema, cwd and paths
# ---------------------------------------------------------------------------


def test_deny_fixed_probe_extra_argv(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(tool_name="tool.python_version", argv=["--version", "--evil"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.ARGV_SCHEMA_VIOLATION)


def test_deny_internal_tool_wrong_arg_count(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(tool_name="internal.file_hash", argv=[])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.ARGV_SCHEMA_VIOLATION)


def test_deny_internal_tool_traversal_argument(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(argv=["../../secrets.txt"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.ARGV_SCHEMA_VIOLATION)


def test_deny_internal_tool_absolute_argument(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(argv=[str(bound.workspace / "input.txt")])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.ARGV_SCHEMA_VIOLATION)


def test_deny_empty_text_search_pattern(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(tool_name="internal.text_search", argv=[""])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.ARGV_SCHEMA_VIOLATION)


def test_deny_cwd_outside_workspace(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(cwd=str(outside)), WORKER_TOKEN),
        DenyReason.CWD_OUTSIDE_ROOT,
    )


def test_deny_cwd_traversal_escape(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    escaping = str(bound.workspace / ".." / ".." / "..")
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(cwd=escaping), WORKER_TOKEN),
        DenyReason.CWD_OUTSIDE_ROOT,
    )


def test_deny_nonexistent_cwd(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    missing = bound.workspace / "nope"
    assert_denied(
        broker.authorize(bound.request(cwd=str(missing)), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


def test_deny_cwd_is_a_file(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    target = file_fixture(bound.workspace, "file.txt", b"x")
    broker = broker_for(bound)
    assert_denied(
        broker.authorize(bound.request(cwd=str(target)), WORKER_TOKEN),
        DenyReason.INVALID_REQUEST,
    )


def test_deny_input_outside_workspace(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    from ctf_solver.core.canonical import file_sha256

    broker = broker_for(bound)
    request = bound.request(
        input_files=[{"path": str(outside), "sha256": file_sha256(outside)}]
    )
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INPUT_OUTSIDE_ROOT)


def test_deny_input_missing(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(input_files=[{"path": "missing.bin", "sha256": "0" * 64}])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INPUT_MISSING)


def test_deny_input_hash_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.bin", b"content")
    broker = broker_for(bound)
    request = bound.request(input_files=[{"path": "input.bin", "sha256": "0" * 64}])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INPUT_HASH_MISMATCH)


def test_deny_input_traversal(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(input_files=[{"path": "../escape.bin", "sha256": "0" * 64}])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.PATH_TRAVERSAL)


def test_allow_input_inside_workspace_with_matching_hash(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.bin", b"content")
    broker = broker_for(bound)
    request = bound.request(
        input_files=[file_input(bound.workspace, "input.bin")],
        argv=["input.bin"],
    )
    assert broker.authorize(request, WORKER_TOKEN).allowed is True


def test_allow_absolute_input_inside_workspace(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    target = file_fixture(bound.workspace, "input.bin", b"content")
    from ctf_solver.core.canonical import file_sha256

    broker = broker_for(bound)
    request = bound.request(
        input_files=[{"path": str(target), "sha256": file_sha256(target)}]
    )
    assert broker.authorize(request, WORKER_TOKEN).allowed is True


def test_deny_absolute_output_path(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(output_paths=[str(bound.workspace / "out.txt")])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.PATH_TRAVERSAL)


def test_deny_output_traversal(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(output_paths=["../escape.txt"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.PATH_TRAVERSAL)


def test_deny_duplicate_output_paths(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(output_paths=["out.txt", "out.txt"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.OUTPUT_CONFLICT)


def test_deny_output_path_is_directory(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    (bound.workspace / "dir").mkdir()
    broker = broker_for(bound)
    request = bound.request(output_paths=["dir"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.OUTPUT_CONFLICT)


def test_allow_workspace_relative_output_path(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    request = bound.request(output_paths=["out.bin"])
    assert broker.authorize(request, WORKER_TOKEN).allowed is True


# ---------------------------------------------------------------------------
# Step 7: approval binding
# ---------------------------------------------------------------------------


def approval_broker(bound: BoundTask) -> Broker:
    return broker_for(bound, catalog=catalog_with(needs_approval_tool()))


def test_deny_tool_requires_approval_without_id(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = approval_broker(bound)
    request = bound.request(tool_name="synth.needs_approval", argv=[])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_MISSING)


def test_deny_unknown_approval_id(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = approval_broker(bound)
    request = bound.request(
        tool_name="synth.needs_approval", argv=[], approval_id="missing-approval"
    )
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_MISSING)


@pytest.mark.parametrize(
    "status", [ApprovalStatus.PENDING, ApprovalStatus.REJECTED, ApprovalStatus.CANCELLED]
)
def test_deny_non_approved_status(tmp_path: Path, status: ApprovalStatus) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request, status=status)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_INVALID)


def test_deny_expired_status_approval(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request, status=ApprovalStatus.EXPIRED)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_EXPIRED)


def test_deny_approval_past_expiry(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request, expires_at=BASE_NOW_MS - 1)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_EXPIRED)


def test_deny_already_consumed_approval(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request, consumed_at=BASE_NOW_MS - 10)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_ALREADY_USED)


def test_deny_approval_for_other_task(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request)
    approval.task_id = "task-2"
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_MISMATCH)


def test_deny_approval_wrong_action_kind(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request, action_kind=ApprovalAction.REMOTE_TARGET)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.APPROVAL_MISMATCH)


def test_deny_approval_digest_for_different_argv(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    approved_request = bound.request(
        tool_name="synth.needs_approval", argv=["action-a"], approval_id="appr-1"
    )
    approval = make_approval(approved_request)
    bound.repository.add_approval(approval)
    current_request = bound.request(
        tool_name="synth.needs_approval", argv=["action-b"], approval_id="appr-1"
    )
    broker = approval_broker(bound)
    assert_denied(
        broker.authorize(current_request, WORKER_TOKEN), DenyReason.APPROVAL_MISMATCH
    )


def test_allow_valid_approval_and_consume_it(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    approval = make_approval(request)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    decision = broker.authorize(request, WORKER_TOKEN)
    assert decision.allowed is True
    assert decision.approval_id == "appr-1"
    assert bound.repository.approvals["appr-1"].consumed_at == BASE_NOW_MS


def test_allow_approval_digest_bound_to_full_request_document(tmp_path: Path) -> None:
    """A Manager may bind the digest to the full request document (both exact)."""

    bound = bind_task(tmp_path)
    request = bound.request(tool_name="synth.needs_approval", argv=[], approval_id="appr-1")
    digest = action_digest("tool_action", request.to_dict())
    approval = make_approval(request, digest=digest)
    bound.repository.add_approval(approval)
    broker = approval_broker(bound)
    assert broker.authorize(request, WORKER_TOKEN).allowed is True


def test_approval_not_consumed_when_later_check_fails(tmp_path: Path) -> None:
    """A network failure after approval validation must not burn the approval."""

    from tests.test_runtime_support import network_stub_tool

    bound = bind_task(tmp_path)
    tool = network_stub_tool(
        name="synth.network_target", requires_approval=ApprovalAction.REMOTE_TARGET
    )
    request = bound.request(
        tool_name="synth.network_target",
        argv=["probe"],
        approval_id="appr-1",
        network_target=make_network_target(),
    )
    approval = make_approval(request, action_kind=ApprovalAction.REMOTE_TARGET)
    bound.repository.add_approval(approval)
    broker = broker_for(bound, catalog=catalog_with(tool), config=network_config())
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.GRANT_MISSING)
    assert bound.repository.approvals["appr-1"].consumed_at is None


def test_approval_required_for_untrusted_code_when_tier2_available(tmp_path: Path) -> None:
    all_tiers = frozenset(
        {ExecutionTier.TIER0_STATIC, ExecutionTier.TIER1_TRUSTED, ExecutionTier.TIER2_ISOLATED}
    )
    bound = bind_task(tmp_path)
    catalog = catalog_with(untrusted_code_tool(), available_tiers=all_tiers)
    request = bound.request(
        tool_name="synth.untrusted",
        argv=[],
        approval_id="appr-1",
        tier=ExecutionTier.TIER2_ISOLATED,
    )
    approval = make_approval(request, action_kind=ApprovalAction.UNTRUSTED_CODE)
    bound.repository.add_approval(approval)
    broker = broker_for(bound, catalog=catalog)
    decision = broker.authorize(request, WORKER_TOKEN)
    assert decision.allowed is True
    assert decision.approval_id == "appr-1"


# ---------------------------------------------------------------------------
# Step 9: resource limits
# ---------------------------------------------------------------------------


def test_deny_requested_output_limit_above_tool_cap(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"x")
    broker = broker_for(bound)
    request = bound.request(max_output_bytes=1024 * 1024)  # file_hash cap is 64 KiB
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.RESOURCE_LIMIT)


def test_deny_requested_output_limit_above_policy_cap(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound, config=BrokerConfig(max_output_bytes=1024))
    file_fixture(bound.workspace, "input.txt", b"x")
    request = bound.request(max_output_bytes=4096)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.RESOURCE_LIMIT)


# ---------------------------------------------------------------------------
# Fail-closed boundary and helpers
# ---------------------------------------------------------------------------


class _ExplodingRepository(FakeRepository):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self._error = error

    def get_worker_by_token(self, token: str):  # type: ignore[override]
        raise self._error


def test_repository_failure_denies_internal_error(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    repository = _ExplodingRepository(StorageError("database is unavailable"))
    broker = Broker(repository, RuntimeCatalog.default(), bound.clock)
    decision = broker.authorize(bound.request(), WORKER_TOKEN)
    assert_denied(decision, DenyReason.INTERNAL_ERROR)


def test_unexpected_repository_exception_still_fails_closed(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    repository = _ExplodingRepository(RuntimeError("bug"))
    broker = Broker(repository, RuntimeCatalog.default(), bound.clock)
    decision = broker.authorize(bound.request(), WORKER_TOKEN)
    assert_denied(decision, DenyReason.INTERNAL_ERROR)


def test_deny_non_exec_request_object(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = broker_for(bound)
    decision = broker.authorize({"task_id": "x"}, WORKER_TOKEN)  # type: ignore[arg-type]
    assert_denied(decision, DenyReason.INVALID_REQUEST)


def test_action_digest_is_order_independent_and_argv_sensitive() -> None:
    first = action_digest("tool_action", {"b": 2, "a": 1, "argv": ["x"]})
    second = action_digest("tool_action", {"argv": ["x"], "a": 1, "b": 2})
    assert first == second
    third = action_digest("tool_action", {"argv": ["y"], "a": 1, "b": 2})
    assert first != third
    assert action_digest("remote_target", {"a": 1}) != action_digest("tool_action", {"a": 1})


def test_approval_details_bind_concrete_action(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    request = bound.request(
        argv=["input.txt"],
        output_paths=["out.txt"],
        network_target=make_network_target(),
        network_grant_id="grant-1",
    )
    details = approval_details(request)
    assert details["task_id"] == TASK_ID
    assert details["tool_name"] == "internal.file_hash"
    assert details["argv"] == ["input.txt"]
    assert details["output_paths"] == ["out.txt"]
    assert details["network_target"]["host"] == details["network_target"]["host"]
    assert details["action"] == "ctf-exec"
    other = bound.request(argv=["other.txt"])
    assert approval_action_digest("tool_action", request) != approval_action_digest(
        "tool_action", other
    )


def test_target_digest_normalizes() -> None:
    first = target_digest(make_network_target(host="Example.COM."))
    second = target_digest(make_network_target(host="example.com"))
    assert first == second
    third = target_digest(make_network_target(port=8443))
    assert first != third


def test_broker_config_can_only_narrow_catalogue_tiers(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    catalog = RuntimeCatalog.default()
    config = BrokerConfig(available_tiers=frozenset({ExecutionTier.TIER2_ISOLATED}))
    broker = Broker(bound.repository, catalog, bound.clock, config=config)
    assert broker.available_tiers == frozenset()
    assert_denied(broker.authorize(bound.request(), WORKER_TOKEN), DenyReason.TIER_NOT_AVAILABLE)

