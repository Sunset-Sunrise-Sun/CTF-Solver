"""Independent adversarial acceptance tests for CTF-Solver Round 1.

Written by ``verifier-round1`` against the frozen documents
(``docs/ACCEPTANCE.md`` §J Round 1, ``docs/ROUND_1_IMPLEMENTATION_TASK.md``
§3 A-I, ``docs/INTERFACES.md``), **not** against what the product happens to do.

These tests intentionally do not reuse the authors' fixtures
(``tests/support/fakes.py``); see ``tests/support/verification_helpers.py``.

Round 1 environment constraints honoured here:
- no model call and no ``session/prompt`` (the client gate is asserted);
- no real CTF target / no network destination access (socket connects are
  blocked for the duration of every test and would fail loudly);
- every write goes to ``tmp_path``; only read-only inspection touches
  ``D:/CTFworker``;
- known product defects are documented with ``xfail`` (see the verification
  report ``round1-evidence/raw/verifier-report.md``) and are never hidden.
"""

from __future__ import annotations

import json
import re
import socket
import sqlite3
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ctf_solver.acp.client import AcpClient
from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import (
    AcpError,
    ConfigError,
    ModelCallNotAuthorized,
    StateError,
    StorageError,
    UnsupportedCompressionError,
    ValidationError,
)
from ctf_solver.core.types import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    CaptureStatus,
    Category,
    ExecutionStatus,
    ExecutionTier,
    ExecRequest,
    GrantRecord,
    GrantStatus,
    NetworkTarget,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.delivery.deliverables import Deliverables
from ctf_solver.delivery.screenshot import FakeScreenCapturer
from ctf_solver.evidence.cas import Cas
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.evidence.zstd_frames import decode_all, probe_backends
from ctf_solver.manager.ipc import ManagerIpcServer
from ctf_solver.manager.service import ManagerService
from ctf_solver.manager.store import ManagerStore
from ctf_solver.mcp.exec_server import ExecToolService, build_server as build_exec_server
from ctf_solver.mcp.manager_server import build_manager_tools, build_server as build_manager_server
from ctf_solver.mcp.protocol import JsonRpcProtocolError, McpToolError
from ctf_solver.policy.broker import Broker, BrokerConfig
from ctf_solver.policy.models import GrantScope, approval_action_digest
from ctf_solver.preflight import doctor as preflight_doctor
from ctf_solver.runtime.catalog import RuntimeCatalog
from ctf_solver.runtime.executor import RuntimeExecutor
from ctf_solver.runtime.pipeline import ExecutionPipeline

from tests.support.verification_helpers import (
    FakeAcpClient,
    SpyExecutor,
    VerificationClock,
    approve_request,
    build_multiframe_session_log,
    build_stack,
    build_verification_tool_specs,
    chain_payload_from_row,
    compress_zstd_frame,
    create_running_task,
    make_request,
    recompute_chain,
    sha256_bytes,
    sha256_file,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = REPO_ROOT / ".dsh" / "skills"
EVIDENCE_RAW = REPO_ROOT / "round1-evidence" / "raw"
BASELINE_PATH = EVIDENCE_RAW / "verifier-environment-baseline.json"

EXPECTED_SKILLS = (
    "ctf-solver",
    "ctf-web",
    "ctf-misc",
    "ctf-crypto",
    "ctf-reverse",
    "ctf-pwn",
)

EXPECTED_MANAGER_TOOLS = {
    "ctf_task_create",
    "ctf_task_list",
    "ctf_task_status",
    "ctf_task_continue",
    "ctf_task_pause",
    "ctf_task_cancel",
    "ctf_task_complete",
    "ctf_approval_request",
    "ctf_approval_list",
    "ctf_grant_revoke",
    "ctf_grant_list",
    "ctf_flag_candidate",
    "ctf_screenshot_capture",
    "ctf_session_ingest",
    "ctf_events_export",
    "ctf_writeup_build",
    "ctf_evidence_zip",
    "ctf_runtime_status",
}

FORBIDDEN_ESCALATION_TOOLS = {"ctf_approval_decide", "ctf_grant_create"}


# ---------------------------------------------------------------------------
# Environment guard: every test in this module must stay offline / model-free
# ---------------------------------------------------------------------------

REAL_ACP_STARTS: list[object] = []


def _deny_network(*args: object, **kwargs: object) -> object:
    raise AssertionError("verifier test attempted a network connection (forbidden in Round 1)")


@pytest.fixture(autouse=True)
def guard_no_real_side_effects(monkeypatch: pytest.MonkeyPatch) -> object:
    """Fail loudly if a verification test tries to reach the network or a real ACP."""

    monkeypatch.setattr(socket, "create_connection", _deny_network, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _deny_network, raising=False)
    try:
        monkeypatch.setattr(socket.socket, "connect", _deny_network)
    except (AttributeError, TypeError):  # pragma: no cover - platform detail
        pass
    monkeypatch.setattr(
        "ctf_solver.runtime.executor.RuntimeExecutor._execute_subprocess", _deny_network
    )

    def _no_real_acp(self: AcpClient) -> None:
        REAL_ACP_STARTS.append(self)
        raise AssertionError("verifier test must not start a real ACP server process")

    monkeypatch.setattr(AcpClient, "start", _no_real_acp)
    yield
    assert REAL_ACP_STARTS == [], "a verification test started a real ACP client"


# ---------------------------------------------------------------------------
# Shared in-test Manager composition (real SQLite / CAS / Broker / Runtime)
# ---------------------------------------------------------------------------


def _build_manager(
    tmp_path: Path,
    *,
    fake: FakeAcpClient | None = None,
    root_name: str = "manager-root",
) -> tuple[ManagerService, FakeAcpClient, ManagerStore, EvidenceStore, SolverConfig]:
    root = tmp_path / root_name
    config = SolverConfig(root=root, capture_mode="fake")
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir))
    catalog = RuntimeCatalog(tools=build_verification_tool_specs())
    broker = Broker(repository=store, catalog=catalog)
    pipeline = ExecutionPipeline(
        repository=store,
        evidence=evidence,
        broker=broker,
        executor=RuntimeExecutor(),
    )
    deliverables = Deliverables(evidence, paths)
    acp = fake or FakeAcpClient()
    service = ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: acp,
        evidence=evidence,
        pipeline=pipeline,
        deliverables=deliverables,
        capturer=FakeScreenCapturer("nonblank"),
    )
    return service, acp, store, evidence, config


def _teardown_manager(
    service: ManagerService, store: ManagerStore, evidence: EvidenceStore
) -> None:
    try:
        service.shutdown()
    finally:
        try:
            store.close()
        finally:
            try:
                evidence.close()
            except Exception:  # noqa: BLE001 - already closed by shutdown
                pass


# ===========================================================================
# A. Broker / Runtime fail-closed matrix with a spy executor
# ===========================================================================


def test_broker_allowed_internal_execution_is_observed(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        request = make_request(
            stack, task, worker, output_paths=["result.txt"]
        )
        (Path(task.workspace_path) / "result.txt").write_bytes(b"artifact\n")

        result = stack.pipeline.execute(request, worker.worker_token)

        assert result.status is ExecutionStatus.COMPLETED
        assert result.exit_code == 0
        assert result.task_id == task.task_id
        assert result.stdout_sha256 and stack.evidence.cas.verify(result.stdout_sha256)
        assert result.output_files[0]["exists"] is True
        assert result.output_files[0]["sha256"] == sha256_bytes(b"artifact\n")
        assert stack.executor.calls == ["test.echo"]
        events = stack.evidence.list_events(task_id=task.task_id)
        types = [event["event_type"] for event in events]
        assert types.count("execution_started") == 1
        assert types.count("execution_completed") == 1
        row = stack.store.conn.execute(
            "SELECT status, exit_code FROM executions WHERE execution_id = ?",
            (result.execution_id,),
        ).fetchone()
        assert row["status"] == "completed" and row["exit_code"] == 0
        assert stack.evidence.chain_status().ok is True
    finally:
        stack.close()


@pytest.mark.parametrize(
    ("case", "overrides", "expected_reason"),
    [
        ("unknown_worker_token", {"worker_token": "not-a-real-token"}, "unknown_worker"),
        (
            "worker_id_mismatch",
            {"worker_token": "token-other", "request": {"worker_id": "w-other"}},
            "worker_mismatch",
        ),
        (
            "cross_task_token",
            {"worker_token": "token-other", "request": {"task_id": "t-other"}},
            "worker_mismatch",
        ),
        ("tool_not_allowed", {"request": {"tool_name": "test.not_listed"}}, "tool_not_allowed"),
        (
            "tool_version_mismatch",
            {"request": {"tool_name": "test.echo", "tool_version": "999"}},
            "tool_version_mismatch",
        ),
        (
            "argv_schema_violation",
            {"request": {"tool_name": "test.fixed_argv", "argv": ["--help"]}},
            "argv_schema_violation",
        ),
        (
            "shell_metacharacters_in_argv0",
            {"request": {"tool_name": "test.echo", "argv": ["echo; rm -rf /"]}},
            "shell_expansion_rejected",
        ),
        (
            "cwd_outside_workspace",
            {"request": {"cwd": "OUTSIDE"}},
            "cwd_outside_root",
        ),
        (
            "input_path_traversal",
            {
                "request": {
                    "input_files": [
                        {"path": "..\\..\\secret.txt", "sha256": "0" * 64}
                    ]
                }
            },
            "path_traversal",
        ),
        (
            "input_absolute_outside",
            {
                "request": {
                    "input_files": [
                        {"path": "ABSOLUTE_OUTSIDE", "sha256": "0" * 64}
                    ]
                }
            },
            "input_outside_root",
        ),
        (
            "input_missing",
            {
                "request": {
                    "input_files": [{"path": "missing.txt", "sha256": "0" * 64}]
                }
            },
            "input_missing",
        ),
        (
            "input_hash_mismatch",
            {
                "request": {
                    "input_files": [{"path": "sample.txt", "sha256": "0" * 64}]
                }
            },
            "input_hash_mismatch",
        ),
        ("output_absolute", {"request": {"output_paths": ["ABSOLUTE_OUTSIDE"]}}, "path_traversal"),
        ("output_traversal", {"request": {"output_paths": ["../escape.bin"]}}, "path_traversal"),
        (
            "duplicate_output",
            {"request": {"output_paths": ["same.bin", "same.bin"]}},
            "output_conflict",
        ),
        ("untrusted_code", {"request": {"tool_name": "test.untrusted"}}, "untrusted_code_requires_tier2"),
        ("tier2_unavailable", {"request": {"tool_name": "test.tier2"}}, "tier_not_available"),
        ("timeout_below_policy", {"request": {"timeout_s": 0.01}}, "resource_limit"),
        ("timeout_above_policy", {"request": {"timeout_s": 601.0}}, "resource_limit"),
        (
            "output_limit_above_policy",
            {"request": {"max_output_bytes": 65 * 1024 * 1024}},
            "resource_limit",
        ),
    ],
)
def test_broker_denies_before_execution(
    tmp_path: Path,
    case: str,
    overrides: dict[str, object],
    expected_reason: str,
) -> None:
    """Every denial happens before the executor is touched (spy proves it)."""

    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        _, other_worker = create_running_task(
            stack,
            task_id="t-other",
            worker_id="w-other",
            session_id="sess-other",
            token="token-other",
        )
        other_task = stack.store.require_task("t-other")
        assert other_worker.worker_id == "w-other"
        (Path(task.workspace_path) / "sample.txt").write_text("abc", encoding="utf-8")

        request_overrides = dict(overrides.get("request") or {})
        cwd = request_overrides.get("cwd")
        if cwd == "OUTSIDE":
            request_overrides["cwd"] = str(tmp_path)
        input_files = request_overrides.get("input_files")
        if input_files:
            request_overrides["input_files"] = [
                {
                    **item,
                    "path": (
                        str(tmp_path / "outside.txt")
                        if item["path"] == "ABSOLUTE_OUTSIDE"
                        else item["path"]
                    ),
                }
                for item in input_files
            ]
        output_paths = request_overrides.get("output_paths")
        if output_paths == ["ABSOLUTE_OUTSIDE"]:
            request_overrides["output_paths"] = [str(tmp_path / "outside.bin")]
        del other_task
        request = make_request(stack, task, worker, **request_overrides)
        result = stack.pipeline.execute(
            request, str(overrides.get("worker_token", worker.worker_token))
        )

        assert result.status is ExecutionStatus.DENIED, (case, result.status, result.reason)
        assert result.reason_code == expected_reason, (case, result.reason_code, result.reason)
        assert result.started_at == result.ended_at
        assert result.exit_code is None
        assert stack.executor.calls == [], f"denied call executed a tool: {case}"
        events = stack.evidence.list_events(task_id=request.task_id)
        types = [event["event_type"] for event in events]
        assert "execution_denied" in types
        assert "execution_started" not in types
        assert stack.evidence.chain_status().ok is True
    finally:
        stack.close()


def test_broker_distinguishes_denied_from_executed_but_failed(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        denied = stack.pipeline.execute(
            make_request(stack, task, worker, tool_name="test.not_listed"),
            worker.worker_token,
        )
        failed = stack.pipeline.execute(
            make_request(stack, task, worker, tool_name="test.fail"), worker.worker_token
        )
        assert denied.status is ExecutionStatus.DENIED
        assert denied.reason_code == "tool_not_allowed"
        assert failed.status is ExecutionStatus.FAILED
        assert failed.exit_code == 7
        assert denied.execution_id != failed.execution_id
        assert stack.executor.calls == ["test.fail"]
        events = stack.evidence.list_events(task_id=task.task_id)
        types = [event["event_type"] for event in events]
        assert "execution_denied" in types
        assert "execution_started" in types
        assert "execution_failed" in types
        assert types.count("execution_denied") == 1
    finally:
        stack.close()


def test_broker_approval_matrix(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        base = make_request(stack, task, worker, tool_name="test.approved")

        # missing approval
        missing = stack.broker.authorize(base, worker.worker_token)
        assert not missing.allowed and missing.reason_code == "approval_missing"

        # cross-task approval
        _, _ = create_running_task(
            stack, task_id="t-other", worker_id="w-other", session_id="sess-other"
        )
        other_request = make_request(
            stack, task, worker, tool_name="test.approved", task_id="t-other"
        )
        cross = approve_request(stack, task_id="t-other", request=other_request)
        cross_decision = stack.broker.authorize(base, worker.worker_token)
        assert not cross_decision.allowed and cross_decision.reason_code == "approval_missing"
        different_rq = make_request(
            stack,
            task,
            worker,
            tool_name="test.approved",
            approval_id=cross.approval_id,
        )
        cross_decision = stack.broker.authorize(different_rq, worker.worker_token)
        assert not cross_decision.allowed and cross_decision.reason_code == "approval_mismatch"

        # wrong action kind
        wrong_kind = approve_request(
            stack,
            task_id=task.task_id,
            request=base,
            action_kind=ApprovalAction.UNTRUSTED_CODE,
        )
        wrong_kind_decision = stack.broker.authorize(
            make_request(
                stack, task, worker, tool_name="test.approved", approval_id=wrong_kind.approval_id
            ),
            worker.worker_token,
        )
        assert (
            not wrong_kind_decision.allowed
            and wrong_kind_decision.reason_code == "approval_mismatch"
        )

        # pending approval is not sufficient
        now = stack.clock.now_ms()
        pending = ApprovalRecord(
            approval_id="apr-verifier-pending",
            task_id=task.task_id,
            action_kind=ApprovalAction.TOOL_ACTION.value,
            action_digest=approval_action_digest(ApprovalAction.TOOL_ACTION.value, base),
            status=ApprovalStatus.PENDING,
            requested_at=now,
        )
        stack.store.create_approval(pending)
        pending_decision = stack.broker.authorize(
            make_request(
                stack, task, worker, tool_name="test.approved", approval_id=pending.approval_id
            ),
            worker.worker_token,
        )
        assert not pending_decision.allowed and pending_decision.reason_code == "approval_invalid"

        # expired approval
        expired = approve_request(stack, task_id=task.task_id, request=base, ttl_ms=500)
        stack.clock.advance(5_000)
        expired_decision = stack.broker.authorize(
            make_request(
                stack, task, worker, tool_name="test.approved", approval_id=expired.approval_id
            ),
            worker.worker_token,
        )
        assert not expired_decision.allowed and expired_decision.reason_code == "approval_expired"

        # valid approval is consumed exactly once
        valid = approve_request(stack, task_id=task.task_id, request=base)
        allowed = stack.broker.authorize(
            make_request(
                stack, task, worker, tool_name="test.approved", approval_id=valid.approval_id
            ),
            worker.worker_token,
        )
        assert allowed.allowed, allowed.reason
        assert allowed.approval_id == valid.approval_id
        consumed = stack.store.get_approval(valid.approval_id)
        assert consumed is not None and consumed.consumed_at is not None
        replay = stack.broker.authorize(
            make_request(
                stack, task, worker, tool_name="test.approved", approval_id=valid.approval_id
            ),
            worker.worker_token,
        )
        assert not replay.allowed and replay.reason_code == "approval_already_used"
    finally:
        stack.close()


def test_broker_grant_scope_matrix(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack", network_enabled=True)
    try:
        task, worker = create_running_task(stack)
        create_running_task(
            stack, task_id="t-other", worker_id="w-other", session_id="sess-other"
        )
        now = stack.clock.now_ms()
        cwd = Path(task.workspace_path)

        def grant(**overrides: object) -> GrantRecord:
            values: dict[str, object] = {
                "grant_id": "grant-verifier",
                "task_id": task.task_id,
                "competition_profile": "synthetic-local",
                "host": "ctf.example.com",
                "port": 8080,
                "protocol": "http",
                "method": "GET",
                "path_prefix": "/api",
                "expires_at": now + 60_000,
                "max_calls": 2,
                "approver": "human-verifier",
                "calls_used": 0,
                "created_at": now,
                "status": GrantStatus.ACTIVE,
            }
            values.update(overrides)
            record = GrantRecord(**values)  # type: ignore[arg-type]
            return stack.store.create_grant(record)

        target = NetworkTarget(host="ctf.example.com", port=8080, protocol="http", method="GET", path="/api/x")

        def request(grant_id: str | None, target_value: NetworkTarget | None = target) -> ExecRequest:
            return make_request(
                stack,
                task,
                worker,
                tool_name="test.net_probe",
                cwd=str(cwd),
                network_grant_id=grant_id,
                network_target=target_value,
            )

        # network tool without a target
        no_target = stack.broker.authorize(
            make_request(stack, task, worker, tool_name="test.net_probe"), worker.worker_token
        )
        assert not no_target.allowed and no_target.reason_code == "network_target_missing"

        # target without a grant
        no_grant = stack.broker.authorize(request(None), worker.worker_token)
        assert not no_grant.allowed and no_grant.reason_code == "grant_missing"

        # unknown grant id
        unknown = stack.broker.authorize(request("grant-does-not-exist"), worker.worker_token)
        assert not unknown.allowed and unknown.reason_code == "grant_missing"

        # wrong task
        grant(grant_id="grant-task", task_id="t-other")
        wrong_task = stack.broker.authorize(request("grant-task"), worker.worker_token)
        assert not wrong_task.allowed and wrong_task.reason_code == "grant_task_mismatch"

        # wrong competition profile
        grant(grant_id="grant-profile", competition_profile="other-profile")
        wrong_profile = stack.broker.authorize(request("grant-profile"), worker.worker_token)
        assert not wrong_profile.allowed and wrong_profile.reason_code == "grant_profile_mismatch"

        # expired
        grant(grant_id="grant-expired", expires_at=now - 1)
        expired = stack.broker.authorize(request("grant-expired"), worker.worker_token)
        assert not expired.allowed and expired.reason_code == "grant_expired"

        # exhausted
        grant(grant_id="grant-exhausted", calls_used=2, max_calls=2)
        exhausted = stack.broker.authorize(request("grant-exhausted"), worker.worker_token)
        assert not exhausted.allowed and exhausted.reason_code == "grant_exhausted"

        # revoked status
        grant(grant_id="grant-revoked", status=GrantStatus.REVOKED)
        revoked = stack.broker.authorize(request("grant-revoked"), worker.worker_token)
        assert not revoked.allowed and revoked.reason_code == "grant_invalid"

        # destination mismatches
        grant(grant_id="grant-host")
        wrong_host = stack.broker.authorize(
            request(
                "grant-host",
                NetworkTarget(host="other.example.com", port=8080, protocol="http", method="GET", path="/api/x"),
            ),
            worker.worker_token,
        )
        assert not wrong_host.allowed and wrong_host.reason_code == "grant_host_mismatch"

        wrong_port = stack.broker.authorize(
            request(
                "grant-host",
                NetworkTarget(host="ctf.example.com", port=8081, protocol="http", method="GET", path="/api/x"),
            ),
            worker.worker_token,
        )
        assert not wrong_port.allowed and wrong_port.reason_code == "grant_port_mismatch"

        wrong_protocol = stack.broker.authorize(
            request(
                "grant-host",
                NetworkTarget(host="ctf.example.com", port=8080, protocol="https", method="GET", path="/api/x"),
            ),
            worker.worker_token,
        )
        assert not wrong_protocol.allowed and wrong_protocol.reason_code == "grant_protocol_mismatch"

        wrong_method = stack.broker.authorize(
            request(
                "grant-host",
                NetworkTarget(host="ctf.example.com", port=8080, protocol="http", method="POST", path="/api/x"),
            ),
            worker.worker_token,
        )
        assert not wrong_method.allowed and wrong_method.reason_code == "grant_action_mismatch"

        wrong_path = stack.broker.authorize(
            request(
                "grant-host",
                NetworkTarget(host="ctf.example.com", port=8080, protocol="http", method="GET", path="/admin"),
            ),
            worker.worker_token,
        )
        assert not wrong_path.allowed and wrong_path.reason_code == "grant_path_mismatch"

        # in-scope request is allowed and consumes exactly one grant call
        allowed_grant = grant(grant_id="grant-ok")
        allowed = stack.broker.authorize(request(allowed_grant.grant_id), worker.worker_token)
        assert allowed.allowed, allowed.reason
        assert allowed.grant_call_consumed is True
        assert stack.store.get_grant(allowed_grant.grant_id).calls_used == 1  # type: ignore[union-attr]
    finally:
        stack.close()


def test_network_disabled_fails_closed_even_with_valid_grant(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack", network_enabled=False)
    try:
        task, worker = create_running_task(stack)
        now = stack.clock.now_ms()
        grant = GrantRecord(
            grant_id="grant-disabled",
            task_id=task.task_id,
            competition_profile="synthetic-local",
            host="ctf.example.com",
            port=8080,
            protocol="http",
            method="GET",
            path_prefix="/",
            expires_at=now + 60_000,
            max_calls=5,
            approver="human-verifier",
            created_at=now,
            status=GrantStatus.ACTIVE,
        )
        stack.store.create_grant(grant)
        request = make_request(
            stack,
            task,
            worker,
            tool_name="test.net_probe",
            network_grant_id=grant.grant_id,
            network_target=NetworkTarget(
                host="ctf.example.com", port=8080, protocol="http", method="GET", path="/"
            ),
        )
        decision = stack.broker.authorize(request, worker.worker_token)
        assert not decision.allowed
        assert decision.reason_code == "tier_not_available"
    finally:
        stack.close()


def test_redirect_and_dns_revalidation_fail_closed(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack", network_enabled=True)
    try:
        now = stack.clock.now_ms()

        def grant(**overrides: object) -> GrantRecord:
            values: dict[str, object] = {
                "grant_id": "grant-net",
                "task_id": "t-verifier",
                "competition_profile": "synthetic-local",
                "host": "ctf.example.com",
                "port": 80,
                "protocol": "http",
                "method": "GET",
                "path_prefix": "/",
                "expires_at": now + 60_000,
                "max_calls": 5,
                "approver": "human-verifier",
            }
            values.update(overrides)
            return GrantRecord(**values)  # type: ignore[arg-type]

        public = NetworkTarget(host="ctf.example.com", port=80, protocol="http", method="GET", path="/a")
        same = stack.broker.validate_redirect(grant(), public, public)
        assert same.allowed, same.reason

        out_of_scope = stack.broker.validate_redirect(
            grant(),
            public,
            NetworkTarget(host="evil.example.net", port=80, protocol="http", method="GET", path="/a"),
        )
        assert not out_of_scope.allowed
        assert out_of_scope.reason_code == "redirect_scope_violation"

        # A private/loopback redirect in granted scope needs an explicit allow_private flag.
        loopback_grant = grant(host="127.0.0.1", port=8080)
        original = NetworkTarget(host="127.0.0.1", port=8080, protocol="http", method="GET", path="/a")
        redirect = NetworkTarget(host="127.0.0.1", port=8080, protocol="http", method="GET", path="/b")
        private_denied = stack.broker.validate_redirect(loopback_grant, original, redirect)
        assert not private_denied.allowed
        assert private_denied.reason_code == "redirect_scope_violation"
        private_allowed = stack.broker.validate_redirect(
            GrantScope.from_record(loopback_grant, allow_private=True), original, redirect
        )
        assert private_allowed.allowed, private_allowed.reason

        dns_target = NetworkTarget(host="ctf.example.com", port=80, protocol="http", method="GET", path="/a")
        assert stack.broker.validate_resolved_address(grant(), dns_target, ["1.2.3.4"]).allowed
        private_dns = stack.broker.validate_resolved_address(grant(), dns_target, ["127.0.0.1"])
        assert not private_dns.allowed and private_dns.reason_code == "dns_scope_violation"
        private_dns2 = stack.broker.validate_resolved_address(grant(), dns_target, ["10.0.0.5"])
        assert not private_dns2.allowed and private_dns2.reason_code == "dns_scope_violation"
        empty_dns = stack.broker.validate_resolved_address(grant(), dns_target, [])
        assert not empty_dns.allowed and empty_dns.reason_code == "dns_scope_violation"
        garbage_dns = stack.broker.validate_resolved_address(grant(), dns_target, ["not-an-ip"])
        assert not garbage_dns.allowed and garbage_dns.reason_code == "dns_scope_violation"

        literal_grant = grant(host="93.184.216.34")
        literal_target = NetworkTarget(
            host="93.184.216.34", port=80, protocol="http", method="GET", path="/a"
        )
        wrong_literal = stack.broker.validate_resolved_address(
            literal_grant, literal_target, ["1.2.3.4"]
        )
        assert not wrong_literal.allowed and wrong_literal.reason_code == "dns_scope_violation"
        right_literal = stack.broker.validate_resolved_address(
            literal_grant, literal_target, ["93.184.216.34"]
        )
        assert right_literal.allowed
    finally:
        stack.close()


def test_argv_array_is_the_only_accepted_form(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ExecRequest.from_mapping(
            {
                "task_id": "t-1",
                "worker_id": "w-1",
                "step_id": "s1",
                "tool_name": "test.echo",
                "argv": "ls -la",  # shell string, forbidden
                "cwd": str(tmp_path),
            }
        )
    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        request = make_request(stack, task, worker)
        request.argv = "ls -la"  # type: ignore[assignment] - deliberate contract abuse
        decision = stack.broker.authorize(request, worker.worker_token)
        assert not decision.allowed
        assert decision.reason_code == "invalid_request"
        assert stack.executor.calls == []
    finally:
        stack.close()


def test_workspace_state_machine_is_enforced(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        with pytest.raises(StateError):
            stack.store.set_task_status(task.task_id, TaskStatus.QUEUED)
        stack.store.set_task_status(task.task_id, TaskStatus.CANCEL_REQUESTED)
        stack.store.set_task_status(task.task_id, TaskStatus.CANCELLED)
        denied = stack.broker.authorize(make_request(stack, task, worker), worker.worker_token)
        assert not denied.allowed and denied.reason_code == "task_not_runnable"
    finally:
        stack.close()


# ===========================================================================
# B. Evidence integrity: hash chain, tamper evidence, CAS, deterministic export,
#    idempotent multi-frame ingestion
# ===========================================================================


def _append_basic_events(store: EvidenceStore, task_id: str = "t-evidence", count: int = 5) -> None:
    for index in range(1, count + 1):
        store.append_event(
            task_id=task_id,
            source="verifier",
            source_id=f"verifier:{index}",
            source_seq=index,
            event_type="verification_event",
            payload={"index": index, "note": f"event-{index}"},
            timestamp=1_700_000_000_000 + index,
        )


def test_evidence_chain_is_clean_and_independently_recomputable(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "db.sqlite", tmp_path / "cas")
    try:
        _append_basic_events(store)
        status = store.chain_status()
        assert status.ok is True, status.error
        assert status.records == 5
        rows = store.list_events()
        assert [row["seq"] for row in rows] == [1, 2, 3, 4, 5]
        recomputed = recompute_chain(store.connection.execute("SELECT * FROM events ORDER BY seq").fetchall())
        for row, (prev_hash, record_hash) in zip(rows, recomputed):
            assert row["prev_hash"] == prev_hash, row["seq"]
            assert row["record_hash"] == record_hash, row["seq"]
        assert store.chain_head() == (5, rows[-1]["record_hash"])
        # chain hash is derived from the record payload and ordering
        first = chain_payload_from_row(
            store.connection.execute("SELECT * FROM events WHERE seq = 1").fetchone()
        )
        assert first["payload"]["index"] == 1
    finally:
        store.close()


def test_evidence_append_only_trigger_and_tamper_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "db.sqlite"
    store = EvidenceStore(db_path, tmp_path / "cas")
    try:
        _append_basic_events(store, count=4)
        # Casual tampering must fail loudly while triggers are installed.
        with pytest.raises(sqlite3.DatabaseError):
            store.connection.execute(
                "UPDATE events SET payload_json = '{}' WHERE seq = 2"
            )
        # A determined attacker can drop the trigger; the chain must still detect it.
        raw = sqlite3.connect(str(db_path))
        try:
            raw.execute("DROP TRIGGER events_no_update")
            raw.execute(
                "UPDATE events SET payload_json = ? WHERE seq = 2",
                (json.dumps({"index": 999, "note": "tampered"}),),
            )
            raw.commit()
        finally:
            raw.close()
        status = store.chain_status()
        assert status.ok is False
        assert status.broken_at_seq == 2
        assert "mismatch" in status.error
    finally:
        store.close()


def test_evidence_deletion_is_detected_as_truncation(tmp_path: Path) -> None:
    db_path = tmp_path / "db.sqlite"
    store = EvidenceStore(db_path, tmp_path / "cas")
    try:
        _append_basic_events(store, count=4)
        raw = sqlite3.connect(str(db_path))
        try:
            raw.execute("DROP TRIGGER events_no_delete")
            raw.execute("DELETE FROM events WHERE seq = 4")
            raw.commit()
        finally:
            raw.close()
        status = store.chain_status()
        assert status.ok is False
        assert "truncated" in status.error or "head" in status.error
    finally:
        store.close()


def test_evidence_export_is_deterministic_and_read_only(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "db.sqlite", tmp_path / "cas")
    try:
        _append_basic_events(store, count=3)
        store.append_event(
            task_id="t-other",
            source="verifier",
            event_type="other_task_event",
            payload={"note": "other"},
        )
        before_count = store.count_events()
        before_head = store.chain_head()
        first = store.export_events_jsonl(task_id="t-evidence", out_path=tmp_path / "one.jsonl")
        second = store.export_events_jsonl(task_id="t-evidence", out_path=tmp_path / "two.jsonl")
        assert (tmp_path / "one.jsonl").read_bytes() == (tmp_path / "two.jsonl").read_bytes()
        assert first.sha256 == second.sha256 == sha256_file(tmp_path / "one.jsonl")
        # A fresh store on the same database must produce byte-identical output.
        store.close()
        reopened = EvidenceStore(tmp_path / "db.sqlite", tmp_path / "cas")
        try:
            third = reopened.export_events_jsonl(task_id="t-evidence", out_path=tmp_path / "three.jsonl")
            assert third.sha256 == first.sha256
            assert reopened.count_events() == before_count
            assert reopened.chain_head() == before_head
            lines = (tmp_path / "three.jsonl").read_text(encoding="utf-8").splitlines()
            seqs = [json.loads(line)["seq"] for line in lines]
            assert seqs == sorted(seqs)
            assert all(isinstance(json.loads(line)["payload"], dict) for line in lines)
            assert all(json.loads(line)["task_id"] == "t-evidence" for line in lines)
        finally:
            reopened.close()
    finally:
        if store.connection is not None:
            store.close()


def test_cas_integrity_and_corruption_fail_closed(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "db.sqlite", tmp_path / "cas")
    try:
        ref = store.store_artifact(b"original-evidence-bytes", media_type="text/plain", source="verifier")
        assert store.cas.verify(ref.sha256) is True
        assert store.read_artifact(ref.sha256) == b"original-evidence-bytes"
        # Same bytes deduplicate to the same immutable object.
        again = store.store_artifact(b"original-evidence-bytes", media_type="text/plain")
        assert again.sha256 == ref.sha256
        # Corrupt the object on disk: verification must report it, not trust it.
        store.cas.path_for(ref.sha256).write_bytes(b"corrupted")
        assert store.cas.verify(ref.sha256) is False
        with pytest.raises(StorageError):
            store.cas.put_bytes(b"original-evidence-bytes")
    finally:
        store.close()


def test_zstd_multiframe_decoding_and_fail_closed_backend(tmp_path: Path) -> None:
    records = [
        {"type": "turn/start", "seq": 1, "time": 1000, "data": {"turn": 1}},
        {"type": "tool/call", "seq": 2, "time": 2000, "data": {"callId": "c1", "name": "internal.file_hash"}},
        {"type": "tool/result", "seq": 3, "time": 3000, "data": {"message": {"toolCallId": "c1", "content": [{"type": "text", "text": "ok exit code: 0"}]}}},
    ]
    data, payload = build_multiframe_session_log(records)
    report = decode_all(data)
    assert report.complete is True
    assert len(report.frames) == 2
    assert report.payload() == payload
    assert report.backend in {"zstandard", "stdlib"}
    assert probe_backends(), "no zstd backend available; ingestion would be BLOCKED"
    with pytest.raises(UnsupportedCompressionError):
        decode_all(data, backend="does-not-exist")

    # A truncated tail frame is an explicit gap, never silently dropped.
    truncated = compress_zstd_frame(records[0].__repr__().encode()) + b"\x28\xb5\x2f\xfd\x00\x00"
    truncated_report = decode_all(truncated)
    assert truncated_report.complete is False
    assert truncated_report.gaps


def test_ingestion_is_multiframe_correlated_and_idempotent(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "db.sqlite", tmp_path / "cas")
    try:
        records = [
            {"type": "turn/start", "seq": 1, "time": 1000, "data": {"turn": 1}},
            {"type": "tool/call", "seq": 2, "time": 2000, "data": {"callId": "c1", "name": "internal.file_hash", "arguments": "{\"path\":\"a\"}"}},
            {"type": "tool/result", "seq": 3, "time": 3000, "data": {"message": {"toolCallId": "c1", "content": [{"type": "text", "text": "digest output exit code: 0"}]}}},
        ]
        data, payload = build_multiframe_session_log(records)
        first = store.ingest_session_log_bytes(
            task_id="t-evidence",
            worker_id="w-evidence",
            session_id="sess-evidence",
            data=data,
            source_id="session:sess-evidence",
        )
        assert first["frames"] == 2
        assert first["decoded_records"] == 3
        assert first["appended"] >= 3
        assert first["complete"] is True
        assert first["raw_sha256"] == sha256_bytes(data)
        assert store.cas.verify(first["raw_sha256"]) is True
        assert store.read_artifact(first["raw_sha256"]) == data
        event_types = [event["event_type"] for event in store.list_events(task_id="t-evidence")]
        assert "tool_call" in event_types and "tool_result" in event_types
        result_event = next(
            event for event in store.list_events(task_id="t-evidence") if event["event_type"] == "tool_result"
        )
        payload_obj = result_event["payload"]
        assert payload_obj["call_id"] == "c1"
        assert payload_obj["exit_code"] == 0
        assert store.cas.verify(payload_obj["content_sha256"]) is True
        head_before = store.chain_head()
        count_before = store.count_events()
        second = store.ingest_session_log_bytes(
            task_id="t-evidence",
            worker_id="w-evidence",
            session_id="sess-evidence",
            data=data,
            source_id="session:sess-evidence",
        )
        assert second["appended"] == 0, second
        assert second["skipped_duplicates"] > 0
        assert store.chain_head() == head_before
        assert store.count_events() == count_before
        assert store.ingest_state("session:sess-evidence") is not None
        assert store.chain_status().ok is True
    finally:
        store.close()


def test_corrupt_frame_ingestion_records_explicit_gaps(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "db.sqlite", tmp_path / "cas")
    try:
        good = compress_zstd_frame(b'{"type":"turn/start","seq":1,"time":1,"data":{}}\n')
        truncated = good + b"\x28\xb5\x2f\xfd" + b"\x00" * 8
        report = store.ingest_session_log_bytes(
            task_id="t-gap",
            worker_id=None,
            session_id="sess-gap",
            data=truncated,
            source_id="session:sess-gap",
        )
        assert report["complete"] is False
        assert report["gaps"]
        gap_events = [
            event
            for event in store.list_events(task_id="t-gap")
            if event["event_type"] == "evidence_gap"
        ]
        assert gap_events, "structural damage must produce explicit gap events"
        assert {event["payload"]["reason"] for event in gap_events} & {
            "truncated_frame",
            "frame_decode_error",
            "trailing_bytes",
        }
        assert store.chain_status().ok is True
    finally:
        store.close()


# ===========================================================================
# C. Manager: fake ACP -> 2 active + 3rd FIFO + promotion, persistence,
#    cancel-close-failure, recovery without duplicate sessions, no prompt
# ===========================================================================


def test_manager_two_active_third_fifo_and_promotion(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        first = service.create_task(title="first", category="misc", conversation_id="conv-1")
        second = service.create_task(title="second", category="web", conversation_id="conv-1")
        third = service.create_task(title="third", category="crypto", conversation_id="conv-1")
        assert first.status is TaskStatus.RUNNING
        assert second.status is TaskStatus.RUNNING
        assert third.status is TaskStatus.QUEUED
        assert store.count_active_slots() == 2
        assert len(fake.new_sessions) == 2
        assert fake.list_sessions_calls == [], "Manager must not depend on session/list"
        assert service.get_task_status(third.task_id)["queue_position"] == 1

        # one Task = one session = one workspace, persisted before ready
        for task in (first, second):
            status = service.get_task_status(task.task_id)
            worker = status["worker"]
            assert worker is not None
            assert status["task"]["acp_session_id"] == worker["acp_session_id"]
            assert Path(worker["workspace_path"]).is_dir()
            assert status["task"]["workspace_path"] == worker["workspace_path"]
            stored_worker = store.get_worker(worker["worker_id"])
            assert stored_worker is not None and stored_worker.worker_token
            session = next(
                item for item in fake.new_sessions if item["cwd"] == worker["workspace_path"]
            )
            mcp_servers = session["mcp_servers"]
            assert mcp_servers and mcp_servers[0]["name"] == "ctf-exec"
            # ACP v1 standard env is an ordered {name, value} entry array.
            env_entries = mcp_servers[0]["env"]
            assert isinstance(env_entries, list)
            env = {entry["name"]: entry["value"] for entry in env_entries}
            assert env["CTF_SOLVER_WORKER_TOKEN"] == stored_worker.worker_token

        sessions = {item["session_id"] for item in fake.new_sessions}
        assert len(sessions) == 2
        workspaces = {item["cwd"] for item in fake.new_sessions}
        assert len(workspaces) == 2

        # FIFO promotion after a slot is released
        cancelled = service.cancel_task(first.task_id, reason="verifier cancel")
        assert cancelled["status"] == "cancelled"
        assert cancelled["quiescent"] is True
        assert len(fake.new_sessions) == 3
        promoted = service.get_task(third.task_id)
        assert promoted.status is TaskStatus.RUNNING
        assert promoted.acp_session_id == fake.new_sessions[2]["session_id"]
        assert store.count_active_slots() == 2
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_persists_mapping_before_worker_is_ready(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    observations: list[tuple[str, object, object]] = []

    def on_new_session(cwd: str, mcp_servers: object) -> None:
        task = next(
            task for task in store.list_tasks() if Path(task.workspace_path).resolve() == Path(cwd).resolve()
        )
        observations.append((task.status.value, store.get_worker_for_task(task.task_id), cwd))

    fake.on_new_session = on_new_session
    service.start()
    try:
        task = service.create_task(title="persisted", category="reverse", conversation_id="conv-1")
        assert observations, "the ACP session must be requested during task start"
        status_at_session_request, worker_at_session_request, cwd = observations[0]
        assert status_at_session_request == "starting"
        assert worker_at_session_request is None, "a Worker must not be READY before session/new"
        stored = store.require_task(task.task_id)
        assert stored.status is TaskStatus.RUNNING
        assert stored.acp_session_id
        worker = store.get_worker_for_task(task.task_id)
        assert worker is not None
        assert worker.acp_session_id == stored.acp_session_id
        assert worker.workspace_path == stored.workspace_path
        assert worker.status in {WorkerStatus.READY, WorkerStatus.RUNNING}
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_cancel_close_failure_keeps_slot_and_stays_cancel_requested(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        first = service.create_task(title="first", category="misc", conversation_id="conv-1")
        second = service.create_task(title="second", category="misc", conversation_id="conv-1")
        third = service.create_task(title="third", category="misc", conversation_id="conv-1")
        first_status = service.get_task_status(first.task_id)
        session_to_break = first_status["worker"]["acp_session_id"]
        fake.close_failure_sessions.add(session_to_break)

        result = service.cancel_task(first.task_id, reason="verifier close failure")
        assert result["status"] == "cancel_requested"
        assert result["quiescent"] is False
        assert "close_error" in result["diagnostics"]
        assert store.require_task(first.task_id).status is TaskStatus.CANCEL_REQUESTED
        # The slot is NOT released: worker still occupies it, third Task stays queued.
        assert store.count_active_slots() == 2
        assert store.require_task(third.task_id).status is TaskStatus.QUEUED
        assert len(fake.new_sessions) == 2
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_start_failure_is_isolated_and_releases_slot(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        first = service.create_task(title="first", category="misc", conversation_id="conv-1")
        second = service.create_task(title="second", category="misc", conversation_id="conv-1")
        third = service.create_task(title="third", category="misc", conversation_id="conv-1")
        fake.fail_new_session = True
        result = service.cancel_task(first.task_id, reason="release slot for failing start")
        assert result["status"] == "cancelled"
        failed = store.require_task(third.task_id)
        assert failed.status is TaskStatus.FAILED
        assert failed.result_state == "start_failed"
        assert store.require_task(second.task_id).status is TaskStatus.RUNNING
        assert store.count_active_slots() == 1
        failures = evidence.list_events(task_id=third.task_id, event_type="task_failed")
        assert failures, "a start failure must be recorded as durable evidence"
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_recovery_never_duplicates_sessions(tmp_path: Path) -> None:
    root = tmp_path / "recovery-root"
    config = SolverConfig(root=root)
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir))
    # Simulate durable state left by a previous Manager process.
    old_workspace = paths.task_workspace("t-recover")
    old_workspace.mkdir(parents=True, exist_ok=True)
    store.create_task(
        TaskRecord(
            task_id="t-recover",
            conversation_id="conv-old",
            title="previous run",
            category=Category.MISC,
            workspace_path=str(old_workspace),
            status=TaskStatus.CREATED,
        )
    )
    store.set_task_status("t-recover", TaskStatus.QUEUED)
    store.set_task_status("t-recover", TaskStatus.STARTING)
    store.activate_task(
        "t-recover",
        worker=WorkerRecord(
            worker_id="w-recover",
            task_id="t-recover",
            acp_session_id="sess-old-session",
            workspace_path=str(old_workspace),
            status=WorkerStatus.READY,
            worker_token="token-old-session",
        ),
    )
    store.set_worker_status("w-recover", WorkerStatus.RUNNING)
    queued_workspace = paths.task_workspace("t-queued")
    queued_workspace.mkdir(parents=True, exist_ok=True)
    store.create_task(
        TaskRecord(
            task_id="t-queued",
            conversation_id="conv-old",
            title="queued task",
            category=Category.WEB,
            workspace_path=str(queued_workspace),
            status=TaskStatus.CREATED,
        )
    )
    store.set_task_status("t-queued", TaskStatus.QUEUED)

    fake = FakeAcpClient()
    service, fake, store, evidence, _config = _build_manager(tmp_path, fake=fake, root_name="recovery-root")
    service.start()
    try:
        recovered = store.require_task("t-recover")
        assert recovered.status is TaskStatus.INTERRUPTED
        assert recovered.acp_session_id == "sess-old-session", "mapping must be preserved truthfully"
        workers = [worker for worker in store.list_workers() if worker.task_id == "t-recover"]
        assert len(workers) == 1
        assert len(fake.new_sessions) == 1, "only the previously queued task may start"
        assert fake.new_sessions[0]["cwd"] != str(old_workspace)
        assert fake.resumed == [], "Round 1 recovery must not resume/duplicate the old session"
        # A second recovery pass honestly interrupts the now-running Task (Round 1
        # does not resume sessions) but must never create a duplicate session.
        second = service.recover()
        assert [item["task_id"] for item in second["interrupted"]] == ["t-queued"]
        assert second["interrupted"][0]["session_duplicate_created"] is False
        assert len(fake.new_sessions) == 1
        workers = [worker for worker in store.list_workers() if worker.task_id == "t-queued"]
        assert len(workers) == 1
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_continue_never_calls_prompt(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        task = service.create_task(title="continue", category="pwn", conversation_id="conv-1")
        result = service.continue_task(task.task_id, "继续")
        assert result["model_call_suppressed"] is True
        assert result["accepted"] is True
        assert fake.prompt_calls == [], "Round 1 must never issue session/prompt"
        suppressed = evidence.list_events(task_id=task.task_id, event_type="model_call_suppressed")
        assert suppressed, "the suppressed continuation must be durable evidence"
        service.cancel_task(task.task_id, reason="terminal")
        with pytest.raises(StateError):
            service.continue_task(task.task_id, "after terminal")
    finally:
        _teardown_manager(service, store, evidence)


class _HumanConfirmationChannel:
    """Round 2 test double: only the local console channel can confirm an approval."""

    def __init__(self, *, os_user: str = "human-verifier") -> None:
        self.os_user = os_user

    def confirm(self, *, approval_digest: str, summary: str):
        from ctf_solver.security.confirmation import HumanConfirmation

        assert approval_digest
        return HumanConfirmation(
            channel="local_console",
            os_user=self.os_user,
            confirmed_at=1_700_000_000_000,
            confirmation_id="conf-verifier",
            approval_digest=approval_digest,
            note="verifier",
        )


def test_manager_approvals_grants_flag_and_screenshots(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        task = service.create_task(title="controls", category="misc", conversation_id="conv-1")
        approval = service.request_approval(
            task.task_id,
            action_kind="remote_target",
            details={
                "target": {
                    "host": "127.0.0.1",
                    "port": 8080,
                    "protocol": "tcp",
                    "method": "GET",
                    "path_prefix": "/",
                },
                "profile": "synthetic-local",
                "grant_ttl_s": 60,
                "max_calls": 2,
            },
            ttl_s=600,
        )
        assert approval.status is ApprovalStatus.PENDING
        # No Agent/MCP path may decide an approval.
        with pytest.raises(StateError):
            service.decide_approval(approval.approval_id, approved=True, approver="")
        with pytest.raises(StateError):
            service.decide_approval(
                approval.approval_id, approved=True, approver="human-verifier"
            )
        approved = service.confirm_approval(
            approval.approval_id, channel=_HumanConfirmationChannel(), note="ok"
        )
        assert approved.status is ApprovalStatus.APPROVED
        assert approved.approver == "human-verifier"
        assert approved.confirmation_channel == "local_console"
        assert service.list_approvals(task_id=task.task_id)[0].approval_id == approval.approval_id

        grant = service.create_grant_from_approval(
            approval.approval_id,
            competition_profile="synthetic-local",
            host="127.0.0.1",
            port=8080,
            protocol="tcp",
            method="GET",
            path_prefix="/",
        )
        assert grant.task_id == task.task_id and grant.grant_digest
        assert grant.max_calls == 2
        assert grant.approval_id == approval.approval_id
        revoked = service.revoke_grant(grant.grant_id)
        assert revoked.status is GrantStatus.REVOKED
        assert service.list_grants(task_id=task.task_id)[0].grant_id == grant.grant_id

        flag = service.record_candidate_flag(task.task_id, flag="FLAG{synthetic_verifier}", source="verifier")
        assert flag["flag_state"] == "candidate"
        assert flag["submitted"] is False
        assert store.require_task(task.task_id).flag_state.value == "candidate"
        flag_events = evidence.list_events(task_id=task.task_id, event_type="flag_candidate")
        assert flag_events
        assert "FLAG{synthetic_verifier}" not in json.dumps(flag_events[0]["payload"])

        screenshot = service.take_screenshot(task.task_id, step_id="step-1", scope="desktop")
        assert screenshot.status is CaptureStatus.OK
        assert screenshot.sha256 and evidence.cas.verify(screenshot.sha256)
        assert screenshot.task_id == task.task_id
        assert screenshot.worker_id is not None
        assert screenshot.session_id == store.require_task(task.task_id).acp_session_id
        assert screenshot.captured_at > 0
        shots = evidence.list_screenshots(task.task_id)
        assert len(shots) == 1 and shots[0].sha256 == screenshot.sha256

        service.capturer = FakeScreenCapturer("blank")
        blank = service.take_screenshot(task.task_id, step_id="step-2")
        assert blank.status is CaptureStatus.BLANK
        assert blank.sha256 is None
        assert blank.failure_reason
        failed_events = evidence.list_events(task_id=task.task_id, event_type="screenshot_failed")
        assert failed_events, "a blank capture must be recorded honestly as a failure"

        status = service.get_task_status(task.task_id)
        assert status["evidence"]["chain_head_hash"] == evidence.chain_head()[1]
        assert status["evidence"]["chain_status"]["ok"] is True
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_pause_is_truthful_and_holds_slot(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        task = service.create_task(title="pause", category="misc", conversation_id="conv-1")
        paused = service.pause_task(task.task_id, reason="verifier pause")
        assert paused["status"] == "paused"
        assert paused["os_kill"] is False
        assert fake.cancelled, "ACP cancel notification must be sent"
        assert store.require_task(task.task_id).status is TaskStatus.PAUSED
        assert store.count_active_slots() == 1
        events = evidence.list_events(task_id=task.task_id, event_type="task_paused")
        assert events and events[0]["payload"]["os_kill"] is False
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_input_validation(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        with pytest.raises(ValidationError):
            service.create_task(title="", category="misc", conversation_id="conv-1")
        with pytest.raises(ValidationError):
            service.create_task(title="x", category="misc", conversation_id="")
        with pytest.raises(ValueError):
            service.create_task(title="x", category="not-a-category", conversation_id="conv-1")
        assert fake.new_sessions == []
    finally:
        _teardown_manager(service, store, evidence)


def test_manager_shared_acp_failure_interrupts_tasks_never_completes(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        first = service.create_task(title="crash-a", category="misc", conversation_id="conv-1")
        second = service.create_task(title="crash-b", category="misc", conversation_id="conv-1")
        result = service.handle_acp_failure("simulated shared ACP server crash")
        assert set(result["interrupted"]) == {first.task_id, second.task_id}
        for task_id in (first.task_id, second.task_id):
            stored = store.require_task(task_id)
            assert stored.status is TaskStatus.INTERRUPTED
            assert stored.status is not TaskStatus.COMPLETED
            worker = store.get_worker_for_task(task_id)
            assert worker is not None and worker.status is WorkerStatus.CRASHED
            events = evidence.list_events(task_id=task_id, event_type="task_interrupted")
            assert events and events[0]["payload"]["quiescent"] is False
        assert store.count_active_slots() == 0
        status = service.runtime_status()
        assert status["acp"]["ready"] is False
    finally:
        _teardown_manager(service, store, evidence)


def test_runtime_status_reports_round1_limits_honestly(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        limits = service.runtime_status()["round1_limits"]
        assert "blocked" in limits["model_calls"].lower()
        assert "blocked" in limits["untrusted_challenge_code"].lower()
        assert limits["main_conversation_entrypoint"].startswith("BLOCKED")
        assert "BLOCKED" in limits["session_log_negative_delivery_test"]
    finally:
        _teardown_manager(service, store, evidence)


# ===========================================================================
# D. MCP surfaces: Manager control tools, ctf-exec typed tool, identity
# ===========================================================================


class _FakeManagerControl:
    """Minimal ManagerControl double used only to build/describe MCP tools."""

    def create_task(self, **kwargs: object) -> dict[str, object]:
        return {"task_id": "t-1", **kwargs}

    def list_tasks(self, **kwargs: object) -> list[object]:
        return []

    def get_task_status(self, task_id: str) -> dict[str, object]:
        return {"task_id": task_id}

    def continue_task(self, task_id: str, message: str = "") -> dict[str, object]:
        return {"task_id": task_id, "model_call_suppressed": True}

    def pause_task(self, task_id: str, reason: str = "") -> dict[str, object]:
        return {"task_id": task_id, "status": "paused"}

    def cancel_task(self, task_id: str, reason: str = "") -> dict[str, object]:
        return {"task_id": task_id, "status": "cancelled"}

    def complete_task(
        self, task_id: str, *, result_state: str, note: str = ""
    ) -> dict[str, object]:
        return {"task_id": task_id, "status": "completed", "result_state": result_state}

    def request_approval(self, task_id: str, **kwargs: object) -> dict[str, object]:
        return {"task_id": task_id, **kwargs}

    def list_approvals(self, task_id: str | None = None) -> list[object]:
        return []

    def revoke_grant(self, grant_id: str) -> dict[str, object]:
        return {"grant_id": grant_id}

    def list_grants(self, task_id: str | None = None) -> list[object]:
        return []

    def record_candidate_flag(self, task_id: str, flag: str, source: str) -> dict[str, object]:
        return {"task_id": task_id, "flag_state": "candidate", "submitted": False}

    def take_screenshot(self, task_id: str, step_id: str | None = None, scope: str = "desktop") -> dict[str, object]:
        return {"task_id": task_id, "status": "ok"}

    def ingest_session_log(self, task_id: str, worker_id: str | None = None) -> dict[str, object]:
        return {"task_id": task_id}

    def export_events(self, task_id: str) -> dict[str, object]:
        return {"task_id": task_id}

    def build_writeup(self, task_id: str) -> dict[str, object]:
        return {"task_id": task_id}

    def export_evidence_zip(self, task_id: str) -> dict[str, object]:
        return {"task_id": task_id}

    def runtime_status(self) -> dict[str, object]:
        return {"active_workers": 0}


def test_manager_mcp_tool_surface_and_no_flag_submission() -> None:
    tools = build_manager_tools(_FakeManagerControl())
    names = {tool.name for tool in tools}
    assert names == EXPECTED_MANAGER_TOOLS
    assert not (names & FORBIDDEN_ESCALATION_TOOLS), "model must not be able to approve or authorize"
    assert all(name.startswith("ctf_") for name in names)
    assert "ctf_flag_candidate" in names
    assert not any("submit" in name.lower() for name in names), "no Flag submission tool may exist"
    assert "ctf_exec" not in names, "the Manager control server must not expose the Worker exec tool"
    for tool in tools:
        assert tool.input_schema.get("additionalProperties") is False, tool.name
        assert "shell" not in tool.input_schema.get("properties", {}), tool.name
        assert "command" not in tool.input_schema.get("properties", {}), tool.name

    server = build_manager_server(_FakeManagerControl())
    result = server._call_tool({"name": "ctf_task_list", "arguments": {}})
    assert result["isError"] is False
    payload = json.loads(result["content"][0]["text"])
    assert payload == []
    with pytest.raises(JsonRpcProtocolError):
        server._call_tool({"name": "ctf_flag_submit", "arguments": {}})
    with pytest.raises(JsonRpcProtocolError):
        server._call_tool({"name": "ctf_task_status", "arguments": {}})  # missing task_id


def test_exec_mcp_server_exposes_one_typed_tool_only() -> None:
    server = build_exec_server(
        env={
            "CTF_SOLVER_IPC_URL": "tcp://127.0.0.1:9",
            "CTF_SOLVER_WORKER_TOKEN": "env-injected-worker-token",
        }
    )
    assert set(server.tools) == {"ctf_exec"}
    tool = server.tools["ctf_exec"]
    properties = tool.input_schema["properties"]
    assert properties["argv"]["type"] == "array"
    assert properties["argv"]["items"]["type"] == "string"
    for forbidden in ("shell", "command", "cmd", "powershell", "executable"):
        assert forbidden not in properties
    assert tool.input_schema["additionalProperties"] is False
    required = set(tool.input_schema["required"])
    assert {"task_id", "worker_id", "step_id", "tool_name", "argv", "cwd"} <= required

    class _RecordingClient:
        def __init__(self) -> None:
            self.requests: list[dict[str, object]] = []

        def execute(self, request: dict[str, object]) -> dict[str, object]:
            self.requests.append(dict(request))
            return {"status": "denied", "reason_code": "synthetic"}

    recording = _RecordingClient()
    service = ExecToolService(recording)  # type: ignore[arg-type]
    with pytest.raises(McpToolError):
        service.ctf_exec({"argv": "ls -la", "tool_name": "test.echo"})
    assert recording.requests == [], "a shell-string argv must be rejected before the IPC call"
    service.ctf_exec({"argv": ["--version"], "tool_name": "test.echo"})
    assert len(recording.requests) == 1


def test_manager_ipc_identity_comes_from_outer_token_not_arguments() -> None:
    class _Handler:
        def __init__(self) -> None:
            self.tokens: list[str] = []
            self.params: list[dict[str, object]] = []

        def ipc_worker_info(self, token: str) -> dict[str, object]:
            self.tokens.append(token)
            return {"worker_id": "w-1"}

        def ipc_exec(self, token: str, params: dict[str, object]) -> dict[str, object]:
            self.tokens.append(token)
            self.params.append(dict(params))
            return {"status": "denied"}

    handler = _Handler()
    server = ManagerIpcServer(handler)  # type: ignore[arg-type]
    response = server._dispatch(
        {
            "id": 1,
            "token": "outer-authenticated-token",
            "method": "ctf_exec",
            "params": {"token": "evil-override", "worker_id": "w-other", "argv": []},
        }
    )
    assert response["result"] == {"status": "denied"}
    assert handler.tokens == ["outer-authenticated-token"]
    assert handler.params[0]["token"] == "evil-override"  # forwarded data, ignored for identity

    missing = server._dispatch({"id": 2, "method": "ctf_exec", "params": {}})
    assert missing["error"]["reason_code"] == "denied"
    assert handler.tokens == ["outer-authenticated-token"]
    unknown = server._dispatch({"id": 3, "token": "t", "method": "not_a_method", "params": {}})
    assert unknown["error"]["reason_code"] == "ipc_error"


def test_no_arbitrary_shell_tool_in_default_catalog(tmp_path: Path) -> None:
    catalog = RuntimeCatalog.default()
    names = catalog.names()
    assert names, "the default catalogue must not be empty"
    for name in names:
        lowered = name.lower()
        for forbidden in ("shell", "cmd", "powershell", "bash", "eval", "docker"):
            assert forbidden not in lowered, f"dangerous catalogue entry {name}"
    assert any(name.startswith("internal.") for name in names)
    assert "tool.remote_probe" in names

    # Even a directly requested argv cannot turn the fixed-argv probe into a shell.
    config = SolverConfig(root=tmp_path / "default-catalog")
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir))
    try:
        workspace = paths.task_workspace("t-default")
        workspace.mkdir(parents=True, exist_ok=True)
        store.create_task(
            TaskRecord(
                task_id="t-default",
                conversation_id="conv",
                title="default catalog",
                category=Category.MISC,
                workspace_path=str(workspace),
                status=TaskStatus.CREATED,
            )
        )
        store.set_task_status("t-default", TaskStatus.QUEUED)
        store.set_task_status("t-default", TaskStatus.STARTING)
        store.activate_task(
            "t-default",
            worker=WorkerRecord(
                worker_id="w-default",
                task_id="t-default",
                acp_session_id="sess-default",
                workspace_path=str(workspace),
                status=WorkerStatus.READY,
                worker_token="token-default",
            ),
        )
        broker = Broker(repository=store, catalog=catalog)
        request = ExecRequest(
            task_id="t-default",
            worker_id="w-default",
            step_id="s1",
            tool_name="tool.python_version",
            argv=["-c", "import os; os.system('whoami')"],
            cwd=str(workspace),
        )
        decision = broker.authorize(request, "token-default")
        assert not decision.allowed
        assert decision.reason_code == "argv_schema_violation"
    finally:
        store.close()
        evidence.close()


def test_writeup_and_evidence_zip_are_reproducible_and_manifest_verifies(tmp_path: Path) -> None:
    """ACCEPTANCE.md section F: writeup from evidence, ZIP + independent manifest."""

    from ctf_solver.delivery.bundle import EvidenceBundleBuilder

    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        task = service.create_task(title="deliverables", category="misc", conversation_id="conv-1")
        worker = store.get_worker_for_task(task.task_id)
        assert worker is not None
        execution = service.ipc_exec(
            worker.worker_token,
            {
                "task_id": task.task_id,
                "worker_id": worker.worker_id,
                "step_id": "step-1",
                "tool_name": "test.echo",
                "argv": ["artifact.bin"],
                "cwd": task.workspace_path,
            },
        )
        assert execution["status"] == "completed", execution
        service.take_screenshot(task.task_id, step_id="step-1", scope="desktop")
        service.record_candidate_flag(task.task_id, flag="FLAG{delivery}", source="verifier")

        first_writeup = service.build_writeup(task.task_id)
        second_writeup = service.build_writeup(task.task_id)
        assert first_writeup.sha256 == second_writeup.sha256
        text = Path(first_writeup.path).read_text(encoding="utf-8")
        assert "## 4. Chronological steps" in text
        assert "artifact.bin" in text
        assert "screenshots/" in text
        assert "`candidate`" in text

        first_zip = service.export_evidence_zip(task.task_id)
        second_zip = service.export_evidence_zip(task.task_id)
        assert first_zip.sha256 == second_zip.sha256, "evidence ZIP must be reproducible"
        report = EvidenceBundleBuilder.verify_zip(first_zip.path, tmp_path / "zip-extract")
        assert report["ok"] is True, report["problems"]
        assert "manifest.sha256" in report["members"]
        assert "writeup.md" in report["members"]
        assert "events.jsonl" in report["members"]
    finally:
        _teardown_manager(service, store, evidence)


# ===========================================================================
# E. Skills: exactly six, UTF-8 without BOM, valid frontmatter, no stubs
# ===========================================================================


def test_six_skills_are_utf8_without_bom_and_have_frontmatter() -> None:
    assert SKILLS_ROOT.is_dir(), f"project-local skills root missing: {SKILLS_ROOT}"
    directories = sorted(entry.name for entry in SKILLS_ROOT.iterdir() if entry.is_dir())
    assert tuple(sorted(directories)) == tuple(sorted(EXPECTED_SKILLS))
    for name in EXPECTED_SKILLS:
        skill_file = SKILLS_ROOT / name / "SKILL.md"
        assert skill_file.is_file(), skill_file
        raw = skill_file.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), f"{skill_file} has a UTF-8 BOM"
        text = raw.decode("utf-8")  # raises if not UTF-8
        match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
        assert match, f"{skill_file} has no YAML frontmatter"
        header = match.group(1)
        name_match = re.search(r"^name:\s*(.+)$", header, re.MULTILINE)
        description_match = re.search(r"^description:\s*(.+)$", header, re.MULTILINE)
        assert name_match and name_match.group(1).strip().strip("\"'") == name
        assert description_match and description_match.group(1).strip()
    core = (SKILLS_ROOT / "ctf-solver" / "SKILL.md").read_text(encoding="utf-8")
    assert "/ctf-solver" in core
    assert "persist" in core.lower()


def test_no_todo_stub_markers_in_product_or_skills() -> None:
    stub_pattern = re.compile(r"\b(?:TODO|FIXME|XXX|TBD|NotImplemented)\b|\bplaceholder\b|not implemented", re.IGNORECASE)
    for skill_file in SKILLS_ROOT.rglob("SKILL.md"):
        text = skill_file.read_text(encoding="utf-8")
        assert not stub_pattern.search(text), f"stub marker in {skill_file}"
    for python_file in (REPO_ROOT / "ctf_solver").rglob("*.py"):
        text = python_file.read_text(encoding="utf-8")
        assert not stub_pattern.search(text), f"stub marker in {python_file}"
        assert "raise NotImplementedError" not in text, f"stub implementation in {python_file}"


# ===========================================================================
# F. Environment / protected state / honest claims / no model call
# ===========================================================================


def test_model_call_gate_and_config_refuse_round1_model_use(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        SolverConfig(root=tmp_path, allow_model_calls=True)
    client = AcpClient([sys.executable, "-c", "pass"], allow_model_calls=False)
    assert client.state == "stopped"
    with pytest.raises(ModelCallNotAuthorized):
        client.prompt("any-session", [{"type": "text", "text": "must never be sent"}])
    assert REAL_ACP_STARTS == [], "the prompt gate must fail before any ACP process starts"


def test_protected_ctfworker_state_and_audit_hash_unchanged() -> None:
    assert BASELINE_PATH.is_file(), f"verifier baseline missing: {BASELINE_PATH}"
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    worker_dir = Path(r"D:\CTFworker")
    if not worker_dir.is_dir():  # pragma: no cover - environment dependent
        pytest.skip("D:\\CTFworker is not present on this machine")
    status = subprocess.run(
        ["git", "-C", str(worker_dir), "status", "--porcelain"],
        capture_output=True,
        check=False,
    )
    current_hash = sha256_bytes(status.stdout)
    assert status.returncode == baseline["worker_status_exit_code"], (
        "git status on the protected D:\\CTFworker directory failed"
    )
    assert current_hash == baseline["worker_status_sha256"], (
        "protected D:\\CTFworker working-tree state changed during verification "
        f"(start={baseline['worker_status_sha256']}, now={current_hash})"
    )
    audit = Path(baseline["audit_path"])
    assert audit.is_file(), "the local audit report cited by the task is missing"
    assert sha256_file(audit) == "955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373"
    assert audit.stat().st_size == 46444
    profiles = Path.home() / ".dsh" / "profiles"
    if profiles.is_dir() and "desktop" in baseline.get("global_profiles_mtimes_ns", {}):
        assert (profiles / "desktop").stat().st_mtime_ns == baseline["global_profiles_mtimes_ns"]["desktop"], (
            "the live Harness profile directory was modified during verification"
        )


def test_preflight_is_read_only_and_never_launches_wsl_or_docker(tmp_path: Path) -> None:
    root = tmp_path / "preflight-root"
    (root / ".dsh" / "skills").mkdir(parents=True)
    (root / "config" / "acp").mkdir(parents=True)
    before = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in root.rglob("*")
        if path.is_file()
    }
    executed: list[list[str]] = []
    original_run = preflight_doctor.subprocess.run

    def recording_run(argv: object, *args: object, **kwargs: object) -> object:
        if isinstance(argv, (list, tuple)):
            executed.append([str(item) for item in argv])
        return original_run(argv, *args, **kwargs)

    preflight_doctor.subprocess.run = recording_run  # type: ignore[assignment]
    try:
        report = preflight_doctor.run_preflight(root)
    finally:
        preflight_doctor.subprocess.run = original_run  # type: ignore[assignment]
    after = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in root.rglob("*")
        if path.is_file()
    }
    assert before == after, "preflight mutated the project root"
    assert report["read_only"] is True
    assert report["mutations"] == []
    assert report["summary"]["no_environment_mutation"] is True
    assert report["skills"]["ok"] is False  # empty temp tree, but reported honestly
    assert "missing Skills" in " ".join(report["skills"]["problems"])
    for argv in executed:
        joined = " ".join(argv).lower()
        assert "wsl" not in joined, f"preflight launched WSL: {argv}"
        assert "docker" not in joined, f"preflight launched Docker: {argv}"
        assert "runsc" not in joined, f"preflight launched gVisor: {argv}"
    # The repository's own preflight reports the six Skills as valid.
    repo_report = preflight_doctor.run_preflight(REPO_ROOT)
    assert repo_report["skills"]["ok"] is True, repo_report["skills"]["problems"]
    assert repo_report["skills"]["missing"] == []
    assert repo_report["privacy_gate"]["project_patch_disables_delivery"] is True
    assert repo_report["summary"]["acp_launcher_found"] is True


def test_privacy_gate_mechanism_evidence_and_canary_blocked() -> None:
    patch_file = REPO_ROOT / "config" / "acp" / "cordis.patch.yml"
    assert patch_file.is_file()
    patch_text = patch_file.read_text(encoding="utf-8")
    assert "session-log-deepseek" in patch_text
    assert "enabled: false" in patch_text
    # Authors' evidence for the isolated-profile mechanism.
    author_dump = EVIDENCE_RAW / "privacy-gate-dump-config.txt"
    assert author_dump.is_file()
    dump_text = author_dump.read_text(encoding="utf-8")
    assert "patched by" in dump_text and "session-log-deepseek" in dump_text
    assert "enabled: false" in dump_text
    result_file = EVIDENCE_RAW / "privacy-gate-result.txt"
    assert result_file.is_file() and "exit_code=0" in result_file.read_text(encoding="utf-8")
    # The verifier independently reproduced the composed-config evidence.
    verifier_dump = EVIDENCE_RAW / "verifier-privacy-gate-dump-config.txt"
    assert verifier_dump.is_file()
    verifier_text = verifier_dump.read_text(encoding="utf-8-sig")
    assert "session-log-deepseek" in verifier_text
    assert "enabled: false" in verifier_text
    assert (EVIDENCE_RAW / "verifier-privacy-gate-result.txt").is_file()
    # The required negative-delivery canary remains BLOCKED (needs a model call).
    summary = (REPO_ROOT / "round1-evidence" / "privacy-gate.md").read_text(encoding="utf-8")
    assert "BLOCKED" in summary
    assert "canary" in summary.lower()


def test_readme_and_round1_notes_do_not_overclaim() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # Round 2 keeps the honest acceptance posture: candidate, not final MVP acceptance.
    assert (
        "does **not** claim final MVP acceptance" in readme
        or "not claim final MVP acceptance" in readme
    )
    for row_marker in (
        "Main-conversation `/ctf-solver` → Manager tools",
        "Session-log negative delivery canary",
        "Model-mediated Worker / `session/prompt`",
    ):
        assert row_marker in readme, row_marker
    status_table = readme.split("## Current implementation status", 1)[1]
    status_rows = [
        line for line in status_table.splitlines() if line.startswith("|") and "BLOCKED" in line
    ]
    assert len(status_rows) >= 3, "status table must mark Round 2 integration items BLOCKED"
    for blocked_row in status_rows:
        assert "|" in blocked_row
    notes = (REPO_ROOT / "docs" / "ROUND_1_ARCHITECTURE_NOTES.md").read_text(encoding="utf-8")
    assert "BLOCKED" in notes
    assert "NOT VERIFIED" in notes
    assert "It never sent `session/prompt`" in notes
    acceptance = (REPO_ROOT / "docs" / "ACCEPTANCE.md").read_text(encoding="utf-8")
    assert "- [x]" not in acceptance, "ACCEPTANCE.md must not be pre-ticked by the implementation"
    # Repository map entries cited by the README must exist.
    for relative in re.findall(r"^- (docs/[A-Z0-9_]+\.md) —", readme, re.MULTILINE):
        assert (REPO_ROOT / relative).is_file(), relative


def test_clean_room_and_no_auto_install_claims() -> None:
    forbidden = (
        "CTFworker",
        "D:\\CTF\\",
        "D:/CTF/",
        "from backend",
        "import backend",
        "MVP_BACKEND",
        "pip install",
        "winget",
        "choco",
        "apt-get",
        "docker run",
        "wsl.exe",
    )
    for python_file in (REPO_ROOT / "ctf_solver").rglob("*.py"):
        text = python_file.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{needle!r} found in {python_file}"
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["dependencies"] == [], (
        "Round 1 must not declare/install runtime dependencies beyond the existing environment"
    )
    assert pyproject["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]


# ===========================================================================
# G. Round 1 verification findings — permanent Round 2 regression tests
#    (the three defects below were fixed in Round 2 and must never regress)
# ===========================================================================


def test_execution_rows_keep_request_and_denied_result_json(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stack")
    try:
        task, worker = create_running_task(stack)
        allowed = stack.pipeline.execute(make_request(stack, task, worker), worker.worker_token)
        denied = stack.pipeline.execute(
            make_request(stack, task, worker, tool_name="test.not_listed"), worker.worker_token
        )
        allowed_row = stack.store.conn.execute(
            "SELECT request_json, result_json FROM executions WHERE execution_id = ?",
            (allowed.execution_id,),
        ).fetchone()
        assert json.loads(allowed_row["request_json"])["task_id"] == task.task_id
        assert json.loads(allowed_row["result_json"])["execution_id"] == allowed.execution_id
        denied_row = stack.store.conn.execute(
            "SELECT request_json, result_json FROM executions WHERE execution_id = ?",
            (denied.execution_id,),
        ).fetchone()
        assert json.loads(denied_row["request_json"])["tool_name"] == "test.not_listed"
        assert json.loads(denied_row["result_json"])["reason_code"] == "tool_not_allowed"
    finally:
        stack.close()


def test_task_evidence_head_is_persisted(tmp_path: Path) -> None:
    service, fake, store, evidence, _config = _build_manager(tmp_path)
    service.start()
    try:
        task = service.create_task(title="evidence head", category="misc", conversation_id="conv-1")
        head_seq, head_hash = evidence.chain_head()
        assert head_seq > 0
        stored = store.require_task(task.task_id)
        assert stored.evidence_head == head_hash
        info = service.build_writeup(task.task_id)
        text = Path(info.path).read_text(encoding="utf-8")
        assert "Evidence chain head: `unknown`" not in text
    finally:
        _teardown_manager(service, store, evidence)


def test_privacy_gate_evidence_files_are_not_empty() -> None:
    citations = [
        EVIDENCE_RAW / "privacy-gate-exit.txt",
        EVIDENCE_RAW / "privacy-gate-home-path.txt",
        EVIDENCE_RAW / "privacy-gate-result.txt",
        EVIDENCE_RAW / "privacy-gate-dump-config.txt",
    ]
    for path in citations:
        assert path.is_file(), path
        assert path.stat().st_size > 0, f"cited raw evidence file is empty: {path.name}"
