"""Independent fixtures for the Round 1 adversarial acceptance verification.

These helpers are deliberately **not** the authors' ``tests/support/fakes.py``.
The verifier builds every fixture from scratch against the frozen contracts
(``docs/INTERFACES.md``) so that a bug or convenience in the authors' test
helpers cannot hide a product defect.

Write scope: ``tests/support/verification_*`` (verifier-owned). Nothing in this
file is imported by the product.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ctf_solver.core.canonical import GENESIS_HASH, canonical_json, chain_hash, sha256_hex
from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import AcpError
from ctf_solver.core.ids import new_id
from ctf_solver.core.types import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    Category,
    ExecutionStatus,
    ExecutionTier,
    ExecRequest,
    RuntimeOutcome,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.manager.store import ManagerStore
from ctf_solver.policy.broker import Broker, BrokerConfig
from ctf_solver.runtime.catalog import RuntimeCatalog
from ctf_solver.runtime.executor import RuntimeExecutor
from ctf_solver.runtime.pipeline import ExecutionPipeline
from ctf_solver.runtime.tools import ToolInvocation, ToolSpec


# ---------------------------------------------------------------------------
# Clock
# ---------------------------------------------------------------------------


class VerificationClock:
    """Deterministic millisecond clock with explicit advancement."""

    def __init__(self, start_ms: int = 1_700_000_000_000) -> None:
        self._now = int(start_ms)

    def now_ms(self) -> int:
        return self._now

    def advance(self, milliseconds: int) -> int:
        self._now += int(milliseconds)
        return self._now


# ---------------------------------------------------------------------------
# Synthetic trusted tools (catalog is Manager-owned and test-extensible)
# ---------------------------------------------------------------------------


def _echo_internal(invocation: ToolInvocation) -> RuntimeOutcome:
    payload = {"argv": list(invocation.argv), "cwd": invocation.cwd}
    return RuntimeOutcome(
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout=canonical_json(payload).encode("utf-8"),
    )


def _failing_internal(invocation: ToolInvocation) -> RuntimeOutcome:
    return RuntimeOutcome(
        status=ExecutionStatus.FAILED,
        exit_code=7,
        stdout=b"partial stdout\n",
        stderr=b"synthetic failure\n",
        error="synthetic tool failure",
    )


def _fixed_argv(argv: list[str]) -> str | None:
    if list(argv) != ["--version"]:
        return "this tool accepts exactly the fixed argv ['--version']"
    return None


def build_verification_tool_specs() -> list[ToolSpec]:
    """Synthetic catalogue covering every Broker decision branch.

    The shipped ``RuntimeCatalog.default()`` is also exercised separately; these
    specs make the tier/network/approval branches reachable without pretending a
    real isolated network tool exists.
    """

    return [
        ToolSpec(
            name="test.echo",
            display_name="Verifier echo (Tier 0 internal)",
            description="Deterministic internal tool returning its own argv/cwd.",
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            internal=_echo_internal,
        ),
        ToolSpec(
            name="test.fail",
            display_name="Verifier failing tool",
            description="Internal tool that always fails with exit code 7.",
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            internal=_failing_internal,
        ),
        ToolSpec(
            name="test.fixed_argv",
            display_name="Verifier fixed-argv probe",
            description="Tier 1 probe accepting exactly ['--version'].",
            tier=ExecutionTier.TIER1_TRUSTED,
            version="1",
            internal=_echo_internal,
            arg_validator=_fixed_argv,
        ),
        ToolSpec(
            name="test.approved",
            display_name="Verifier approval-required tool",
            description="Tier 1 tool requiring a Task-scoped human approval.",
            tier=ExecutionTier.TIER1_TRUSTED,
            version="1",
            internal=_echo_internal,
            requires_approval=ApprovalAction.TOOL_ACTION,
        ),
        ToolSpec(
            name="test.net_probe",
            display_name="Verifier network-scope tool",
            description="Tier 1 network-capable stub used only to exercise grant policy.",
            tier=ExecutionTier.TIER1_TRUSTED,
            version="1",
            internal=_echo_internal,
            network=True,
        ),
        ToolSpec(
            name="test.untrusted",
            display_name="Verifier untrusted-code tool",
            description="Would execute challenge-provided code; must be denied in Round 1.",
            tier=ExecutionTier.TIER1_TRUSTED,
            version="1",
            internal=_echo_internal,
            executes_challenge_code=True,
            requires_approval=ApprovalAction.UNTRUSTED_CODE,
        ),
        ToolSpec(
            name="test.tier2",
            display_name="Verifier Tier 2 tool",
            description="Declared Tier 2 tool; Tier 2 is unavailable in Round 1.",
            tier=ExecutionTier.TIER2_ISOLATED,
            version="1",
            internal=_echo_internal,
        ),
    ]


# ---------------------------------------------------------------------------
# Real Manager/Runtime/Broker/Evidence stack on tmp_path
# ---------------------------------------------------------------------------


@dataclass
class VerificationStack:
    root: Path
    config: SolverConfig
    store: ManagerStore
    evidence: EvidenceStore
    catalog: RuntimeCatalog
    broker: Broker
    executor: RuntimeExecutor
    pipeline: ExecutionPipeline
    clock: VerificationClock

    def close(self) -> None:
        for candidate in (self.store, self.evidence):
            try:
                candidate.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass


class SpyExecutor(RuntimeExecutor):
    """Records every executor call so 'denied before execution' is provable."""

    def __init__(self, clock: VerificationClock | None = None) -> None:
        super().__init__(clock=clock)
        self.calls: list[str] = []
        self.invocations: list[ToolInvocation] = []

    def execute(self, spec: ToolSpec, invocation: ToolInvocation) -> RuntimeOutcome:  # type: ignore[override]
        self.calls.append(spec.name)
        self.invocations.append(invocation)
        return super().execute(spec, invocation)


def build_stack(
    root: Path,
    *,
    network_enabled: bool = False,
    available_tiers: tuple[ExecutionTier, ...] | None = None,
) -> VerificationStack:
    config = SolverConfig(root=root)
    paths = config.ensure_layout()
    clock = VerificationClock()
    store = ManagerStore(str(paths.db_path), clock)
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir), clock=clock)
    catalog_kwargs: dict[str, Any] = {}
    if available_tiers is not None:
        catalog_kwargs["available_tiers"] = available_tiers
    catalog = RuntimeCatalog(tools=build_verification_tool_specs(), **catalog_kwargs)
    broker = Broker(
        repository=store,
        catalog=catalog,
        clock=clock,
        config=BrokerConfig(network_enabled=network_enabled),
    )
    executor = SpyExecutor(clock)
    pipeline = ExecutionPipeline(
        repository=store,
        evidence=evidence,
        broker=broker,
        executor=executor,
        clock=clock,
    )
    return VerificationStack(
        root=root,
        config=config,
        store=store,
        evidence=evidence,
        catalog=catalog,
        broker=broker,
        executor=executor,
        pipeline=pipeline,
        clock=clock,
    )


def create_running_task(
    stack: VerificationStack,
    *,
    task_id: str = "t-verify-1",
    worker_id: str = "w-verify-1",
    session_id: str = "sess-verify-1",
    token: str | None = None,
    title: str = "Verifier synthetic task",
    scope_profile: str = "synthetic-local",
) -> tuple[TaskRecord, WorkerRecord]:
    workspace = stack.config.paths.task_workspace(task_id)
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskRecord(
        task_id=task_id,
        conversation_id="conv-verify",
        title=title,
        category=Category.MISC,
        workspace_path=str(workspace),
        scope_profile=scope_profile,
        status=TaskStatus.CREATED,
    )
    stack.store.create_task(task)
    stack.store.set_task_status(task_id, TaskStatus.QUEUED)
    stack.store.set_task_status(task_id, TaskStatus.STARTING)
    worker = WorkerRecord(
        worker_id=worker_id,
        task_id=task_id,
        acp_session_id=session_id,
        workspace_path=str(workspace),
        status=WorkerStatus.READY,
        worker_token=token or f"token-{worker_id}",
    )
    stack.store.activate_task(task_id, worker=worker)
    stack.store.set_worker_status(worker_id, WorkerStatus.RUNNING)
    return stack.store.require_task(task_id), stack.store.require_worker(worker_id)


def make_request(
    stack: VerificationStack,
    task: TaskRecord,
    worker: WorkerRecord,
    **overrides: Any,
) -> ExecRequest:
    values: dict[str, Any] = {
        "task_id": task.task_id,
        "worker_id": worker.worker_id,
        "step_id": "step-1",
        "tool_name": "test.echo",
        "argv": ["sample.txt"],
        "cwd": str(Path(task.workspace_path)),
    }
    values.update(overrides)
    return ExecRequest(**values)


def approve_request(
    stack: VerificationStack,
    *,
    task_id: str,
    request: ExecRequest,
    action_kind: ApprovalAction = ApprovalAction.TOOL_ACTION,
    ttl_ms: int | None = 60_000,
) -> ApprovalRecord:
    """Create a legitimately APPROVED Task-scoped approval bound to ``request``."""

    from ctf_solver.policy.models import approval_action_digest

    now = stack.clock.now_ms()
    record = ApprovalRecord(
        approval_id=new_id("apr"),
        task_id=task_id,
        action_kind=action_kind.value,
        action_digest=approval_action_digest(action_kind.value, request),
        status=ApprovalStatus.APPROVED,
        requested_at=now,
        decided_at=now,
        approver="human-verifier",
        expires_at=(now + int(ttl_ms)) if ttl_ms is not None else None,
    )
    stack.store.create_approval(record)
    return record


# ---------------------------------------------------------------------------
# Fake ACP client (implements ctf_solver.core.protocols.AcpSessionClient)
# ---------------------------------------------------------------------------


class FakeAcpClient:
    """Small deterministic ACP client used by the independent Manager tests."""

    def __init__(self) -> None:
        self.state = "stopped"
        self.started = 0
        self.stopped = 0
        self.alive = False
        self.new_sessions: list[dict[str, Any]] = []
        self.closed: list[str] = []
        self.cancelled: list[str] = []
        self.resumed: list[tuple[str, str]] = []
        self.prompt_calls: list[tuple[str, Any]] = []
        self.list_sessions_calls: list[str | None] = []
        self.on_new_session: Any = None
        self.fail_new_session = False
        self.close_failure_sessions: set[str] = set()
        self.permission_handler: Any = None
        self.session_update_handler: Any = None

    # lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self.started += 1
        self.alive = True
        self.state = "ready"

    def stop(self, timeout_s: float = 10.0) -> None:
        self.stopped += 1
        self.alive = False
        self.state = "stopped"

    def is_alive(self) -> bool:
        return self.alive

    def diagnostics(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "pid": 4242,
            "exit_code": 0 if self.stopped else None,
            "is_alive": self.alive,
            "allow_model_calls": False,
        }

    # sessions ----------------------------------------------------------
    def new_session(self, cwd: str, mcp_servers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if self.on_new_session is not None:
            self.on_new_session(cwd, mcp_servers)
        if self.fail_new_session:
            raise AcpError("synthetic session/new failure")
        session_id = f"sess-verify-{len(self.new_sessions) + 1:03d}"
        self.new_sessions.append(
            {"cwd": cwd, "mcp_servers": mcp_servers, "session_id": session_id}
        )
        return {"sessionId": session_id, "configOptions": []}

    def list_sessions(self, cwd: str | None = None) -> dict[str, Any]:
        # The Manager must never depend on this to decide state; every call is
        # recorded so the test can assert zero calls.
        self.list_sessions_calls.append(cwd)
        return {"sessions": []}

    def resume_session(self, session_id: str, cwd: str) -> dict[str, Any]:
        self.resumed.append((session_id, cwd))
        return {"sessionId": session_id, "configOptions": []}

    def close_session(self, session_id: str) -> None:
        if session_id in self.close_failure_sessions:
            raise AcpError(f"synthetic session/close failure for {session_id}")
        self.closed.append(session_id)

    def cancel_session(self, session_id: str) -> None:
        self.cancelled.append(session_id)

    def prompt(self, session_id: str, content: list[dict[str, Any]]) -> dict[str, Any]:
        # Records the attempt; Manager Round 1 must never reach this.
        self.prompt_calls.append((session_id, content))
        raise AssertionError("Round 1 verification must never issue session/prompt")

    def set_session_update_handler(self, handler: Any) -> None:
        self.session_update_handler = handler

    def set_permission_handler(self, handler: Any) -> None:
        self.permission_handler = handler


# ---------------------------------------------------------------------------
# Multi-frame zstd + evidence-chain helpers
# ---------------------------------------------------------------------------


def compress_zstd_frame(data: bytes) -> bytes:
    """Compress ``data`` as one standalone zstd frame using an installed backend."""

    try:  # installed dependency (optional per INTERFACES.md)
        import zstandard  # type: ignore

        return zstandard.ZstdCompressor().compress(data)
    except ImportError:
        pass
    from compression import zstd  # type: ignore  # Python >= 3.14 stdlib

    compressor = getattr(zstd, "ZstdCompressor", None)
    if compressor is not None:
        return compressor().compress(data)
    return zstd.compress(data)  # type: ignore[attr-defined]


def build_multiframe_session_log(records: list[dict[str, Any]]) -> tuple[bytes, bytes]:
    """Return ``(concatenated_frames, jsonl_payload)`` with a line split across frames."""

    lines = [json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n" for record in records]
    payload = b"".join(lines)
    if len(lines) >= 2:
        cut = len(lines[0]) + max(1, len(lines[1]) // 2)
    else:
        cut = max(1, len(payload) // 2)
    cut = min(cut, len(payload))
    frames = [compress_zstd_frame(payload[:cut]), compress_zstd_frame(payload[cut:])]
    return b"".join(frames), payload


def chain_payload_from_row(row: Any) -> dict[str, Any]:
    """Reconstruct the hashed record payload from a raw SQLite ``events`` row.

    This is written from the INTERFACES.md evidence-record contract, not by
    calling the product's own helper, so the recomputation is independent.
    """

    payload_json = row["payload_json"]
    payload = json.loads(payload_json) if isinstance(payload_json, str) else payload_json
    return {
        "seq": int(row["seq"]),
        "record_id": row["record_id"],
        "task_id": row["task_id"],
        "worker_id": row["worker_id"],
        "session_id": row["session_id"],
        "source": row["source"],
        "source_id": row["source_id"],
        "source_seq": row["source_seq"],
        "event_type": row["event_type"],
        "timestamp": int(row["timestamp"]),
        "payload": payload,
        "ingested_at": int(row["ingested_at"]),
    }


def recompute_chain(rows: list[Any]) -> list[tuple[str, str]]:
    """Independently recompute ``(prev_hash, record_hash)`` for every event row."""

    previous = GENESIS_HASH
    result: list[tuple[str, str]] = []
    for row in rows:
        computed = chain_hash(previous, chain_payload_from_row(row))
        result.append((previous, computed))
        previous = computed
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
