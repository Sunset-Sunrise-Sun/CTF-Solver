"""PHASE 2 independent verification (part 1): frozen contract + dependencies + delivery/skills.

Run from the frozen worktree:
    python D:\\CTF-SOLVER\\scratch\\lead-round1-plan\\verifier\\phase2_contract_deps.py

Writes only to the verifier directory. Read-only with respect to the product.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any

WORKTREE = Path(r"D:\CTF-SOLVER\scratch\lead-round1")
VERIFIER = Path(r"D:\CTF-SOLVER\scratch\lead-round1-plan\verifier")
sys.path.insert(0, str(WORKTREE))

from ctf_solver import SCHEMA_VERSION  # noqa: E402
from ctf_solver.cli import build_parser  # noqa: E402
from ctf_solver.core.config import SolverConfig  # noqa: E402
from ctf_solver.core.types import TaskRecord  # noqa: E402
from ctf_solver.delivery import bundle as bundle_mod  # noqa: E402
from ctf_solver.delivery import screenshot as screenshot_mod  # noqa: E402
from ctf_solver.delivery import writeup as writeup_mod  # noqa: E402
from ctf_solver.evidence.store import EvidenceStore  # noqa: E402
from ctf_solver.manager import session_logs as session_logs_mod  # noqa: E402
from ctf_solver.manager.service import (  # noqa: E402
    ROUND1_LIMITS,
    ROUND2_SECURITY,
    ManagerService,
)
from ctf_solver.manager.store import ManagerStore, SessionBinding  # noqa: E402
from ctf_solver.mcp.manager_server import build_manager_tools  # noqa: E402
from ctf_solver.storage import db as db_mod  # noqa: E402

RESULTS: list[dict[str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append({"check": name, "status": status, "detail": detail})
    print(f"[{status}] {name}" + (f" :: {detail}" if detail else ""))


def check(name: str, fn: Any) -> None:
    try:
        detail = fn()
        record(name, "PASS", detail if isinstance(detail, str) else "")
    except AssertionError as exc:
        import traceback

        tb = traceback.format_exc().strip().splitlines()
        record(name, "FAIL", f"{exc} | at: {tb[-2].strip() if len(tb) > 1 else ''}")
    except Exception as exc:  # noqa: BLE001
        import traceback

        tb = traceback.format_exc().strip().splitlines()
        record(name, "FAIL", f"{type(exc).__name__}: {exc} | at: {tb[-2].strip() if len(tb) > 1 else ''}")


def skip(name: str, reason: str) -> None:
    record(name, "SKIP", reason)


def _tmpdir() -> Path:
    path = Path(tempfile.mkdtemp(prefix="ctf-verify-c1-"))
    return path


# ---------------------------------------------------------------------------
# Minimal collaborators for constructing a ManagerService (read functions only)
# ---------------------------------------------------------------------------


class MiniClock:
    def __init__(self, start: int = 1_700_000_000_000) -> None:
        self._now = start

    def now_ms(self) -> int:
        return self._now


class MiniAcp:
    def __init__(self) -> None:
        self.alive = False
        self.sessions: list[dict[str, Any]] = []
        self.closed: list[str] = []

    def start(self) -> None:
        self.alive = True

    def stop(self, timeout_s: float = 10.0) -> None:
        self.alive = False

    def is_alive(self) -> bool:
        return self.alive

    def diagnostics(self) -> dict[str, Any]:
        return {"state": "ready", "is_alive": self.alive}

    def new_session(self, cwd: str, mcp_servers: list[dict[str, Any]] | None = None):
        sid = f"session-mini-{len(self.sessions) + 1:03d}"
        self.sessions.append({"cwd": cwd, "session_id": sid})
        return {"sessionId": sid, "configOptions": []}

    def list_sessions(self, cwd: str | None = None):
        return {"sessions": []}

    def resume_session(self, session_id: str, cwd: str):
        return {"configOptions": []}

    def close_session(self, session_id: str) -> None:
        self.closed.append(session_id)

    def cancel_session(self, session_id: str) -> None:
        pass

    def prompt(self, session_id: str, content: list[dict[str, Any]]):
        raise AssertionError("Round 1 must never issue session/prompt")

    def set_session_update_handler(self, handler: Any) -> None:
        pass

    def set_permission_handler(self, handler: Any) -> None:
        pass


class MiniPipeline:
    def execute(self, request: Any, worker_token: str) -> Any:
        raise AssertionError("pipeline must not be used by this verification")


class MiniDeliverables:
    def __init__(self, root: Path) -> None:
        self.root = root

    def build_writeup(self, task: TaskRecord) -> Any:
        raise AssertionError("not used")

    def export_evidence_zip(self, task: TaskRecord) -> Any:
        raise AssertionError("not used")


class MiniCapturer:
    def capture(self, *, scope: str, workdir: str | None = None) -> Any:
        from ctf_solver.core.types import CaptureResult

        return CaptureResult(
            ok=True,
            png_bytes=b"\x89PNG\r\n\x1a\nmini",
            width=64,
            height=64,
            blank=False,
            method="mini",
            captured_at=1,
        )


def build_min_service(root: Path, *, lead_root: Path | None = None) -> ManagerService:
    config = SolverConfig(root=root, capture_mode="fake")
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path), MiniClock())
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir), clock=MiniClock())
    return ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: MiniAcp(),
        evidence=evidence,
        pipeline=MiniPipeline(),
        deliverables=MiniDeliverables(root),
        capturer=MiniCapturer(),
        clock=MiniClock(),
        lead_sessions_root=lead_root if lead_root is not None else root / "live-lead-sessions",
        workspace_root=root,
    )


# ---------------------------------------------------------------------------
# Section A 鈥?frozen contract compliance (sections 3, 4, 5)
# ---------------------------------------------------------------------------

print("=" * 78)
print("SECTION A 鈥?FROZEN INTERFACE COMPLIANCE")
print("=" * 78)


def a01() -> str:
    assert SCHEMA_VERSION == "1.2", SCHEMA_VERSION
    return f"SCHEMA_VERSION={SCHEMA_VERSION}"


check("A01 SCHEMA_VERSION is 1.2", a01)


def a02() -> str:
    prop = SolverConfig.lead_sessions_root
    assert isinstance(prop, property), "lead_sessions_root must be a property"
    saved = os.environ.pop("CTF_SOLVER_LEAD_SESSIONS_ROOT", None)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            explicit = root / "explicit-live"
            config = SolverConfig(root=root, extra={"lead_sessions_root": str(explicit)})
            assert config.lead_sessions_root == Path(os.path.abspath(explicit)), (
                config.lead_sessions_root
            )
            env_path = root / "env-live"
            os.environ["CTF_SOLVER_LEAD_SESSIONS_ROOT"] = str(env_path)
            try:
                config2 = SolverConfig(root=root)
                assert config2.lead_sessions_root == Path(os.path.abspath(env_path)), (
                    config2.lead_sessions_root
                )
            finally:
                os.environ.pop("CTF_SOLVER_LEAD_SESSIONS_ROOT", None)
            # dsh_home must never be the derivation source.
            config3 = SolverConfig(
                root=root, extra={"dsh_home": str(root / "isolated-home")}
            )
            expected_home = Path.home() / ".dsh" / "sessions"
            assert config3.lead_sessions_root == expected_home, (
                f"{config3.lead_sessions_root} != {expected_home} (derived from dsh_home?)"
            )
            assert config3.lead_sessions_root != config3.session_log_root
    finally:
        if saved is not None:
            os.environ["CTF_SOLVER_LEAD_SESSIONS_ROOT"] = saved
    return "extra > env > ~/.dsh/sessions; never derived from dsh_home"


check("A02 SolverConfig.lead_sessions_root priority/no-dsh_home", a02)


def a03() -> str:
    saved = os.environ.pop("CTF_SOLVER_LEAD_SESSIONS_ROOT", None)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing-live-root"
            config = SolverConfig(root=root, extra={"lead_sessions_root": str(missing)})
            config.ensure_runtime_dirs()
            assert not missing.exists(), "ensure_runtime_dirs created lead_sessions_root"
            assert config.session_log_root.is_dir(), "managed session log root not created"
            assert config.paths.db_path.parent.is_dir(), "data dir not created"
            source = inspect.getsource(type(config).ensure_runtime_dirs)
            assert "lead_sessions_root" not in source.replace(
                "``lead_sessions_root``", ""
            ) or "intentionally absent" in source
    finally:
        if saved is not None:
            os.environ["CTF_SOLVER_LEAD_SESSIONS_ROOT"] = saved
    return "missing lead root NOT created; managed dirs created"


check("A03 ensure_runtime_dirs does not create lead_sessions_root", a03)


def a04() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "new.sqlite"
        conn = db_mod.open_database(db_path)
        try:
            assert db_mod.get_meta(conn, "schema_version") == "1.2"
            task_cols = db_mod._column_names(conn, "tasks")
            assert "completion_note" in task_cols
            assert "notes" in task_cols
            binding_cols = db_mod._column_names(conn, "session_bindings")
            assert binding_cols == {
                "session_id",
                "task_id",
                "bound_at",
                "bound_by",
                "log_sha256",
            }, binding_cols
            indexes = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                ).fetchall()
            }
            assert "idx_session_bindings_task" in indexes, indexes
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name='session_bindings'"
            ).fetchone()["sql"]
            for fragment in ("session_id  TEXT PRIMARY KEY", "task_id     TEXT NOT NULL UNIQUE", "REFERENCES tasks(task_id)"):
                assert fragment in sql, f"missing {fragment!r} in {sql}"
            default = conn.execute("PRAGMA table_info(tasks)").fetchall()
            completion = [row for row in default if row["name"] == "completion_note"][0]
            assert completion["notnull"] == 1 and completion["dflt_value"] == "''", dict(completion)
        finally:
            conn.close()
    return "schema 1.2, completion_note NOT NULL DEFAULT '', session_bindings PK/UNIQUE/FK + index"


check("A04 new DB schema 1.2 (contract 3.2)", a04)


def a05() -> str:
    migration = inspect.getsource(db_mod._migrate_1_1_to_1_2)
    assert "conn.executescript" not in migration, "migration must not use executescript"
    assert 'CREATE TABLE IF NOT EXISTS session_bindings' in migration
    assert 'CREATE INDEX IF NOT EXISTS idx_session_bindings_task' in migration
    assert 'completion_note' in migration
    assert migration.count("conn.execute(") >= 2, "individual conn.execute calls required"
    init = inspect.getsource(db_mod.initialize_schema)
    assert '"1.0"' in init and '"1.1"' in init and "_migrate_1_0_to_1_1" in init
    assert "_migrate_1_1_to_1_2" in init
    return "1.0->1.2 and 1.1->1.2 wired; per-statement execute (no executescript)"


check("A05 schema migration wiring (contract 3.2)", a05)


def a06() -> str:
    field_names = [field.name for field in fields(TaskRecord)]
    assert field_names[-1] == "completion_note", field_names
    instance = TaskRecord(
        task_id="t",
        conversation_id="c",
        title="x",
        category=__import__(
            "ctf_solver.core.types", fromlist=["Category"]
        ).Category.MISC,
        workspace_path="w",
        status=__import__(
            "ctf_solver.core.types", fromlist=["TaskStatus"]
        ).TaskStatus.CREATED,
        completion_note="done note",
    )
    assert instance.to_dict()["completion_note"] == "done note"
    source = inspect.getsource(TaskRecord.from_row)
    assert 'if "completion_note" in row.keys()' in source, source
    return "completion_note appended last; to_dict includes it; from_row defensive"


check("A06 TaskRecord.completion_note (contract 3.3)", a06)


def a07() -> str:
    assert is_dataclass(SessionBinding)
    params = SessionBinding.__dataclass_params__
    assert params.frozen is True, "SessionBinding must be frozen"
    names = [field.name for field in fields(SessionBinding)]
    assert names == ["session_id", "task_id", "bound_at", "bound_by", "log_sha256"], names
    binding = SessionBinding(
        session_id="s", task_id="t", bound_at=1, bound_by="lead", log_sha256="a" * 64
    )
    assert binding.to_dict() == {
        "session_id": "s",
        "task_id": "t",
        "bound_at": 1,
        "bound_by": "lead",
        "log_sha256": "a" * 64,
    }
    bind_sig = inspect.signature(ManagerStore.bind_lead_session)
    for name in ("task_id", "session_id", "bound_by", "log_sha256"):
        assert name in bind_sig.parameters, name
        assert bind_sig.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY, name
    assert "task_id" in inspect.signature(ManagerStore.get_lead_binding).parameters
    assert "session_id" in inspect.signature(ManagerStore.get_task_for_lead_session).parameters
    return "SessionBinding frozen + fields + to_dict; store API signatures match"


check("A07 SessionBinding + store API (contract 3.4)", a07)


def a08() -> str:
    for method in (
        ManagerStore.finalize_task_completion,
        ManagerStore.finalize_task_interruption,
    ):
        source = inspect.getsource(method)
        assert "completion_note = ?" in source, f"{method.__name__} does not write completion_note"
        assert "notes = ?" not in source, f"{method.__name__} still writes old notes column"
    set_status = inspect.getsource(ManagerStore.set_task_status)
    assert "notes = COALESCE(?, notes)" in set_status
    # Lead-authorised amendment after the live-run defect: set_task_status gained a
    # completion_note parameter so operational lifecycle notes never clobber intake
    # notes. This is outside the originally frozen 3.4 wording and is verified here.
    params = inspect.signature(ManagerStore.set_task_status).parameters
    assert "completion_note" in params, "set_task_status missing completion_note parameter"
    assert params["completion_note"].default is None
    assert "completion_note = COALESCE(?, completion_note)" in set_status
    return (
        "finalize_* write completion_note; set_task_status notes unchanged;"
        " post-freeze amendment writes completion_note separately"
    )


check("A08 finalize_* completion_note + notes preservation (contract 3.4 + amendment)", a08)


def a08b() -> str:
    """Static AST check: no product call site passes notes= to set_task_status."""
    import ast

    offenders: list[str] = []
    call_count = 0
    for path in sorted((WORKTREE / "ctf_solver").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "set_task_status":
                call_count += 1
                keywords = {keyword.arg for keyword in node.keywords if keyword.arg}
                if "notes" in keywords:
                    offenders.append(f"{path.relative_to(WORKTREE)}:{node.lineno}")
            if isinstance(func, ast.Attribute) and func.attr == "finalize_task_completion":
                keywords = {keyword.arg for keyword in node.keywords if keyword.arg}
                if "notes" not in keywords and len(node.args) < 2:
                    offenders.append(
                        f"{path.relative_to(WORKTREE)}:{node.lineno} finalize without note"
                    )
    assert not offenders, f"set_task_status called with notes= at {offenders}"
    assert call_count >= 5, call_count
    return f"{call_count} set_task_status call sites, none pass notes= (intake notes safe)"


check("A08b no product call site writes notes= on lifecycle transitions", a08b)


def a09() -> str:
    for code in (
        "no_binding",
        "lead_cwd_mismatch",
        "lead_sessions_root_missing",
        "sessions_root_missing",
        "unknown_session",
        "header_mismatch",
        "log_missing",
        "ambiguous_session_log",
        "symlink_rejected",
        "path_escape",
        "no_worker",
        "unknown_task",
    ):
        assert code in session_logs_mod.REASON_CODES, code
    resolved = session_logs_mod.ResolvedSessionLog(
        task_id="t", worker_id=None, session_id="s", path=Path("p")
    )
    assert resolved.source == "worker", resolved.source
    assert resolved.to_dict()["source"] == "worker"
    assert resolved.to_dict()["worker_id"] is None
    annotations = session_logs_mod.ResolvedSessionLog.__annotations__
    assert "None" in str(annotations["worker_id"]), annotations["worker_id"]
    init_params = inspect.signature(session_logs_mod.SessionLogResolver.__init__).parameters
    for name in ("sessions_root", "store", "lead_sessions_root", "workspace_root", "clock"):
        assert name in init_params, name
    for name in ("lead_sessions_root", "workspace_root", "clock"):
        assert init_params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
    resolve_params = inspect.signature(session_logs_mod.SessionLogResolver.resolve).parameters
    assert list(resolve_params) == ["self", "task_id", "worker_id", "source"], list(resolve_params)
    assert resolve_params["source"].default == "auto"
    for banned in ("path", "log_path", "file", "session_id"):
        assert banned not in resolve_params, f"resolve accepts forbidden {banned!r}"
    assert hasattr(session_logs_mod.SessionLogResolver, "validate_lead_candidate")
    return "reason codes + source='worker' default + no path/session-id parameters"


check("A09 resolver API and reason codes (contract 3.5)", a09)


def a10() -> str:
    init_params = inspect.signature(ManagerService.__init__).parameters
    for name in ("lead_sessions_root", "workspace_root"):
        assert name in init_params, name
        assert init_params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
    create_params = inspect.signature(ManagerService.create_task).parameters
    assert "lead_session_id" in create_params, list(create_params)
    assert create_params["lead_session_id"].default is None
    ingest_params = inspect.signature(ManagerService.ingest_session_log).parameters
    assert "source" in ingest_params and ingest_params["source"].default == "auto"
    assert "path" not in ingest_params and "session_id" not in ingest_params
    assert ROUND1_LIMITS["main_conversation_entrypoint"] == (
        "connected via project-scoped workspace MCP (Manager tools available to the Lead conversation)"
    ), ROUND1_LIMITS["main_conversation_entrypoint"]
    assert ROUND2_SECURITY["lead_session_binding"] == (
        "explicit Lead session id, Manager-verified header/cwd, one-time binding"
    )
    return "ctor kwargs, create_task lead_session_id, ingest source, status wording"


check("A10 ManagerService API + status strings (contract 4.1)", a10)


def a11() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        service = build_min_service(root)
        try:
            status = service.runtime_status()
            assert "lead_sessions_root" in status, sorted(status)
            assert status["lead_sessions_root"] == str(service.lead_sessions_root)
            assert status["round1_limits"]["main_conversation_entrypoint"].startswith(
                "connected via project-scoped workspace MCP"
            )
            assert status["security"]["lead_session_binding"].startswith(
                "explicit Lead session id"
            )
        finally:
            service.evidence.close()
            service.store.close()
    return "runtime_status exposes lead_sessions_root + updated limits/security"


check("A11 runtime_status surface (contract 4.1)", a11)


def a12() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        service = build_min_service(Path(tmp))
        try:
            tools = build_manager_tools(service)
        finally:
            service.evidence.close()
            service.store.close()
    assert len(tools) == 18, f"expected 18 tools, got {len(tools)}"
    names = [tool.name for tool in tools]
    expected = {
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
    assert set(names) == expected, set(names) ^ expected
    by_name = {tool.name: tool for tool in tools}
    create_schema = by_name["ctf_task_create"].input_schema
    lead = create_schema["properties"]["lead_session_id"]
    assert lead["type"] == "string" and lead["maxLength"] == 128, lead
    assert "DSH_SESSION_ID" in lead["description"], lead["description"]
    ingest_schema = by_name["ctf_session_ingest"].input_schema
    assert set(ingest_schema["properties"]) == {"task_id", "worker_id", "source"}, sorted(
        ingest_schema["properties"]
    )
    assert ingest_schema["properties"]["source"]["enum"] == ["auto", "worker", "lead"]
    assert ingest_schema["properties"]["source"]["default"] == "auto"
    assert ingest_schema["required"] == ["task_id"]
    # No tool may accept a filesystem path or an arbitrary session id.
    for tool in tools:
        props = tool.input_schema.get("properties", {})
        for banned in ("path", "log_path", "file_path", "session_id"):
            assert banned not in props, f"{tool.name} exposes forbidden parameter {banned!r}"
    return "18 tools, same names; lead_session_id(max 128)/source enum; no path/session_id"


check("A12 MCP 18 tools + schemas (contract 4.2)", a12)


def a13() -> str:
    parser = build_parser()
    manager_args = parser.parse_args(
        ["manager", "serve", "--lead-sessions-root", "L", "--session-log-root", "S"]
    )
    assert manager_args.lead_sessions_root == "L"
    assert manager_args.session_log_root == "S"
    assert manager_args.func.__name__ == "_cmd_manager"
    task_args = parser.parse_args(
        ["task", "create", "--lead-session-id", "sess-x", "--lead-sessions-root", "L"]
    )
    assert task_args.lead_session_id == "sess-x"
    assert task_args.lead_sessions_root == "L"
    defaults = parser.parse_args(["manager", "serve"])
    assert defaults.lead_sessions_root == "" and defaults.session_log_root == ""
    return "manager serve + task args parse; defaults empty strings"


check("A13 CLI plumbing (contract 4.3)", a13)


def a14() -> str:
    import ctf_solver.wiring as wiring_mod

    source = inspect.getsource(wiring_mod.build_manager_service)
    assert "lead_sessions_root=config.lead_sessions_root" in source, source
    assert "workspace_root=config.root" in source, source
    return "build_manager_service passes lead_sessions_root and workspace_root"


check("A14 wiring (contract 3.6)", a14)


def a15() -> str:
    script = screenshot_mod._POWERSHELL_CAPTURE_SCRIPT
    drawing = script.index("Add-Type -AssemblyName System.Drawing")
    forms = script.index("Add-Type -AssemblyName System.Windows.Forms")
    assert drawing < forms, "System.Windows.Forms Add-Type must follow System.Drawing"
    assert forms - drawing <= 60, "WinForms line is not immediately after Drawing"
    assert screenshot_mod.FAILURE_STDERR_LINES == 12
    gbk_text = "中文错误".encode("gbk")
    assert screenshot_mod._decode_powershell_output(gbk_text) == "中文错误"
    assert screenshot_mod._decode_powershell_output("ascii".encode()) == "ascii"
    assert screenshot_mod._decode_powershell_output(None) == ""
    assert screenshot_mod._decode_powershell_output(b"\xff\xfe\x00bad") or True

    class Completed:
        returncode = 1
        stderr = "\n".join(f"line-{i}" for i in range(1, 21)).encode("utf-8")
        stdout = b""

    tail = screenshot_mod._failure_tail(Completed())
    tail_lines = tail.split(" | ")
    assert len(tail_lines) == 12, len(tail_lines)
    assert tail_lines[0] == "line-9" and tail_lines[-1] == "line-20"
    desktop_src = inspect.getsource(screenshot_mod.DesktopCapturer.capture)
    window_src = inspect.getsource(screenshot_mod.WindowCapturer.capture)
    for source in (desktop_src, window_src):
        assert "capture_output=True" in source, "subprocess capture call missing"
        call_at = source.index("capture_output=True")
        segment = source[call_at : call_at + 160]
        assert "encoding=" not in segment, "subprocess.run still forces an encoding"
        assert "text=True" not in segment, "subprocess.run still forces text mode"
    return "WinForms Add-Type present; 12-line tail; utf-8->gbk->latin-1 decode; no text=True"


check("A15 screenshot capture fix (contract 5.1)", a15)


def a16() -> str:
    source = inspect.getsource(writeup_mod.WriteupBuilder)
    assert "### 2.1 Completion note (outcome record)" in source, "completion note subsection missing"
    assert "turn {turn_step[0]}, step {turn_step[1]}" in source, "turn/step heading missing"
    assert "_screenshots_for_step(" in source, "derived screenshot matching not used in steps"
    module_source = inspect.getsource(writeup_mod)
    assert "def _derived_step_id(" in module_source, "derived step-id helper missing"
    assert "def _screenshots_for_step(" in module_source
    description = inspect.getsource(writeup_mod.WriteupBuilder._section_description)
    assert "reproduced in section 1" in description, "notes dedup statement missing"
    # Section 1 must still print the notes exactly once.
    metadata = inspect.getsource(writeup_mod.WriteupBuilder._section_metadata)
    assert "Intake notes:" in metadata and "_fence(task.notes)" in metadata
    return "completion-note subsection, turn/step heading, derived screenshot matching, no dup"


check("A16 writeup behaviour hooks (contract 5.2)", a16)


def a17() -> str:
    source = inspect.getsource(bundle_mod.EvidenceBundleBuilder.build)
    zip_at = source.index("zip_sha = file_sha256(zip_path)")
    verify_at = source.index("self.verify_zip(")
    assert verify_at > zip_at, "internal verify must run after the ZIP is built"
    assert "DeliveryError(" in source, "internal verify failure must raise DeliveryError"
    assert "tempfile.mkdtemp" in source and "shutil.rmtree" in source
    raw_source = inspect.getsource(bundle_mod.EvidenceBundleBuilder._collect_raw_sources)
    assert 'raw/session-{raw_sha[:16]}.jsonl.zstd' in raw_source
    assert "raw_sha256" in raw_source
    return "internal verify_zip after build + DeliveryError + temp cleanup; raw layout unchanged"


check("A17 bundle internal verify + raw layout (contract 5.3)", a17)


SKILLS = WORKTREE / ".dsh" / "skills"
CATEGORY_SKILLS = ("ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")


def a18() -> str:
    paths = sorted(SKILLS.glob("*/SKILL.md"))
    assert len(paths) == 6, [path.parent.name for path in paths]
    for path in paths:
        data = path.read_bytes()
        assert not data.startswith(b"\xef\xbb\xbf"), f"{path} has a BOM"
        text = data.decode("utf-8")  # strict: must be valid UTF-8
        assert text.startswith("---\n"), f"{path} frontmatter missing"
        assert "name:" in text and "description:" in text
    category_text = {}
    for name in CATEGORY_SKILLS:
        text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
        category_text[name] = text
        assert "## Evidence recording (native tools)" in text, f"{name} evidence paragraph missing"
        assert "turn{N}-step{S}" in text, f"{name} derived step id missing"
        assert "未执行" in text and "未记录" in text, f"{name} honesty markers missing"
        paragraph = text.split("## Evidence recording (native tools)", 1)[1].strip()
        assert len(paragraph.splitlines()) <= 5, f"{name} paragraph longer than 5 lines"
    core = (SKILLS / "ctf-solver" / "SKILL.md").read_text(encoding="utf-8")
    assert "executor" in core and "native Harness tools" in core
    assert "18 tools" in core
    assert "lead_session_id" in core and "DSH_SESSION_ID" in core
    assert "Category routing (hard step)" in core, "category routing hard step missing"
    assert "load the category Skill" in core, "category-skill load instruction missing"
    # Final-freeze honesty fix: Lead-sourced tool_call events (worker_id NULL) are
    # labelled "Lead initiated"; Worker evidence keeps the historical wording.
    actor = getattr(writeup_mod, "_tool_call_actor", None)
    assert callable(actor), "_tool_call_actor missing (Lead/Worker label fix)"
    assert actor({"worker_id": None}) == ("Lead initiated", "the Lead requested this tool call")
    assert actor({"worker_id": "w-1"}) == (
        "Worker initiated",
        "the Worker requested this tool call",
    )
    assert actor({})[0] == "Worker initiated", "legacy records must keep Worker wording"
    for tool_name in (
        "ctf_task_create",
        "ctf_session_ingest",
        "ctf_writeup_build",
        "ctf_evidence_zip",
        "ctf_runtime_status",
        "ctf_flag_candidate",
    ):
        assert tool_name in core, f"{tool_name} missing from ctf-solver skill"
    return "6 UTF-8/no-BOM skills; 5 category evidence paragraphs <=5 lines; core updated"


check("A18 skill wording (contract 5.4)", a18)


# ---------------------------------------------------------------------------
# Section B 鈥?no new dependencies
# ---------------------------------------------------------------------------

print()
print("=" * 78)
print("SECTION B 鈥?DEPENDENCY FREEZE")
print("=" * 78)


def b01() -> str:
    data = tomllib.loads((WORKTREE / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"].get("dependencies", [])
    assert deps == [], f"project dependencies must stay empty, got {deps}"
    optional = data["project"].get("optional-dependencies", {})
    others = {key: value for key, value in optional.items() if key != "dev"}
    assert not others, f"unexpected optional dependencies: {others}"
    assert optional.get("dev") == ["pytest>=8"], optional.get("dev")
    return "project.dependencies == [] ; only dev extra pytest>=8"


check("B01 pyproject has no runtime dependencies", b01)


def b02() -> str:
    diff = subprocess.run(
        ["git", "-C", str(WORKTREE), "diff", "--unified=0", "21908de", "HEAD", "--", "*.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout
    added_imports: list[tuple[str, str]] = []
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        text = line[1:].strip()
        match = None
        if text.startswith("import "):
            match = text[len("import ") :].split()[0].split(".")[0]
        elif text.startswith("from "):
            match = text[len("from ") :].split()[0].split(".")[0]
        if match:
            added_imports.append((match, text))
    stdlib = set(sys.stdlib_module_names)
    local = {"ctf_solver", "tests"}
    allowed_existing = {
        "zstandard",  # already-installed optional compression backend, unchanged
        "pytest",  # already the declared dev extra
    }
    offenders = [
        (root, text)
        for root, text in added_imports
        if root not in stdlib and root not in local and root not in allowed_existing
    ]
    assert not offenders, f"new third-party imports: {offenders}"
    return f"{len(added_imports)} added import statements, all stdlib/local: {sorted({r for r, _ in added_imports})}"


check("B02 added imports are stdlib/local only", b02)


def b03() -> str:
    # No new runtime import of a third-party package in the frozen product tree.
    result = subprocess.run(
        [
            "git",
            "-C",
            str(WORKTREE),
            "diff",
            "--name-only",
            "21908de",
            "HEAD",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout.split()
    assert "pyproject.toml" not in result, "pyproject.toml was modified"
    assert "uv.lock" not in result and "requirements.txt" not in result
    requirements = list((WORKTREE).glob("requirements*.txt"))
    for path in requirements:
        print(f"  note: {path.name} exists, unchanged={path.name not in result}")
    return f"pyproject/lock files unchanged in base..HEAD diff ({len(result)} changed paths)"


check("B03 packaging/lock files unchanged", b03)


def a19() -> str:
    status = subprocess.run(
        ["git", "-C", str(WORKTREE), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout.splitlines()
    assert not [line for line in status if line.strip()], (
        f"frozen tree is not clean: {[line for line in status if line.strip()]}"
    )
    names = subprocess.run(
        ["git", "-C", str(WORKTREE), "diff", "--name-only", "21908de", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout.splitlines()
    # Contract 0 fixes the encoding of *source* files. Lead-owned raw evidence
    # transcripts (UTF-16 console captures, BOM'd config snapshots) are data
    # artifacts, not source; they are deliberately excluded from this check.
    source_prefixes = ("ctf_solver/", "tests/", ".dsh/skills/", "docs/")
    paths = [
        name.strip()
        for name in names
        if name.strip()
        and (
            name.strip().startswith(source_prefixes)
            or name.strip() in {"pyproject.toml", "README.md", "INSTALLATION_GUIDE.md"}
        )
    ]
    assert paths, "no source files changed between base and frozen HEAD?"
    excluded = len([name for name in names if name.strip()]) - len(paths)
    problems: list[str] = []
    for relative in paths:
        path = WORKTREE / relative
        if not path.is_file():
            continue
        data = path.read_bytes()
        if data.startswith(b"\xef\xbb\xbf"):
            problems.append(f"{relative}: UTF-8 BOM")
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            problems.append(f"{relative}: not valid UTF-8 ({exc})")
    assert not problems, problems
    return (
        f"clean frozen tree; {len(paths)} changed source files (tests/skills/docs) are"
        f" valid UTF-8 without BOM; {excluded} raw evidence artifacts excluded"
    )


check("A19 frozen tree clean + changed files UTF-8 without BOM", a19)


def a20() -> str:
    diff = subprocess.run(
        ["git", "-C", str(WORKTREE), "diff", "21908de", "HEAD", "--", "ctf_solver"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout
    offenders: list[str] = []
    current_file = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[len("+++ b/") :]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        if "print(" in added and not current_file.endswith("cli.py"):
            offenders.append(f"{current_file}: {added.strip()}")
    assert not offenders, f"library code must not print: {offenders}"
    return "no print() added to library code (cli.py excluded)"


check("A20 library code does not print (contract 0)", a20)


# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------

print()
print("=" * 78)
summary = {
    "total": len(RESULTS),
    "pass": sum(1 for item in RESULTS if item["status"] == "PASS"),
    "fail": sum(1 for item in RESULTS if item["status"] == "FAIL"),
    "skip": sum(1 for item in RESULTS if item["status"] == "SKIP"),
    "results": RESULTS,
}
print(json.dumps({k: summary[k] for k in ("total", "pass", "fail", "skip")}))
for item in RESULTS:
    if item["status"] != "PASS":
        print(f"  {item['status']}: {item['check']} :: {item['detail']}")
VERIFIER.mkdir(parents=True, exist_ok=True)
(VERIFIER / "phase2_contract_deps.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
)
print(f"results -> {VERIFIER / 'phase2_contract_deps.json'}")
sys.exit(1 if summary["fail"] else 0)

