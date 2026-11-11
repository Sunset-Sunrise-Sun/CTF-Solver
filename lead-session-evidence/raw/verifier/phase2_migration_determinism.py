"""PHASE 2 independent verification (part 3): real 1.1 DB migration + determinism.

Read-only with respect to the real Manager database: a consistent snapshot is made
with the SQLite backup API through a mode=ro connection, and the copy is migrated.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

WORKTREE = Path(r"D:\CTF-SOLVER\scratch\lead-round1")
VERIFIER = Path(r"D:\CTF-SOLVER\scratch\lead-round1-plan\verifier")
WORK = VERIFIER / "work"
# Genuine pre-Round-1 1.1 database snapshot (real rows, real chain) taken by the
# Lead before development started. The live manager.sqlite was already migrated
# to 1.2 by the Lead's live run, so this backup is the authoritative 1.1 source.
PRE_ROUND1_DB = Path(r"D:\CTF-SOLVER\scratch\lead-round1-plan\manager-pre-round1.sqlite")
LIVE_DB = Path(r"D:\CTF-SOLVER\.ctf-solver-data\manager.sqlite")
sys.path.insert(0, str(WORKTREE))

from ctf_solver.core.canonical import canonical_json  # noqa: E402
from ctf_solver.core.config import SolverConfig  # noqa: E402
from ctf_solver.core.types import (  # noqa: E402
    CaptureStatus,
    Category,
    ScreenshotRecord,
    TaskRecord,
    TaskStatus,
)
from ctf_solver.delivery.bundle import EvidenceBundleBuilder  # noqa: E402
from ctf_solver.delivery.writeup import WriteupBuilder  # noqa: E402
from ctf_solver.evidence.store import EvidenceStore  # noqa: E402
from ctf_solver.manager.store import ManagerStore  # noqa: E402
from ctf_solver.storage import db as db_mod  # noqa: E402
from tests.support.png import solid_png  # noqa: E402
from tests.support.verification_helpers import recompute_chain  # noqa: E402

RESULTS: list[dict[str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append({"check": name, "status": status, "detail": detail})
    print(f"[{status}] {name}" + (f" :: {detail}" if detail else ""))


def check(name: str, fn: Any) -> None:
    try:
        detail = fn()
        record(name, "PASS", detail if isinstance(detail, str) else "")
    except AssertionError as exc:
        record(name, "FAIL", str(exc))
    except Exception as exc:  # noqa: BLE001
        record(name, "FAIL", f"{type(exc).__name__}: {exc}")


def skip(name: str, reason: str) -> None:
    record(name, "SKIP", reason)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SimpleClock:
    def __init__(self, start: int = 1_700_000_000_000) -> None:
        self._now = start

    def now_ms(self) -> int:
        return self._now

    def advance(self, ms: int) -> int:
        self._now += ms
        return self._now


# ===========================================================================
print("=" * 78)
print("SECTION F — REAL 1.1 DATABASE MIGRATION")
print("=" * 78)

MIGRATION = WORK / "migration"
if MIGRATION.exists():
    import shutil

    shutil.rmtree(MIGRATION)
MIGRATION.mkdir(parents=True)

MIGRATION_STATE: dict[str, Any] = {}


def _snapshot_readonly(source_path: Path, destination: Path) -> tuple[str, list[str], dict[str, int], dict[str, list[dict]], dict[str, str]]:
    """Copy a live SQLite DB through a mode=ro connection (consistent incl. WAL)."""

    uri = "file:" + source_path.as_posix() + "?mode=ro"
    source = sqlite3.connect(uri, uri=True)
    source.row_factory = sqlite3.Row
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(destination))
        try:
            source.backup(target)
        finally:
            target.close()
        version = source.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"]
        tables = [
            row["name"]
            for row in source.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        counts = {
            table: source.execute(f'SELECT COUNT(*) AS n FROM "{table}"').fetchone()["n"]
            for table in tables
        }
        rows = {
            table: [
                dict(row)
                for row in source.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
            ]
            for table in ("tasks", "workers", "approvals", "network_grants", "events")
            if table in tables
        }
        meta = {
            row["key"]: row["value"]
            for row in source.execute("SELECT key, value FROM meta").fetchall()
        }
    finally:
        source.close()
    return version, tables, counts, rows, meta


def f01() -> str:
    assert PRE_ROUND1_DB.is_file(), f"pre-Round-1 1.1 DB missing: {PRE_ROUND1_DB}"
    MIGRATION_STATE["sha_before_main"] = sha256_file(PRE_ROUND1_DB)
    copy_path = MIGRATION / "manager_1_1_copy.sqlite"
    version, tables, counts, rows, meta = _snapshot_readonly(PRE_ROUND1_DB, copy_path)
    MIGRATION_STATE.update(
        {
            "copy": copy_path,
            "source_version": version,
            "tables": tables,
            "counts": counts,
            "rows": rows,
            "meta": meta,
        }
    )
    assert version == "1.1", f"migration source is not 1.1: {version!r}"
    assert "session_bindings" not in tables, "source already has the 1.2 table"
    assert "tasks" in tables and counts["tasks"] >= 1, "no real Task rows to migrate"
    assert counts["events"] >= 1, "no real evidence rows to migrate"
    (MIGRATION / "source_snapshot.json").write_text(
        json.dumps(
            {
                "source": str(PRE_ROUND1_DB),
                "source_version": version,
                "tables": tables,
                "counts": counts,
                "meta_schema_version": meta.get("schema_version"),
                "chain_head": meta.get("events_chain_head"),
                "chain_head_seq": meta.get("events_chain_head_seq"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return (
        f"genuine 1.1 snapshot: {len(tables)} tables, {counts['tasks']} tasks,"
        f" {counts['events']} events"
    )


check("F01 read-only snapshot of the real 1.1 database", f01)


def f02() -> str:
    conn = db_mod.open_database(MIGRATION_STATE["copy"])
    try:
        MIGRATION_STATE["after_meta"] = {
            row["key"]: row["value"]
            for row in conn.execute("SELECT key, value FROM meta").fetchall()
        }
        MIGRATION_STATE["after_tables"] = db_mod.table_names(conn)
        MIGRATION_STATE["after_counts"] = {
            table: conn.execute(f'SELECT COUNT(*) AS n FROM "{table}"').fetchone()["n"]
            for table in MIGRATION_STATE["after_tables"]
        }
        MIGRATION_STATE["after_rows"] = {
            table: [dict(row) for row in conn.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()]
            for table in ("tasks", "workers", "approvals", "network_grants", "events")
            if table in MIGRATION_STATE["after_tables"]
        }
        task_columns = db_mod._column_names(conn, "tasks")
        binding_columns = db_mod._column_names(conn, "session_bindings")
        indexes = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        }
    finally:
        conn.close()
    after_meta = MIGRATION_STATE["after_meta"]
    assert after_meta["schema_version"] == "1.2", after_meta["schema_version"]
    assert "completion_note" in task_columns, sorted(task_columns)
    assert binding_columns == {"session_id", "task_id", "bound_at", "bound_by", "log_sha256"}
    assert "idx_session_bindings_task" in indexes
    before_tables = set(MIGRATION_STATE["tables"])
    after_tables = set(MIGRATION_STATE["after_tables"])
    assert before_tables <= after_tables, before_tables - after_tables
    added = sorted(after_tables - before_tables)
    assert added == ["session_bindings"], f"unexpected new tables: {added}"
    # Additive only: every pre-existing table keeps its exact row count.
    count_diffs = {
        table: (MIGRATION_STATE["counts"][table], MIGRATION_STATE["after_counts"][table])
        for table in MIGRATION_STATE["counts"]
        if MIGRATION_STATE["counts"][table] != MIGRATION_STATE["after_counts"].get(table)
    }
    assert not count_diffs, f"row counts changed: {count_diffs}"
    return (
        f"1.1 -> 1.2 additive: version=1.2, completion_note + session_bindings added,"
        f" {len(before_tables)} tables' row counts unchanged"
    )


check("F02 migration 1.1 -> 1.2 is additive (rows preserved)", f02)


def f03() -> str:
    before_rows = MIGRATION_STATE["rows"]
    after_rows = MIGRATION_STATE["after_rows"]
    for table, rows in before_rows.items():
        after = after_rows[table]
        assert len(rows) == len(after), (table, len(rows), len(after))
        for index, (old, new) in enumerate(zip(rows, after)):
            common = {key: old[key] for key in old if key in new}
            new_common = {key: new[key] for key in common}
            assert common == new_common, f"{table} row {index} changed: {common} != {new_common}"
    # The new column must default to '' for every migrated Task (not NULL/None).
    tasks_after = after_rows["tasks"]
    missing_note = [row["task_id"] for row in tasks_after if row.get("completion_note") != ""]
    assert not missing_note, f"completion_note not '' for {missing_note[:5]}"
    return (
        f"{sum(len(rows) for rows in before_rows.values())} rows in tasks/workers/"
        "approvals/network_grants/events byte-identical; completion_note defaults to ''"
    )


check("F03 all migrated row values preserved; completion_note default", f03)


def f04() -> str:
    rows = MIGRATION_STATE["after_rows"]["events"]
    stored = [(row["prev_hash"], row["record_hash"]) for row in rows]
    recomputed = recompute_chain(rows)
    assert stored == recomputed, "hash chain does not recompute on the migrated copy"
    meta = MIGRATION_STATE["after_meta"]
    if rows:
        assert meta["events_chain_head"] == rows[-1]["record_hash"], "chain head mismatch"
        assert meta["events_chain_head_seq"] == str(len(rows)), (
            meta["events_chain_head_seq"],
            len(rows),
        )
    else:
        assert meta["events_chain_head"] == "0" * 64
    # Independent product check as well.
    evidence = EvidenceStore(
        str(MIGRATION_STATE["copy"]), str(MIGRATION / "cas"), clock=SimpleClock()
    )
    try:
        status = evidence.chain_status()
    finally:
        evidence.close()
    assert status.ok, status
    assert status.records == len(rows)
    assert status.head_hash == (rows[-1]["record_hash"] if rows else "0" * 64)
    return f"chain recomputes independently and chain_status ok over {len(rows)} events"


check("F04 evidence hash chain verifies after migration", f04)


def f05() -> str:
    # The 1.1 source backup must be bit-identical after this verification run.
    after = sha256_file(PRE_ROUND1_DB)
    before = MIGRATION_STATE["sha_before_main"]
    assert before == after, "pre-Round-1 1.1 database file changed during verification"
    uri = "file:" + PRE_ROUND1_DB.as_posix() + "?mode=ro"
    source = sqlite3.connect(uri, uri=True)
    try:
        version = source.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    finally:
        source.close()
    assert version == "1.1", f"1.1 source schema_version changed: {version}"
    return "pre-Round-1 1.1 backup byte-identical; still schema 1.1"


check("F05 real 1.1 source DB untouched", f05)


def f06() -> str:
    """Observe the live DB the Lead's live run already migrated 1.1 -> 1.2."""
    assert LIVE_DB.is_file(), f"live DB missing: {LIVE_DB}"
    live_copy = MIGRATION / "live_manager_snapshot.sqlite"
    version, tables, counts, rows, meta = _snapshot_readonly(LIVE_DB, live_copy)
    assert version == "1.2", f"live DB version {version!r} (expected post-migration 1.2)"
    assert "session_bindings" in tables
    live_conn = sqlite3.connect(str(live_copy))
    try:
        task_columns = {row[1] for row in live_conn.execute("PRAGMA table_info(tasks)")}
    finally:
        live_conn.close()
    assert "completion_note" in task_columns
    events_rows = rows["events"]
    stored = [(row["prev_hash"], row["record_hash"]) for row in events_rows]
    assert stored == recompute_chain(events_rows), "live DB chain does not recompute"
    if events_rows:
        assert meta["events_chain_head"] == events_rows[-1]["record_hash"]
        assert meta["events_chain_head_seq"] == str(len(events_rows))
    null_notes = [
        row["task_id"]
        for row in rows["tasks"]
        if row["completion_note"] is None
    ]
    assert not null_notes, f"live tasks with NULL completion_note: {null_notes}"
    live = sqlite3.connect(str(live_copy))
    live.row_factory = sqlite3.Row
    try:
        binding_rows = live.execute("SELECT * FROM session_bindings").fetchall()
        binding_summary = {
            "bindings": len(binding_rows),
            "sessions": sorted(row["session_id"] for row in binding_rows),
            "tasks": sorted(row["task_id"] for row in binding_rows),
        }
        demo_notes = [
            {
                "task_id": row["task_id"],
                "status": row["status"],
                "notes_len": len(row["notes"] or ""),
                "completion_note_len": len(row["completion_note"] or ""),
                "notes_eq_completion": row["notes"] == row["completion_note"],
            }
            for row in live.execute(
                "SELECT task_id, status, notes, completion_note FROM tasks ORDER BY created_at"
            ).fetchall()
        ]
    finally:
        live.close()
    (MIGRATION / "live_observation.json").write_text(
        json.dumps(
            {
                "version": version,
                "counts": counts,
                "meta": {key: meta.get(key) for key in ("schema_version", "events_chain_head", "events_chain_head_seq")},
                "bindings": binding_summary,
                "tasks": demo_notes,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return (
        f"live DB already 1.2: chain ok over {len(events_rows)} events,"
        f" {counts['tasks']} tasks, {binding_summary['bindings']} binding(s)"
    )


check("F06 live DB post-migration state verifies", f06)


# ===========================================================================
print()
print("=" * 78)
print("SECTION G — DELIVERY DETERMINISM (writeup + ZIP + raw log inclusion)")
print("=" * 78)

DET = WORK / "determinism"
if DET.exists():
    import shutil

    shutil.rmtree(DET)
DET.mkdir(parents=True)

config = SolverConfig(root=DET, capture_mode="fake")
paths = config.ensure_layout()
clock = SimpleClock()
store = ManagerStore(str(paths.db_path), clock)
evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir), clock=clock)

NOTES = "Intake record: deterministic synthetic challenge — keep exactly once 中文"
COMPLETION_NOTE = "Outcome record: candidate flag reproduced locally (synthetic)"
TASK_ID = "t-determinism"
task = store.create_task(
    TaskRecord(
        task_id=TASK_ID,
        conversation_id="conv-det",
        title="Deterministic synthetic challenge",
        category=Category.MISC,
        workspace_path=str(paths.task_dir(TASK_ID) / "work"),
        scope_profile="synthetic-local",
        status=TaskStatus.COMPLETED,
        notes=NOTES,
    )
)
task_for_build = replace(task, completion_note=COMPLETION_NOTE)

SESSION_ID = "det-session-0001"
SOURCE_ID = f"session:{SESSION_ID}"
TS = 1_700_000_100_000


def append(event_type: str, payload: dict[str, Any], *, source_seq: int | None = None) -> None:
    evidence.append_event(
        task_id=TASK_ID,
        session_id=SESSION_ID,
        source="lead",
        source_id=SOURCE_ID,
        source_seq=source_seq,
        event_type=event_type,
        payload=payload,
        timestamp=clock.now_ms(),
    )
    clock.advance(10)


stdout_ref = evidence.store_artifact(b"uid=0(root) gid=0(root)\n", media_type="text/plain", source="det")
png = solid_png(48, 32, (12, 34, 56))
png_ref = evidence.store_artifact(png, media_type="image/png", source="det:screenshot")

append(
    "task_created",
    {
        "title": task.title,
        "category": "misc",
        "conversation_id": "conv-det",
        "source": "",
        "scope_profile": "synthetic-local",
        "notes": NOTES,
        "lead_session_id": SESSION_ID,
        "supplied_files": [],
    },
    source_seq=0,
)
append(
    "execution_started",
    {
        "execution_id": "exec-1",
        "step_id": "turn2-step3",
        "tool_name": "bash",
        "argv": ["id"],
        "cwd": str(paths.task_dir(TASK_ID) / "work"),
    },
    source_seq=2,
)
append(
    "tool_call",
    {
        "turn": 2,
        "step": 3,
        "call_id": "call-1",
        "tool_name": "bash",
        "arguments": '{"command":"id"}',
    },
    source_seq=3,
)
append(
    "tool_result",
    {
        "call_id": "call-1",
        "turn": 2,
        "step": 3,
        "status": "ok",
        "content": "uid=0(root) gid=0(root)",
    },
    source_seq=4,
)
append(
    "execution_completed",
    {
        "execution_id": "exec-1",
        "step_id": "turn2-step3",
        "tool_name": "bash",
        "status": "completed",
        "exit_code": 0,
        "stdout_sha256": stdout_ref.sha256,
        "stderr_sha256": None,
        "duration_ms": 5,
    },
    source_seq=5,
)
append(
    "flag_candidate",
    {
        "flag_state": "candidate",
        "flag_digest": hashlib.sha256(b"flag{synthetic_determinism}").hexdigest(),
        "source": "synthetic verification",
    },
    source_seq=6,
)
append(
    "task_completed",
    {"result_state": "solved_flag_candidate", "status": "completed"},
    source_seq=7,
)
evidence.record_screenshot(
    ScreenshotRecord(
        screenshot_id="shot-1",
        task_id=TASK_ID,
        scope="desktop",
        captured_at=clock.now_ms(),
        status=CaptureStatus.OK,
        step_id="turn2-step3",
        session_id=SESSION_ID,
        sha256=png_ref.sha256,
        width=48,
        height=32,
        media_type="image/png",
    )
)
RAW_LOG = b"\x28\xb5\x2f\xfd synthetic-raw-lead-session-log-bytes" * 8
raw_ref = evidence.store_artifact(RAW_LOG, media_type="application/zstd", source="det:raw")
evidence.record_ingestion(
    SOURCE_ID,
    task_id=TASK_ID,
    session_id=SESSION_ID,
    last_seq=7,
    sha256=hashlib.sha256(RAW_LOG).hexdigest(),
    raw_sha256=raw_ref.sha256,
    frames=3,
    records=8,
    gaps=0,
)

WRITEUP_1 = DET / "writeup_1.md"
WRITEUP_2 = DET / "writeup_2.md"


def g01() -> str:
    info1 = WriteupBuilder(evidence).build(task_for_build, WRITEUP_1)
    info2 = WriteupBuilder(evidence).build(task_for_build, WRITEUP_2)
    bytes1 = WRITEUP_1.read_bytes()
    bytes2 = WRITEUP_2.read_bytes()
    assert bytes1 == bytes2, "two writeup builds are not byte-identical"
    assert info1["sha256"] == info2["sha256"] == hashlib.sha256(bytes1).hexdigest()
    DET_STATE["writeup"] = bytes1.decode("utf-8")
    return f"two builds byte-identical (sha256 {info1['sha256'][:16]}…, {len(bytes1)} bytes)"


DET_STATE: dict[str, str] = {}
check("G01 writeup determinism", g01)


def g02() -> str:
    text = DET_STATE["writeup"]
    assert text.count(NOTES) == 1, f"intake notes rendered {text.count(NOTES)} times"
    assert text.count(COMPLETION_NOTE) == 1, (
        f"completion note rendered {text.count(COMPLETION_NOTE)} times"
    )
    assert "## 2. Challenge description and scope" in text
    assert "### 2.1 Completion note (outcome record)" in text
    assert "reproduced in section 1" in text
    # Notes must not be duplicated inside section 2.
    section2 = text.split("## 2. Challenge description and scope", 1)[1]
    assert NOTES not in section2, "intake notes duplicated in section 2"
    first_index = text.index(NOTES)
    completion_index = text.index(COMPLETION_NOTE)
    assert first_index < text.index("## 2. Challenge description and scope"), (
        "notes are not in section 1"
    )
    assert completion_index > text.index("### 2.1 Completion note"), (
        "completion note not in subsection 2.1"
    )
    (DET / "writeup_checked.md").write_text(text, encoding="utf-8")
    return "notes exactly once (section 1); completion note once (2.1); no duplication"


check("G02 writeup notes/completion-note rendering", g02)


def g03() -> str:
    text = DET_STATE["writeup"]
    # The tool_call branch heading must carry the recorded (turn, step) and the
    # final-freeze actor label (this fixture's tool_call has worker_id NULL => Lead).
    for line in text.splitlines():
        if "initiated" in line and "(turn 2, step 3)" in line:
            tool_heading_line = line
            break
    else:
        tool_heading_line = ""
    assert tool_heading_line, "no tool_call heading with (turn 2, step 3)"
    assert "Lead initiated `bash`" in tool_heading_line, (
        f"Lead tool_call not labelled 'Lead initiated': {tool_heading_line!r}"
    )
    tool_heading_at = text.index(tool_heading_line)
    screenshot_at = text.index("screenshots/shot-1.png", tool_heading_at)
    next_heading = text.find("### Step", tool_heading_at + len(tool_heading_line))
    if next_heading == -1:
        next_heading = text.find("## ", tool_heading_at + len(tool_heading_line))
    assert next_heading == -1 or screenshot_at < next_heading, (
        "screenshot not attached to the turn2-step3 tool-call step"
    )
    # Recorded observation: the synthetic fixture intentionally contains BOTH the
    # Manager execution_started event and the Lead tool_call for the same step, so
    # the same screenshot is listed under each matching step section.
    screenshot_count = text.count("screenshots/shot-1.png")
    DET_STATE["screenshot_count"] = str(screenshot_count)
    return (
        f"tool_call heading `{tool_heading_line.strip()}`; derived-step screenshot attached"
        f" (listed {screenshot_count}x because both event families share step turn2-step3)"
    )


check("G03 writeup turn/step heading + derived screenshot binding", g03)


ZIP_SHA: dict[str, str] = {}


def g04() -> str:
    builder = EvidenceBundleBuilder(evidence, paths)
    info1 = builder.build(task_for_build)
    sha1 = sha256_file(Path(info1.path))
    bytes1 = Path(info1.path).read_bytes()
    info2 = EvidenceBundleBuilder(evidence, paths).build(task_for_build)
    sha2 = sha256_file(Path(info2.path))
    bytes2 = Path(info2.path).read_bytes()
    assert sha1 == sha2, f"two ZIP builds differ: {sha1} != {sha2}"
    assert bytes1 == bytes2, "ZIP bytes are not deterministic"
    assert info1.sha256 == sha2
    ZIP_SHA["sha"] = sha1
    ZIP_SHA["path"] = info1.path
    extract = DET / "zip-extract"
    report = EvidenceBundleBuilder.verify_zip(info1.path, extract)
    assert report["ok"], report["problems"]
    members = set(report["members"])
    expected = {
        "writeup.md",
        "events.jsonl",
        f"raw/session-{raw_ref.sha256[:16]}.jsonl.zstd",
        "screenshots/shot-1.png",
        "manifest.sha256",
    }
    assert expected <= members, expected - members
    extracted_raw = (extract / f"raw/session-{raw_ref.sha256[:16]}.jsonl.zstd").read_bytes()
    assert extracted_raw == RAW_LOG, "raw Lead log bytes not preserved in the ZIP"
    extracted_writeup = (extract / "writeup.md").read_text(encoding="utf-8")
    assert extracted_writeup == DET_STATE["writeup"], "ZIP writeup differs from the built writeup"
    # events.jsonl is this Task's events.
    events_lines = [
        json.loads(line)
        for line in (extract / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(events_lines) == 7, len(events_lines)
    assert {event["task_id"] for event in events_lines} == {TASK_ID}
    return (
        f"ZIP determinism sha256 {sha1[:16]}…; internal verify ok; writeup+events+"
        "screenshot+raw session log included"
    )


check("G04 ZIP determinism + internal verify + raw log inclusion", g04)


def g05() -> str:
    from ctf_solver.delivery.bundle import DeliveryError

    builder = EvidenceBundleBuilder(evidence, paths)
    builder.verify_zip = staticmethod(  # type: ignore[method-assign]
        lambda *args, **kwargs: {"ok": False, "problems": ["synthetic forced manifest failure"]}
    )
    try:
        builder.build(task_for_build)
    except DeliveryError as exc:
        assert "internal verification" in str(exc), str(exc)
        assert "synthetic forced manifest failure" in str(exc), str(exc)
        return "forced manifest failure raises DeliveryError (fail closed)"
    finally:
        # Restore a valid ZIP for later inspection.
        EvidenceBundleBuilder(evidence, paths).build(task_for_build)
    raise AssertionError("build did not raise DeliveryError on failed internal verification")


check("G05 bundle fails closed when internal verify fails", g05)


def g06() -> str:
    zip_path = Path(ZIP_SHA["path"])
    if not zip_path.is_file():
        raise AssertionError("ZIP missing")
    report = EvidenceBundleBuilder.verify_zip(zip_path, DET / "zip-extract-2")
    assert report["ok"], report["problems"]
    return f"final ZIP still verifies ({len(report['members'])} members)"


check("G06 final ZIP manifest verifies", g06)

# ===========================================================================
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
(VERIFIER / "phase2_migration_determinism.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
)
print(f"results -> {VERIFIER / 'phase2_migration_determinism.json'}")
try:
    evidence.close()
finally:
    store.close()
sys.exit(1 if summary["fail"] else 0)
