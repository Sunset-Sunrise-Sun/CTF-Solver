"""Worker-resolution parity scenarios (run under both trees)."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.getcwd())
from ctf_solver.core.types import Category, TaskRecord, TaskStatus, WorkerRecord, WorkerStatus
from ctf_solver.manager.session_logs import SessionLogResolver
from ctf_solver.manager.store import ManagerStore

try:
    import zstandard as _zstd
    def _compress(data):
        return _zstd.ZstdCompressor(level=3).compress(data)
except ImportError:
    from compression import zstd as _stdz
    def _compress(data):
        return (
            _stdz.ZstdCompressor().compress(data)
            if hasattr(_stdz, "ZstdCompressor")
            else _stdz.compress(data)
        )


def log_bytes(records):
    payload = b"".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for record in records
    )
    return _compress(payload)


def header(session_id, cwd):
    return {"type": "session", "seq": 0, "time": 1, "data": {"id": session_id, "cwd": cwd}}


def main() -> int:
    work = Path(sys.argv[1])
    if work.exists():
        import shutil
        shutil.rmtree(work)
    work.mkdir(parents=True)
    db = work / "db.sqlite"
    store = ManagerStore(str(db))
    tasks = work / "tasks"
    worker_root = work / "worker-sessions"

    def task(task_id, *, with_worker, session_id=None):
        record = TaskRecord(
            task_id=task_id,
            conversation_id="c",
            title="t",
            category=Category.MISC,
            workspace_path=str(tasks / task_id / "work"),
            status=TaskStatus.RUNNING,
            acp_session_id=session_id,
        )
        store.create_task(record)
        if with_worker and session_id:
            store.create_worker(
                WorkerRecord(
                    worker_id="w-" + task_id,
                    task_id=task_id,
                    acp_session_id=session_id,
                    workspace_path=str(tasks / task_id / "work"),
                    status=WorkerStatus.RUNNING,
                    worker_token="tok-" + task_id,
                )
            )

    task("t-noworker", with_worker=False)
    task("t-missing", with_worker=True, session_id="sess-missing")
    task("t-mismatch", with_worker=True, session_id="sess-mismatch")
    task("t-ok", with_worker=True, session_id="sess-ok")

    (worker_root / "slug" / "sess-mismatch").mkdir(parents=True)
    (worker_root / "slug" / "sess-mismatch" / "session.v4.jsonl.zstd").write_bytes(
        log_bytes([header("other-session", str(work))])
    )
    (worker_root / "slug" / "sess-ok").mkdir(parents=True)
    (worker_root / "slug" / "sess-ok" / "session.v4.jsonl.zstd").write_bytes(
        log_bytes([header("sess-ok", str(work))])
    )

    outcomes = {}

    def capture(name, resolver, task_id):
        try:
            resolved = resolver.resolve(task_id)
            outcomes[name] = {
                "ok": True,
                "source": getattr(resolved, "source", None),
                "filename": resolved.path.name,
                "worker_id": resolved.worker_id,
            }
        except Exception as exc:  # noqa: BLE001
            outcomes[name] = {
                "ok": False,
                "reason_code": getattr(exc, "reason_code", type(exc).__name__),
                "message": str(exc),
            }

    good_resolver = SessionLogResolver(worker_root, store)
    capture("unknown_task", good_resolver, "t-unknown")
    capture("no_worker", good_resolver, "t-noworker")
    capture("log_missing", good_resolver, "t-missing")
    capture("header_mismatch", good_resolver, "t-mismatch")
    capture("valid", good_resolver, "t-ok")
    missing_root = SessionLogResolver(work / "no-such-root", store)
    capture("root_missing", missing_root, "t-ok")
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
