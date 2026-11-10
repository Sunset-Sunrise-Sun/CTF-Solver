"""Fakes implementing the frozen protocols for Manager/service tests (Lead-owned)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from ctf_solver.core.canonical import sha256_hex
from ctf_solver.core.errors import AcpError, AcpProcessExited, ModelCallNotAuthorized
from ctf_solver.core.types import (
    ArtifactRef,
    CaptureResult,
    ChainStatus,
    ExecutionResult,
    ExecutionStatus,
    ExportInfo,
    ScreenshotRecord,
    TaskRecord,
)


class FakeAcp:
    """In-process fake ACP client implementing AcpSessionClient."""

    def __init__(self, *, fail_new_session_for: set[str] | None = None) -> None:
        self.state = "stopped"
        self.alive = False
        self.fail_new_session_for = set(fail_new_session_for or set())
        self.sessions: dict[str, dict[str, Any]] = {}
        self.new_session_calls: list[dict[str, Any]] = []
        self.cancel_calls: list[str] = []
        self.close_calls: list[str] = []
        self.prompt_calls: list[dict[str, Any]] = []
        self.close_should_fail = False
        self.cancel_should_fail = False
        self.on_new_session: Any = None
        self.permission_handler = None
        self.session_update_handler = None
        self._counter = 0
        self._lock = threading.Lock()

    # AcpSessionClient -------------------------------------------------

    def start(self) -> None:
        self.state = "ready"
        self.alive = True

    def stop(self, timeout_s: float = 10.0) -> None:
        self.state = "stopped"
        self.alive = False

    def is_alive(self) -> bool:
        return self.alive

    def diagnostics(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "alive": self.alive,
            "new_sessions": len(self.sessions),
            "cancel_calls": len(self.cancel_calls),
            "close_calls": len(self.close_calls),
            "prompt_calls": len(self.prompt_calls),
        }

    def new_session(self, cwd: str, mcp_servers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if not Path(cwd).is_absolute():
            raise AcpError(f"cwd must be absolute: {cwd!r}")
        if self.on_new_session is not None:
            self.on_new_session(cwd, mcp_servers)
        for marker in self.fail_new_session_for:
            if marker in cwd:
                raise AcpError(f"synthetic new_session failure for {marker}")
        with self._lock:
            self._counter += 1
            session_id = f"session-fake-{self._counter:04d}"
        self.new_session_calls.append({"cwd": cwd, "mcp_servers": mcp_servers, "session_id": session_id})
        self.sessions[session_id] = {"cwd": cwd, "mcp_servers": mcp_servers, "active": True}
        return {"sessionId": session_id, "configOptions": [{"id": "model", "currentValue": "fake"}]}

    def list_sessions(self, cwd: str | None = None) -> dict[str, Any]:
        sessions = [
            {"sessionId": session_id, "cwd": info["cwd"]}
            for session_id, info in self.sessions.items()
            if not info["active"]
        ]
        return {"sessions": sessions}

    def resume_session(self, session_id: str, cwd: str) -> dict[str, Any]:
        info = self.sessions.get(session_id)
        if info is None or info["active"]:
            raise AcpError("cannot resume active/unknown session")
        return {"configOptions": []}

    def close_session(self, session_id: str) -> None:
        self.close_calls.append(session_id)
        if self.close_should_fail:
            raise AcpError("synthetic close failure")
        info = self.sessions.get(session_id)
        if info is None:
            raise AcpError("unknown session")
        info["active"] = False

    def cancel_session(self, session_id: str) -> None:
        self.cancel_calls.append(session_id)
        if self.cancel_should_fail:
            raise AcpError("synthetic cancel failure")

    def prompt(self, session_id: str, content: list[dict[str, Any]]) -> dict[str, Any]:
        self.prompt_calls.append({"session_id": session_id, "content": content})
        raise ModelCallNotAuthorized("Round 1 forbids session/prompt")

    def set_session_update_handler(self, handler) -> None:
        self.session_update_handler = handler

    def set_permission_handler(self, handler) -> None:
        self.permission_handler = handler

    # helpers ----------------------------------------------------------

    def simulate_crash(self) -> None:
        self.alive = False
        self.state = "crashed"

    def session_for(self, cwd: str) -> dict[str, Any] | None:
        for call in self.new_session_calls:
            if call["cwd"] == cwd:
                return call
        return None


class FakeEvidence:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.artifacts: dict[str, bytes] = {}
        self.screenshots: list[ScreenshotRecord] = []
        self.exports: list[ExportInfo] = []
        self.closed = False

    def append_event(
        self,
        *,
        task_id: str,
        worker_id: str | None = None,
        session_id: str | None = None,
        source: str,
        source_id: str | None = None,
        source_seq: int | None = None,
        event_type: str,
        payload: dict[str, Any],
        timestamp: int | None = None,
        record_id: str | None = None,
    ) -> str:
        record_id = record_id or f"ev-{len(self.events) + 1:04d}"
        self.events.append(
            {
                "record_id": record_id,
                "task_id": task_id,
                "worker_id": worker_id,
                "session_id": session_id,
                "source": source,
                "source_id": source_id,
                "source_seq": source_seq,
                "event_type": event_type,
                "payload": dict(payload),
                "timestamp": timestamp or 0,
            }
        )
        return record_id

    def store_artifact(self, data: bytes, *, media_type: str = "application/octet-stream", source: str = "") -> ArtifactRef:
        digest = sha256_hex(data)
        self.artifacts[digest] = data
        return ArtifactRef(sha256=digest, size=len(data), media_type=media_type)

    def store_artifact_file(self, path, *, media_type: str = "application/octet-stream", source: str = "") -> ArtifactRef:
        return self.store_artifact(Path(path).read_bytes(), media_type=media_type, source=source)

    def chain_head(self) -> tuple[int, str]:
        return (len(self.events), "f" * 64)

    def chain_status(self) -> ChainStatus:
        return ChainStatus(ok=True, records=len(self.events), head_hash="f" * 64)

    def record_screenshot(self, record: ScreenshotRecord) -> None:
        self.screenshots.append(record)

    def list_screenshots(self, task_id: str) -> list[ScreenshotRecord]:
        return [record for record in self.screenshots if record.task_id == task_id]

    def list_events(self, *, task_id=None, after_seq=None, limit=None, event_type=None):
        items = list(self.events)
        if task_id is not None:
            items = [item for item in items if item["task_id"] == task_id]
        if event_type is not None:
            items = [item for item in items if item["event_type"] == event_type]
        if after_seq is not None:
            items = items[after_seq:]
        if limit is not None:
            items = items[:limit]
        return items

    def export_events_jsonl(self, *, task_id: str, out_path) -> ExportInfo:
        import json

        target = Path(out_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = "\n".join(json.dumps(event, ensure_ascii=False) for event in self.events) + "\n"
        target.write_text(text, encoding="utf-8")
        payload = text.encode("utf-8")
        return ExportInfo(kind="events_jsonl", path=str(target), sha256=sha256_hex(payload), size=len(payload), entries=len(self.events))

    def ingest_session_log_file(self, *, task_id: str, worker_id: str | None, session_id: str | None, path: str):
        return {
            "task_id": task_id,
            "worker_id": worker_id,
            "session_id": session_id,
            "path": path,
            "frames": 2,
            "decoded_records": 3,
            "appended": 3,
            "skipped_duplicates": 0,
            "gaps": [],
            "raw_sha256": "a" * 64,
            "complete": True,
        }

    def record_export(self, info: ExportInfo) -> None:
        self.exports.append(info)

    def close(self) -> None:
        self.closed = True


class FakePipeline:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, str]] = []

    def execute(self, request, worker_token: str) -> ExecutionResult:
        self.calls.append((request, worker_token))
        return ExecutionResult(
            execution_id=f"exec-{len(self.calls):04d}",
            task_id=request.task_id,
            worker_id=request.worker_id,
            step_id=request.step_id,
            tool_name=request.tool_name,
            tool_version="1.0",
            argv=list(request.argv),
            cwd=request.cwd,
            status=ExecutionStatus.COMPLETED,
            started_at=1,
            ended_at=2,
            exit_code=0,
            stdout_preview="fake output",
        )


class FakeDeliverables:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.writeups: list[str] = []
        self.zips: list[str] = []

    def build_writeup(self, task: TaskRecord) -> ExportInfo:
        path = self.root / "tasks" / task.task_id / "writeup.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {task.title}\n", encoding="utf-8")
        self.writeups.append(task.task_id)
        return ExportInfo(kind="writeup", path=str(path), sha256="b" * 64, size=8, entries=1)

    def export_evidence_zip(self, task: TaskRecord) -> ExportInfo:
        path = self.root / "tasks" / task.task_id / "evidence.zip"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"PK")
        self.zips.append(task.task_id)
        return ExportInfo(kind="evidence_zip", path=str(path), sha256="c" * 64, size=2, entries=1)


class FakeCapturer:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.calls: list[dict[str, Any]] = []

    def capture(self, *, scope: str, workdir: str | None = None) -> CaptureResult:
        self.calls.append({"scope": scope, "workdir": workdir})
        if self.mode == "ok":
            return CaptureResult(ok=True, png_bytes=b"\x89PNG\r\n\x1a\nfake", width=96, height=64, blank=False, method="fake", captured_at=1234)
        if self.mode == "blank":
            return CaptureResult(ok=True, png_bytes=b"\x89PNG\r\n\x1a\nblank", width=96, height=64, blank=True, method="fake", captured_at=1234)
        return CaptureResult(ok=False, png_bytes=b"", error="synthetic capture failure", method="fake", captured_at=1234)
