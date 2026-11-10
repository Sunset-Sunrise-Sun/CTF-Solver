"""A minimal ManagerControl stub for MCP/manager-server tests (Lead-owned)."""

from __future__ import annotations

from typing import Any

from ctf_solver.core.errors import NotFoundError
from ctf_solver.core.types import (
    ApprovalRecord,
    ApprovalStatus,
    Category,
    ExportInfo,
    FlagState,
    GrantRecord,
    GrantStatus,
    ScreenshotRecord,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
    CaptureStatus,
)


def _task(task_id: str = "t-stub0001") -> TaskRecord:
    return TaskRecord(
        task_id=task_id,
        conversation_id="conv-1",
        title="Synthetic stub challenge",
        category=Category.MISC,
        workspace_path=f"D:/tmp/{task_id}/work",
        status=TaskStatus.RUNNING,
        acp_session_id="session-stub",
        worker_id="w-stub0001",
        created_at=1_700_000_000_000,
        updated_at=1_700_000_000_100,
        started_at=1_700_000_000_050,
        flag_state=FlagState.NONE,
    )


class StubManager:
    """Implements enough of ManagerControl for MCP surface tests."""

    def __init__(self) -> None:
        self.task = _task()
        self.approvals: dict[str, ApprovalRecord] = {
            "apr-1": ApprovalRecord(
                approval_id="apr-1",
                task_id=self.task.task_id,
                action_kind="remote_target",
                action_digest="0" * 64,
                status=ApprovalStatus.APPROVED,
                requested_at=1_700_000_000_000,
                decided_at=1_700_000_000_100,
                approver="human-stub",
            )
        }
        self.grants: dict[str, GrantRecord] = {
            "grant-1": GrantRecord(
                grant_id="grant-1",
                task_id=self.task.task_id,
                competition_profile="synthetic-local",
                host="127.0.0.1",
                port=31337,
                protocol="tcp",
                method="GET",
                path_prefix="/",
                expires_at=1_900_000_000_000,
                max_calls=5,
                approver="human-stub",
                created_at=1_700_000_000_000,
            )
        }

    def _require_task(self, task_id: str) -> TaskRecord:
        if task_id != self.task.task_id:
            raise NotFoundError(f"unknown task: {task_id}")
        return self.task

    def create_task(self, **kwargs: Any) -> TaskRecord:
        return self.task

    def list_tasks(self, *, status: str | None = None, conversation_id: str | None = None) -> list[TaskRecord]:
        return [self.task]

    def get_task(self, task_id: str) -> TaskRecord:
        return self._require_task(task_id)

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        self._require_task(task_id)
        return {"task": self.task.to_dict(), "worker": {"worker_id": "w-stub0001"}, "queue_position": None}

    def continue_task(self, task_id: str, message: str = "") -> dict[str, Any]:
        self._require_task(task_id)
        return {"task_id": task_id, "accepted": True, "model_call_suppressed": True}

    def pause_task(self, task_id: str, reason: str = "") -> dict[str, Any]:
        self._require_task(task_id)
        return {"task_id": task_id, "status": "paused"}

    def cancel_task(self, task_id: str, reason: str = "") -> dict[str, Any]:
        self._require_task(task_id)
        return {"task_id": task_id, "status": "cancel_requested"}

    def request_approval(
        self, task_id: str, *, action_kind: str, details: dict[str, Any], ttl_s: int | None = None
    ) -> ApprovalRecord:
        self._require_task(task_id)
        record = ApprovalRecord(
            approval_id="apr-2",
            task_id=task_id,
            action_kind=action_kind,
            action_digest="1" * 64,
            status=ApprovalStatus.PENDING,
            requested_at=1_700_000_000_000,
        )
        self.approvals[record.approval_id] = record
        return record

    def decide_approval(
        self, approval_id: str, *, approved: bool, approver: str, note: str = ""
    ) -> ApprovalRecord:
        record = self.approvals.get(approval_id)
        if record is None:
            raise NotFoundError(f"unknown approval: {approval_id}")
        return record

    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]:
        return list(self.approvals.values())

    def create_network_grant(self, task_id: str, **kwargs: Any) -> GrantRecord:
        self._require_task(task_id)
        record = GrantRecord(
            grant_id="grant-2",
            task_id=task_id,
            competition_profile=str(kwargs.get("competition_profile", "synthetic-local")),
            host=str(kwargs.get("host", "127.0.0.1")),
            port=int(kwargs.get("port", 31337)),
            protocol=str(kwargs.get("protocol", "tcp")),
            method=str(kwargs.get("method", "GET")),
            path_prefix=str(kwargs.get("path_prefix", "/")),
            expires_at=1_900_000_000_000,
            max_calls=int(kwargs.get("max_calls", 10)),
            approver=str(kwargs.get("approver", "human-stub")),
            created_at=1_700_000_000_000,
        )
        self.grants[record.grant_id] = record
        return record

    def revoke_grant(self, grant_id: str) -> GrantRecord:
        record = self.grants.get(grant_id)
        if record is None:
            raise NotFoundError(f"unknown grant: {grant_id}")
        return record

    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]:
        return list(self.grants.values())

    def record_candidate_flag(self, task_id: str, *, flag: str, source: str) -> dict[str, Any]:
        self._require_task(task_id)
        return {"task_id": task_id, "flag_state": "candidate", "source": source}

    def take_screenshot(self, task_id: str, *, step_id: str | None = None, scope: str = "desktop") -> ScreenshotRecord:
        self._require_task(task_id)
        return ScreenshotRecord(
            screenshot_id="shot-stub",
            task_id=task_id,
            worker_id=self.task.worker_id,
            step_id=step_id,
            session_id=self.task.acp_session_id,
            scope=scope,
            captured_at=1_700_000_000_200,
            status=CaptureStatus.OK,
            sha256="2" * 64,
            width=96,
            height=64,
        )

    def ingest_session_log(self, task_id: str, *, path: str, worker_id: str | None = None) -> dict[str, Any]:
        self._require_task(task_id)
        return {"task_id": task_id, "path": path, "appended": 0, "skipped_duplicates": 0, "gaps": []}

    def export_events(self, task_id: str) -> ExportInfo:
        self._require_task(task_id)
        return ExportInfo(kind="events_jsonl", path=f"D:/tmp/{task_id}/evidence/events.jsonl", sha256="3" * 64, size=10, entries=1)

    def build_writeup(self, task_id: str) -> ExportInfo:
        self._require_task(task_id)
        return ExportInfo(kind="writeup", path=f"D:/tmp/{task_id}/writeup.md", sha256="4" * 64, size=10, entries=1)

    def export_evidence_zip(self, task_id: str) -> ExportInfo:
        self._require_task(task_id)
        return ExportInfo(kind="evidence_zip", path=f"D:/tmp/{task_id}/evidence.zip", sha256="5" * 64, size=10, entries=1)

    def recover(self) -> dict[str, Any]:
        return {"recovered": 0}

    def runtime_status(self) -> dict[str, Any]:
        return {"acp": {"state": "ready"}, "active_workers": 1, "queued_tasks": 0}

    def shutdown(self) -> None:
        pass
