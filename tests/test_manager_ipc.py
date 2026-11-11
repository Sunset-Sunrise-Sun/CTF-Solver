"""Tests for the Manager loopback IPC endpoint and the Worker bridge path."""

from __future__ import annotations

import json
import socket

import pytest

from ctf_solver.core.types import ExecutionResult, ExecutionStatus
from ctf_solver.mcp.bridge import ManagerIpcClient
from ctf_solver.core.errors import IpcError
from tests.support.fakes import FakeAcp, FakeCapturer, FakeDeliverables, FakeEvidence, FakePipeline
from tests.test_manager_service import build_service


def _ipc_call(service, payload: dict) -> dict:
    host_port = service.ipc_url[len("tcp://") :]
    host, port_text = host_port.rsplit(":", 1)
    with socket.create_connection((host, int(port_text)), timeout=10) as sock:
        sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        buffer = bytearray()
        while b"\n" not in buffer:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buffer.extend(chunk)
    return json.loads(bytes(buffer).split(b"\n", 1)[0].decode("utf-8"))


def test_ipc_ping_and_worker_info(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        ping = _ipc_call(service, {"id": 1, "method": "ping", "token": worker.worker_token, "params": {}})
        assert ping["result"]["ok"] is True
        info = _ipc_call(
            service, {"id": 2, "method": "worker_info", "token": worker.worker_token, "params": {}}
        )
        assert info["result"]["worker_id"] == worker.worker_id
        assert info["result"]["task_id"] == task.task_id
    finally:
        service.shutdown()
        store.close()


def test_ipc_rejects_invalid_token(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        response = _ipc_call(
            service,
            {
                "id": 3,
                "method": "ctf_exec",
                "token": "not-a-real-token",
                "params": {
                    "task_id": "t-1",
                    "worker_id": "w-1",
                    "step_id": "s1",
                    "tool_name": "internal.file_hash",
                    "argv": ["x"],
                    "cwd": "/tmp",
                },
            },
        )
        assert "error" in response
        assert response["error"]["reason_code"] == "unknown_worker"
        assert service.pipeline.calls == []
    finally:
        service.shutdown()
        store.close()


def test_ipc_rejects_malformed_json(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        host_port = service.ipc_url[len("tcp://") :]
        host, port_text = host_port.rsplit(":", 1)
        with socket.create_connection((host, int(port_text)), timeout=10) as sock:
            sock.sendall(b"{not json\n")
            buffer = bytearray()
            while b"\n" not in buffer:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer.extend(chunk)
        response = json.loads(bytes(buffer).split(b"\n", 1)[0].decode("utf-8"))
        assert "error" in response
    finally:
        service.shutdown()
        store.close()


def test_ipc_exec_requires_matching_worker_identity(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        response = _ipc_call(
            service,
            {
                "id": 4,
                "method": "ctf_exec",
                "token": worker.worker_token,
                "params": {
                    "task_id": "t-other",
                    "worker_id": "w-other",
                    "step_id": "s1",
                    "tool_name": "internal.file_hash",
                    "argv": ["x"],
                    "cwd": task.workspace_path,
                },
            },
        )
        assert "error" in response
        assert response["error"]["reason_code"] == "worker_mismatch"
        assert service.pipeline.calls == []
    finally:
        service.shutdown()
        store.close()


def test_ipc_exec_forwards_to_pipeline(tmp_path) -> None:
    service, _acp, _evidence, pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        worker = store.get_worker_for_task(task.task_id)
        host_port = service.ipc_url[len("tcp://") :].rsplit(":", 1)
        bridge = ManagerIpcClient(service.ipc_url, worker.worker_token, timeout_s=10)
        payload = {
            "task_id": task.task_id,
            "worker_id": worker.worker_id,
            "step_id": "step-1",
            "tool_name": "internal.file_hash",
            "argv": ["README.md"],
            "cwd": task.workspace_path,
        }
        result = bridge.execute(payload)
        assert result["status"] == "completed"
        assert result["task_id"] == task.task_id
        assert len(pipeline.calls) == 1
        forwarded_request, token = pipeline.calls[0]
        assert forwarded_request.step_id == "step-1"
        assert token == worker.worker_token
        info = bridge.worker_info()
        assert info["worker_id"] == worker.worker_id
    finally:
        service.shutdown()
        store.close()
