"""Synthetic Harness ``session.v4`` event builders for deterministic tests."""

from __future__ import annotations

from typing import Any, Iterable


def session_header(
    session_id: str,
    *,
    cwd: str = "D:/synthetic/tasks/t-demo/work",
    created_at: int = 1_700_000_000_000,
    origin: str | None = None,
    parent_session: str | None = None,
    delegation_depth: int = 0,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": session_id,
        "cwd": cwd,
        "createdAt": created_at,
        "version": 4,
        "isSeeded": False,
        "delegationDepth": delegation_depth,
        "agentPreset": "standard",
    }
    if origin:
        data["origin"] = origin
    if parent_session:
        data["parentSession"] = parent_session
    return {"type": "session", "seq": 0, "time": created_at, "data": data}


def _record(event_type: str, seq: int, time: int, data: dict[str, Any]) -> dict[str, Any]:
    return {"type": event_type, "seq": seq, "time": time, "data": data}


def sandbox_mode(seq: int, time: int, mode: str = "workspace-write") -> dict[str, Any]:
    return _record("sandbox/mode", seq, time, {"mode": mode})


def approval_policy(seq: int, time: int, policy: str = "ask") -> dict[str, Any]:
    return _record("approval/policy", seq, time, {"policy": policy})


def turn_start(seq: int, time: int, turn: int = 1) -> dict[str, Any]:
    return _record("turn/start", seq, time, {"turn": turn})


def turn_end(seq: int, time: int, turn: int = 1) -> dict[str, Any]:
    return _record("turn/end", seq, time, {"turn": turn})


def step_start(seq: int, time: int, turn: int = 1, step: int = 1) -> dict[str, Any]:
    return _record("step/start", seq, time, {"turn": turn, "step": step})


def step_end(seq: int, time: int, turn: int = 1, step: int = 1) -> dict[str, Any]:
    return _record("step/end", seq, time, {"turn": turn, "step": step})


def tool_call(
    seq: int,
    time: int,
    call_id: str,
    name: str,
    arguments: dict[str, Any] | str,
    *,
    turn: int = 1,
    step: int = 1,
) -> dict[str, Any]:
    argv = arguments if isinstance(arguments, str) else __import__("json").dumps(arguments)
    return _record(
        "tool/call",
        seq,
        time,
        {"turn": turn, "step": step, "callId": call_id, "name": name, "arguments": argv},
    )


def tool_result(
    seq: int,
    time: int,
    call_id: str,
    content: str,
    *,
    is_error: bool = False,
    cwd: str = "D:/synthetic/tasks/t-demo/work",
    turn: int = 1,
    step: int = 1,
) -> dict[str, Any]:
    return _record(
        "tool/result",
        seq,
        time,
        {
            "turn": turn,
            "step": step,
            "message": {
                "id": f"msg-{call_id}",
                "role": "tool",
                "toolCallId": call_id,
                "isError": is_error,
                "content": [{"type": "text", "text": content}],
                "source": {"kind": "tool", "callId": call_id},
            },
            "meta": {"cwd": cwd},
        },
    )


def job_registered(
    seq: int,
    time: int,
    job_id: str,
    tool_call_id: str,
    *,
    kind: str = "shell",
    label: str = "synthetic-job",
) -> dict[str, Any]:
    return _record(
        "job/registered",
        seq,
        time,
        {
            "jobId": job_id,
            "kind": kind,
            "label": label,
            "owner": "worker",
            "startedAt": time,
            "toolCall": tool_call_id,
        },
    )


def job_settled(
    seq: int,
    time: int,
    job_id: str,
    tool_call_id: str,
    *,
    status: str = "completed",
    cause: str = "exit",
    detail: str = "exit code: 0",
    kind: str = "shell",
) -> dict[str, Any]:
    return _record(
        "job/settled",
        seq,
        time,
        {
            "jobId": job_id,
            "kind": kind,
            "status": status,
            "cause": cause,
            "detail": detail,
            "startedAt": time - 10,
            "finishedAt": time,
            "toolCall": tool_call_id,
        },
    )


def approval_asked(
    seq: int,
    time: int,
    approval_id: str,
    call_id: str,
    tool_name: str = "mcp__ctf-exec__ctf_exec",
    reason: str = "synthetic approval",
) -> dict[str, Any]:
    return _record(
        "approval/asked",
        seq,
        time,
        {"id": approval_id, "callId": call_id, "toolName": tool_name, "reason": reason},
    )


def approval_decided(seq: int, time: int, approval_id: str, outcome: str = "approved") -> dict[str, Any]:
    return _record("approval/decided", seq, time, {"id": approval_id, "outcome": outcome})


def command_run(seq: int, time: int, command: str) -> dict[str, Any]:
    return _record("command/run", seq, time, {"command": command, "startedAt": time})


def command_done(seq: int, time: int, command: str, exit_code: int = 0) -> dict[str, Any]:
    return _record("command/done", seq, time, {"command": command, "exitCode": exit_code})


def delivery_accepted(seq: int, time: int, watermark: int = 0) -> dict[str, Any]:
    return _record(
        "session-log-deepseek/delivery-accepted",
        seq,
        time,
        {"watermark": watermark, "maxBytes": 65536},
    )


def assistant_message(seq: int, time: int, text: str = "synthetic plan") -> dict[str, Any]:
    return _record(
        "assistant/message",
        seq,
        time,
        {"content": [{"type": "text", "text": text}]},
    )


def user_message(seq: int, time: int, text: str = "synthetic challenge") -> dict[str, Any]:
    return _record("user/message", seq, time, {"content": [{"type": "text", "text": text}]})


def standard_session(
    *,
    session_id: str = "11111111-2222-3333-4444-555555555555",
    base_time: int = 1_700_000_000_000,
    include_approval: bool = False,
    include_unmatched_result: bool = False,
    include_unmatched_call: bool = False,
    include_gap: bool = False,
    include_delivery_accept: bool = True,
) -> list[dict[str, Any]]:
    """Build a realistic ordered session event list."""

    records: list[dict[str, Any]] = [session_header(session_id, created_at=base_time)]
    seq = 1
    time = base_time + 10
    records.append(sandbox_mode(seq, time))
    seq += 1
    time += 1
    records.append(approval_policy(seq, time))
    seq += 1
    time += 1
    records.append(user_message(seq, time))
    seq += 1
    time += 1
    records.append(turn_start(seq, time))
    seq += 1
    time += 1
    records.append(step_start(seq, time))
    seq += 1
    time += 1
    records.append(
        tool_call(
            seq,
            time,
            "call-0001",
            "mcp__ctf-exec__ctf_exec",
            {"tool_name": "internal.file_hash", "argv": ["README.md"]},
        )
    )
    seq += 1
    time += 1
    records.append(
        tool_result(
            seq,
            time,
            "call-0001",
            "sha256=deadbeef size=12\n",
        )
    )
    seq += 1
    time += 1
    records.append(job_registered(seq, time, "job-1", "call-0001"))
    seq += 1
    time += 1
    records.append(job_settled(seq, time, "job-1", "call-0001"))
    seq += 1
    time += 1
    if include_approval:
        records.append(approval_asked(seq, time, "apr-1", "call-0001"))
        seq += 1
        time += 1
        records.append(approval_decided(seq, time, "apr-1", "approved"))
        seq += 1
        time += 1
    if include_unmatched_result:
        records.append(tool_result(seq, time, "call-missing", "orphan output\n"))
        seq += 1
        time += 1
    if include_unmatched_call:
        records.append(tool_call(seq, time, "call-orphan", "write_file", {"path": "x"}))
        seq += 1
        time += 1
    if include_gap:
        seq += 2  # deliberately skip seq numbers to exercise gap detection
        time += 2
    records.append(command_run(seq, time, "synthetic-command"))
    seq += 1
    time += 1
    records.append(command_done(seq, time, "synthetic-command", 0))
    seq += 1
    time += 1
    records.append(assistant_message(seq, time))
    seq += 1
    time += 1
    if include_delivery_accept:
        records.append(delivery_accepted(seq, time))
        seq += 1
        time += 1
    records.append(step_end(seq, time))
    seq += 1
    time += 1
    records.append(turn_end(seq, time))
    return records


def records_without(records: Iterable[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [record for record in records if record.get("type") != event_type]
