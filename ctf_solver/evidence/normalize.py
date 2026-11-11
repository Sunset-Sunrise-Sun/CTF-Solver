"""Deterministic normalization of Harness ``session.v4`` records into evidence events.

The Harness session log is a JSON-Lines stream of records shaped as
``{"type": str, "seq": int, "time": int, "data": object}``. Normalization turns
those raw records into the frozen canonical event contract
(``docs/INTERFACES.md`` §4.6):

- ``tool/call`` ↔ ``tool/result`` correlate by ``callId``;
- tool-result content text is stored in CAS (full bytes) with a bounded preview,
  ``is_error`` and an exit code parsed from ``exit code: N``;
- job, harness-approval, command, turn and step records keep their structured
  state; other known message records and unknown record types become explicit
  ``passthrough`` events that preserve the raw ``data`` (bounded, with a CAS
  reference when bounded);
- unmatched calls/results and sequence gaps become explicit ``evidence_gap``
  events instead of being dropped;
- ``record_id`` is derived from the canonical identity of the record so
  re-ingesting the same bytes produces the same ids (idempotent ingestion).

Normalization performs no SQLite writes and no clock reads: the same raw
records plus the same CAS always produce byte-identical events.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..core.canonical import canonical_bytes, canonical_json, sha256_hex
from ..core.types import ArtifactRef

SOURCE_SESSION_LOG = "session_log"

#: Bounded preview length for tool-result content (characters).
CONTENT_PREVIEW_CHARS = 4096

#: Maximum size (characters) of a raw ``data`` value kept inline before it is
#: bounded and additionally preserved in CAS.
DATA_INLINE_CHARS = 32768

#: Per-string bound when a large ``data`` value is bounded.
DATA_STRING_CHARS = 4096

_EXIT_CODE_RE = re.compile(r"exit\s+code\s*:\s*(-?\d+)", re.IGNORECASE)

#: Raw record type -> canonical event type (frozen in INTERFACES §4.6).
RECORD_EVENT_TYPES: dict[str, str] = {
    "tool/call": "tool_call",
    "tool/result": "tool_result",
    "job/registered": "job_registered",
    "job/settled": "job_settled",
    "approval/asked": "harness_approval_asked",
    "approval/decided": "harness_approval_decided",
    "command/run": "command_run",
    "command/done": "command_done",
    "turn/start": "turn_start",
    "turn/end": "turn_end",
    "step/start": "step_start",
    "step/end": "step_end",
    "assistant/message": "assistant_message",
}

#: Event types whose payload always carries the raw ``data`` under ``data``.
PASSTHROUGH_EVENT = "passthrough"
EVIDENCE_GAP_EVENT = "evidence_gap"

#: Frozen ``evidence_gap`` reasons.
GAP_UNMATCHED_CALL = "unmatched_call"
GAP_UNMATCHED_RESULT = "unmatched_result"
GAP_SEQUENCE_GAP = "sequence_gap"
GAP_TORN_LINE = "torn_line"
GAP_FRAME_DECODE_ERROR = "frame_decode_error"
GAP_TRUNCATED_FRAME = "truncated_frame"


@dataclass
class NormalizedBatch:
    """Result of normalizing one parsed batch of session records."""

    events: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    artifacts: list[ArtifactRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": len(self.events),
            "gaps": [dict(gap) for gap in self.gaps],
            "stats": dict(self.stats),
            "artifacts": [ref.to_dict() for ref in self.artifacts],
        }


# ---------------------------------------------------------------------------
# Deterministic identity helpers
# ---------------------------------------------------------------------------


def deterministic_record_id(identity: dict[str, Any]) -> str:
    """Return ``ev-<sha256(canonical identity)[:24]>`` for an event identity."""

    return "ev-" + sha256_hex(canonical_bytes(identity))[:24]


def make_event(
    *,
    task_id: str,
    worker_id: str | None,
    session_id: str | None,
    source_id: str,
    source_seq: int | None,
    event_type: str,
    payload: dict[str, Any],
    timestamp: int = 0,
    identity: dict[str, Any] | None = None,
    source: str = SOURCE_SESSION_LOG,
) -> dict[str, Any]:
    """Build one normalized event dict with a deterministic ``record_id``."""

    record_id = deterministic_record_id(
        identity
        or {
            "kind": "event",
            "source": source,
            "source_id": source_id,
            "source_seq": source_seq,
            "event_type": event_type,
            "payload_sha256": sha256_hex(canonical_bytes(payload)),
        }
    )
    return {
        "record_id": record_id,
        "task_id": task_id,
        "worker_id": worker_id,
        "session_id": session_id,
        "source": source,
        "source_id": source_id,
        "source_seq": source_seq,
        "event_type": event_type,
        "timestamp": int(timestamp or 0),
        "payload": payload,
    }


def gap_event(
    *,
    task_id: str,
    worker_id: str | None,
    session_id: str | None,
    source_id: str,
    reason: str,
    detail: str,
    timestamp: int = 0,
    source_seq: int | None = None,
    extra: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
    source: str = SOURCE_SESSION_LOG,
) -> dict[str, Any]:
    """Build one explicit ``evidence_gap`` event.

    ``extra`` adds structured context (matching range, call id, frame index …).
    The identity defaults to the reason plus the structured context, so the same
    gap detected again by a later ingestion deduplicates by ``record_id``.
    """

    payload: dict[str, Any] = {"reason": reason, "detail": detail}
    if source_seq is not None:
        payload["source_seq"] = source_seq
    if extra:
        for key, value in extra.items():
            payload.setdefault(key, value)
    gap_identity = identity or {
        "kind": "evidence_gap",
        "source": source,
        "source_id": source_id,
        "reason": reason,
        "source_seq": source_seq,
        "extra": extra or {},
    }
    return make_event(
        task_id=task_id,
        worker_id=worker_id,
        session_id=session_id,
        source_id=source_id,
        source_seq=None,
        event_type=EVIDENCE_GAP_EVENT,
        payload=payload,
        timestamp=timestamp,
        identity=gap_identity,
        source=source,
    )


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"-?\d+", text):
            return int(text)
    return None


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return canonical_json(value)


def parse_exit_code(text: str | None) -> int | None:
    """Extract the first ``exit code: N`` value from free text."""

    if not text:
        return None
    match = _EXIT_CODE_RE.search(text)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:  # pragma: no cover - regex guarantees digits
        return None


def _canonical_size(value: Any) -> int:
    try:
        return len(canonical_bytes(value))
    except (TypeError, ValueError):
        return len(canonical_json(repr(value)))


def _bound_value(value: Any, *, max_string: int) -> Any:
    if isinstance(value, str):
        if len(value) <= max_string:
            return value
        return value[:max_string]
    if isinstance(value, list):
        return [_bound_value(item, max_string=max_string) for item in value]
    if isinstance(value, dict):
        return {str(key): _bound_value(item, max_string=max_string) for key, item in value.items()}
    return value


@dataclass
class _RawData:
    """Bounded inline view of a raw ``data`` value plus optional CAS reference."""

    inline: Any
    sha256: str | None = None
    size: int = 0
    bounded: bool = False


def _prepare_raw_data(data: Any, cas: Any, artifacts: list[ArtifactRef]) -> _RawData:
    """Bound a raw ``data`` value for metadata and preserve full bytes in CAS.

    Small values are embedded verbatim. Large values are bounded per string and
    the full canonical bytes are additionally stored in CAS so no evidence is
    lost while the SQLite payload stays bounded.
    """

    size = _canonical_size(data)
    if size <= DATA_INLINE_CHARS:
        return _RawData(inline=data, sha256=None, size=size, bounded=False)
    full_bytes = canonical_bytes(data)
    ref = cas.put_bytes(full_bytes, media_type="application/octet-stream")
    artifacts.append(ref)
    return _RawData(
        inline=_bound_value(data, max_string=DATA_STRING_CHARS),
        sha256=ref.sha256,
        size=size,
        bounded=True,
    )


def _raw_payload(
    raw_data: Any, cas: Any, artifacts: list[ArtifactRef], *, source_type: str
) -> dict[str, Any]:
    prepared = _prepare_raw_data(raw_data, cas, artifacts)
    payload: dict[str, Any] = {"data": prepared.inline, "source_type": source_type}
    if prepared.bounded:
        payload["data_sha256"] = prepared.sha256
        payload["data_size"] = prepared.size
        payload["data_bounded"] = True
    return payload


def _extract_result_text(data: dict[str, Any]) -> tuple[str, str | None, bool, list[str]]:
    """Extract (text, call_id, is_error, content_item_types) from a tool result."""

    message = data.get("message")
    if not isinstance(message, dict):
        message = {}
    content = message.get("content", data.get("content"))
    texts: list[str] = []
    item_types: list[str] = []
    if isinstance(content, str):
        texts.append(content)
        item_types.append("text")
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                item_type = _as_str(item.get("type"), "unknown")
                item_types.append(item_type)
                if item_type == "text":
                    texts.append(_as_str(item.get("text")))
            elif isinstance(item, str):
                texts.append(item)
                item_types.append("text")
    elif content is not None:
        texts.append(_as_str(content))
        item_types.append("text")
    call_id = message.get("toolCallId") or data.get("callId")
    if not call_id:
        source = message.get("source")
        if isinstance(source, dict):
            call_id = source.get("callId")
    is_error = bool(message.get("isError", data.get("isError", False)))
    return "\n".join(texts), (_as_str(call_id) if call_id else None), is_error, item_types


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_session_records(
    *,
    task_id: str,
    worker_id: str | None,
    session_id: str | None,
    raw_records: Sequence[dict] | Iterable[dict],
    cas: Any,
    source_id: str | None = None,
) -> NormalizedBatch:
    """Normalize raw session records into the frozen evidence event contract.

    ``source_id`` defaults to ``session:<session_id>``. ``worker_id`` and
    ``session_id`` may be ``None`` but ``task_id`` is required.
    """

    if not task_id:
        raise ValueError("task_id is required to normalize session records")
    if cas is None:
        raise ValueError("a CAS instance is required to normalize session records")
    if source_id is None:
        source_id = f"session:{session_id or task_id}"

    events: list[dict] = []
    gaps: list[dict] = []
    artifacts: list[ArtifactRef] = []
    counts: dict[str, int] = {}
    pending_calls: dict[str, dict[str, Any]] = {}
    seen_sequences: set[int] = set()
    previous_max_seq: int | None = None
    last_timestamp = 0
    correlated_pairs = 0
    duplicate_sequences = 0

    records = list(raw_records)

    def emit_gap(
        reason: str,
        detail: str,
        *,
        timestamp: int,
        source_seq: int | None = None,
        extra: dict[str, Any] | None = None,
        identity: dict[str, Any] | None = None,
    ) -> None:
        gap = gap_event(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            source_id=source_id,
            reason=reason,
            detail=detail,
            timestamp=timestamp,
            source_seq=source_seq,
            extra=extra,
            identity=identity,
        )
        events.append(gap)
        gaps.append(dict(gap["payload"]))
        counts[EVIDENCE_GAP_EVENT] = counts.get(EVIDENCE_GAP_EVENT, 0) + 1

    def emit_event(event: dict[str, Any]) -> None:
        events.append(event)
        event_type = event["event_type"]
        counts[event_type] = counts.get(event_type, 0) + 1

    for position, raw in enumerate(records):
        if not isinstance(raw, dict):
            emit_gap(
                GAP_SEQUENCE_GAP,
                f"raw record {position} is not a JSON object ({type(raw).__name__}); "
                "preserved as a passthrough event",
                timestamp=last_timestamp,
                extra={"index": position},
                identity={"kind": "invalid_record", "source_id": source_id, "index": position},
            )
            emit_event(
                make_event(
                    task_id=task_id,
                    worker_id=worker_id,
                    session_id=session_id,
                    source_id=source_id,
                    source_seq=None,
                    event_type=PASSTHROUGH_EVENT,
                    payload=_raw_payload(raw, cas, artifacts, source_type="invalid_record"),
                    timestamp=last_timestamp,
                    identity={
                        "kind": "passthrough",
                        "source_id": source_id,
                        "index": position,
                        "raw": _as_str(raw),
                    },
                )
            )
            continue

        raw_type = raw.get("type")
        raw_type_str = _as_str(raw_type)
        timestamp = _as_int(raw.get("time"))
        if timestamp is None:
            timestamp = last_timestamp
        else:
            last_timestamp = timestamp
        seq = _as_int(raw.get("seq"))
        data = raw.get("data")
        if not isinstance(data, dict):
            data = {"value": data}

        source_seq = seq
        duplicate_seq = False
        if seq is not None:
            if seq in seen_sequences:
                duplicate_seq = True
                duplicate_sequences += 1
                emit_gap(
                    GAP_SEQUENCE_GAP,
                    f"duplicate sequence number {seq} in session log",
                    timestamp=timestamp,
                    source_seq=seq,
                    extra={"duplicate_seq": seq},
                    identity={
                        "kind": "duplicate_sequence",
                        "source_id": source_id,
                        "seq": seq,
                        "index": position,
                    },
                )
                source_seq = None
            else:
                if previous_max_seq is not None and seq > previous_max_seq + 1:
                    missing_from = previous_max_seq + 1
                    missing_to = seq - 1
                    emit_gap(
                        GAP_SEQUENCE_GAP,
                        f"missing session sequence numbers {missing_from}..{missing_to} "
                        f"before seq {seq}",
                        timestamp=timestamp,
                        extra={
                            "missing_from": missing_from,
                            "missing_to": missing_to,
                            "detected_at_seq": seq,
                        },
                        identity={
                            "kind": "sequence_gap",
                            "source_id": source_id,
                            "missing_from": missing_from,
                            "missing_to": missing_to,
                        },
                    )
                elif previous_max_seq is not None and seq <= previous_max_seq:
                    emit_gap(
                        GAP_SEQUENCE_GAP,
                        f"out-of-order session sequence number {seq} after {previous_max_seq}",
                        timestamp=timestamp,
                        source_seq=seq,
                        extra={"out_of_order_seq": seq, "previous_max_seq": previous_max_seq},
                        identity={
                            "kind": "out_of_order_sequence",
                            "source_id": source_id,
                            "seq": seq,
                            "previous_max_seq": previous_max_seq,
                        },
                    )
                seen_sequences.add(seq)
                previous_max_seq = seq if previous_max_seq is None else max(previous_max_seq, seq)

        event_type, payload, identity = _normalize_record(
            raw_type=raw_type_str,
            data=data,
            seq=seq,
            timestamp=timestamp,
            cas=cas,
            artifacts=artifacts,
            source_id=source_id,
            pending_calls=pending_calls,
            emit_gap=emit_gap,
        )
        identity = dict(identity)
        identity["source_id"] = source_id
        identity["source_seq"] = source_seq
        if duplicate_seq:
            identity["duplicate_of_seq"] = seq
        emit_event(
            make_event(
                task_id=task_id,
                worker_id=worker_id,
                session_id=session_id,
                source_id=source_id,
                source_seq=source_seq,
                event_type=event_type,
                payload=payload,
                timestamp=timestamp,
                identity=identity,
            )
        )
        if event_type == "tool_result" and payload.get("call_matched"):
            correlated_pairs += 1

    for call_id, call in pending_calls.items():
        emit_gap(
            GAP_UNMATCHED_CALL,
            f"tool call {call_id!r} ({call.get('tool_name') or 'unknown tool'}) has no "
            "matching tool result in the ingested log",
            timestamp=call.get("timestamp", 0),
            source_seq=call.get("source_seq"),
            extra={"call_id": call_id, "tool_name": call.get("tool_name")},
            identity={"kind": "unmatched_call", "source_id": source_id, "call_id": call_id},
        )

    stats: dict[str, Any] = {
        "records": len(records),
        "events": len(events),
        "gap_events": counts.get(EVIDENCE_GAP_EVENT, 0),
        "unmatched_calls": len(pending_calls),
        "unmatched_results": sum(
            1 for gap in gaps if gap.get("reason") == GAP_UNMATCHED_RESULT
        ),
        "sequence_gaps": sum(
            1
            for gap in gaps
            if gap.get("reason") == GAP_SEQUENCE_GAP and "missing_from" in gap
        ),
        "duplicate_sequences": duplicate_sequences,
        "correlated_pairs": correlated_pairs,
        "event_counts": dict(sorted(counts.items())),
        "content_artifacts": len(artifacts),
    }
    return NormalizedBatch(events=events, gaps=gaps, stats=stats, artifacts=artifacts)


def _normalize_record(
    *,
    raw_type: str,
    data: dict[str, Any],
    seq: int | None,
    timestamp: int,
    cas: Any,
    artifacts: list[ArtifactRef],
    source_id: str,
    pending_calls: dict[str, dict[str, Any]],
    emit_gap: Any,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Normalize one raw record; return (event_type, payload, identity)."""

    if raw_type == "tool/call":
        call_id = _as_str(data.get("callId") or data.get("call_id")) or None
        tool_name = _as_str(data.get("name") or data.get("tool") or data.get("toolName"))
        arguments = data.get("arguments")
        if arguments is None:
            arguments = data.get("input", "")
        arguments_text = _as_str(arguments)
        payload = {
            "call_id": call_id,
            "tool_name": tool_name,
            "arguments": arguments_text,
            "turn": _as_int(data.get("turn")),
            "step": _as_int(data.get("step")),
        }
        if call_id:
            pending_calls[call_id] = {
                "tool_name": tool_name,
                "timestamp": timestamp,
                "source_seq": seq,
            }
        else:
            emit_gap(
                GAP_UNMATCHED_CALL,
                "tool/call record has no callId; call cannot be correlated with its result",
                timestamp=timestamp,
                source_seq=seq,
                extra={"tool_name": tool_name},
                identity={
                    "kind": "uncorrelatable_call",
                    "source_id": source_id,
                    "source_seq": seq,
                },
            )
        return "tool_call", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type == "tool/result":
        text, call_id, is_error, item_types = _extract_result_text(data)
        content_bytes = text.encode("utf-8")
        ref = cas.put_bytes(content_bytes, media_type="application/octet-stream")
        artifacts.append(ref)
        exit_code = parse_exit_code(text)
        matched = bool(call_id and call_id in pending_calls)
        call_info = pending_calls.pop(call_id, None) if matched and call_id else None
        if not matched:
            emit_gap(
                GAP_UNMATCHED_RESULT,
                f"tool result for callId {call_id!r} has no matching tool/call record",
                timestamp=timestamp,
                source_seq=seq,
                extra={"call_id": call_id},
                identity={
                    "kind": "unmatched_result",
                    "source_id": source_id,
                    "source_seq": seq,
                    "call_id": call_id,
                },
            )
        message = data.get("message") if isinstance(data.get("message"), dict) else {}
        meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
        payload = {
            "call_id": call_id,
            "is_error": is_error,
            "content_preview": text[:CONTENT_PREVIEW_CHARS],
            "content_sha256": ref.sha256,
            "content_size": len(content_bytes),
            "exit_code": exit_code,
            "cwd": _as_str(meta.get("cwd") or ""),
            "turn": _as_int(data.get("turn")),
            "step": _as_int(data.get("step")),
            "call_matched": matched,
            "content_preview_truncated": len(text) > CONTENT_PREVIEW_CHARS,
            "content_item_types": item_types,
            "message_id": _as_str(message.get("id") or "") or None,
        }
        if call_info is not None:
            payload["tool_name"] = call_info.get("tool_name") or ""
        return "tool_result", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type == "job/registered":
        payload = {
            "job_id": _as_str(data.get("jobId") or data.get("job_id")) or None,
            "tool_call_id": _as_str(data.get("toolCall") or data.get("toolCallId")) or None,
            "kind": _as_str(data.get("kind")),
            "label": _as_str(data.get("label")),
            "owner": _as_str(data.get("owner")),
            "started_at": _as_int(data.get("startedAt")),
        }
        return "job_registered", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type == "job/settled":
        detail = _as_str(data.get("detail"))
        payload = {
            "job_id": _as_str(data.get("jobId") or data.get("job_id")) or None,
            "tool_call_id": _as_str(data.get("toolCall") or data.get("toolCallId")) or None,
            "kind": _as_str(data.get("kind")),
            "status": _as_str(data.get("status")),
            "cause": _as_str(data.get("cause")),
            "detail": detail,
            "started_at": _as_int(data.get("startedAt")),
            "finished_at": _as_int(data.get("finishedAt")),
            "exit_code": parse_exit_code(detail),
        }
        return "job_settled", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type == "approval/asked":
        payload = {
            "approval_id": _as_str(data.get("id") or data.get("approvalId")) or None,
            "call_id": _as_str(data.get("callId")) or None,
            "tool_name": _as_str(data.get("toolName")),
            "reason": _as_str(data.get("reason")),
            "turn": _as_int(data.get("turn")),
            "step": _as_int(data.get("step")),
        }
        return (
            "harness_approval_asked",
            payload,
            {"kind": "record", "source_seq": seq, "type": raw_type},
        )

    if raw_type == "approval/decided":
        payload = {
            "approval_id": _as_str(data.get("id") or data.get("approvalId")) or None,
            "outcome": _as_str(data.get("outcome")),
            "decided_at": _as_int(data.get("decidedAt")),
        }
        return (
            "harness_approval_decided",
            payload,
            {"kind": "record", "source_seq": seq, "type": raw_type},
        )

    if raw_type == "command/run":
        payload = {
            "command": _as_str(data.get("command")),
            "started_at": _as_int(data.get("startedAt")) or timestamp,
            "cwd": _as_str(data.get("cwd") or ""),
        }
        return "command_run", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type == "command/done":
        payload = {
            "command": _as_str(data.get("command")),
            "exit_code": _as_int(data.get("exitCode")),
            "finished_at": _as_int(data.get("finishedAt")),
        }
        return "command_done", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type in ("turn/start", "turn/end", "step/start", "step/end"):
        event_type = RECORD_EVENT_TYPES[raw_type]
        payload = _raw_payload(data, cas, artifacts, source_type=raw_type)
        payload["turn"] = _as_int(data.get("turn"))
        payload["step"] = _as_int(data.get("step"))
        return event_type, payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    if raw_type == "assistant/message":
        payload = _raw_payload(data, cas, artifacts, source_type=raw_type)
        payload["text_preview"] = _assistant_text(data)[:CONTENT_PREVIEW_CHARS]
        return "assistant_message", payload, {"kind": "record", "source_seq": seq, "type": raw_type}

    payload = _raw_payload(data, cas, artifacts, source_type=raw_type or "unknown")
    if "type" not in payload:
        payload["type"] = raw_type
    return PASSTHROUGH_EVENT, payload, {"kind": "record", "source_seq": seq, "type": raw_type}


def _assistant_text(data: dict[str, Any]) -> str:
    content = data.get("content")
    texts: list[str] = []
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(_as_str(item.get("text")))
            elif isinstance(item, str):
                texts.append(item)
    return "\n".join(texts)


__all__ = [
    "CONTENT_PREVIEW_CHARS",
    "DATA_INLINE_CHARS",
    "EVIDENCE_GAP_EVENT",
    "GAP_FRAME_DECODE_ERROR",
    "GAP_SEQUENCE_GAP",
    "GAP_TORN_LINE",
    "GAP_TRUNCATED_FRAME",
    "GAP_UNMATCHED_CALL",
    "GAP_UNMATCHED_RESULT",
    "NormalizedBatch",
    "PASSTHROUGH_EVENT",
    "RECORD_EVENT_TYPES",
    "SOURCE_SESSION_LOG",
    "deterministic_record_id",
    "gap_event",
    "make_event",
    "normalize_session_records",
    "parse_exit_code",
]
