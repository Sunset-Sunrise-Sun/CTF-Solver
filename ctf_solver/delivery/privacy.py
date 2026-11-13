"""Deterministic delivery privacy projection shared by every delivery path.

The delivery surface (Writeup, ``events.jsonl`` export and the evidence ZIP) must
never expose model reasoning, raw passthrough payloads or Skill bodies. This
module is the single projection used by all three, so the delivered view cannot
drift between them:

- each event is projected onto a fixed identity shape (no hash-chain internals);
- only an explicit allowlist of event types survives; every other type is
  dropped (default deny);
- turn/step lifecycle events keep only their numeric ``turn``/``step`` metadata;
- ``tool_result`` payloads for the Harness ``skill`` tool have their body
  replaced by a fixed policy notice while retaining hashes, sizes and status;
- tool calls/results, gaps, task lifecycle, approvals, screenshots and Flags are
  real evidence and are retained with their payload copied.

The projection performs no I/O, no clock reads and no global state changes: the
same event sequence always yields the same projected list, and input order is
preserved.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Iterable, Mapping

#: Event types allowed through the delivery projection.
#:
#: The runtime ``execution_*`` lifecycle events are retained because the Worker
#: Writeup (tool/version section and execution steps) is derived from them; their
#: payloads carry only tool/argv/status metadata, never reasoning text. The
#: confidential session-message types (``assistant_message``, ``passthrough``),
#: job/command bookkeeping and any unrecognized type are intentionally absent, so
#: they are denied by default.
DELIVERY_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "tool_call",
        "tool_result",
        "evidence_gap",
        "evidence_ingested",
        "execution_started",
        "execution_completed",
        "execution_failed",
        "execution_denied",
        "task_created",
        "task_started",
        "task_completed",
        "task_failed",
        "task_paused",
        "task_cancelled",
        "task_interrupted",
        "flag_candidate",
        "screenshot_captured",
        "screenshot_failed",
        "lead_session_bound",
        "harness_approval_asked",
        "harness_approval_decided",
        "turn_start",
        "turn_end",
        "step_start",
        "step_end",
    }
)

#: Lifecycle event types that keep only numeric ``turn``/``step`` metadata.
TURN_STEP_EVENT_TYPES: frozenset[str] = frozenset(
    {"turn_start", "turn_end", "step_start", "step_end"}
)

#: Harness tool name whose result body must never be delivered.
SKILL_TOOL_NAME = "skill"

#: Fixed policy notice replacing a Skill tool-result body.
SKILL_RESULT_POLICY_TEMPLATE = (
    "Skill loaded: {name} (content omitted by delivery privacy policy)"
)

#: Fixed policy notice replacing the body of an *unmatched* tool result.
#:
#: An unmatched result has no correlated ``tool/call`` record, so the tool cannot
#: be classified safely (it could be a Skill body) and its content preview is not
#: delivered. The hash/size/error metadata and the raw CAS object remain local.
UNMATCHED_RESULT_POLICY_TEMPLATE = (
    "tool result content omitted by delivery privacy policy: unmatched call_id "
    "(the tool cannot be classified safely)"
)

#: Payload fields that may be delivered for an ``evidence_gap`` event.
#:
#: Gap payloads are structural diagnostics (reason/detail/ids/offsets). Raw log
#: fragments such as the ``preview`` of a torn line are deliberately absent: they
#: can contain assistant reasoning or passthrough text, so they stay in the local
#: append-only evidence DB and are never delivered.
GAP_SAFE_PAYLOAD_FIELDS: frozenset[str] = frozenset(
    {
        "reason",
        "detail",
        "source_seq",
        "call_id",
        "tool_name",
        "line_number",
        "byte_offset",
        "line_reason",
        "frame_index",
        "offset",
        "length",
        "decode_reason",
        "missing_from",
        "missing_to",
        "detected_at_seq",
        "duplicate_seq",
        "duplicate_of_seq",
        "index",
        "original_type",
    }
)

#: Fallback Skill name when the originating ``tool_call`` cannot be resolved.
UNKNOWN_SKILL_NAME = "unknown"

#: Identity fields kept on every projected event, in this order.
PROJECTED_EVENT_FIELDS: tuple[str, ...] = (
    "seq",
    "record_id",
    "task_id",
    "worker_id",
    "session_id",
    "source",
    "source_id",
    "source_seq",
    "event_type",
    "timestamp",
    "payload",
)


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _payload_object(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return a private copy of an event payload as a plain dict."""

    payload = event.get("payload")
    if isinstance(payload, Mapping):
        return copy.deepcopy(dict(payload))
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except (TypeError, ValueError):
            return {}
        if isinstance(parsed, Mapping):
            return copy.deepcopy(dict(parsed))
    return {}


def _turn_step_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _skill_name_from_arguments(arguments: Any) -> str:
    """Extract ``name`` from a ``skill`` tool call's arguments value."""

    parsed: Any = arguments
    if isinstance(arguments, str):
        text = arguments.strip()
        if not text:
            return ""
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            return ""
    if not isinstance(parsed, Mapping):
        return ""
    name = parsed.get("name")
    if isinstance(name, str) and name:
        return name
    return ""


def _skill_names_by_call_id(events: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Map ``call_id -> Skill name`` from ordered ``skill`` tool-call events."""

    names: dict[str, str] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if event.get("event_type") != "tool_call":
            continue
        payload = _payload_object(event)
        if payload.get("tool_name") != SKILL_TOOL_NAME:
            continue
        call_id = payload.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            continue
        name = _skill_name_from_arguments(payload.get("arguments"))
        if name:
            names[call_id] = name
    return names


def sanitize_evidence_gap(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a delivery-safe copy of an ``evidence_gap`` payload.

    Only structural gap diagnostics are delivered. Any other field (notably the
    ``preview`` of a torn/unparsable session-log line, which can contain
    assistant reasoning or passthrough text) is dropped; the omitted field names
    are recorded so the gap stays honest. The raw event in the append-only
    evidence DB is not modified.
    """

    result: dict[str, Any] = {}
    for key, value in payload.items():
        if key in GAP_SAFE_PAYLOAD_FIELDS and not isinstance(value, (bytes, bytearray)):
            result[str(key)] = copy.deepcopy(value)
    omitted = sorted(str(key) for key in payload if key not in GAP_SAFE_PAYLOAD_FIELDS)
    if omitted:
        result["omitted_fields"] = omitted
    return result


def sanitize_tool_result(
    payload: Mapping[str, Any], skill_names: Mapping[str, str]
) -> dict[str, Any]:
    """Return a delivery-safe copy of a tool-result payload.

    Non-Skill, correlated results are returned unchanged (tool output is
    evidence). A Skill result (``tool_name == "skill"``, or a result whose
    ``call_id`` matches a known Skill tool call) has its body preview replaced by
    the fixed policy notice. An **unmatched** result (``call_matched`` is false,
    i.e. no correlated ``tool/call``) cannot be classified safely — it may be a
    Skill body — so its content preview is also replaced by a policy notice.
    Hashes, sizes, error status and exit code are preserved in all cases. The
    Skill name is resolved through ``skill_names`` by ``call_id`` and falls back
    to ``unknown``.
    """

    result = copy.deepcopy(dict(payload))
    call_id = result.get("call_id")
    is_skill = result.get("tool_name") == SKILL_TOOL_NAME
    if not is_skill and isinstance(call_id, str) and call_id:
        # Defensive: a result correlated to a known ``skill`` tool call is a
        # Skill result even when the normalized payload lacks ``tool_name``.
        is_skill = isinstance(skill_names, Mapping) and call_id in skill_names
    if not is_skill:
        if result.get("call_matched") is False:
            result["content_preview"] = UNMATCHED_RESULT_POLICY_TEMPLATE
            result.pop("content_item_types", None)
        return result
    name = ""
    if isinstance(call_id, str) and call_id:
        candidate = skill_names.get(call_id) if isinstance(skill_names, Mapping) else None
        if isinstance(candidate, str) and candidate:
            name = candidate
    result["content_preview"] = SKILL_RESULT_POLICY_TEMPLATE.format(
        name=name or UNKNOWN_SKILL_NAME
    )
    result.pop("content_item_types", None)
    return result


def project_event(
    event: Mapping[str, Any],
    skill_names: Mapping[str, str] | None = None,
) -> dict[str, Any] | None:
    """Project one event onto the delivery-safe shape, or ``None`` to drop it.

    ``skill_names`` is the optional ``call_id -> Skill name`` context used to
    label a ``skill`` tool result; an isolated call without context falls back to
    the ``unknown`` name. The function is pure and always returns fresh objects.
    """

    if not isinstance(event, Mapping):
        return None
    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        return None
    if event_type not in DELIVERY_EVENT_TYPES:
        return None
    payload = _payload_object(event)
    if event_type in TURN_STEP_EVENT_TYPES:
        payload = {
            "turn": _turn_step_number(payload.get("turn")),
            "step": _turn_step_number(payload.get("step")),
        }
    elif event_type == "tool_result":
        payload = sanitize_tool_result(payload, skill_names if skill_names is not None else {})
    elif event_type == "evidence_gap":
        payload = sanitize_evidence_gap(payload)
    return {
        "seq": event.get("seq"),
        "record_id": event.get("record_id"),
        "task_id": event.get("task_id"),
        "worker_id": event.get("worker_id"),
        "session_id": event.get("session_id"),
        "source": event.get("source"),
        "source_id": event.get("source_id"),
        "source_seq": event.get("source_seq"),
        "event_type": event_type,
        "timestamp": event.get("timestamp"),
        "payload": payload,
    }


def filter_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project an ordered event iterable, dropping everything not deliverable."""

    ordered = list(events)
    skill_names = _skill_names_by_call_id(ordered)
    projected: list[dict[str, Any]] = []
    for event in ordered:
        item = project_event(event, skill_names)
        if item is not None:
            projected.append(item)
    return projected


__all__ = [
    "DELIVERY_EVENT_TYPES",
    "GAP_SAFE_PAYLOAD_FIELDS",
    "PROJECTED_EVENT_FIELDS",
    "SKILL_RESULT_POLICY_TEMPLATE",
    "SKILL_TOOL_NAME",
    "TURN_STEP_EVENT_TYPES",
    "UNMATCHED_RESULT_POLICY_TEMPLATE",
    "filter_events",
    "project_event",
    "sanitize_evidence_gap",
    "sanitize_tool_result",
]
