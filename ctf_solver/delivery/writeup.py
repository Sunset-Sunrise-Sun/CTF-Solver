"""Chronological, evidence-derived Markdown Writeup generation.

Every statement in the generated Writeup must come from committed evidence
records or the durable Task row. The generator never invents tool output,
screenshots or Flags, and it marks missing evidence explicitly.

The events used here are projected through the shared delivery privacy policy
(:func:`ctf_solver.delivery.privacy.filter_events`), so the Writeup, the exported
``events.jsonl`` and the evidence ZIP all render the same delivery-safe view.
Successful captures are embedded as real Markdown images and materialised next
to the standalone Writeup; captures whose bytes cannot be read are reported as
explicitly unavailable instead of being faked.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ..core.canonical import sha256_hex
from ..core.errors import DeliveryError
from ..core.types import ExecutionStatus, FlagState, ScreenshotRecord, TaskRecord
from .privacy import filter_events

MAX_PREVIEW_CHARS = 1200

#: Worker ``ctf-exec`` execution lifecycle event types that report a tool version.
EXECUTION_EVENT_TYPES = frozenset(
    {"execution_started", "execution_completed", "execution_failed"}
)

#: Manager tools whose own result can never appear in the log snapshot they ingest.
#: An unmatched call to one of them is an expected capture boundary, not a gap.
INGEST_TOOL_NAMES = frozenset(
    {"ctf_session_ingest", "mcp__ctf-solver__ctf_session_ingest"}
)

#: Derived gap states rendered in sections 5 and 7 (evidence stays append-only).
GAP_RESOLVED = "resolved (matched by a later ingestion)"
GAP_CAPTURE_BOUNDARY = "Expected capture-boundary gap"
GAP_UNRESOLVED = "unresolved"


def _iso(timestamp_ms: int | None) -> str:
    if not timestamp_ms:
        return "unknown"
    try:
        return (
            datetime.fromtimestamp(int(timestamp_ms) / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3]
            + "Z"
        )
    except (OverflowError, OSError, ValueError):
        return "unknown"


def _as_event_dict(event: Any) -> dict[str, Any]:
    if isinstance(event, Mapping):
        result = dict(event)
        result.setdefault("worker_id", None)
        return result
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        result = dict(to_dict())
        result.setdefault("worker_id", None)
        return result
    payload = getattr(event, "payload", None)
    return {
        "seq": getattr(event, "seq", 0),
        "record_id": getattr(event, "record_id", ""),
        "event_type": getattr(event, "event_type", ""),
        "timestamp": getattr(event, "timestamp", 0),
        "payload": payload if isinstance(payload, Mapping) else {},
        "source": getattr(event, "source", ""),
        "source_id": getattr(event, "source_id", ""),
        "source_seq": getattr(event, "source_seq", None),
        "worker_id": getattr(event, "worker_id", None),
    }


def _tool_call_actor(event: Mapping[str, Any]) -> tuple[str, str]:
    """Who initiated a recorded ``tool_call``: the Lead or a Worker.

    Lead-sourced evidence records the call with a NULL ``worker_id`` (the Lead
    conversation is not a Worker); Worker ``ctf-exec`` calls keep their Worker
    id. A record that does not carry the field at all is treated as the
    historical Worker wording so older evidence renders unchanged.
    """

    if "worker_id" in event and not event.get("worker_id"):
        return "Lead initiated", "the Lead requested this tool call"
    return "Worker initiated", "the Worker requested this tool call"


def _payload(event: Mapping[str, Any]) -> dict[str, Any]:
    value = event.get("payload")
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return dict(value) if isinstance(value, Mapping) else {}


def _preview(text: Any, limit: int = MAX_PREVIEW_CHARS) -> str:
    if text is None:
        return ""
    if not isinstance(text, str):
        text = json.dumps(text, ensure_ascii=False, sort_keys=True)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, total {len(text)} chars]"


def _fence(text: str, language: str = "text") -> str:
    if not text:
        return "_no output recorded_\n"
    longest = 3
    run = 0
    for char in text:
        if char == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}\n"


def _turn_step(payload: Mapping[str, Any]) -> tuple[int, int] | None:
    """Return the recorded ``(turn, step)`` for one tool-call record, when present."""

    turn = payload.get("turn")
    step = payload.get("step")
    if isinstance(turn, bool) or isinstance(step, bool):
        return None
    try:
        turn_value = int(turn)  # type: ignore[arg-type]
        step_value = int(step)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return turn_value, step_value


def _derived_step_id(payload: Mapping[str, Any]) -> str:
    """Return the default-derived screenshot step id ``turn{T}-step{S}``."""

    pair = _turn_step(payload)
    if pair is None:
        return ""
    return f"turn{pair[0]}-step{pair[1]}"


def _step_ids_for(payload: Mapping[str, Any]) -> list[str]:
    """Candidate step ids a screenshot may be bound to for this record."""

    candidates: list[str] = []
    explicit = str(payload.get("step_id") or "")
    if explicit:
        candidates.append(explicit)
    derived = _derived_step_id(payload)
    if derived and derived not in candidates:
        candidates.append(derived)
    return candidates


def _screenshots_for_step(
    shots_by_step: Mapping[str, list[ScreenshotRecord]], payload: Mapping[str, Any]
) -> list[ScreenshotRecord]:
    """Screenshots bound by exact ``step_id`` or by derived ``turn{T}-step{S}``."""

    matched: list[ScreenshotRecord] = []
    seen: set[str] = set()
    for step_id in _step_ids_for(payload):
        for shot in shots_by_step.get(step_id, []):
            if shot.screenshot_id in seen:
                continue
            seen.add(shot.screenshot_id)
            matched.append(shot)
    matched.sort(key=lambda item: (item.captured_at, item.screenshot_id))
    return matched


def _recorded(value: Any) -> str:
    """Render a recorded metadata value, or the explicit ``not recorded`` marker."""

    if value is None:
        return "not recorded"
    text = str(value).strip()
    return text if text else "not recorded"


def _screenshot_metadata_line(shot: ScreenshotRecord, capture: Mapping[str, Any]) -> str:
    """One indented metadata line for an embedded screenshot.

    ``capture_method``/``target_pid``/``scope`` come from the matching
    ``screenshot_captured``/``screenshot_failed`` event payload because the
    screenshot row has no columns for them (no migration is permitted); absent
    values are rendered as ``not recorded``.
    """

    if shot.width is not None and shot.height is not None:
        dimensions = f"{shot.width}x{shot.height}"
    else:
        dimensions = "not recorded"
    session_id = _recorded(capture.get("session_id") or shot.session_id)
    return (
        f"  - sha256: `{_recorded(shot.sha256)}`; captured_at: `{_iso(shot.captured_at)}`; "
        f"dimensions: {dimensions}; capture_method: `{_recorded(capture.get('capture_method'))}`; "
        f"target_pid: `{_recorded(capture.get('target_pid'))}`; "
        f"scope: `{_recorded(capture.get('scope'))}`; session_id: `{session_id}`"
    )


def _screenshot_capture_metadata(
    events: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Map ``screenshot_id`` -> capture event payload (first recorded event wins)."""

    metadata: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("event_type") not in {"screenshot_captured", "screenshot_failed"}:
            continue
        payload = _payload(event)
        screenshot_id = str(payload.get("screenshot_id") or "")
        if screenshot_id and screenshot_id not in metadata:
            metadata[screenshot_id] = payload
    return metadata


def _read_cas_bytes(evidence: Any, sha256: str) -> bytes:
    """Read a CAS object through any supported evidence/CAS accessor.

    Mirrors the accessor pattern used by :mod:`ctf_solver.delivery.bundle` so the
    Writeup materialises exactly the bytes the evidence ZIP ships.
    """

    cas = getattr(evidence, "cas", None)
    if cas is not None and callable(getattr(cas, "get_bytes", None)):
        return bytes(cas.get_bytes(sha256))
    for name in ("read_artifact", "get_artifact", "read_bytes"):
        reader = getattr(evidence, name, None)
        if callable(reader):
            result = reader(sha256)
            if isinstance(result, (bytes, bytearray)):
                return bytes(result)
            data = getattr(result, "data", None)
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
    raise DeliveryError("evidence store exposes no readable CAS accessor")


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _gap_states(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Classify every recorded ``evidence_gap`` for the delivery view.

    The event log stays append-only: nothing is deleted or rewritten. Derived
    status values are:

    - ``unmatched_call``: ``resolved`` when a later ``tool_result`` with the same
      ``call_id`` exists; the expected capture boundary when the call is the
      latest ``ctf_session_ingest`` call (its own result cannot appear in the
      snapshot it ingests); otherwise unresolved.
    - ``unmatched_result``: ``resolved`` when a ``tool_call`` with the same
      ``call_id`` exists; otherwise unresolved.
    - every other gap reason: unresolved.
    """

    ordered = list(events)
    calls: dict[str, dict[str, Any]] = {}
    results: dict[str, list[dict[str, Any]]] = {}
    ingest_source_seqs: list[int] = []
    for event in ordered:
        event_type = event.get("event_type")
        payload = _payload(event)
        call_id = str(payload.get("call_id") or "")
        if event_type == "tool_call" and call_id:
            calls.setdefault(call_id, dict(event))
            if str(payload.get("tool_name") or "") in INGEST_TOOL_NAMES:
                source_seq = _int_or_none(event.get("source_seq"))
                if source_seq is None:
                    source_seq = _int_or_none(payload.get("source_seq"))
                if source_seq is not None:
                    ingest_source_seqs.append(source_seq)
        elif event_type == "tool_result" and call_id:
            results.setdefault(call_id, []).append(dict(event))
    last_ingest_source_seq = max(ingest_source_seqs) if ingest_source_seqs else None
    states: list[dict[str, Any]] = []
    for event in ordered:
        if event.get("event_type") != "evidence_gap":
            continue
        payload = _payload(event)
        reason = str(payload.get("reason") or "")
        call_id = str(payload.get("call_id") or "")
        gap_seq = _int_or_none(event.get("seq"))
        origin_call = calls.get(call_id)
        origin_payload = _payload(origin_call) if origin_call is not None else {}
        tool_name = str(origin_payload.get("tool_name") or payload.get("tool_name") or "")
        source_seq = _int_or_none(origin_call.get("source_seq")) if origin_call else None
        if source_seq is None:
            source_seq = _int_or_none(payload.get("source_seq"))
        status = GAP_UNRESOLVED
        if reason == "unmatched_call":
            later_results = [
                result
                for result in results.get(call_id, [])
                if gap_seq is not None
                and _int_or_none(result.get("seq")) is not None
                and _int_or_none(result.get("seq")) > gap_seq
            ]
            if call_id and later_results:
                status = GAP_RESOLVED
            elif (
                tool_name in INGEST_TOOL_NAMES
                and source_seq is not None
                and source_seq == last_ingest_source_seq
            ):
                status = GAP_CAPTURE_BOUNDARY
        elif reason == "unmatched_result":
            if call_id and call_id in calls:
                status = GAP_RESOLVED
        states.append(
            {
                "seq": gap_seq,
                "record_id": str(event.get("record_id") or ""),
                "reason": reason,
                "detail": str(payload.get("detail") or ""),
                "call_id": call_id,
                "tool_name": tool_name,
                "source_seq": source_seq,
                "status": status,
            }
        )
    return states


def _gap_status_line(state: Mapping[str, Any]) -> str:
    """One section-5 line for a gap with its derived tri-state status."""

    label = f"Evidence gap at seq {state.get('seq')} (`{state.get('reason')}`"
    if state.get("call_id"):
        label += f", call `{state.get('call_id')}`"
    label += ")"
    return f"- {label}: status **{state.get('status')}** — {state.get('detail')}"


def _capture_boundary_line(state: Mapping[str, Any]) -> str:
    """One section-7 line for the expected ingestion-time capture boundary."""

    return (
        f"- Expected capture-boundary gap at seq {state.get('seq')} "
        f"(`{state.get('reason')}`, tool `{state.get('tool_name') or 'unknown'}`): "
        "an expected ingestion-time boundary, not a missing solve step; the ingestion "
        "call's own result cannot appear in the log snapshot it ingests. "
        f"{state.get('detail')}"
    )


class WriteupBuilder:
    def __init__(self, evidence: Any) -> None:
        self.evidence = evidence

    # -- data loading -------------------------------------------------

    def _events(self, task_id: str) -> list[dict[str, Any]]:
        raw = [_as_event_dict(item) for item in self.evidence.list_events(task_id=task_id)]
        # One shared delivery privacy projection for the Writeup, events.jsonl
        # and the evidence ZIP; raw reasoning/passthrough/Skill bodies never
        # reach the delivered document.
        events = filter_events(raw)
        events.sort(key=lambda item: (int(item.get("seq") or 0), str(item.get("record_id", ""))))
        return events

    def _screenshots(self, task_id: str) -> list[ScreenshotRecord]:
        try:
            screenshots = self.evidence.list_screenshots(task_id)
        except Exception:  # noqa: BLE001 - delivery must not crash on partial stores
            return []
        result: list[ScreenshotRecord] = []
        for item in screenshots:
            if isinstance(item, ScreenshotRecord):
                result.append(item)
            else:
                result.append(ScreenshotRecord.from_row(dict(item)))
        result.sort(key=lambda item: (item.captured_at, item.screenshot_id))
        return result

    def _screenshot_bytes(self, shot: ScreenshotRecord) -> tuple[bytes | None, str]:
        """Return ``(png bytes, "")`` for a stored capture, else ``(None, reason)``.

        A capture that is failed/blank, has no recorded hash, or whose CAS object
        cannot be read is never represented as an image link: the caller renders
        an explicit ``screenshot unavailable`` line instead.
        """

        status = shot.status.value
        if status != "ok":
            reason = f"capture status `{status}`"
            if shot.failure_reason:
                reason += f" ({shot.failure_reason})"
            return None, reason
        if not shot.sha256:
            return None, "sha256 not recorded for the capture"
        try:
            data = _read_cas_bytes(self.evidence, shot.sha256)
        except Exception:  # noqa: BLE001 - a missing CAS object is an explicit gap
            return None, (
                f"CAS object sha256:{shot.sha256} is not readable from the evidence store"
            )
        if not data:
            return None, f"CAS object sha256:{shot.sha256} is empty"
        return data, ""

    def _append_screenshots(
        self,
        lines: list[str],
        shots: Iterable[ScreenshotRecord],
        metadata: Mapping[str, Mapping[str, Any]],
    ) -> None:
        for shot in shots:
            data, reason = self._screenshot_bytes(shot)
            if data is None:
                lines.append(
                    f"- screenshot unavailable: {reason} "
                    f"(screenshot `{shot.screenshot_id}`; no image link emitted)"
                )
                continue
            lines.append(
                f"![Screenshot {shot.screenshot_id}](screenshots/{shot.screenshot_id}.png)"
            )
            lines.append(_screenshot_metadata_line(shot, metadata.get(shot.screenshot_id, {})))

    def _materialise_screenshots(self, task: TaskRecord, task_dir: Any) -> list[dict[str, Any]]:
        """Write readable capture bytes to ``<task_dir>/screenshots/<id>.png``.

        The standalone ``tasks/<task_id>/writeup.md`` then renders the images it
        links, and the same relative member path resolves inside the evidence ZIP.
        A capture whose bytes cannot be read is skipped explicitly; no file is
        fabricated and the Writeup reports it as unavailable.
        """

        from pathlib import Path

        base = Path(task_dir)
        written: list[dict[str, Any]] = []
        for shot in self._screenshots(task.task_id):
            data, reason = self._screenshot_bytes(shot)
            if data is None:
                written.append(
                    {"screenshot_id": shot.screenshot_id, "written": False, "reason": reason}
                )
                continue
            target = base / "screenshots" / f"{shot.screenshot_id}.png"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            written.append(
                {
                    "screenshot_id": shot.screenshot_id,
                    "written": True,
                    "path": str(target),
                    "sha256": sha256_hex(data),
                }
            )
        return written

    # -- rendering ----------------------------------------------------

    def render(self, task: TaskRecord) -> str:
        events = self._events(task.task_id)
        screenshots = self._screenshots(task.task_id)
        lines: list[str] = []
        lines.append(f"# CTF Writeup — {task.title}")
        lines.append("")
        lines.append("> Generated by CTF-Solver from committed evidence records. SQLite is the")
        lines.append("> authoritative store; this document is a deterministic derived view.")
        lines.append("> No tool output, screenshot or Flag in this document is fabricated; gaps are marked.")
        lines.append("")
        lines.append(f"- Task ID: `{task.task_id}`")
        lines.append(f"- Category: `{task.category.value}`")
        lines.append(f"- Status: `{task.status.value}`")
        lines.append(f"- Result state: `{task.result_state}`")
        lines.append(f"- Source: {task.source or '_not recorded_'}")
        lines.append(f"- Scope profile: {task.scope_profile or '_not recorded_'}")
        lines.append(f"- Created: {_iso(task.created_at)}")
        lines.append(f"- Started: {_iso(task.started_at)}")
        lines.append(f"- Ended: {_iso(task.ended_at)}")
        lines.append(f"- Evidence chain head: `{task.evidence_head or 'unknown'}`")
        lines.append("")

        lines.extend(self._section_metadata(task, events))
        lines.extend(self._section_description(task))
        lines.extend(self._section_versions(events))
        lines.extend(self._section_steps(events, screenshots, task))
        lines.extend(self._section_failures(events))
        lines.extend(self._section_flag(task))
        lines.extend(self._section_unresolved(events, screenshots, task))
        lines.extend(self._section_evidence_index(events, screenshots))
        text = "\n".join(lines).rstrip() + "\n"
        if not text.endswith("\n"):
            text += "\n"
        return text

    def _section_metadata(self, task: TaskRecord, events: list[dict[str, Any]]) -> list[str]:
        lines = ["## 1. Challenge metadata and supplied materials", ""]
        lines.append(f"- Challenge title: {task.title}")
        lines.append(f"- Challenge category: {task.category.value}")
        lines.append(f"- Task workspace (runtime, outside Git): `{task.workspace_path}`")
        created = [event for event in events if event.get("event_type") == "task_created"]
        supplied: list[str] = []
        material_rows: list[dict[str, Any]] = []
        for event in created:
            payload = _payload(event)
            for item in payload.get("supplied_inputs", []) or []:
                if isinstance(item, Mapping):
                    material_rows.append(dict(item))
            for item in payload.get("supplied_files", []) or []:
                supplied.append(str(item))
        if material_rows:
            lines.append("- Imported challenge materials (Manager-controlled intake, copied into the")
            lines.append("  Task workspace; hashes are over the imported bytes):")
            lines.append("")
            lines.append("| path | size | media type | sha256 | source |")
            lines.append("|---|---|---|---|---|")
            for item in material_rows:
                lines.append(
                    "| `{rel}` | {size} | {media} | `{sha}` | `{source}` |".format(
                        rel=str(item.get("rel_path", "")),
                        size=int(item.get("size", 0) or 0),
                        media=str(item.get("media_type", "application/octet-stream")),
                        sha=str(item.get("sha256", "")),
                        source=str(item.get("source_rel_path", "")),
                    )
                )
            lines.append("")
        elif supplied:
            lines.append("- Supplied materials recorded at intake:")
            for item in supplied:
                lines.append(f"  - `{item}`")
        else:
            lines.append("- Supplied materials: no file inventory was recorded in the evidence.")
        lines.append("")
        if task.notes:
            lines.append("Intake notes:")
            lines.append("")
            lines.append(_fence(task.notes))
        return lines

    def _section_description(self, task: TaskRecord) -> list[str]:
        lines = ["## 2. Challenge description and scope", ""]
        if task.notes:
            lines.append(
                "The challenge description is the intake record stored with the Task; it is "
                "reproduced in section 1 and not duplicated here."
            )
        else:
            lines.append("No challenge description was recorded in the Task notes.")
        lines.append("")
        lines.append(
            "Scope: analysis and permitted local operations only. Public research/documentation "
            "lookup is distinct from competition-target traffic; target access requires a "
            "Task-scoped grant."
        )
        lines.append("")
        completion_note = str(getattr(task, "completion_note", "") or "").strip()
        if completion_note:
            lines.append("### 2.1 Completion note (outcome record)")
            lines.append("")
            lines.append(
                "The Task completion outcome recorded by the Manager when the Task closed "
                "(an outcome record, not part of the intake record):"
            )
            lines.append("")
            lines.append(_fence(completion_note))
        return lines

    def _section_versions(self, events: list[dict[str, Any]]) -> list[str]:
        versions: dict[tuple[str, str], int] = {}
        execution_tools: set[str] = set()
        for event in events:
            if event.get("event_type") not in EXECUTION_EVENT_TYPES:
                continue
            payload = _payload(event)
            tool = str(payload.get("tool_name", ""))
            version = str(payload.get("tool_version", "") or "unknown")
            if tool:
                versions[(tool, version)] = versions.get((tool, version), 0) + 1
                execution_tools.add(tool)
        native: dict[str, int] = {}
        for event in events:
            if event.get("event_type") != "tool_call":
                continue
            tool = str(_payload(event).get("tool_name") or "").strip()
            if tool:
                native[tool] = native.get(tool, 0) + 1
        lines = ["## 3. Tool and environment versions actually observed", ""]
        if versions:
            lines.append(
                "Worker `ctf-exec` execution records (tool and version reported at "
                "execution time):"
            )
            lines.append("")
            for (tool, version), count in sorted(versions.items()):
                lines.append(f"- `{tool}` — version `{version}` ({count} execution record(s))")
        if native:
            total = sum(native.values())
            lines.append("")
            lines.append(
                "Harness-native tool calls recorded in the ingested session logs "
                f"({total} call(s) across {len(native)} tool(s)):"
            )
            lines.append("")
            for tool in sorted(native):
                if tool in execution_tools:
                    lines.append(
                        f"- `{tool}` — worker execution record version listed above; "
                        "Harness-native tool version not recorded separately."
                    )
                else:
                    lines.append(
                        f"- `{tool}` — Harness-native tool call "
                        "(tool version not recorded separately); "
                        f"{native[tool]} call(s)"
                    )
        if not versions and not native:
            lines.append("No tool executions were recorded for this Task.")
        lines.append("")
        return lines

    def _section_steps(
        self,
        events: list[dict[str, Any]],
        screenshots: list[ScreenshotRecord],
        task: TaskRecord,
    ) -> list[str]:
        lines = ["## 4. Chronological steps", ""]
        capture_metadata = _screenshot_capture_metadata(events)
        shots_by_step: dict[str, list[ScreenshotRecord]] = {}
        for shot in screenshots:
            shots_by_step.setdefault(shot.step_id or "", []).append(shot)
        step_index = 0
        for event in events:
            event_type = str(event.get("event_type", ""))
            payload = _payload(event)
            timestamp = int(event.get("timestamp") or 0)
            if event_type == "execution_started":
                step_index += 1
                step_id = str(payload.get("step_id") or "")
                lines.append(
                    f"### Step {step_index} — `ctf-exec` execution of `{payload.get('tool_name')}` "
                    f"at {_iso(timestamp)}"
                )
                lines.append("")
                lines.append(f"- Reason/hypothesis: not separately recorded in the execution contract; the")
                lines.append(f"  request is the Worker's proposed action (step `{step_id or 'unknown'}`).")
                lines.append(f"- Working directory: `{payload.get('cwd', '')}`")
                argv = payload.get("argv") or []
                if isinstance(argv, list) and argv:
                    lines.append("- Actual argv:")
                    lines.append("")
                    lines.append(_fence(json.dumps(argv, ensure_ascii=False), "json"))
                else:
                    lines.append("- Actual argv: _not recorded_")
                lines.append(f"- Execution tier: {payload.get('tier', 'unknown')}")
                related = self._execution_outcome(events, str(payload.get("execution_id", "")))
                if related is not None:
                    self._append_outcome(lines, related)
                else:
                    lines.append("- Outcome: _no matching completion event recorded (explicit gap)._")
                step_shots = _screenshots_for_step(shots_by_step, payload)
                if step_shots:
                    self._append_screenshots(lines, step_shots, capture_metadata)
                else:
                    lines.append(
                        "- Screenshot: _not captured for this step_ (no explicit capture was "
                        "requested; failed captures are reported explicitly when recorded)."
                    )
                lines.append("")
            elif event_type == "tool_call":
                step_index += 1
                turn_step = _turn_step(payload)
                turn_step_suffix = (
                    f" (turn {turn_step[0]}, step {turn_step[1]})" if turn_step is not None else ""
                )
                actor, actor_sentence = _tool_call_actor(event)
                lines.append(
                    f"### Step {step_index} — {actor} `{payload.get('tool_name')}`"
                    f"{turn_step_suffix} at {_iso(timestamp)}"
                )
                lines.append("")
                lines.append(
                    f"- Reason/hypothesis: {actor_sentence}; the recorded arguments "
                    "are the actual proposed action."
                )
                arguments = payload.get("arguments")
                lines.append("- Actual arguments:")
                lines.append("")
                lines.append(_fence(_preview(arguments), "json"))
                call_id = str(payload.get("call_id", ""))
                result = self._tool_result(events, call_id)
                if result is not None:
                    result_payload = _payload(result)
                    lines.append(f"- Actual result (is_error={result_payload.get('is_error')}):")
                    lines.append("")
                    lines.append(_fence(_preview(result_payload.get("content_preview"))))
                    if result_payload.get("exit_code") is not None:
                        lines.append(f"- Exit code: {result_payload.get('exit_code')}")
                    if result_payload.get("content_sha256"):
                        lines.append(
                            f"- Full output CAS ref: `sha256:{result_payload.get('content_sha256')}`"
                        )
                else:
                    lines.append("- Outcome: _no matching tool/result recorded (explicit gap)._")
                step_shots = _screenshots_for_step(shots_by_step, payload)
                if step_shots:
                    self._append_screenshots(lines, step_shots, capture_metadata)
                lines.append("")
        if step_index == 0:
            lines.append("No execution or tool-call steps were recorded for this Task.")
            lines.append("")
        lines.append(f"Task workspace: `{task.workspace_path}`")
        lines.append("")
        return lines

    def _execution_outcome(self, events: Iterable[dict[str, Any]], execution_id: str) -> dict[str, Any] | None:
        if not execution_id:
            return None
        for event in events:
            if event.get("event_type") not in {
                "execution_completed",
                "execution_failed",
                "execution_denied",
            }:
                continue
            payload = _payload(event)
            if str(payload.get("execution_id", "")) == execution_id:
                return event
        return None

    def _tool_result(self, events: Iterable[dict[str, Any]], call_id: str) -> dict[str, Any] | None:
        if not call_id:
            return None
        for event in events:
            if event.get("event_type") != "tool_result":
                continue
            if str(_payload(event).get("call_id", "")) == call_id:
                return event
        return None

    def _append_outcome(self, lines: list[str], event: Mapping[str, Any]) -> None:
        payload = _payload(event)
        status = payload.get("status", "unknown")
        lines.append(f"- Outcome status: `{status}`")
        if payload.get("reason_code"):
            lines.append(f"- Reason code: `{payload.get('reason_code')}`")
        if payload.get("exit_code") is not None:
            lines.append(f"- Exit code: {payload.get('exit_code')}")
        stdout = payload.get("stdout_preview")
        stderr = payload.get("stderr_preview")
        lines.append("- Actual stdout (bounded preview):")
        lines.append("")
        lines.append(_fence(_preview(stdout)))
        if stderr:
            lines.append("- Actual stderr (bounded preview):")
            lines.append("")
            lines.append(_fence(_preview(stderr)))
        for key in ("stdout_sha256", "stderr_sha256"):
            if payload.get(key):
                lines.append(f"- {key}: `{payload.get(key)}`")

    def _section_failures(self, events: list[dict[str, Any]]) -> list[str]:
        lines = ["## 5. Failed attempts and meaningful negative results", ""]
        gap_states = {state["record_id"]: state for state in _gap_states(events)}
        failures: list[str] = []
        for event in events:
            event_type = event.get("event_type")
            payload = _payload(event)
            if event_type == "execution_failed":
                failures.append(
                    f"- `{payload.get('tool_name', 'tool')}` failed (status `{payload.get('status')}`, "
                    f"exit code {payload.get('exit_code')}, reason `{payload.get('reason_code')}`)."
                )
            elif event_type == "execution_denied":
                failures.append(
                    f"- `{payload.get('tool_name', 'tool')}` was denied before execution "
                    f"(reason `{payload.get('reason_code')}`)."
                )
            elif event_type == "tool_result" and payload.get("is_error"):
                failures.append(
                    f"- Worker tool call `{payload.get('call_id')}` returned an error "
                    f"(exit code {payload.get('exit_code')})."
                )
            elif event_type == "evidence_gap":
                state = gap_states.get(str(event.get("record_id") or ""))
                if state is not None:
                    failures.append(_gap_status_line(state))
                else:
                    failures.append(
                        f"- Evidence gap: `{payload.get('reason')}` — {payload.get('detail', '')}"
                    )
        if failures:
            lines.extend(failures)
        else:
            lines.append("No failed attempts, denials or negative results were recorded.")
        lines.append("")
        return lines

    def _section_flag(self, task: TaskRecord) -> list[str]:
        lines = ["## 6. Candidate Flag and exact verification status", ""]
        state = task.flag_state
        lines.append(f"- Flag state: `{state.value}`")
        lines.append(
            "- Status definitions: `candidate` = Agent identified a possible Flag; "
            "`user_confirmed` = the user confirmed it; `platform_verified` = the platform "
            "accepted it. These states are never conflated."
        )
        if state is FlagState.NONE:
            lines.append("- No candidate Flag was recorded for this Task.")
        else:
            lines.append("- Candidate Flag (recorded by the Agent, not submitted):")
            lines.append("")
            lines.append(_fence(task.flag_value or "(value not retained)"))
        lines.append(
            "- Submission: always performed by the user. CTF-Solver does not submit Flags "
            "automatically, and this Writeup does not claim platform acceptance."
        )
        lines.append("")
        return lines

    def _section_unresolved(
        self, events: list[dict[str, Any]], screenshots: list[ScreenshotRecord], task: TaskRecord
    ) -> list[str]:
        lines = ["## 7. Unresolved or blocked steps", ""]
        items: list[str] = []
        # Only genuinely open items belong here: the expected ingestion-time
        # boundary is shown so it is not mistaken for a missing solve step;
        # gaps resolved by a later ingestion are handled in section 5 only.
        for state in _gap_states(events):
            if state["status"] == GAP_UNRESOLVED:
                items.append(_gap_status_line(state))
            elif state["status"] == GAP_CAPTURE_BOUNDARY:
                items.append(_capture_boundary_line(state))
        for shot in screenshots:
            if shot.status.value != "ok":
                items.append(
                    f"- Screenshot `{shot.screenshot_id}` was not usable: status `{shot.status.value}`"
                    f" (reason: {shot.failure_reason or 'not recorded'})."
                )
                continue
            data, reason = self._screenshot_bytes(shot)
            if data is None:
                items.append(
                    f"- screenshot unavailable: {reason} "
                    f"(screenshot `{shot.screenshot_id}`; no image link emitted)"
                )
        if task.status.value in {"blocked", "interrupted", "cancel_requested"}:
            items.append(f"- The Task ended this round in state `{task.status.value}`.")
        if not items:
            lines.append("No unresolved, blocked or failed steps were recorded.")
        else:
            lines.extend(items)
        lines.append("")
        return lines

    def _section_evidence_index(
        self, events: list[dict[str, Any]], screenshots: list[ScreenshotRecord]
    ) -> list[str]:
        lines = ["## 8. Evidence index and hashes", ""]
        lines.append(f"- Normalized evidence records: **{len(events)}**")
        lines.append(f"- Screenshots recorded: **{len(screenshots)}**")
        cas_refs: set[str] = set()
        for event in events[-50:]:
            payload = _payload(event)
            for key in ("content_sha256", "stdout_sha256", "stderr_sha256"):
                value = payload.get(key)
                if value:
                    cas_refs.add(str(value))
        lines.append("- Artifact CAS references (SHA-256):")
        if cas_refs:
            for value in sorted(cas_refs):
                lines.append(f"  - `sha256:{value}`")
        else:
            lines.append("  - none recorded")
        lines.append("- Last evidence record hashes:")
        for event in events[-10:]:
            lines.append(
                f"  - seq {event.get('seq')} `{event.get('event_type')}` record `{event.get('record_id')}`"
            )
        if not events:
            lines.append("  - none")
        lines.append(
            "- Integrity: the ZIP manifest (`manifest.sha256`) lists every included file; the "
            "SQLite hash chain is tamper-evident relative to its protected chain head but is not "
            "a digital signature."
        )
        lines.append("")
        return lines

    # -- writing ------------------------------------------------------

    def build(self, task: TaskRecord, out_path: str | "object") -> dict[str, Any]:
        from pathlib import Path

        target = Path(out_path)  # type: ignore[arg-type]
        # Materialise the captures the Writeup links before writing the document,
        # so the standalone tasks/<task_id>/writeup.md renders its images and the
        # same screenshots/<id>.png member path resolves inside the evidence ZIP.
        self._materialise_screenshots(task, target.parent)
        text = self.render(task)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        payload = text.encode("utf-8")
        return {
            "kind": "writeup",
            "path": str(target),
            "sha256": sha256_hex(payload),
            "size": len(payload),
            "entries": 1,
        }
