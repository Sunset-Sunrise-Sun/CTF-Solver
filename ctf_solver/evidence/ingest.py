"""Idempotent session-log ingestion: raw CAS retention, all frames, explicit gaps.

Ingestion flow (docs/INTERFACES.md §4.5):

1. store the **raw** log bytes in CAS (SHA-256) so the original evidence is
   always retained;
2. decode **every** concatenated zstd frame;
3. parse the JSON-Lines payload across frame boundaries; torn lines become
   explicit ``torn_line`` gap events;
4. normalize records into the frozen event contract (call/result correlation,
   CAS content references, job/approval/command/turn/step state, explicit gaps
   for unmatched pairs and missing sequence numbers);
5. append idempotently — ``UNIQUE(source_id, source_seq)`` plus deterministic
   ``record_id`` values make re-ingestion append 0 rows;
6. update the ``ingestion_sources`` watermark (monotonic ``last_seq``).

Structural completeness (``IngestReport.complete``) is true only when every
frame decoded and no JSON line was torn; semantic gaps (sequence gaps,
unmatched call/result) are still reported and recorded even when the log is
structurally complete.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..core.canonical import canonical_bytes, sha256_hex
from ..core.errors import NotFoundError, ValidationError
from .normalize import (
    GAP_FRAME_DECODE_ERROR,
    GAP_TORN_LINE,
    GAP_TRUNCATED_FRAME,
    SOURCE_SESSION_LOG,
    gap_event,
    normalize_session_records,
)
from .zstd_frames import (
    REASON_TRUNCATED_FRAME,
    decode_all,
    iter_payload_segments,
    parse_json_lines,
)


@dataclass
class IngestReport:
    """Outcome of one session-log ingestion (JSON-serializable)."""
    frames: int
    decoded_records: int
    appended: int
    skipped_duplicates: int
    gaps: list[dict[str, Any]]
    raw_sha256: str
    complete: bool
    source_id: str = ""
    task_id: str = ""
    worker_id: str | None = None
    session_id: str | None = None
    last_seq: int = -1
    raw_path: str | None = None
    raw_size: int = 0
    events_total: int = 0
    gap_reasons: dict[str, int] = field(default_factory=dict)
    backend: str | None = None
    pre_boundary_excluded: int = 0
    boundary_applied: bool = False

    @property
    def gap_count(self) -> int:
        """Number of explicit gaps recorded by this ingestion."""

        return len(self.gaps)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["gap_reasons"] = dict(sorted(self.gap_reasons.items()))
        data["gap_count"] = self.gap_count
        return data


BOUNDARY_VERSION = 1


def session_log_boundary(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Describe the decoded-payload snapshot of a Lead session log at Task creation.

    The boundary is defined over the **decompressed JSON-Lines payload stream**
    (not compressed frame offsets), so it is independent of zstd frame layout.
    The Manager records it with the one-time Lead binding; ingestion verifies
    the same payload prefix still exists and only normalizes records starting at
    or after it, so pre-Task conversation history never enters task evidence.
    """

    raw = bytes(data)
    report = decode_all(raw)
    if report.gaps:
        raise ValidationError(
            "the Lead session log has undecodable zstd frame gaps; refusing to "
            "record a task-creation boundary from a partially decodable log"
        )
    payload = b"".join(segment.payload for segment in iter_payload_segments(report))
    return {
        "version": BOUNDARY_VERSION,
        "payload_size": len(payload),
        "payload_sha256": sha256_hex(payload),
    }


def _validate_boundary(boundary: Mapping[str, Any], payload: bytes) -> int:
    """Validate a recorded boundary against the current decoded payload; return size."""

    if not isinstance(boundary, Mapping):
        raise ValidationError("task boundary must be a JSON object")
    version = boundary.get("version")
    if version != BOUNDARY_VERSION:
        raise ValidationError(
            f"unsupported task boundary version {version!r}; refusing to ingest"
        )
    payload_size = boundary.get("payload_size")
    if (
        isinstance(payload_size, bool)
        or not isinstance(payload_size, int)
        or payload_size < 0
    ):
        raise ValidationError(
            "task boundary payload_size must be a non-negative integer"
        )
    payload_sha = boundary.get("payload_sha256")
    if not isinstance(payload_sha, str) or len(payload_sha) != 64:
        raise ValidationError("task boundary payload_sha256 must be a SHA-256 hex string")
    if len(payload) < payload_size:
        raise ValidationError(
            "the session-log payload is shorter than the recorded task-creation "
            "boundary; the log may have been rotated or truncated — refusing to ingest"
        )
    if sha256_hex(payload[:payload_size]) != payload_sha.strip().lower():
        raise ValidationError(
            "the session-log payload prefix does not match the recorded "
            "task-creation boundary (the log was rewritten/rotated) — refusing to ingest"
        )
    return payload_size


def _parse_lines_with_offsets(
    payload: bytes | bytearray | memoryview, base_offset: int
) -> list[tuple[dict[str, Any], int, int]]:
    """Return ``(record, start_offset, end_offset)`` for successfully parsed lines.

    Mirrors :func:`parse_json_lines` record selection (UTF-8 JSON objects only);
    offsets are absolute byte positions in the raw log.
    """

    buffer = bytes(payload)
    length = len(buffer)
    start = 0
    result: list[tuple[dict[str, Any], int, int]] = []
    while start < length:
        newline = buffer.find(b"\n", start)
        if newline < 0:
            raw = buffer[start:]
            next_start = length
        else:
            raw = buffer[start:newline]
            next_start = newline + 1
        if raw.strip():
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = None
            if isinstance(value, dict):
                result.append((value, base_offset + start, base_offset + next_start))
        start = next_start
    return result


def _gap_start_offset(gap: Mapping[str, Any]) -> int | None:
    value = gap.get("byte_offset", gap.get("offset"))
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


class Ingestor:
    """Coordinate CAS retention, frame decoding, normalization and append."""

    def __init__(self, store: Any, cas: Any) -> None:
        if store is None:
            raise ValidationError("Ingestor requires an evidence store")
        if cas is None:
            raise ValidationError("Ingestor requires a CAS instance")
        self._store = store
        self._cas = cas

    @property
    def store(self) -> Any:
        return self._store

    @property
    def cas(self) -> Any:
        return self._cas

    # -- public API -----------------------------------------------------

    def ingest_session_log_bytes(
        self,
        *,
        task_id: str,
        worker_id: str | None,
        session_id: str | None,
        data: bytes | bytearray | memoryview,
        source_id: str,
        path: str | None = None,
        boundary: Mapping[str, Any] | None = None,
    ) -> IngestReport:
        """Ingest raw ``.jsonl.zstd`` bytes for one Task/Worker/session.

        ``boundary`` is the Manager-recorded task-creation boundary for a bound
        Lead-session log (Release-UAT remediation F2). When present, only bytes
        appended after the boundary are normalized into task evidence; the raw
        log is still retained in the local CAS for audit.
        """

        if not isinstance(task_id, str) or not task_id:
            raise ValidationError("ingest requires a non-empty task_id")
        if not isinstance(source_id, str) or not source_id:
            raise ValidationError("ingest requires a non-empty source_id")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValidationError(
                f"ingest_session_log_bytes requires bytes, not {type(data).__name__}"
            )
        raw = bytes(data)
        boundary_size: int | None = None

        # 1. Raw evidence retention (also records the artifact metadata row).
        raw_ref = self._store.store_artifact(
            raw, media_type="application/zstd", source=SOURCE_SESSION_LOG
        )

        # 2. Decode every frame; structural problems become explicit gap events.
        decode_report = decode_all(raw)
        payload_stream = b"".join(
            segment.payload for segment in iter_payload_segments(decode_report)
        )
        if boundary is not None:
            if decode_report.gaps:
                raise ValidationError(
                    "the Lead session log has undecodable zstd frame gaps; refusing "
                    "to apply a task boundary to a partially decodable log"
                )
            boundary_size = _validate_boundary(boundary, payload_stream)
        events: list[dict[str, Any]] = []
        gap_records: list[dict[str, Any]] = []
        gap_reasons: dict[str, int] = {}

        def note_gap_reason(reason: str) -> None:
            gap_reasons[reason] = gap_reasons.get(reason, 0) + 1

        for gap in decode_report.gaps:
            is_truncated = gap.reason == REASON_TRUNCATED_FRAME
            reason = GAP_TRUNCATED_FRAME if is_truncated else GAP_FRAME_DECODE_ERROR
            note_gap_reason(reason)
            gap_records.append(
                {
                    "reason": reason,
                    "detail": gap.detail or f"zstd frame gap ({gap.reason})",
                    "frame_index": gap.frame_index,
                    "offset": gap.offset,
                    "length": gap.length,
                    "decode_reason": gap.reason,
                }
            )
            events.append(
                gap_event(
                    task_id=task_id,
                    worker_id=worker_id,
                    session_id=session_id,
                    source_id=source_id,
                    reason=reason,
                    detail=gap.detail or f"zstd frame gap ({gap.reason})",
                    timestamp=0,
                    extra={
                        "frame_index": gap.frame_index,
                        "offset": gap.offset,
                        "length": gap.length,
                        "decode_reason": gap.reason,
                    },
                    identity={
                        "kind": "frame_gap",
                        "source_id": source_id,
                        "decode_reason": gap.reason,
                        "frame_index": gap.frame_index,
                        "offset": gap.offset,
                        "length": gap.length,
                    },
                )
            )

        # 3. Parse JSON lines per contiguous frame run (a line may span frames).
        records: list[dict[str, Any]] = []
        line_gaps = 0
        payload_base = 0
        for segment in iter_payload_segments(decode_report):
            parsed, parse_gaps = parse_json_lines(segment.payload)
            records.extend(parsed)
            for parse_gap in parse_gaps:
                line_gaps += 1
                note_gap_reason(GAP_TORN_LINE)
                byte_offset = payload_base + parse_gap.offset
                gap_records.append(
                    {
                        "reason": GAP_TORN_LINE,
                        "detail": (
                            f"session log line {parse_gap.line_number} could not be parsed "
                            f"({parse_gap.reason}): {parse_gap.detail}"
                        ),
                        "line_number": parse_gap.line_number,
                        "byte_offset": byte_offset,
                        "line_reason": parse_gap.reason,
                        "preview": parse_gap.raw_preview,
                    }
                )
                events.append(
                    gap_event(
                        task_id=task_id,
                        worker_id=worker_id,
                        session_id=session_id,
                        source_id=source_id,
                        reason=GAP_TORN_LINE,
                        detail=(
                            f"session log line {parse_gap.line_number} could not be parsed "
                            f"({parse_gap.reason}): {parse_gap.detail}"
                        ),
                        timestamp=0,
                        extra={
                            "line_number": parse_gap.line_number,
                            "byte_offset": byte_offset,
                            "line_reason": parse_gap.reason,
                            "preview": parse_gap.raw_preview,
                        },
                        identity={
                            "kind": "line_gap",
                            "source_id": source_id,
                            "line_number": parse_gap.line_number,
                            "byte_offset": byte_offset,
                            "line_reason": parse_gap.reason,
                        },
                    )
                )
            payload_base += len(segment.payload)

        # 3b. Apply the Manager-recorded Task-creation boundary (bound Lead log).
        # Only records whose decoded-payload bytes start at/after the boundary are
        # eligible; pre-Task conversation history is never normalized into evidence.
        pre_boundary_excluded = 0
        if boundary_size is not None:
            record_spans: list[tuple[dict[str, Any], int, int]] = []
            payload_offset = 0
            for segment in iter_payload_segments(decode_report):
                record_spans.extend(
                    _parse_lines_with_offsets(segment.payload, payload_offset)
                )
                payload_offset += len(segment.payload)
            if len(record_spans) != len(records):
                raise ValidationError(
                    "cannot determine session-log record positions for the recorded "
                    "task boundary; refusing to ingest without a verifiable boundary"
                )
            kept_records: list[dict[str, Any]] = []
            for record, (_, start_offset, _end_offset) in zip(records, record_spans):
                if start_offset >= boundary_size:
                    kept_records.append(record)
            pre_boundary_excluded = len(records) - len(kept_records)
            records = kept_records

            kept_gaps: list[dict[str, Any]] = []
            for gap in gap_records:
                offset = _gap_start_offset(gap)
                if offset is None:
                    raise ValidationError(
                        "a session-log gap has no byte position; refusing to guess "
                        "whether it belongs before the task boundary"
                    )
                if offset >= boundary_size:
                    kept_gaps.append(gap)
            gap_records = kept_gaps

            kept_events: list[dict[str, Any]] = []
            for event in events:
                if event.get("event_type") != "evidence_gap":
                    kept_events.append(event)
                    continue
                payload = event.get("payload") or {}
                offset = payload.get("byte_offset", payload.get("offset"))
                if isinstance(offset, bool) or not isinstance(offset, int):
                    raise ValidationError(
                        "a session-log gap event has no byte position; refusing to "
                        "guess whether it belongs before the task boundary"
                    )
                if offset >= boundary_size:
                    kept_events.append(event)
            events = kept_events
            gap_reasons = {}
            for gap in gap_records:
                reason = str(gap.get("reason", "evidence_gap"))
                gap_reasons[reason] = gap_reasons.get(reason, 0) + 1

        # 4. Normalize into the frozen event contract.
        batch = normalize_session_records(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            raw_records=records,
            cas=self._cas,
            source_id=source_id,
        )
        events.extend(batch.events)
        for gap in batch.gaps:
            note_gap_reason(str(gap.get("reason", "evidence_gap")))
            gap_records.append(dict(gap))

        # CAS metadata for content referenced by normalized events (deterministic,
        # deduplicated by primary key).
        for ref in batch.artifacts:
            self._store.record_artifact(ref, source=SOURCE_SESSION_LOG)

        # 5. Idempotent append (UNIQUE(source_id, source_seq) via the store).
        appended_ids = self._store.append_events(events, skip_duplicates=True)
        skipped = len(events) - len(appended_ids)

        # 6. Watermark update.
        sequence_numbers = [
            int(record["seq"])
            for record in records
            if isinstance(record.get("seq"), int) and not isinstance(record.get("seq"), bool)
        ]
        last_seq = max(sequence_numbers) if sequence_numbers else -1
        batch_sha256 = sha256_hex(
            canonical_bytes([event["record_id"] for event in events])
        )
        total_gaps = len(gap_records)
        self._store.record_ingestion(
            source_id,
            task_id=task_id,
            session_id=session_id,
            last_seq=last_seq,
            sha256=batch_sha256,
            raw_sha256=raw_ref.sha256,
            frames=len(decode_report.frames),
            records=len(records),
            gaps=total_gaps,
        )

        return IngestReport(
            frames=len(decode_report.frames),
            decoded_records=len(records),
            appended=len(appended_ids),
            skipped_duplicates=skipped,
            gaps=gap_records,
            raw_sha256=raw_ref.sha256,
            complete=decode_report.complete and line_gaps == 0,
            source_id=source_id,
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            last_seq=last_seq,
            raw_path=path,
            raw_size=len(raw),
            events_total=len(events),
            gap_reasons=dict(sorted(gap_reasons.items())),
            backend=decode_report.backend,
            pre_boundary_excluded=pre_boundary_excluded,
            boundary_applied=boundary_size is not None,
        )

    def ingest_session_log_file(
        self,
        *,
        task_id: str,
        worker_id: str | None,
        session_id: str | None,
        path: str | os.PathLike[str],
        source_id: str | None = None,
        boundary: Mapping[str, Any] | None = None,
    ) -> IngestReport:
        """Ingest a ``session.v4.jsonl.zstd`` file from disk."""

        target = Path(os.fspath(path))
        if not target.is_file():
            raise NotFoundError(f"session log not found: {target}")
        resolved_source = source_id or f"session:{session_id or target.name}"
        try:
            data = target.read_bytes()
        except OSError as exc:  # pragma: no cover - permission failure
            raise ValidationError(f"cannot read session log {target}: {exc}") from exc
        return self.ingest_session_log_bytes(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            data=data,
            source_id=resolved_source,
            path=str(target),
            boundary=boundary,
        )


__all__ = [
    "BOUNDARY_VERSION",
    "IngestReport",
    "Ingestor",
    "session_log_boundary",
]
