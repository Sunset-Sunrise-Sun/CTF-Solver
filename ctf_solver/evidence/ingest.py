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

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

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

    @property
    def gap_count(self) -> int:
        """Number of explicit gaps recorded by this ingestion."""

        return len(self.gaps)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["gap_reasons"] = dict(sorted(self.gap_reasons.items()))
        data["gap_count"] = self.gap_count
        return data


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
    ) -> IngestReport:
        """Ingest raw ``.jsonl.zstd`` bytes for one Task/Worker/session."""

        if not isinstance(task_id, str) or not task_id:
            raise ValidationError("ingest requires a non-empty task_id")
        if not isinstance(source_id, str) or not source_id:
            raise ValidationError("ingest requires a non-empty source_id")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValidationError(
                f"ingest_session_log_bytes requires bytes, not {type(data).__name__}"
            )
        raw = bytes(data)

        # 1. Raw evidence retention (also records the artifact metadata row).
        raw_ref = self._store.store_artifact(
            raw, media_type="application/zstd", source=SOURCE_SESSION_LOG
        )

        # 2. Decode every frame; structural problems become explicit gap events.
        decode_report = decode_all(raw)
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
        for segment in iter_payload_segments(decode_report):
            parsed, parse_gaps = parse_json_lines(segment.payload)
            records.extend(parsed)
            for parse_gap in parse_gaps:
                line_gaps += 1
                note_gap_reason(GAP_TORN_LINE)
                byte_offset = segment.offset + parse_gap.offset
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
        )

    def ingest_session_log_file(
        self,
        *,
        task_id: str,
        worker_id: str | None,
        session_id: str | None,
        path: str | os.PathLike[str],
        source_id: str | None = None,
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
        )


__all__ = ["IngestReport", "Ingestor"]
