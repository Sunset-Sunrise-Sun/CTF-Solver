"""Evidence ingestion, CAS, SQLite hash chain and deterministic JSONL export.

Public surface (see ``docs/INTERFACES.md`` §4):

- :class:`~ctf_solver.evidence.zstd_frames.DecodeReport` / ``decode_all`` —
  complete multi-frame zstd decoding with explicit gaps.
- :class:`~ctf_solver.evidence.cas.Cas` — SHA-256 content-addressed store.
- :func:`~ctf_solver.evidence.normalize.normalize_session_records` — frozen
  canonical event normalization (call/result correlation, explicit gaps).
- :class:`~ctf_solver.evidence.store.EvidenceStore` — append-only hash-chained
  SQLite event store implementing ``EvidenceSink``.
- :class:`~ctf_solver.evidence.ingest.Ingestor` / ``IngestReport`` — idempotent
  session-log ingestion with raw CAS retention.
- ``write_manifest`` / ``verify_manifest`` — SHA-256 manifest generation and
  independent verification.
"""

from __future__ import annotations

from .cas import Cas
from .ingest import IngestReport, Ingestor
from .manifest import (
    ManifestReport,
    build_manifest_text,
    verify_manifest,
    write_manifest,
    write_manifest_for_tree,
)
from .normalize import (
    EVIDENCE_GAP_EVENT,
    NormalizedBatch,
    deterministic_record_id,
    gap_event,
    make_event,
    normalize_session_records,
    parse_exit_code,
)
from .store import EvidenceStore
from .zstd_frames import (
    ZSTD_MAGIC,
    DecodeGap,
    DecodeReport,
    FrameDecode,
    FrameSpan,
    GapInfo,
    PayloadSegment,
    decode_all,
    decompress_frame,
    iter_payload_segments,
    parse_json_lines,
    probe_backends,
    scan_frames,
)

__all__ = [
    "Cas",
    "DecodeGap",
    "DecodeReport",
    "EVIDENCE_GAP_EVENT",
    "EvidenceStore",
    "FrameDecode",
    "FrameSpan",
    "GapInfo",
    "IngestReport",
    "Ingestor",
    "ManifestReport",
    "NormalizedBatch",
    "PayloadSegment",
    "ZSTD_MAGIC",
    "build_manifest_text",
    "decode_all",
    "decompress_frame",
    "deterministic_record_id",
    "gap_event",
    "iter_payload_segments",
    "make_event",
    "normalize_session_records",
    "parse_exit_code",
    "parse_json_lines",
    "probe_backends",
    "scan_frames",
    "verify_manifest",
    "write_manifest",
    "write_manifest_for_tree",
]
