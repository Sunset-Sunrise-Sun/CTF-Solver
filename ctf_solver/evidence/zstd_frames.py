"""Multi-frame zstd decoding for Harness ``session.v4.jsonl.zstd`` logs.

DeepSeek Harness writes its session log as *concatenated independent zstd
frames* holding a JSON-Lines payload. A single-frame decode silently loses the
evidence after the first frame, so this module decodes **every** frame:

- ``scan_frames`` locates frame boundaries structurally from the zstd framing
  format (magic ``28 B5 2F FD`` plus header/block layout). Frame lengths are
  therefore known without a decompression backend and a truncated tail frame is
  reported as such.
- ``decode_all`` decodes each frame with ``zstandard`` when available and falls
  back to the Python 3.14 standard-library ``compression.zstd``; when neither
  backend exists it raises :class:`~ctf_solver.core.errors.UnsupportedCompressionError`
  instead of pretending the first frame is the whole log.
- ``parse_json_lines`` reconstructs the JSON-Lines stream (a line may span frame
  boundaries) and turns torn/invalid lines into explicit gaps instead of
  silently dropping them.

Every gap has a stable reason string so ingestion can turn it into an explicit
``evidence_gap`` event.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..core.errors import UnsupportedCompressionError

#: Standard zstd frame magic number (little endian ``0xFD2FB528``).
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

#: Maximum number of characters of a torn line preserved in a gap preview.
GAP_PREVIEW_CHARS = 512

#: Backend identifiers, in preference order.
BACKEND_ORDER = ("zstandard", "stdlib")

#: Gap reason strings (stable; ingestion maps them to ``evidence_gap`` events).
REASON_TRUNCATED_FRAME = "truncated_frame"
REASON_FRAME_DECODE_ERROR = "frame_decode_error"
REASON_UNSCANNED_BYTES = "unscanned_bytes"
REASON_TRAILING_BYTES = "trailing_bytes"
REASON_NO_FRAMES = "no_zstd_frames"


@dataclass(frozen=True)
class FrameSpan:
    """One zstd frame located inside the concatenated byte stream."""

    index: int
    offset: int
    length: int
    declared_length: int | None = None
    truncated: bool = False
    error: str | None = None

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class FrameDecode:
    """Decoded (or failed) frame; ``error`` is set when the frame is unusable."""

    index: int
    offset: int
    length: int
    payload: bytes = b""
    error: str | None = None
    truncated: bool = False


@dataclass
class DecodeGap:
    """Explicit evidence gap produced while decoding a byte stream."""

    reason: str
    offset: int
    length: int
    frame_index: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "offset": self.offset,
            "length": self.length,
            "frame_index": self.frame_index,
            "detail": self.detail,
        }


@dataclass
class DecodeReport:
    """Result of decoding a complete concatenated multit-frame stream."""

    frames: list[FrameDecode] = field(default_factory=list)
    gaps: list[DecodeGap] = field(default_factory=list)
    complete: bool = True
    backend: str | None = None

    def payload(self) -> bytes:
        """Concatenated payload of all successfully decoded frames."""

        return b"".join(frame.payload for frame in self.frames if frame.error is None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frames": [
                {
                    "index": frame.index,
                    "offset": frame.offset,
                    "length": frame.length,
                    "error": frame.error,
                    "truncated": frame.truncated,
                }
                for frame in self.frames
            ],
            "gaps": [gap.to_dict() for gap in self.gaps],
            "complete": self.complete,
            "backend": self.backend,
        }


@dataclass
class GapInfo:
    """Explicit gap produced while parsing the JSON-Lines payload."""

    reason: str
    line_number: int
    offset: int
    raw_preview: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "line_number": self.line_number,
            "offset": self.offset,
            "raw_preview": self.raw_preview,
            "detail": self.detail,
        }


@dataclass
class PayloadSegment:
    """A contiguous run of decoded frames (no failed frame in between).

    JSON lines can only be reconstructed across frames that are adjacent in the
    byte stream; a failed frame breaks the run, so ingestion parses each segment
    independently.
    """

    offset: int
    payload: bytes
    frame_indices: tuple[int, ...]


# ---------------------------------------------------------------------------
# Decoder backends
# ---------------------------------------------------------------------------


def _import_zstandard() -> Any | None:
    try:  # pragma: no cover - import success is the normal path
        import zstandard

        return zstandard
    except ImportError:  # pragma: no cover - exercised only without the package
        return None


def _import_stdlib_zstd() -> Any | None:
    try:  # pragma: no cover - Python >= 3.14 path
        from compression import zstd

        return zstd
    except ImportError:  # pragma: no cover - Python < 3.14 without zstandard
        return None


def _decode_zstandard_frame(frame: bytes) -> bytes:
    """Decode exactly one complete zstd frame with the ``zstandard`` package."""

    zstandard = _import_zstandard()
    if zstandard is None:  # pragma: no cover - defensive
        raise UnsupportedCompressionError("zstandard backend disappeared at decode time")
    decompressor = zstandard.ZstdDecompressor()
    stream = decompressor.decompressobj()
    output = bytearray(stream.decompress(frame))
    if not getattr(stream, "eof", False):
        # Ask the stream to finish; a frame with an unknown content size still
        # completes here once the end marker has been seen.
        output.extend(stream.decompress(b""))
    if not getattr(stream, "eof", False):
        raise ValueError("incomplete zstd frame (decoder did not reach end marker)")
    unused = getattr(stream, "unused_data", b"")
    if unused:
        raise ValueError(f"zstd frame boundary mismatch: {len(unused)} trailing byte(s)")
    flush = getattr(stream, "flush", None)
    if callable(flush):
        output.extend(flush())
    return bytes(output)


def _decode_stdlib_frame(frame: bytes) -> bytes:
    """Decode exactly one complete zstd frame with ``compression.zstd``."""

    zstd = _import_stdlib_zstd()
    if zstd is None:  # pragma: no cover - defensive
        raise UnsupportedCompressionError("stdlib zstd backend disappeared at decode time")
    decompressor = zstd.ZstdDecompressor()
    output = bytearray()
    pending = frame
    for _ in range(1_000_000):
        output.extend(decompressor.decompress(pending))
        if getattr(decompressor, "eof", False):
            break
        if getattr(decompressor, "needs_input", False):
            raise ValueError("incomplete zstd frame (decoder needs more input)")
        pending = b""
    else:  # pragma: no cover - pathological stream guard
        raise ValueError("zstd decoder made no progress")
    unused = getattr(decompressor, "unused_data", b"")
    if unused:
        raise ValueError(f"zstd frame boundary mismatch: {len(unused)} trailing byte(s)")
    return bytes(output)


_DECODERS: dict[str, Callable[[bytes], bytes]] = {
    "zstandard": _decode_zstandard_frame,
    "stdlib": _decode_stdlib_frame,
}


def probe_backends() -> list[str]:
    """Return the available zstd decoder backends in preference order."""

    available: list[str] = []
    if _import_zstandard() is not None:
        available.append("zstandard")
    if _import_stdlib_zstd() is not None:
        available.append("stdlib")
    return available


def _select_backend(preferred: str | None = None) -> tuple[str, Callable[[bytes], bytes]]:
    available = probe_backends()
    if preferred is not None:
        if preferred not in BACKEND_ORDER:
            raise UnsupportedCompressionError(
                f"unknown zstd backend {preferred!r}; expected one of {', '.join(BACKEND_ORDER)}"
            )
        if preferred not in available:
            raise UnsupportedCompressionError(
                f"zstd backend {preferred!r} is not available on this interpreter"
            )
        return preferred, _DECODERS[preferred]
    if not available:
        raise UnsupportedCompressionError(
            "no zstd decoder backend is available: install the optional 'zstandard' "
            "package or use Python >= 3.14 (compression.zstd). Evidence ingestion is "
            "BLOCKED; refusing to decode a single frame and silently lose evidence."
        )
    name = available[0]
    return name, _DECODERS[name]


def decompress_frame(frame: bytes, *, backend: str | None = None) -> bytes:
    """Decode one complete zstd frame; raises when the frame is invalid."""

    raw = _as_bytes(frame)
    _, decoder = _select_backend(backend)
    return decoder(raw)


# ---------------------------------------------------------------------------
# Structural frame scanning
# ---------------------------------------------------------------------------


def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"zstd input must be bytes-like, not {type(data).__name__}")


def _parse_frame_span(data: bytes, offset: int, index: int) -> FrameSpan:
    """Determine the extent of one zstd frame starting at ``offset``."""

    available = len(data) - offset
    if available < 5:
        return FrameSpan(
            index=index,
            offset=offset,
            length=max(0, available),
            declared_length=None,
            truncated=True,
            error="truncated frame header",
        )
    descriptor = data[offset + 4]
    single_segment = bool(descriptor & 0x20)
    content_size_flag = (descriptor >> 6) & 0x03
    dictionary_flag = descriptor & 0x03
    checksum_flag = bool(descriptor & 0x04)
    if descriptor & 0x08:
        return FrameSpan(
            index=index,
            offset=offset,
            length=max(0, available),
            error="invalid zstd frame header (reserved bit set)",
        )

    position = offset + 5
    if not single_segment:
        position += 1  # Window_Descriptor
    position += 4 if dictionary_flag == 3 else dictionary_flag
    if content_size_flag == 0:
        position += 1 if single_segment else 0
    else:
        position += {1: 2, 2: 4, 3: 8}[content_size_flag]
    if position > len(data):
        return FrameSpan(
            index=index,
            offset=offset,
            length=available,
            truncated=True,
            error="truncated frame header",
        )

    while True:
        if position + 3 > len(data):
            return FrameSpan(
                index=index,
                offset=offset,
                length=available,
                truncated=True,
                error="truncated frame (incomplete block header)",
            )
        block_header = int.from_bytes(data[position : position + 3], "little")
        position += 3
        last_block = bool(block_header & 0x01)
        block_type = (block_header >> 1) & 0x03
        block_size = block_header >> 3
        if block_type == 3:
            return FrameSpan(
                index=index,
                offset=offset,
                length=available,
                error="invalid zstd frame (reserved block type)",
            )
        position += 1 if block_type == 1 else block_size
        if position > len(data):
            return FrameSpan(
                index=index,
                offset=offset,
                length=available,
                truncated=True,
                error="truncated frame (incomplete block data)",
            )
        if last_block:
            break

    if checksum_flag:
        position += 4
        if position > len(data):
            return FrameSpan(
                index=index,
                offset=offset,
                length=available,
                truncated=True,
                error="truncated frame (incomplete content checksum)",
            )

    declared = position - offset
    return FrameSpan(index=index, offset=offset, length=declared, declared_length=declared)


def scan_frames(data: bytes | bytearray | memoryview) -> list[FrameSpan]:
    """Locate every concatenated zstd frame by magic and framing structure.

    Scanning stops after a truncated or structurally invalid frame because the
    following boundary can no longer be trusted; ``decode_all`` records the
    remaining bytes as an explicit gap.
    """

    buffer = _as_bytes(data)
    spans: list[FrameSpan] = []
    position = 0
    index = 0
    while position < len(buffer):
        start = buffer.find(ZSTD_MAGIC, position)
        if start < 0:
            break
        span = _parse_frame_span(buffer, start, index)
        spans.append(span)
        if span.error is not None or span.truncated:
            break
        position = span.end
        index += 1
    return spans


# ---------------------------------------------------------------------------
# Full decoding
# ---------------------------------------------------------------------------


def decode_all(
    data: bytes | bytearray | memoryview, *, backend: str | None = None
) -> DecodeReport:
    """Decode every concatenated zstd frame and report explicit gaps.

    ``UnsupportedCompressionError`` is raised when no decoder backend exists;
    this is the documented BLOCKED state. An empty byte stream is a valid empty
    log (``complete=True``).
    """

    buffer = _as_bytes(data)
    backend_name, decoder = _select_backend(backend)

    spans = scan_frames(buffer)
    if not spans:
        if not buffer:
            return DecodeReport(complete=True, backend=backend_name)
        return DecodeReport(
            gaps=[
                DecodeGap(
                    reason=REASON_NO_FRAMES,
                    offset=0,
                    length=len(buffer),
                    detail="no zstd frame magic found in non-empty log",
                )
            ],
            complete=False,
            backend=backend_name,
        )

    frames: list[FrameDecode] = []
    gaps: list[DecodeGap] = []
    expected_offset = 0

    for span in spans:
        if span.offset > expected_offset:
            gap_length = span.offset - expected_offset
            gaps.append(
                DecodeGap(
                    reason=REASON_UNSCANNED_BYTES,
                    offset=expected_offset,
                    length=gap_length,
                    detail=(
                        f"{gap_length} byte(s) before frame {span.index} are not part of "
                        "any decodable zstd frame"
                    ),
                )
            )
        if span.truncated or span.error is not None:
            reason = REASON_TRUNCATED_FRAME if span.truncated else REASON_FRAME_DECODE_ERROR
            detail = span.error or "truncated zstd frame"
            frames.append(
                FrameDecode(
                    index=span.index,
                    offset=span.offset,
                    length=span.length,
                    payload=b"",
                    error=detail,
                    truncated=span.truncated,
                )
            )
            gaps.append(
                DecodeGap(
                    reason=reason,
                    offset=span.offset,
                    length=span.length,
                    frame_index=span.index,
                    detail=detail,
                )
            )
            expected_offset = span.end
            continue
        frame_bytes = buffer[span.offset : span.end]
        try:
            payload = decoder(frame_bytes)
        except Exception as exc:  # noqa: BLE001 - per-frame failure becomes a gap
            detail = f"{type(exc).__name__}: {exc}"
            frames.append(
                FrameDecode(
                    index=span.index,
                    offset=span.offset,
                    length=span.length,
                    payload=b"",
                    error=detail,
                )
            )
            gaps.append(
                DecodeGap(
                    reason=REASON_FRAME_DECODE_ERROR,
                    offset=span.offset,
                    length=span.length,
                    frame_index=span.index,
                    detail=detail,
                )
            )
        else:
            frames.append(
                FrameDecode(
                    index=span.index,
                    offset=span.offset,
                    length=span.length,
                    payload=payload,
                )
            )
        expected_offset = span.end

    if expected_offset < len(buffer):
        gaps.append(
            DecodeGap(
                reason=REASON_TRAILING_BYTES,
                offset=expected_offset,
                length=len(buffer) - expected_offset,
                detail=(
                    f"{len(buffer) - expected_offset} trailing byte(s) after the last "
                    "decoded frame"
                ),
            )
        )

    return DecodeReport(
        frames=frames,
        gaps=gaps,
        complete=not gaps,
        backend=backend_name,
    )


def iter_payload_segments(report: DecodeReport) -> list[PayloadSegment]:
    """Group decoded frames into contiguous payload runs.

    A JSON line may span two adjacent frames but never a failed frame, so each
    contiguous run is parsed independently. Failed frames consume their byte
    span and therefore split the run.
    """

    segments: list[PayloadSegment] = []
    current_offset: int | None = None
    current_chunks: list[bytes] = []
    current_indices: list[int] = []
    expected_next: int | None = None

    def flush() -> None:
        nonlocal current_offset, current_chunks, current_indices
        if current_offset is not None:
            segments.append(
                PayloadSegment(
                    offset=current_offset,
                    payload=b"".join(current_chunks),
                    frame_indices=tuple(current_indices),
                )
            )
        current_offset = None
        current_chunks = []
        current_indices = []

    for frame in report.frames:
        if frame.error is not None:
            flush()
            expected_next = frame.offset + frame.length
            continue
        if expected_next is None or frame.offset != expected_next or current_offset is None:
            flush()
            current_offset = frame.offset
        current_chunks.append(frame.payload)
        current_indices.append(frame.index)
        expected_next = frame.offset + frame.length
    flush()
    return segments


# ---------------------------------------------------------------------------
# JSON-Lines parsing
# ---------------------------------------------------------------------------


def _preview(raw: bytes) -> str:
    return raw[:GAP_PREVIEW_CHARS].decode("utf-8", errors="replace")


def parse_json_lines(payload: bytes | bytearray | memoryview) -> tuple[list[dict], list[GapInfo]]:
    """Parse a JSON-Lines payload, preserving torn lines as explicit gaps.

    Blank lines are ignored (they carry no evidence). Every non-empty line that
    is not a JSON object becomes a :class:`GapInfo` with the raw text preserved
    in ``raw_preview``; nothing is silently discarded.
    """

    buffer = _as_bytes(payload)
    records: list[dict] = []
    gaps: list[GapInfo] = []
    length = len(buffer)
    start = 0
    line_number = 0

    while start < length:
        newline = buffer.find(b"\n", start)
        if newline < 0:
            raw = buffer[start:]
            next_start = length
        else:
            raw = buffer[start:newline]
            next_start = newline + 1
        line_number += 1
        if raw.strip():
            _parse_line(raw, line_number, start, records, gaps)
        start = next_start

    return records, gaps


def _parse_line(
    raw: bytes,
    line_number: int,
    offset: int,
    records: list[dict],
    gaps: list[GapInfo],
) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        gaps.append(
            GapInfo(
                reason="invalid_utf8",
                line_number=line_number,
                offset=offset,
                raw_preview=_preview(raw),
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
        return
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        gaps.append(
            GapInfo(
                reason="torn_line",
                line_number=line_number,
                offset=offset,
                raw_preview=_preview(raw),
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
        return
    if not isinstance(value, dict):
        gaps.append(
            GapInfo(
                reason="not_an_object",
                line_number=line_number,
                offset=offset,
                raw_preview=_preview(raw),
                detail=f"JSON line decoded to {type(value).__name__}, expected object",
            )
        )
        return
    records.append(value)


def summarize_gaps(gaps: Iterable[DecodeGap | GapInfo]) -> dict[str, int]:
    """Count gaps by reason (deterministic helper for reports)."""

    counts: dict[str, int] = {}
    for gap in gaps:
        counts[gap.reason] = counts.get(gap.reason, 0) + 1
    return dict(sorted(counts.items()))
