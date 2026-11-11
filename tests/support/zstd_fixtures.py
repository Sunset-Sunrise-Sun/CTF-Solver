"""Helpers for building multi-frame zstd session-log fixtures.

The real Harness writes ``session.v4.jsonl.zstd`` as *concatenated independent
zstd frames* containing a JSON-Lines stream. Tests must reproduce arbitrary
frame boundaries (including mid-line boundaries), truncation and malformed
payloads without depending on a real Harness run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Sequence

try:  # pragma: no cover - exercised indirectly on every machine
    import zstandard as _zstandard

    def _compress_frame(data: bytes) -> bytes:
        return _zstandard.ZstdCompressor(level=3).compress(data)

except ImportError:  # pragma: no cover - Python >= 3.14 stdlib fallback
    from compression import zstd as _stdlib_zstd

    def _compress_frame(data: bytes) -> bytes:
        return _stdlib_zstd.compress(data)


def frame_bytes(chunks: Sequence[bytes]) -> bytes:
    """Concatenate one independent zstd frame per chunk."""

    return b"".join(_compress_frame(bytes(chunk)) for chunk in chunks)


def jsonl_bytes(records: Iterable[dict]) -> bytes:
    """Serialize records exactly as a JSON-Lines payload stream."""

    return b"\n".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for record in records
    ) + b"\n"


def build_session_log(
    records: Iterable[dict],
    *,
    frames: int = 4,
    trailing_newline: bool = True,
) -> bytes:
    """Build a multi-frame zstd log for ``records`` split into ``frames`` frames.

    The JSONL payload is split at even byte boundaries, deliberately allowing
    frame boundaries to fall in the middle of a JSON line.
    """

    payload = b"\n".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for record in records
    )
    if trailing_newline:
        payload += b"\n"
    count = max(1, int(frames))
    size = len(payload)
    boundaries = [round(size * index / count) for index in range(count + 1)]
    chunks: list[bytes] = []
    for index in range(count):
        start, end = boundaries[index], boundaries[index + 1]
        if end > start:
            chunks.append(payload[start:end])
    return frame_bytes(chunks)


def build_log_from_chunks(chunks: Sequence[bytes]) -> bytes:
    return frame_bytes(chunks)


def write_session_log(
    path: str | os.PathLike[str],
    records: Iterable[dict],
    *,
    frames: int = 4,
    trailing_newline: bool = True,
) -> bytes:
    data = build_session_log(records, frames=frames, trailing_newline=trailing_newline)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def truncate_last_frame(data: bytes, drop: int = 8) -> bytes:
    """Return ``data`` with ``drop`` bytes removed from the final frame."""

    return data[: max(0, len(data) - int(drop))]


def corrupt_frame(data: bytes, offset: int) -> bytes:
    """Flip one byte at ``offset`` (used to force a per-frame decode gap)."""

    mutable = bytearray(data)
    if not mutable:
        return bytes(mutable)
    index = min(max(0, offset), len(mutable) - 1)
    mutable[index] ^= 0xFF
    return bytes(mutable)
