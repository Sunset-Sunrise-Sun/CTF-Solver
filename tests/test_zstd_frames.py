"""Deterministic tests for multi-frame zstd decoding and JSON-Lines parsing."""

from __future__ import annotations

import json

import pytest

from ctf_solver.core.errors import UnsupportedCompressionError
from ctf_solver.evidence import zstd_frames
from ctf_solver.evidence.zstd_frames import (
    REASON_FRAME_DECODE_ERROR,
    REASON_NO_FRAMES,
    REASON_TRAILING_BYTES,
    REASON_TRUNCATED_FRAME,
    REASON_UNSCANNED_BYTES,
    decode_all,
    decompress_frame,
    iter_payload_segments,
    parse_json_lines,
    probe_backends,
    scan_frames,
)
from tests.support.zstd_fixtures import (
    build_log_from_chunks,
    build_session_log,
    corrupt_frame,
    frame_bytes,
    jsonl_bytes,
    truncate_last_frame,
)
from tests.support.session_events import standard_session


def _payload_records(count: int = 6) -> list[dict[str, object]]:
    return [
        {"type": "synthetic", "seq": index, "text": "x" * index, "marker": f"record-{index}"}
        for index in range(count)
    ]


def _payload() -> bytes:
    return jsonl_bytes(_payload_records())


def _mid_line_chunks(payload: bytes, count: int = 4) -> list[bytes]:
    boundaries = [0, 5, 23, 57, len(payload)]
    chunks: list[bytes] = []
    for start, end in zip(boundaries, boundaries[1:]):
        if end > start:
            chunks.append(payload[start:end])
    assert len(chunks) == count
    return chunks


# ---------------------------------------------------------------------------
# Backend probing
# ---------------------------------------------------------------------------


def test_probe_backends_reports_available_decoders() -> None:
    available = probe_backends()
    assert "zstandard" in available  # declared available in this environment
    assert "stdlib" in available  # Python 3.14 compression.zstd
    assert available[0] == "zstandard"  # documented preference order


def test_no_backend_raises_unsupported_compression_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zstd_frames, "probe_backends", lambda: [])
    data = frame_bytes([_payload()])
    with pytest.raises(UnsupportedCompressionError):
        decode_all(data)
    with pytest.raises(UnsupportedCompressionError):
        decode_all(b"")  # BLOCKED even for an empty log
    with pytest.raises(UnsupportedCompressionError):
        decompress_frame(data)
    # Structural scanning needs no decoding backend and still works.
    assert len(scan_frames(data)) == 1


def test_unknown_or_unavailable_explicit_backend_rejected() -> None:
    data = frame_bytes([_payload()])
    with pytest.raises(UnsupportedCompressionError):
        decode_all(data, backend="not-a-backend")


@pytest.mark.parametrize("backend", ["zstandard", "stdlib"])
def test_each_available_backend_decodes_all_frames(backend: str) -> None:
    if backend not in probe_backends():  # pragma: no cover - environment dependent
        pytest.skip(f"backend {backend} unavailable")
    payload = _payload()
    data = build_log_from_chunks(_mid_line_chunks(payload))
    report = decode_all(data, backend=backend)
    assert report.backend == backend
    assert report.complete is True
    assert report.gaps == []
    assert report.payload() == payload


# ---------------------------------------------------------------------------
# Frame scanning
# ---------------------------------------------------------------------------


def test_scan_frames_finds_every_concatenated_frame() -> None:
    chunks = [b'{"a":1}\n', b'{"b":2}\n', b'{"c":3}\n']
    data = frame_bytes(chunks)
    spans = scan_frames(data)
    assert [span.index for span in spans] == [0, 1, 2]
    assert spans[0].offset == 0
    for index, span in enumerate(spans):
        assert span.error is None
        assert span.truncated is False
        assert span.declared_length == span.length
        assert span.length > 0
        if index:
            assert span.offset == spans[index - 1].end
    assert spans[-1].end == len(data)


def test_scan_frames_ignores_magic_bytes_inside_frame_payload() -> None:
    # A frame whose compressed bytes contain the zstd magic must not be split.
    inner = b"\x28\xb5\x2f\xfd" + b"synthetic-magic-in-payload"
    data = frame_bytes([inner, b'{"a":1}\n'])
    spans = scan_frames(data)
    assert len(spans) == 2
    report = decode_all(data)
    assert report.complete is True
    assert report.payload() == inner + b'{"a":1}\n'


# ---------------------------------------------------------------------------
# Multi-frame decoding
# ---------------------------------------------------------------------------


def test_decode_all_multi_frame_with_mid_line_splits() -> None:
    payload = _payload()
    chunks = _mid_line_chunks(payload)
    # Prove the fixture really splits JSON lines across frame boundaries.
    assert any(not chunk.endswith(b"\n") for chunk in chunks)
    data = build_log_from_chunks(chunks)
    report = decode_all(data)
    assert len(report.frames) == len(chunks)
    assert report.complete is True
    assert report.gaps == []
    assert report.payload() == payload
    records, gaps = parse_json_lines(report.payload())
    assert gaps == []
    assert len(records) == 6
    assert [record["marker"] for record in records] == [f"record-{i}" for i in range(6)]


def test_decode_all_more_than_two_frames() -> None:
    records = standard_session()
    data = build_session_log(records, frames=9)
    spans = scan_frames(data)
    assert len(spans) == 9  # every frame is non-empty for this fixture
    report = decode_all(data)
    assert len(report.frames) == 9
    assert report.complete is True
    parsed, gaps = parse_json_lines(report.payload())
    assert gaps == []
    assert len(parsed) == len(records)


def test_decode_all_frames_without_content_size_header() -> None:
    zstandard = pytest.importorskip("zstandard")
    payload = _payload()
    chunks = _mid_line_chunks(payload)
    compressor = zstandard.ZstdCompressor(level=3, write_content_size=False)
    data = b"".join(compressor.compress(chunk) for chunk in chunks)
    spans = scan_frames(data)
    assert len(spans) == len(chunks)
    assert all(span.declared_length == span.length for span in spans)
    report = decode_all(data)
    assert len(report.frames) == len(chunks)
    assert report.complete is True
    assert report.payload() == payload


def test_single_frame_regression() -> None:
    payload = _payload()
    data = frame_bytes([payload])
    report = decode_all(data)
    assert len(report.frames) == 1
    assert report.complete is True
    records, gaps = parse_json_lines(report.payload())
    assert gaps == []
    assert len(records) == 6


def test_decode_all_empty_input_is_complete() -> None:
    report = decode_all(b"")
    assert report.frames == []
    assert report.gaps == []
    assert report.complete is True


def test_decode_all_non_zstd_input_is_explicit_gap() -> None:
    report = decode_all(b"this is not a zstd log")
    assert report.frames == []
    assert [gap.reason for gap in report.gaps] == [REASON_NO_FRAMES]
    assert report.complete is False


# ---------------------------------------------------------------------------
# Damaged input
# ---------------------------------------------------------------------------


def test_truncated_last_frame_becomes_truncated_frame_gap() -> None:
    records = standard_session()
    data = build_session_log(records, frames=3)
    full = decode_all(data)
    truncated = truncate_last_frame(data, drop=6)
    spans = scan_frames(truncated)
    assert len(spans) == 3
    assert spans[-1].truncated is True

    report = decode_all(truncated)
    assert report.complete is False
    assert len(report.frames) == 3
    assert report.frames[-1].error is not None
    assert [gap.reason for gap in report.gaps] == [REASON_TRUNCATED_FRAME]
    # Every intact frame before the truncation is still decoded.
    assert full.payload().startswith(report.payload())
    assert report.payload()  # decoded prefix is non-empty evidence


def test_corrupt_frame_magic_loses_one_frame_but_decodes_others() -> None:
    records = standard_session()
    data = build_session_log(records, frames=4)
    original = decode_all(data)
    spans = scan_frames(data)
    corrupted = corrupt_frame(data, spans[1].offset)  # destroy the 2nd frame magic
    report = decode_all(corrupted)
    assert report.complete is False
    unscanned = [gap for gap in report.gaps if gap.reason == REASON_UNSCANNED_BYTES]
    assert len(unscanned) == 1
    assert unscanned[0].offset == spans[1].offset
    assert unscanned[0].length == spans[1].length
    decoded_offsets = [frame.offset for frame in report.frames if frame.error is None]
    assert decoded_offsets == [spans[0].offset, spans[2].offset, spans[3].offset]
    by_offset = {
        frame.offset: frame
        for frame in original.frames
        if frame.error is None
    }
    for frame in report.frames:
        if frame.error is None:
            assert frame.payload == by_offset[frame.offset].payload


@pytest.mark.parametrize("backend", ["zstandard", "stdlib"])
def test_corrupt_checksummed_frame_becomes_decode_error(backend: str) -> None:
    if backend not in probe_backends():  # pragma: no cover - environment dependent
        pytest.skip(f"backend {backend} unavailable")
    zstandard = pytest.importorskip("zstandard")
    first_payload = b'{"type":"turn/start","seq":1,"data":{"turn":1}}\n'
    second_payload = b'{"type":"turn/end","seq":2,"data":{"turn":1}}\n'
    compressor = zstandard.ZstdCompressor(level=3, write_checksum=True)
    first = compressor.compress(first_payload)
    second = compressor.compress(second_payload)
    data = first + second
    spans = scan_frames(data)
    assert len(spans) == 2
    corrupted = bytearray(data)
    corrupted[spans[0].end - 1] ^= 0xFF  # flip the frame content checksum
    report = decode_all(bytes(corrupted), backend=backend)
    assert report.complete is False
    assert report.frames[0].error is not None
    assert report.frames[1].error is None
    assert report.frames[1].payload == second_payload
    assert [gap.reason for gap in report.gaps] == [REASON_FRAME_DECODE_ERROR]


def test_leading_garbage_is_an_explicit_gap() -> None:
    data = b"GARBAGE" + frame_bytes([_payload()])
    report = decode_all(data)
    assert len(report.frames) == 1
    assert report.frames[0].payload == _payload()
    assert [gap.reason for gap in report.gaps] == [REASON_UNSCANNED_BYTES]
    assert report.gaps[0].offset == 0
    assert report.gaps[0].length == len(b"GARBAGE")
    assert report.complete is False


def test_trailing_bytes_after_last_frame_is_a_gap() -> None:
    data = frame_bytes([_payload()]) + b"leftover"
    report = decode_all(data)
    assert [gap.reason for gap in report.gaps] == [REASON_TRAILING_BYTES]
    assert report.complete is False


# ---------------------------------------------------------------------------
# Payload segments
# ---------------------------------------------------------------------------


def test_payload_segments_split_at_failed_frames() -> None:
    records = standard_session()
    data = build_session_log(records, frames=4)
    spans = scan_frames(data)
    corrupted = corrupt_frame(data, spans[1].offset)
    report = decode_all(corrupted)
    segments = iter_payload_segments(report)
    assert len(segments) == 2
    assert segments[0].offset == spans[0].offset
    assert segments[0].frame_indices == (0,)
    assert segments[1].offset == spans[2].offset
    assert segments[1].frame_indices == (1, 2)
    assert b"".join(segment.payload for segment in segments) == report.payload()


# ---------------------------------------------------------------------------
# JSON-Lines parsing
# ---------------------------------------------------------------------------


def test_parse_json_lines_accepts_multiple_objects() -> None:
    payload = jsonl_bytes(_payload_records(3))
    records, gaps = parse_json_lines(payload)
    assert gaps == []
    assert len(records) == 3
    assert records[0]["marker"] == "record-0"


def test_parse_json_lines_preserves_torn_line_as_gap() -> None:
    payload = b'{"type":"a","seq":1}\n{"torn": \n{"type":"b","seq":2}\n'
    records, gaps = parse_json_lines(payload)
    assert [record["type"] for record in records] == ["a", "b"]
    assert len(gaps) == 1
    assert gaps[0].reason == "torn_line"
    assert gaps[0].line_number == 2
    assert gaps[0].raw_preview.startswith('{"torn"')
    assert "JSONDecodeError" in gaps[0].detail


def test_parse_json_lines_rejects_non_object_json_as_gap() -> None:
    payload = b'[1,2,3]\n{"ok":true}\n'
    records, gaps = parse_json_lines(payload)
    assert len(records) == 1
    assert len(gaps) == 1
    assert gaps[0].reason == "not_an_object"


def test_parse_json_lines_invalid_utf8_is_gap() -> None:
    records, gaps = parse_json_lines(b"\xff\xfe\x00bad\n")
    assert records == []
    assert len(gaps) == 1
    assert gaps[0].reason == "invalid_utf8"


def test_parse_json_lines_skips_blank_lines_without_gaps() -> None:
    records, gaps = parse_json_lines(b'\n{"a":1}\n\n')
    assert len(records) == 1
    assert gaps == []


def test_parse_json_lines_without_trailing_newline_keeps_valid_record() -> None:
    records, gaps = parse_json_lines(b'{"a":1}')
    assert len(records) == 1
    assert gaps == []


def test_parse_json_lines_line_spanning_frame_boundary() -> None:
    record = {"type": "x", "seq": 1, "data": {"blob": "y" * 200}}
    payload = jsonl_bytes([record])
    # Split inside the JSON line, then inside the object value.
    data = build_log_from_chunks([payload[:10], payload[10:120], payload[120:]])
    report = decode_all(data)
    assert report.complete is True
    records, gaps = parse_json_lines(report.payload())
    assert gaps == []
    assert records == [record]
