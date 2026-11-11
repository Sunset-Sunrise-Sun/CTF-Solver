"""Tiny dependency-free PNG writer for synthetic screenshot fixtures."""

from __future__ import annotations

import struct
import zlib


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def make_png(width: int, height: int, rows: bytes) -> bytes:
    """Encode RGB rows (``height * width * 3`` bytes) as a PNG file."""

    expected = width * height * 3
    if len(rows) != expected:
        raise ValueError(f"expected {expected} RGB bytes, got {len(rows)}")
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)  # filter type 0
        raw.extend(rows[y * stride : (y + 1) * stride])
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _chunk(b"IEND", b"")
    )


def solid_png(width: int = 64, height: int = 48, color: tuple[int, int, int] = (0, 0, 0)) -> bytes:
    return make_png(width, height, bytes(color) * (width * height))


def blank_png(width: int = 64, height: int = 48) -> bytes:
    """Uniform black image: must be detected as a blank/failed capture."""

    return solid_png(width, height, (0, 0, 0))


def gradient_png(width: int = 64, height: int = 48) -> bytes:
    rows = bytearray()
    for y in range(height):
        for x in range(width):
            rows.extend(((x * 255) // max(1, width - 1), (y * 255) // max(1, height - 1), 128))
    return make_png(width, height, bytes(rows))


def checker_png(width: int = 64, height: int = 48) -> bytes:
    rows = bytearray()
    for y in range(height):
        for x in range(width):
            value = 255 if (x // 8 + y // 8) % 2 == 0 else 0
            rows.extend((value, value, value))
    return make_png(width, height, bytes(rows))


def png_size(data: bytes) -> tuple[int, int]:
    """Return (width, height) from a PNG byte string without external deps."""

    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a PNG file")
    width, height = struct.unpack(">II", data[16:24])
    return int(width), int(height)
