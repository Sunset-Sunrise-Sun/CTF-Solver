"""Explicit screenshot capture implementations.

Capture is an explicit operation: the Manager calls a capturer once, for one
Task/Worker/Step, and records the result (``ok`` / ``blank`` / ``failed``).
There is no continuous or silent desktop recording in this module.

* ``DesktopCapturer`` uses a fixed, project-owned PowerShell script with
  ``System.Drawing.CopyFromScreen`` and per-monitor DPI awareness (verified by
  the integration audit: default DPI-unaware capture was 1707x1067, aware
  capture 2560x1600; ``PrintWindow`` needs flag 2).
* ``FakeScreenCapturer`` produces deterministic PNGs for tests.

Blank detection is done in Python from the PNG pixels (mean/stddev sampling) so
a capturer that returns a black frame is recorded as a failed/blank capture, not
as evidence.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any

from ..core.errors import CaptureError
from ..core.types import CaptureResult

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
BLANK_STDDEV_THRESHOLD = 1.0
MIN_CAPTURE_SIDE = 8


# ---------------------------------------------------------------------------
# Minimal PNG decoding / statistics (stdlib only)
# ---------------------------------------------------------------------------

_CHANNELS = {0: 1, 2: 3, 4: 2, 6: 4}


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def decode_png_rgb(data: bytes) -> tuple[int, int, bytes]:
    """Decode an 8-bit non-interlaced PNG to RGB bytes.

    Supports colour types 0/2/4/6 (grayscale, RGB, gray+alpha, RGBA). Raises
    ``CaptureError`` for unsupported PNG variants. No third-party dependency.
    """

    if not data.startswith(PNG_SIGNATURE):
        raise CaptureError("capture is not a PNG file")
    offset = len(PNG_SIGNATURE)
    width = height = bit_depth = colour_type = interlace = None
    idat = bytearray()
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        if len(payload) != length:
            raise CaptureError("truncated PNG chunk")
        offset += 12 + length
        if kind == b"IHDR":
            width = int.from_bytes(payload[0:4], "big")
            height = int.from_bytes(payload[4:8], "big")
            bit_depth = payload[8]
            colour_type = payload[9]
            interlace = payload[12]
        elif kind == b"IDAT":
            idat.extend(payload)
        elif kind == b"IEND":
            break
    if width is None or height is None:
        raise CaptureError("PNG missing IHDR")
    if bit_depth != 8 or colour_type not in _CHANNELS or interlace != 0:
        raise CaptureError(
            f"unsupported PNG format (bit_depth={bit_depth}, colour_type={colour_type}, "
            f"interlace={interlace})"
        )
    channels = _CHANNELS[colour_type]
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error as exc:
        raise CaptureError(f"invalid PNG image data: {exc}") from exc
    stride = width * channels
    expected = (stride + 1) * height
    if len(raw) < expected:
        raise CaptureError("truncated PNG image data")
    out = bytearray()
    previous = bytearray(stride)
    position = 0
    for _y in range(height):
        filter_type = raw[position]
        position += 1
        row = bytearray(raw[position : position + stride])
        position += stride
        if filter_type == 1:  # Sub
            for i in range(channels, stride):
                row[i] = (row[i] + row[i - channels]) & 0xFF
        elif filter_type == 2:  # Up
            for i in range(stride):
                row[i] = (row[i] + previous[i]) & 0xFF
        elif filter_type == 3:  # Average
            for i in range(stride):
                left = row[i - channels] if i >= channels else 0
                row[i] = (row[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif filter_type == 4:  # Paeth
            for i in range(stride):
                left = row[i - channels] if i >= channels else 0
                up_left = previous[i - channels] if i >= channels else 0
                row[i] = (row[i] + _paeth(left, previous[i], up_left)) & 0xFF
        elif filter_type != 0:
            raise CaptureError(f"unsupported PNG filter type {filter_type}")
        previous = row
        if colour_type == 2:
            out.extend(row)
        elif colour_type == 6:
            for x in range(width):
                base = x * 4
                out.extend(row[base : base + 3])
        elif colour_type == 0:
            for value in row:
                out.extend((value, value, value))
        elif colour_type == 4:
            for x in range(width):
                value = row[x * 2]
                out.extend((value, value, value))
    return width, height, bytes(out)


def png_statistics(data: bytes) -> dict[str, Any]:
    """Return width/height/mean/stddev over sampled RGB channels."""

    width, height, pixels = decode_png_rgb(data)
    if width <= 0 or height <= 0:
        raise CaptureError("capture has zero dimensions")
    step = max(1, max(width, height) // 128)
    channel_sum = [0, 0, 0]
    channel_sq = [0, 0, 0]
    count = 0
    for y in range(0, height, step):
        row_base = y * width * 3
        for x in range(0, width, step):
            base = row_base + x * 3
            for channel in range(3):
                value = pixels[base + channel]
                channel_sum[channel] += value
                channel_sq[channel] += value * value
            count += 1
    if count == 0:
        raise CaptureError("capture sampling produced no pixels")
    channel_stddevs: list[float] = []
    channel_means: list[float] = []
    for channel in range(3):
        mean = channel_sum[channel] / count
        variance = max(0.0, (channel_sq[channel] / count) - mean * mean)
        channel_means.append(mean)
        channel_stddevs.append(variance**0.5)
    # Blank detection is *spatial* variation: a uniform image of any colour is
    # blank. Cross-channel differences alone must not count as content.
    stddev = max(channel_stddevs)
    mean = sum(channel_means) / 3.0
    return {
        "width": width,
        "height": height,
        "mean": round(mean, 3),
        "stddev": round(stddev, 3),
        "blank": stddev < BLANK_STDDEV_THRESHOLD,
        "unique_sampled": len({pixels[i] for i in range(0, len(pixels), max(1, len(pixels) // 4096))}),
        "channel_stddev": [round(value, 3) for value in channel_stddevs],
    }


# ---------------------------------------------------------------------------
# Capturers
# ---------------------------------------------------------------------------


class DesktopCapturer:
    """Capture the primary desktop through a fixed PowerShell helper script."""

    name = "desktop"

    def __init__(self, *, powershell: str = "powershell.exe", timeout_s: float = 30.0) -> None:
        self.powershell = powershell
        self.timeout_s = timeout_s
        self._script_text = _POWERSHELL_CAPTURE_SCRIPT

    def capture(self, *, scope: str = "desktop", workdir: str | None = None) -> CaptureResult:
        captured_at = int(time.time() * 1000)
        if scope != "desktop":
            return CaptureResult(
                ok=False,
                png_bytes=b"",
                error=f"unsupported desktop capture scope: {scope!r} (only 'desktop' is verified)",
                method=self.name,
                captured_at=captured_at,
            )
        temp_dir = Path(tempfile.mkdtemp(prefix="ctf-solver-shot-"))
        script_path = temp_dir / "capture.ps1"
        out_path = temp_dir / "capture.png"
        try:
            script_path.write_text(self._script_text, encoding="utf-8")
            command = [
                self.powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-OutPath",
                str(out_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout_s,
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return CaptureResult(
                    ok=False,
                    png_bytes=b"",
                    error=f"capture process failed: {exc}",
                    method=self.name,
                    captured_at=captured_at,
                )
            if completed.returncode != 0 or not out_path.is_file():
                stderr_tail = (completed.stderr or "").strip().splitlines()[-3:]
                return CaptureResult(
                    ok=False,
                    png_bytes=b"",
                    error=f"capture failed (exit {completed.returncode}): {' | '.join(stderr_tail)}",
                    method=self.name,
                    captured_at=captured_at,
                )
            data = out_path.read_bytes()
            if not data:
                return CaptureResult(
                    ok=False,
                    png_bytes=b"",
                    error="capture wrote an empty file",
                    method=self.name,
                    captured_at=captured_at,
                )
            try:
                stats = png_statistics(data)
            except CaptureError as exc:
                return CaptureResult(ok=False, png_bytes=data, error=str(exc), method=self.name, captured_at=captured_at)
            return CaptureResult(
                ok=True,
                png_bytes=data,
                width=int(stats["width"]),
                height=int(stats["height"]),
                blank=bool(stats["blank"]),
                error="",
                method=self.name,
                captured_at=captured_at,
            )
        finally:
            try:
                out_path.unlink(missing_ok=True)
                script_path.unlink(missing_ok=True)
                temp_dir.rmdir()
            except OSError:
                pass


class FakeScreenCapturer:
    """Deterministic capturer used only by tests / explicit fake mode."""

    name = "fake"

    def __init__(self, mode: str = "nonblank") -> None:
        if mode not in {"nonblank", "blank", "fail"}:
            raise ValueError(f"unsupported fake capture mode: {mode!r}")
        self.mode = mode

    def capture(self, *, scope: str = "desktop", workdir: str | None = None) -> CaptureResult:
        captured_at = int(time.time() * 1000)
        if self.mode == "fail":
            return CaptureResult(
                ok=False,
                png_bytes=b"",
                error="synthetic capture failure (fake mode)",
                method=self.name,
                captured_at=captured_at,
            )
        if self.mode == "blank":
            data = _solid_png(64, 48, (0, 0, 0))
            return CaptureResult(
                ok=True,
                png_bytes=data,
                width=64,
                height=48,
                blank=True,
                method=self.name,
                captured_at=captured_at,
            )
        data = _checker_png(96, 64)
        stats = png_statistics(data)
        return CaptureResult(
            ok=True,
            png_bytes=data,
            width=int(stats["width"]),
            height=int(stats["height"]),
            blank=bool(stats["blank"]),
            method=self.name,
            captured_at=captured_at,
        )


def build_capturer(mode: str = "desktop") -> DesktopCapturer | FakeScreenCapturer:
    if mode == "fake":
        return FakeScreenCapturer("nonblank")
    if mode == "fake-blank":
        return FakeScreenCapturer("blank")
    return DesktopCapturer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big")
        + kind
        + payload
        + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def _make_png(width: int, height: int, rows: bytes) -> bytes:
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        raw.extend(rows[y * stride : (y + 1) * stride])
    header = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes((8, 2, 0, 0, 0))
    )
    return (
        PNG_SIGNATURE
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _png_chunk(b"IEND", b"")
    )


def _solid_png(width: int, height: int, colour: tuple[int, int, int]) -> bytes:
    return _make_png(width, height, bytes(colour) * (width * height))


def _checker_png(width: int = 96, height: int = 64) -> bytes:
    rows = bytearray()
    for y in range(height):
        for x in range(width):
            value = 230 if (x // 8 + y // 8) % 2 == 0 else 20
            rows.extend((value, value, value))
    return _make_png(width, height, bytes(rows))


_POWERSHELL_CAPTURE_SCRIPT = r"""
param([Parameter(Mandatory=$true)][string]$OutPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CtfDpi {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
}
'@
try { [void][CtfDpi]::SetProcessDpiAwarenessContext([IntPtr](-4)) } catch { }
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
if ($bounds.Width -le 0 -or $bounds.Height -le 0) {
    $bounds = New-Object System.Drawing.Rectangle 0,0,1920,1080
}
$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
try {
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
} finally {
    $graphics.Dispose()
}
$bitmap.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
$step = [Math]::Max(1, [Math]::Max($bounds.Width, $bounds.Height) / 128)
$sum = 0.0; $sumSq = 0.0; $count = 0
for ($y = 0; $y -lt $bounds.Height; $y += $step) {
    for ($x = 0; $x -lt $bounds.Width; $x += $step) {
        $pixel = $bitmap.GetPixel($x, $y)
        foreach ($channel in @($pixel.R, $pixel.G, $pixel.B)) {
            $sum += $channel
            $sumSq += ($channel * $channel)
            $count += 1
        }
    }
}
$bitmap.Dispose()
$mean = if ($count -gt 0) { $sum / $count } else { 0 }
$variance = if ($count -gt 0) { [Math]::Max(0, ($sumSq / $count) - ($mean * $mean)) } else { 0 }
$result = [ordered]@{
    ok = $true
    width = $bounds.Width
    height = $bounds.Height
    mean = [Math]::Round($mean, 3)
    stddev = [Math]::Round([Math]::Sqrt($variance), 3)
    path = $OutPath
}
$result | ConvertTo-Json -Compress
"""
