"""Tests for explicit screenshot capture and blank-frame handling."""

from __future__ import annotations

import types

import pytest

from ctf_solver.core.errors import CaptureError, ConfigError
from ctf_solver.core.types import CaptureStatus
from ctf_solver.delivery import screenshot as screenshot_module
from ctf_solver.delivery.screenshot import (
    DesktopCapturer,
    FakeScreenCapturer,
    WindowCapturer,
    _decode_powershell_output,
    _POWERSHELL_CAPTURE_SCRIPT,
    build_capturer,
    decode_png_rgb,
    png_statistics,
)
from tests.support.png import blank_png, gradient_png, solid_png


def test_png_decoding_and_statistics() -> None:
    blank = png_statistics(blank_png())
    assert blank["width"] == 64 and blank["height"] == 48
    assert blank["blank"] is True
    assert blank["stddev"] < 1.0

    gradient = png_statistics(gradient_png())
    assert gradient["blank"] is False
    assert gradient["stddev"] > 5.0

    solid = png_statistics(solid_png(32, 32, (200, 10, 30)))
    assert solid["blank"] is True


def test_solid_colour_png_has_expected_pixels() -> None:
    width, height, pixels = decode_png_rgb(solid_png(4, 3, (1, 2, 3)))
    assert (width, height) == (4, 3)
    assert len(pixels) == 4 * 3 * 3
    assert pixels[:3] == bytes((1, 2, 3))


def test_invalid_png_is_rejected() -> None:
    with pytest.raises(CaptureError):
        png_statistics(b"not a png")
    with pytest.raises(CaptureError):
        decode_png_rgb(b"\x89PNG\r\n\x1a\n" + b"garbage")


def test_fake_capturer_modes() -> None:
    nonblank = FakeScreenCapturer("nonblank").capture(scope="desktop")
    assert nonblank.ok is True
    assert nonblank.blank is False
    assert nonblank.status is CaptureStatus.OK
    assert nonblank.width == 96 and nonblank.height == 64
    assert nonblank.png_bytes.startswith(b"\x89PNG")

    blank = FakeScreenCapturer("blank").capture(scope="desktop")
    assert blank.ok is True and blank.blank is True
    assert blank.status is CaptureStatus.BLANK

    failed = FakeScreenCapturer("fail").capture(scope="desktop")
    assert failed.ok is False
    assert failed.status is CaptureStatus.FAILED
    assert "synthetic capture failure" in failed.error


def test_desktop_capturer_rejects_unverified_scope_without_running_anything() -> None:
    capturer = DesktopCapturer()
    result = capturer.capture(scope="window")
    assert result.ok is False
    assert result.status is CaptureStatus.FAILED
    assert "unsupported desktop capture scope" in result.error


def test_desktop_capturer_reports_missing_powershell() -> None:
    capturer = DesktopCapturer(powershell="definitely-not-a-real-powershell-binary")
    result = capturer.capture(scope="desktop")
    assert result.ok is False
    assert result.status is CaptureStatus.FAILED
    assert "capture process failed" in result.error


def test_build_capturer_modes() -> None:
    assert isinstance(build_capturer("desktop"), DesktopCapturer)
    assert isinstance(build_capturer("fake"), FakeScreenCapturer)
    fake_blank = build_capturer("fake-blank")
    assert isinstance(fake_blank, FakeScreenCapturer)
    assert fake_blank.mode == "blank"
    # The production default mode is real-window and requires an explicit PID.
    window = build_capturer("real-window", target_pid=4321)
    assert isinstance(window, WindowCapturer)
    assert window.target_pid == 4321
    with pytest.raises(ValueError):
        FakeScreenCapturer("bogus")


def test_build_capturer_real_window_requires_an_explicit_positive_pid() -> None:
    # Missing PID (including the default argument) fails closed: no capturer is
    # ever built that could silently capture the desktop.
    with pytest.raises(ConfigError, match="positive target window PID"):
        build_capturer("real-window")
    with pytest.raises(ConfigError):
        build_capturer("real-window", target_pid=None)
    # Invalid PID values, including bool (an int subclass) and non-int values.
    for invalid in (0, -1, True, False, 4321.0, "4321"):
        with pytest.raises(ConfigError):
            build_capturer("real-window", target_pid=invalid)  # type: ignore[arg-type]
    # Unknown modes fail closed instead of silently returning a desktop capturer.
    with pytest.raises(ConfigError, match="unsupported capture mode"):
        build_capturer("bogus")


# ---------------------------------------------------------------------------
# Round 1 fixes: WinForms assembly load and robust failure diagnostics.
# ---------------------------------------------------------------------------


def test_capture_script_loads_winforms_assembly_before_use() -> None:
    lines = _POWERSHELL_CAPTURE_SCRIPT.splitlines()
    drawing = lines.index("Add-Type -AssemblyName System.Drawing")
    winforms = lines.index("Add-Type -AssemblyName System.Windows.Forms")
    usage = lines.index("$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen")
    assert winforms == drawing + 1
    assert winforms < usage


def test_decode_powershell_output_handles_utf8_gbk_and_latin1() -> None:
    assert _decode_powershell_output("中文错误".encode("utf-8")) == "中文错误"
    # GBK bytes are not valid UTF-8; the Chinese Windows OEM code page fallback
    # must decode them instead of raising UnicodeDecodeError.
    assert _decode_powershell_output(b"\xd6\xd0\xce\xc4") == "中文"
    assert _decode_powershell_output(b"\xff\xfe") == b"\xff\xfe".decode("latin-1")
    assert _decode_powershell_output(b"") == ""
    assert _decode_powershell_output(None) == ""


def _fake_completed(*, returncode: int, stderr: bytes = b"", stdout: bytes = b""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_desktop_capture_failure_reports_decoded_stderr_tail(monkeypatch) -> None:
    calls: list[dict] = []

    def fake_run(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return _fake_completed(returncode=1, stderr=GBK_STDERR)

    monkeypatch.setattr(screenshot_module.subprocess, "run", fake_run)
    result = DesktopCapturer().capture(scope="desktop")
    assert result.ok is False
    assert result.status is CaptureStatus.FAILED
    assert "capture failed (exit 1)" in result.error
    # Up to 12 stderr lines are retained; the oldest lines are dropped.
    assert "line-04" in result.error
    assert "line-03" not in result.error
    assert "line-14" in result.error
    assert "错误详情" in result.error
    kwargs = calls[0]
    assert kwargs["capture_output"] is True
    assert kwargs["shell"] is False
    assert "text" not in kwargs and "encoding" not in kwargs


def test_window_capture_failure_reports_decoded_stderr_tail(monkeypatch) -> None:
    calls: list[dict] = []

    def fake_run(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return _fake_completed(returncode=2, stderr=GBK_STDERR)

    monkeypatch.setattr(screenshot_module.subprocess, "run", fake_run)
    result = WindowCapturer(target_pid=4321).capture(scope="window")
    assert result.ok is False
    assert result.status is CaptureStatus.FAILED
    assert "window capture failed (exit 2)" in result.error
    assert "line-04" in result.error
    assert "line-03" not in result.error
    assert "错误详情" in result.error
    assert "4321" in calls[0]["command"]
    assert calls[0]["capture_output"] is True
    assert "text" not in calls[0] and "encoding" not in calls[0]


GBK_STDERR = (
    "\n".join([f"line-{index:02d}" for index in range(1, 15)])
    + "\n"
    + "错误详情：捕获失败"
).encode("gbk")
