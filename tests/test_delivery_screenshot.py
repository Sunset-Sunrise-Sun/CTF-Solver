"""Tests for explicit screenshot capture and blank-frame handling."""

from __future__ import annotations

import pytest

from ctf_solver.core.errors import CaptureError
from ctf_solver.core.types import CaptureStatus
from ctf_solver.delivery.screenshot import (
    DesktopCapturer,
    FakeScreenCapturer,
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
    with pytest.raises(ValueError):
        FakeScreenCapturer("bogus")
