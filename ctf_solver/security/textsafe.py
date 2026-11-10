"""Terminal-safe normalization for untrusted approval content (Round 2 P0-2).

Human confirmation is a security boundary: the text shown to the human must be
exactly the canonical, digest-bound action content, never attacker-controlled
terminal output. This module provides two things:

* :func:`normalize_field` / :func:`require_displayable` rigorously reject
  control characters, ANSI/OSC escape sequences, CR/LF injection, Unicode
  bidi/format controls, over-long values and invalid patterns. Normalized
  values are the only values that enter an approval payload and therefore the
  action digest.
* :func:`terminal_safe` is a defence-in-depth escaper for the confirmation
  console output. It is applied to every line the channel writes, even though
  summaries are already constructed from normalized fields.

Nothing here silently "cleans then approves": a value either normalizes to the
exact text that will be hashed and displayed, or it is rejected.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from ..core.errors import ValidationError

#: Hard upper bound for the complete human-readable confirmation summary.
MAX_SUMMARY_CHARS = 1200

#: Unicode bidirectional / zero-width formatting controls that can visually
#: reorder or hide text in a terminal.
_BIDI_AND_FORMAT_RANGES: tuple[tuple[int, int], ...] = (
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x200B, 0x200F),  # ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),  # LRE .. RLO
    (0x2060, 0x2064),  # WORD JOINER .. INVISIBLE PLUS
    (0x2066, 0x2069),  # LRI .. PDI
    (0xFEFF, 0xFEFF),  # ZERO WIDTH NO-BREAK SPACE / BOM
)

_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


class UnsafeTextError(ValidationError):
    """Untrusted text cannot be safely displayed/approved; fail closed."""

    reason_code = "unsafe_text"


def _is_unsafe_char(char: str) -> bool:
    code = ord(char)
    if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
        return True
    for start, end in _BIDI_AND_FORMAT_RANGES:
        if start <= code <= end:
            return True
    return unicodedata.category(char) in _UNSAFE_CATEGORIES


def find_unsafe_char(text: str) -> tuple[int, str] | None:
    """Return ``(index, char)`` of the first unsafe character, if any."""

    for index, char in enumerate(text):
        if _is_unsafe_char(char):
            return index, char
    return None


def normalize_field(
    value: Any,
    *,
    field: str,
    max_length: int,
    allow_empty: bool = False,
    pattern: str | None = None,
    pattern_description: str | None = None,
) -> str:
    """Validate and normalize one single-line untrusted token.

    Rejects non-strings, embedded NUL/C0/C1 controls (including ESC), CR/LF,
    Unicode format/bidi controls, line/paragraph separators, over-long values
    and values that do not match ``pattern``. Surrounding ASCII spaces are
    stripped after the safety check (they cannot inject terminal control).
    """

    if not isinstance(value, str):
        raise UnsafeTextError(f"{field} must be a string")
    unsafe = find_unsafe_char(value)
    if unsafe is not None:
        index, char = unsafe
        raise UnsafeTextError(
            f"{field} contains a forbidden control/format character "
            f"(U+{ord(char):04X}) at index {index}; refusing to approve"
        )
    text = value.strip(" ")
    if not text and not allow_empty:
        raise UnsafeTextError(f"{field} must not be empty")
    if len(text) > int(max_length):
        raise UnsafeTextError(f"{field} exceeds {max_length} characters")
    if pattern is not None and not re.fullmatch(pattern, text):
        raise UnsafeTextError(
            f"{field} does not match the required format"
            + (f" ({pattern_description})" if pattern_description else "")
        )
    return text


def require_displayable(text: Any, *, field: str = "summary", max_length: int = MAX_SUMMARY_CHARS) -> str:
    """Validate a complete multi-field summary for human display.

    Unlike :func:`normalize_field` this preserves internal spaces (the summary
    joins fields), but still rejects every control/format character, CR/LF and
    over-long content. It never strips or rewrites characters: what is
    displayed must be exactly what the caller hashed.
    """

    if not isinstance(text, str):
        raise UnsafeTextError(f"{field} must be a string")
    if not text.strip():
        raise UnsafeTextError(f"{field} must not be empty")
    unsafe = find_unsafe_char(text)
    if unsafe is not None:
        index, char = unsafe
        raise UnsafeTextError(
            f"{field} contains a forbidden control/format character "
            f"(U+{ord(char):04X}) at index {index}; refusing to display it for approval"
        )
    if len(text) > int(max_length):
        raise UnsafeTextError(f"{field} exceeds {max_length} characters")
    return text


_ESCAPE_MAP = {
    "\x1b": "\\x1b",
    "\r": "\\r",
    "\n": "\\n",
    "\t": "\\t",
    "\x7f": "\\x7f",
}


def terminal_safe(text: Any, *, max_length: int = 4000) -> str:
    """Defence-in-depth terminal escaper for confirmation output.

    Normal approval summaries are already validated; this function guarantees
    that no C0/C1/ESC/bidi/format character can reach the terminal even if a
    future caller passes an unvalidated string. It escapes rather than deletes,
    so the output remains auditable.
    """

    raw = str(text)
    if len(raw) > int(max_length):
        raw = raw[: int(max_length)] + "...[truncated]"
    out: list[str] = []
    for char in raw:
        mapped = _ESCAPE_MAP.get(char)
        if mapped is None and _is_unsafe_char(char):
            mapped = f"\\u{ord(char):04x}"
        out.append(mapped if mapped is not None else char)
    return "".join(out)


__all__ = [
    "MAX_SUMMARY_CHARS",
    "UnsafeTextError",
    "find_unsafe_char",
    "normalize_field",
    "require_displayable",
    "terminal_safe",
]
