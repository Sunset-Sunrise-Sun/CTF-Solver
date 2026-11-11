"""Process-safe identifier generation and validation."""

from __future__ import annotations

import re
import secrets
import uuid

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
_STEP_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def new_id(prefix: str) -> str:
    """Create a random, prefixed identifier (UUID4 hex, 32 chars)."""

    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,15}", prefix):
        raise ValueError(f"invalid identifier prefix: {prefix!r}")
    return f"{prefix}-{uuid.uuid4().hex}"


def new_worker_token() -> str:
    """Create an unguessable per-Worker IPC bearer token."""

    return secrets.token_urlsafe(32)


def is_valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_PATTERN.fullmatch(value))


def is_valid_step_id(value: object) -> bool:
    return isinstance(value, str) and bool(_STEP_ID_PATTERN.fullmatch(value))


def validate_id(value: object, *, name: str = "id") -> str:
    if not is_valid_id(value):
        raise ValueError(f"invalid {name}: {value!r}")
    return str(value)


def validate_step_id(value: object) -> str:
    if not is_valid_step_id(value):
        raise ValueError(f"invalid step_id: {value!r}")
    return str(value)
