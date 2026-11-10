"""Policy-side models and deterministic helpers for the execution Broker.

The Broker is the trusted policy enforcement point for typed ``ctf-exec``
requests (docs/INTERFACES.md section 5.2). This module holds the pure,
deterministic pieces so they can be unit-tested without a repository or a
clock:

- action / target digests used to bind approvals to a concrete action;
- host, path and protocol normalisation plus scope matching;
- private/loopback classification (no DNS is ever performed here; resolved
  addresses always arrive as injected synthetic data);
- :class:`GrantScope`, a policy-side view of an authorized network grant that
  can carry the optional ``allow_private`` flag.

Frozen-contract note
--------------------
``ctf_solver.core.types.GrantRecord`` intentionally has no free-form payload
dictionary, so the ``allow_private`` redirect/DNS scope flag cannot live on the
frozen record. :class:`GrantScope` carries it for callers that need the flag;
:func:`grant_allows_private` accepts a :class:`GrantRecord`, a
:class:`GrantScope`, a mapping, or any object exposing an ``allow_private`` or
``payload["allow_private"]`` attribute, so redirect/DNS validation works with
both shapes. This is reported to the Lead as an integration contract note.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass
from typing import Any, Mapping

from ..core.canonical import canonical_json, sha256_hex
from ..core.types import ExecRequest, GrantRecord, NetworkTarget

#: Network protocols the Round 1 policy model understands.
ALLOWED_NETWORK_PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp", "http", "https"})

#: Protocols that require a concrete request action/method.
METHOD_REQUIRED_PROTOCOLS: frozenset[str] = frozenset({"http", "https"})

#: Hostname suffixes that are never treated as public destinations.
_LOCAL_HOST_SUFFIXES: tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
    ".invalid",
    ".test",
)

_LOCAL_HOSTNAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


# ---------------------------------------------------------------------------
# Canonicalisation and digests
# ---------------------------------------------------------------------------


def _jsonable(value: Any) -> Any:
    """Convert arbitrary policy payloads into deterministic JSONable values."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return _jsonable(value.value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"bytes_sha256": sha256_hex(bytes(value))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(item) for item in value), key=canonical_json)
    return str(value)


def action_digest(action_kind: str, details: Mapping[str, Any] | Any) -> str:
    """Return the stable SHA-256 digest binding an approval to one action.

    ``details`` must be JSON-serialisable (or convertible by
    :func:`_jsonable`); the canonical JSON form makes the digest independent of
    dictionary insertion order so an independent verifier reproduces it.
    """

    payload = {"action_kind": str(action_kind), "details": _jsonable(details)}
    return sha256_hex(canonical_json(payload).encode("utf-8"))


def approval_details(request: ExecRequest) -> dict[str, Any]:
    """Canonical action description an approval must be bound to.

    Manager ``request_approval`` callers must use these details (or call
    :func:`approval_action_digest`) so that the Broker can recompute the same
    digest from the actual execution request. Every field is a property of the
    request itself, so an approval can never authorize a different argv, cwd,
    path set or network destination.
    """

    return {
        "action": "ctf-exec",
        "task_id": request.task_id,
        "tool_name": request.tool_name,
        "tool_version": request.tool_version,
        "argv": list(request.argv),
        "cwd": str(request.cwd),
        "input_files": [
            {
                "path": str(item.get("path", "")),
                "sha256": str(item.get("sha256", "")).lower(),
            }
            for item in request.input_files
        ],
        "output_paths": list(request.output_paths),
        "network_target": request.network_target.to_dict() if request.network_target else None,
        "timeout_s": float(request.timeout_s),
        "tier": int(request.tier),
        "max_output_bytes": request.max_output_bytes,
    }


def approval_action_digest(action_kind: str, request: ExecRequest) -> str:
    """Digest of :func:`approval_details` for one execution request."""

    return action_digest(action_kind, approval_details(request))


def target_digest(target: NetworkTarget) -> str:
    """Stable digest of a normalized network destination."""

    return sha256_hex(
        canonical_json(
            {
                "host": normalize_host(target.host),
                "port": int(target.port),
                "protocol": normalize_protocol(target.protocol),
                "method": normalize_method(target.method),
                "path": normalize_path(target.path),
            }
        ).encode("utf-8")
    )


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Lower-case a host, strip IPv6 brackets and normalise IP literals."""

    value = str(host).strip().lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    value = value.rstrip(".")
    parsed = parse_ip(value)
    if parsed is not None:
        return str(parsed)
    return value


def hosts_match(left: str, right: str) -> bool:
    """Case-insensitive host equality with IP-literal normalisation."""

    return normalize_host(left) == normalize_host(right)


def normalize_protocol(protocol: str) -> str:
    return str(protocol).strip().lower()


def normalize_method(method: str) -> str:
    return str(method).strip().upper()


def normalize_path(path: str) -> str:
    value = str(path).strip()
    if not value:
        return "/"
    return value if value.startswith("/") else "/" + value


def normalize_path_prefix(prefix: str) -> str:
    """Normalise a grant path prefix; "" and "/" both mean "all paths"."""

    value = normalize_path(prefix)
    if value == "/":
        return "/"
    return value.rstrip("/") or "/"


def path_prefix_matches(path: str, prefix: str) -> bool:
    """True when ``path`` is covered by a grant path prefix."""

    normalized_prefix = normalize_path_prefix(prefix)
    if normalized_prefix == "/":
        return normalize_path(path).startswith("/")
    normalized_path = normalize_path(path)
    if normalized_path == normalized_prefix:
        return True
    return normalized_path.startswith(normalized_prefix + "/")


# ---------------------------------------------------------------------------
# Address classification (synthetic data only; no DNS in policy code)
# ---------------------------------------------------------------------------


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal without ever resolving a hostname."""

    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def is_loopback_ip(value: str) -> bool:
    parsed = parse_ip(value)
    return bool(parsed is not None and parsed.is_loopback)


def is_private_ip(value: str) -> bool:
    """True for loopback/private/link-local/reserved/unspecified/multicast IPs."""

    parsed = parse_ip(value)
    if parsed is None:
        return False
    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_unspecified
        or parsed.is_multicast
    )


def is_loopback_host(host: str) -> bool:
    """True when the host is an IPv4/IPv6 loopback literal or a localhost name."""

    value = normalize_host(host)
    if not value:
        return False
    parsed = parse_ip(value)
    if parsed is not None:
        return bool(parsed.is_loopback)
    return value in _LOCAL_HOSTNAMES or value.endswith(".localhost")


def is_private_host(host: str) -> bool:
    """True when a host is a local/private destination or an empty host.

    Hostnames are classified conservatively from known-local names only; a
    hostname is *not* assumed public just because DNS was not consulted. DNS
    answers are validated separately by
    :meth:`ctf_solver.policy.broker.Broker.validate_resolved_address`.
    """

    value = normalize_host(host)
    if not value:
        return True
    parsed = parse_ip(value)
    if parsed is not None:
        return is_private_ip(value)
    if is_loopback_host(value):
        return True
    return any(value == suffix.lstrip(".") or value.endswith(suffix) for suffix in _LOCAL_HOST_SUFFIXES)


# ---------------------------------------------------------------------------
# Grant scope view
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GrantScope:
    """Policy-side view of a network grant, optionally allowing private scope.

    The field names mirror :class:`ctf_solver.core.types.GrantRecord` so both
    objects can be passed to the same scope-matching helpers.
    """

    grant_id: str
    task_id: str
    competition_profile: str
    host: str
    port: int
    protocol: str
    method: str
    path_prefix: str
    expires_at: int
    max_calls: int
    calls_used: int = 0
    approver: str = ""
    status: str = "active"
    allow_private: bool = False

    @classmethod
    def from_record(
        cls, grant: GrantRecord, *, allow_private: bool = False
    ) -> "GrantScope":
        return cls(
            grant_id=grant.grant_id,
            task_id=grant.task_id,
            competition_profile=grant.competition_profile,
            host=grant.host,
            port=int(grant.port),
            protocol=grant.protocol,
            method=grant.method,
            path_prefix=grant.path_prefix,
            expires_at=int(grant.expires_at),
            max_calls=int(grant.max_calls),
            calls_used=int(grant.calls_used),
            approver=grant.approver,
            status=grant.status.value if isinstance(grant.status, enum.Enum) else str(grant.status),
            allow_private=bool(allow_private),
        )


def grant_allows_private(grant: Any) -> bool:
    """Return the optional ``allow_private`` scope flag of a grant-like object.

    Accepts :class:`GrantScope`, :class:`GrantRecord`, a mapping, or any object
    exposing ``allow_private`` directly or inside a ``payload`` mapping. The
    default is ``False`` (fail closed).
    """

    flag = getattr(grant, "allow_private", None)
    if flag is not None:
        return bool(flag)
    if isinstance(grant, Mapping):
        return bool(grant.get("allow_private"))
    payload = getattr(grant, "payload", None)
    if isinstance(payload, Mapping):
        return bool(payload.get("allow_private"))
    return False


def grant_scope(grant: GrantRecord | GrantScope, *, allow_private: bool | None = None) -> GrantScope:
    """Return a :class:`GrantScope` view, preserving an explicit private flag."""

    if isinstance(grant, GrantScope):
        if allow_private is None:
            return grant
        return GrantScope(
            **{**grant.__dict__, "allow_private": bool(allow_private)}  # type: ignore[arg-type]
        )
    return GrantScope.from_record(
        grant, allow_private=grant_allows_private(grant) if allow_private is None else allow_private
    )


__all__ = [
    "ALLOWED_NETWORK_PROTOCOLS",
    "METHOD_REQUIRED_PROTOCOLS",
    "GrantScope",
    "action_digest",
    "approval_action_digest",
    "approval_details",
    "grant_allows_private",
    "grant_scope",
    "hosts_match",
    "is_loopback_host",
    "is_loopback_ip",
    "is_private_host",
    "is_private_ip",
    "normalize_host",
    "normalize_method",
    "normalize_path",
    "normalize_path_prefix",
    "normalize_protocol",
    "parse_ip",
    "path_prefix_matches",
    "target_digest",
]
