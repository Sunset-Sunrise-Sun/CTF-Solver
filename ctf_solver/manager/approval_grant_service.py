"""Approval / network-grant use cases bound to real human confirmation.

This module is the Round 2 P0 replacement for the Round 1 free-form approval
and grant control API. The model (through MCP) may only *request* an approval;
the only decision path is :meth:`ApprovalGrantService.confirm_approval`, which
requires a :class:`~ctf_solver.security.confirmation.ConsoleConfirmationChannel`
(local interactive TTY). A network grant can only be minted from an APPROVED,
unexpired, unconsumed ``remote_target`` approval whose recorded target digest
matches the requested target, and doing so consumes the approval exactly once.

Design rules (docs/ROUND_2_INTERFACES.md 2.2):

- no method accepts a raw ``approver`` string, and no method accepts
  ``approved``/``approver`` flags from a caller;
- the confirmation OS user is the recorded approver; the caller-supplied
  identity can never become the approver;
- replay, expiry, cross-Task use, target/profile mismatch, tampered payloads
  and double consumption all fail closed before any durable change;
- every request/decision/grant creation emits a frozen-payload evidence event.
"""

from __future__ import annotations

import uuid
from typing import Any, Mapping

from ..core.canonical import canonical_json, sha256_hex
from ..core.config import SolverConfig
from ..core.errors import NotFoundError, StateError, StorageError, ValidationError
from ..core.ids import new_id
from ..core.protocols import Clock, EvidenceSink, SystemClock
from ..core.types import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    GrantRecord,
    GrantStatus,
    NetworkTarget,
)
from ..policy.models import (
    ALLOWED_NETWORK_PROTOCOLS,
    METHOD_REQUIRED_PROTOCOLS,
    action_digest,
    normalize_host,
    normalize_method,
    normalize_path,
    normalize_path_prefix,
    normalize_protocol,
    target_digest,
)
from ..security.confirmation import (
    CHANNEL_LOCAL_CONSOLE,
    ConfirmationError,
    ConsoleConfirmationChannel,
    HumanConfirmation,
)
from ..security.textsafe import (
    UnsafeTextError,
    normalize_field,
    require_displayable,
)
from .store import ManagerStore

_REMOTE_TARGET = ApprovalAction.REMOTE_TARGET.value

#: Bounds for the human-approved network authorization scope.
MAX_GRANT_TTL_S = 7 * 24 * 3600
MAX_GRANT_CALLS = 10_000

_PROFILE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_TASK_ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_HOST_PATTERN = r"[A-Za-z0-9._:%-]{1,253}"
_PROTOCOL_PATTERN = r"[A-Za-z][A-Za-z0-9+.-]{0,15}"
_METHOD_PATTERN = r"[A-Za-z]{1,16}"
#: URL path-prefix grammar: absolute path, no query/fragment/whitespace.
_PATH_PREFIX_PATTERN = r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,511}"


def _require_positive_int(value: Any, field: str, *, maximum: int) -> int:
    """Strictly require a plain Python ``int`` in ``1..maximum``.

    ``bool`` is a subclass of ``int`` in Python but must never be accepted as a
    TTL/call count; floats, numeric strings and other coercible values are also
    rejected instead of being silently converted.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    number = int(value)
    if number <= 0:
        raise ValueError(f"{field} must be a positive integer")
    if number > int(maximum):
        raise ValueError(f"{field} must be <= {maximum}")
    return number


def _require_task_id(value: Any) -> str:
    return normalize_field(
        value,
        field="task_id",
        max_length=64,
        pattern=_TASK_ID_PATTERN,
        pattern_description="Task ID token",
    )


def _require_profile(value: Any) -> str:
    return normalize_field(
        value,
        field="competition_profile",
        max_length=64,
        pattern=_PROFILE_PATTERN,
        pattern_description="letters/digits/dot/dash/underscore",
    )

#: Maximum number of payload characters echoed in a human-readable summary.
_SUMMARY_DETAIL_CHARS = 400


# ---------------------------------------------------------------------------
# Canonical remote-target binding helpers (also reusable by the local CLI)
# ---------------------------------------------------------------------------


def canonical_remote_target_details(
    *,
    task_id: str,
    host: str,
    port: int,
    protocol: str = "tcp",
    method: str = "GET",
    path_prefix: str = "/",
    competition_profile: str,
    grant_ttl_s: int,
    max_calls: int,
) -> dict[str, Any]:
    """Return the canonical, digest-bound ``remote_target`` approval details.

    Round 2 P0-1/P0-2: the human-approved scope includes the owning Task, the
    competition profile, the exact destination, and the **network grant TTL and
    call budget**. Every field participates in :func:`action_digest`, so a grant
    cannot later widen its duration or call count.

    The mapping is::

        {"task_id", "profile",
         "target": {"host", "port", "protocol", "method", "path_prefix"},
         "grant_ttl_s", "max_calls"}

    All untrusted strings are normalized here (single-line, no C0/C1/ESC/ANSI/
    bidi controls, bounded length, restricted grammar); the normalized mapping
    is the only content that is hashed, displayed and stored. Raises
    ``ValueError`` for invalid input (callers convert it to ``ValidationError``).
    """

    try:
        normalized_task_id = _require_task_id(task_id)
        profile = _require_profile(competition_profile)
        host_text = normalize_field(
            host,
            field="network target host",
            max_length=253,
            pattern=_HOST_PATTERN,
            pattern_description="letters/digits/dot/dash/underscore/colon/percent",
        )
        protocol_text = normalize_field(
            protocol,
            field="network target protocol",
            max_length=16,
            pattern=_PROTOCOL_PATTERN,
            pattern_description="protocol token",
        )
        if method is None:
            method = ""
        method_text = normalize_field(
            method,
            field="network target method",
            max_length=16,
            allow_empty=True,
            pattern=_METHOD_PATTERN if str(method).strip() else None,
            pattern_description="letters only",
        )
        if not isinstance(path_prefix, str):
            raise ValueError("network target path_prefix must be a string")
        # Reject traversal segments before/after normalization.
        raw_path = path_prefix.strip(" ")
        if raw_path and not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        if any(segment == ".." for segment in raw_path.split("/")):
            raise ValueError("network target path_prefix must not contain '..' segments")
        path_text = normalize_field(
            raw_path,
            field="network target path_prefix",
            max_length=512,
            pattern=_PATH_PREFIX_PATTERN,
            pattern_description="absolute URL path without query/fragment/whitespace",
        )
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("network target port must be an integer")
        port_int = int(port)
        if not 1 <= port_int <= 65535:
            raise ValueError("network target port must be within 1..65535")
        ttl = _require_positive_int(grant_ttl_s, "grant_ttl_s", maximum=MAX_GRANT_TTL_S)
        calls = _require_positive_int(max_calls, "max_calls", maximum=MAX_GRANT_CALLS)
    except UnsafeTextError as exc:
        raise ValueError(exc.message) from exc

    try:
        target = NetworkTarget.from_mapping(
            {
                "host": host_text,
                "port": port_int,
                "protocol": protocol_text,
                "method": method_text,
                "path": normalize_path(path_text),
            }
        )
    except ValueError as exc:  # pragma: no cover - message varies by Python version
        raise ValueError(f"invalid network target: {exc}") from exc
    normalized_protocol = normalize_protocol(target.protocol)
    if normalized_protocol not in ALLOWED_NETWORK_PROTOCOLS:
        raise ValueError(f"unsupported network protocol: {target.protocol!r}")
    normalized_method = normalize_method(target.method)
    if len(normalized_method) > 16:
        raise ValueError("network target method is too long")
    if normalized_protocol in METHOD_REQUIRED_PROTOCOLS and not normalized_method:
        raise ValueError(f"protocol {normalized_protocol!r} requires an action/method")
    normalized_host = normalize_host(target.host)
    if not normalized_host:
        raise ValueError("network target host must not be empty after normalization")
    normalized_path = normalize_path_prefix(target.path)
    return {
        "task_id": normalized_task_id,
        "profile": profile,
        "target": {
            "host": normalized_host,
            "port": int(target.port),
            "protocol": normalized_protocol,
            "method": normalized_method,
            "path_prefix": normalized_path,
        },
        "grant_ttl_s": ttl,
        "max_calls": calls,
    }


def remote_target_action_digest(
    *,
    task_id: str,
    host: str,
    port: int,
    protocol: str = "tcp",
    method: str = "GET",
    path_prefix: str = "/",
    competition_profile: str,
    grant_ttl_s: int,
    max_calls: int,
) -> str:
    """Digest binding one full network authorization scope to an approval Task."""

    return action_digest(
        _REMOTE_TARGET,
        canonical_remote_target_details(
            task_id=task_id,
            host=host,
            port=port,
            protocol=protocol,
            method=method,
            path_prefix=path_prefix,
            competition_profile=competition_profile,
            grant_ttl_s=grant_ttl_s,
            max_calls=max_calls,
        ),
    )


def canonical_approval_details(
    action_kind: str,
    details: Mapping[str, Any],
    *,
    task_id: str | None = None,
) -> dict[str, Any]:
    """Canonicalize caller-supplied approval details for the given action kind.

    ``remote_target`` has a frozen machine-checkable shape and always includes
    the owning Task and the network grant TTL/call budget. Other action kinds
    keep the caller's mapping verbatim (the Broker recomputes its own digest
    from the typed execution request).
    """

    if not isinstance(details, Mapping):
        raise ValidationError("approval details must be a JSON object")
    if action_kind != _REMOTE_TARGET:
        return {str(key): value for key, value in details.items()}

    target = details.get("target")
    profile = details.get("profile")
    if not isinstance(target, Mapping):
        raise ValidationError(
            "a remote_target approval requires details={'target': {...}, 'profile': ..., "
            "'grant_ttl_s': int, 'max_calls': int}"
        )
    if profile is None or not str(profile).strip():
        raise ValidationError(
            "a remote_target approval requires a non-empty competition profile"
        )
    payload_task_id = details.get("task_id")
    if payload_task_id is not None and task_id is not None:
        if str(payload_task_id) != str(task_id):
            raise ValidationError(
                "remote_target approval details task_id does not match the owning Task"
            )
    effective_task_id = task_id if task_id is not None else payload_task_id
    if effective_task_id is None:
        raise ValidationError("a remote_target approval requires the owning Task ID")
    try:
        return canonical_remote_target_details(
            task_id=str(effective_task_id),
            host=target.get("host"),  # type: ignore[arg-type]
            port=target.get("port"),  # type: ignore[arg-type]
            protocol=target.get("protocol", "tcp"),
            method=target.get("method", "GET"),
            path_prefix=target.get("path_prefix", target.get("path", "/")),  # type: ignore[arg-type]
            competition_profile=str(profile),
            grant_ttl_s=details.get("grant_ttl_s"),  # type: ignore[arg-type]
            max_calls=details.get("max_calls"),  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid remote_target approval details: {exc}") from exc


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ApprovalGrantService:
    """Human-confirmed approval decisions and approval-bound network grants."""

    def __init__(
        self,
        store: ManagerStore,
        evidence: EvidenceSink,
        clock: Clock | None,
        config: SolverConfig,
    ) -> None:
        self.store = store
        self.evidence = evidence
        self.clock: Clock = clock or SystemClock()
        self.config = config
        self._event_errors: list[str] = []

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    @property
    def event_errors(self) -> list[str]:
        return list(self._event_errors)

    def _emit(self, task_id: str, event_type: str, payload: dict[str, Any]) -> None:
        try:
            self.evidence.append_event(
                task_id=task_id,
                source="manager",
                source_id=f"manager:{event_type}:{uuid.uuid4().hex}",
                event_type=event_type,
                payload=payload,
                timestamp=self.clock.now_ms(),
            )
        except Exception as exc:  # noqa: BLE001 - durable store remains authoritative
            self._event_errors.append(f"{event_type}: {type(exc).__name__}: {exc}")

    def _append_event_required(
        self, task_id: str, event_type: str, payload: dict[str, Any]
    ) -> str:
        """Append a decision evidence event and propagate any write failure.

        A human confirmation is only usable if its independent evidence record is
        durably stored; callers must fail closed when this raises.
        """

        try:
            return self.evidence.append_event(
                task_id=task_id,
                source="manager",
                source_id=f"manager:{event_type}:{uuid.uuid4().hex}",
                event_type=event_type,
                payload=payload,
                timestamp=self.clock.now_ms(),
            )
        except Exception as exc:  # noqa: BLE001 - evidence failure is fatal here
            raise StorageError(
                f"could not persist {event_type} evidence: {type(exc).__name__}: {exc}",
                details={"event_type": event_type, "task_id": task_id},
            ) from exc

    @staticmethod
    def _event_payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = event.get("payload")
        return payload if isinstance(payload, Mapping) else {}

    def _decision_events(self, approval_id: str, task_id: str) -> list[Mapping[str, Any]]:
        lister = getattr(self.evidence, "list_events", None)
        if not callable(lister):
            raise StateError(
                "the evidence store cannot list decision events; refusing to trust an "
                "unverifiable approval confirmation"
            )
        try:
            events = lister(task_id=task_id, event_type="approval_decided")
        except Exception as exc:  # noqa: BLE001 - evidence read failure fails closed
            raise StateError(
                f"could not read approval decision evidence: {type(exc).__name__}: {exc}"
            ) from exc
        matches: list[Mapping[str, Any]] = []
        for event in events or []:
            if not isinstance(event, Mapping):
                raise StateError("approval decision evidence contains a malformed event")
            payload = self._event_payload(event)
            if str(payload.get("approval_id") or "") == str(approval_id):
                matches.append(event)
        return matches

    def _verify_decision_evidence(
        self, record: ApprovalRecord, *, require_approved: bool
    ) -> Mapping[str, Any]:
        """Cross-check an approval row against its independent hash-chain event.

        The Manager stores the human decision twice: in the approvals table and
        as an ``approval_decided`` event inside the append-only evidence hash
        chain. This method requires the chain to be intact and the event to be
        unique and field-for-field consistent with the row. It defends against a
        tampered approvals row (including payload+digest rewrites) and isolated
        event edits/deletions.

        Threat-model limit (not overstated): an attacker able to atomically
        rewrite the entire SQLite database, the whole event chain and all
        associated metadata consistently is not defeated by this check; there is
        no external anchor/signature in this development cycle.
        """

        chain_status = getattr(self.evidence, "chain_status", None)
        if not callable(chain_status):
            raise StateError(
                "the evidence store cannot verify the hash chain; refusing to trust "
                "an unverifiable approval confirmation"
            )
        try:
            status = chain_status()
        except Exception as exc:  # noqa: BLE001
            raise StateError(
                f"evidence hash-chain verification failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not bool(getattr(status, "ok", False)):
            raise StateError(
                "evidence hash chain is not intact; refusing to trust an approval confirmation"
            )

        events = self._decision_events(record.approval_id, record.task_id)
        if len(events) != 1:
            raise StateError(
                f"approval {record.approval_id} has {len(events)} approval_decided "
                "evidence event(s); exactly one consistent human confirmation is required"
            )
        event = events[0]
        if str(event.get("task_id") or "") != str(record.task_id):
            raise StateError("approval decision evidence belongs to a different Task")
        payload = self._event_payload(event)
        expected_approved = record.status is ApprovalStatus.APPROVED
        if require_approved and not expected_approved:
            raise StateError(
                f"approval {record.approval_id} is {record.status.value}; a network "
                "grant requires an APPROVED human-confirmed approval"
            )
        checks: list[tuple[str, Any, Any]] = [
            ("task_id", payload.get("task_id"), record.task_id),
            ("action_kind", payload.get("action_kind"), record.action_kind),
            (
                "action_digest",
                str(payload.get("action_digest") or "").strip().lower(),
                str(record.action_digest or "").strip().lower(),
            ),
            ("approved", payload.get("approved"), expected_approved),
            ("confirmation_channel", payload.get("confirmation_channel"), CHANNEL_LOCAL_CONSOLE),
            ("confirmation_id", payload.get("confirmation_id"), record.confirmation_id),
            (
                "confirmation_os_user",
                payload.get("confirmation_os_user"),
                record.confirmation_os_user,
            ),
        ]
        for field, observed, expected in checks:
            if observed != expected:
                raise StateError(
                    f"approval decision evidence field {field!r} is inconsistent with "
                    f"approval {record.approval_id}; refusing to use it"
                )
        if not record.confirmation_id or not record.confirmation_os_user:
            raise StateError(
                "approval confirmation is missing its local-console identity fields"
            )
        return payload

    # ------------------------------------------------------------------
    # Approval request
    # ------------------------------------------------------------------

    def request_approval(
        self,
        task_id: str,
        *,
        action_kind: str,
        details: dict[str, Any],
        ttl_s: int | None = None,
    ) -> ApprovalRecord:
        """Create a PENDING approval request; never decides it."""

        task = self.store.require_task(task_id)
        try:
            kind = ApprovalAction(str(action_kind))
        except ValueError as exc:
            raise ValidationError(f"unknown approval action_kind: {action_kind!r}") from exc
        if not isinstance(details, Mapping):
            raise ValidationError("approval details must be a JSON object")
        canonical = canonical_approval_details(kind.value, details, task_id=task.task_id)

        expires_at: int | None = None
        if ttl_s is not None:
            try:
                ttl = _require_positive_int(ttl_s, "approval ttl_s", maximum=MAX_GRANT_TTL_S)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            expires_at = self.clock.now_ms() + ttl * 1000

        now = int(self.clock.now_ms())
        record = ApprovalRecord(
            approval_id=new_id("apr"),
            task_id=task.task_id,
            action_kind=kind.value,
            action_digest=action_digest(kind.value, canonical),
            status=ApprovalStatus.PENDING,
            requested_at=now,
            payload=canonical,
            expires_at=expires_at,
        )
        self.store.create_approval(record)
        self._emit(
            task.task_id,
            "approval_requested",
            {
                "approval_id": record.approval_id,
                "task_id": task.task_id,
                "action_kind": record.action_kind,
                "action_digest": record.action_digest,
                "approved": False,
                "approver": None,
                "requested_at": record.requested_at,
                "expires_at": record.expires_at,
            },
        )
        return self.store.get_approval(record.approval_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Human decision (the only decision path)
    # ------------------------------------------------------------------

    def confirm_approval(
        self,
        approval_id: str,
        *,
        channel: ConsoleConfirmationChannel,
        reject: bool = False,
        note: str = "",
    ) -> ApprovalRecord:
        """Ask the local human to approve/reject one PENDING approval.

        Any caller-supplied decision flag or approver identity is impossible by
        construction: this method's only decision input is the human
        confirmation returned by the local console channel.
        """

        if not isinstance(reject, bool):
            raise ValidationError("reject must be a boolean")
        # A local-console channel implementation is required. Structural
        # (duck-typed) test/host implementations are accepted, but the returned
        # HumanConfirmation is always validated below; there is no caller
        # identity or decision flag that can substitute for it.
        decision_method = getattr(channel, "reject" if reject else "confirm", None)
        if not callable(decision_method):
            raise ConfirmationError(
                "approvals can only be decided through a local interactive console "
                "confirmation channel; no caller identity or flag can decide an approval"
            )
        record = self.store.get_approval(approval_id)
        if record is None:
            raise NotFoundError(f"unknown approval: {approval_id}")
        if record.status is not ApprovalStatus.PENDING:
            raise StateError(f"approval {approval_id} is already {record.status.value}")
        now = int(self.clock.now_ms())
        if record.expires_at is not None and int(record.expires_at) <= now:
            self.store.mark_approval_expired(approval_id)
            raise StateError(f"approval {approval_id} has expired")

        summary = self.summarize(record)
        # The summary is built from the canonical stored payload; make sure a
        # tampered payload (SQLite manipulation) can never reach the human or be
        # confirmed: re-derive the digest before asking for a decision.
        self._verified_payload(record, require_approved=False)
        confirmation = decision_method(
            approval_digest=record.action_digest, summary=summary
        )
        if not isinstance(confirmation, HumanConfirmation):
            raise ConfirmationError(
                "the confirmation channel returned an invalid human confirmation record"
            )
        if (
            confirmation.approval_digest.strip().lower()
            != str(record.action_digest or "").strip().lower()
        ):
            raise ConfirmationError(
                "the human confirmation digest does not match the approval action; "
                "refusing to record a decision"
            )

        decided = self.store.record_approval_confirmation(
            approval_id,
            approved=not reject,
            confirmation=confirmation,
            note=str(note or ""),
        )
        try:
            self._append_event_required(
                decided.task_id,
                "approval_decided",
                {
                    "approval_id": decided.approval_id,
                    "task_id": decided.task_id,
                    "action_kind": decided.action_kind,
                    "action_digest": decided.action_digest,
                    "approved": decided.status is ApprovalStatus.APPROVED,
                    "approver": decided.approver,
                    "confirmation_channel": decided.confirmation_channel,
                    "confirmation_id": decided.confirmation_id,
                    "confirmation_os_user": decided.confirmation_os_user,
                    "decided_at": decided.decided_at,
                    "note": decided.confirmation_note or "",
                },
            )
            # The decision is only usable if the independent event is present in
            # an intact chain and matches the row exactly.
            self._verify_decision_evidence(decided, require_approved=False)
        except Exception as exc:  # noqa: BLE001 - invalidate then fail closed
            try:
                self.store.invalidate_approval(
                    approval_id,
                    reason=f"decision evidence not durable: {type(exc).__name__}",
                )
            except Exception:  # noqa: BLE001
                pass
            raise StateError(
                "the human decision could not be durably evidenced; the approval was "
                "invalidated and cannot be used to create a grant",
                details={"approval_id": approval_id},
            ) from exc
        return decided

    # ------------------------------------------------------------------
    # Grant creation (only from a confirmed approval)
    # ------------------------------------------------------------------

    def _verified_payload(
        self, record: ApprovalRecord, *, require_approved: bool
    ) -> dict[str, Any]:
        """Re-derive the canonical payload/digest and fail closed on tampering.

        Round 2 P0-1: the stored approval row is not trusted. The payload is
        canonicalized again (including Task, target, TTL and call budget) and
        must reproduce the recorded digest. A tampered SQLite row therefore can
        neither be displayed to a human nor mint a grant.
        """

        if record.action_kind != _REMOTE_TARGET:
            raise StateError(
                f"approval {record.approval_id} is {record.action_kind!r}; only a "
                "remote_target approval can authorize a network grant"
            )
        try:
            payload = canonical_approval_details(
                _REMOTE_TARGET, record.payload or {}, task_id=record.task_id
            )
        except ValidationError as exc:
            raise StateError(
                "the stored approval payload is not a valid remote_target action; "
                f"refusing to use a tampered approval ({exc.message})"
            ) from exc
        recomputed = action_digest(_REMOTE_TARGET, payload)
        stored_digest = str(record.action_digest or "").strip().lower()
        if not stored_digest or recomputed != stored_digest:
            raise StateError(
                "approval payload does not match its recorded digest; refusing to "
                "use a tampered approval"
            )
        if str(payload.get("task_id")) != str(record.task_id):
            raise StateError(
                "approval payload Task does not match the approval Task; refusing to "
                "use a cross-Task approval"
            )
        if require_approved and record.status is not ApprovalStatus.APPROVED:
            raise StateError(
                f"approval {record.approval_id} is {record.status.value}; a network "
                "grant requires an APPROVED human-confirmed approval"
            )
        return payload

    def create_grant_from_approval(
        self,
        approval_id: str,
        *,
        competition_profile: str,
        host: str,
        port: int,
        protocol: str = "tcp",
        method: str = "GET",
        path_prefix: str = "/",
        ttl_s: int | None = None,
        max_calls: int | None = None,
    ) -> GrantRecord:
        """Mint one Task-scoped network grant from a human-confirmed approval.

        Round 2 P0-1: the grant TTL and call budget are read from the immutable
        human-approved payload. Optional ``ttl_s``/``max_calls`` parameters are
        accepted only for explicit compatibility checking: if supplied they must
        be strict positive integers **equal** to the approved values, otherwise
        the request is rejected before consumption.
        """

        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise NotFoundError(f"unknown approval: {approval_id}")
        if approval.consumed_at is not None:
            raise StateError(
                f"approval {approval_id} has already been consumed; it cannot mint "
                "another grant"
            )
        now = int(self.clock.now_ms())
        if approval.expires_at is not None and int(approval.expires_at) <= now:
            self.store.mark_approval_expired(approval_id)
            raise StateError(f"approval {approval_id} has expired")
        if not (
            approval.confirmation_channel == CHANNEL_LOCAL_CONSOLE
            and approval.confirmation_id
            and approval.confirmation_os_user
        ):
            raise StateError(
                f"approval {approval_id} has no recorded local-console human "
                "confirmation; refusing to create a network grant from it"
            )
        self.store.require_task(approval.task_id)

        # 1. Re-derive the approved, immutable payload and verify its digest.
        payload = self._verified_payload(approval, require_approved=True)
        # 1b. Cross-check the row against the independent human-decision event in
        #     the intact evidence hash chain (dual-record tamper detection).
        self._verify_decision_evidence(approval, require_approved=True)
        approved_ttl = payload["grant_ttl_s"]
        approved_calls = payload["max_calls"]

        # 2. Compatible callers may repeat the approved values, never widen them.
        if ttl_s is not None:
            try:
                supplied_ttl = _require_positive_int(
                    ttl_s, "grant ttl_s", maximum=MAX_GRANT_TTL_S
                )
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            if supplied_ttl != approved_ttl:
                raise StateError(
                    "the requested grant TTL differs from the human-approved TTL; "
                    "the approval scope cannot be widened after approval"
                )
        if max_calls is not None:
            try:
                supplied_calls = _require_positive_int(
                    max_calls, "max_calls", maximum=MAX_GRANT_CALLS
                )
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            if supplied_calls != approved_calls:
                raise StateError(
                    "the requested max_calls differs from the human-approved call "
                    "budget; the approval scope cannot be widened after approval"
                )

        # 3. Re-validate the caller's requested destination/profile against the
        #    approved scope (including TTL/call budget).
        try:
            requested = canonical_remote_target_details(
                task_id=approval.task_id,
                host=host,
                port=port,
                protocol=protocol,
                method=method,
                path_prefix=path_prefix,
                competition_profile=competition_profile,
                grant_ttl_s=approved_ttl,
                max_calls=approved_calls,
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"invalid network grant target/profile: {exc}") from exc
        if requested != payload:
            raise StateError(
                "the requested network target/profile does not match the human-approved "
                "scope; the grant was NOT created"
            )
        approved_target = NetworkTarget.from_mapping(
            {
                "host": payload["target"]["host"],
                "port": payload["target"]["port"],
                "protocol": payload["target"]["protocol"],
                "method": payload["target"]["method"],
                "path": payload["target"]["path_prefix"],
            }
        )

        grant = GrantRecord(
            grant_id=new_id("grant"),
            task_id=approval.task_id,
            competition_profile=payload["profile"],
            host=approved_target.host,
            port=int(approved_target.port),
            protocol=approved_target.protocol,
            method=approved_target.method,
            path_prefix=normalize_path(approved_target.path),
            expires_at=now + int(approved_ttl) * 1000,
            max_calls=int(approved_calls),
            approver=approval.confirmation_os_user,
            created_at=now,
            status=GrantStatus.ACTIVE,
            approval_id=approval.approval_id,
            confirmation_id=approval.confirmation_id,
            confirmation_os_user=approval.confirmation_os_user,
        )
        grant.grant_digest = _grant_digest(grant, approval)

        created = self.store.create_grant_from_approval(
            approval.approval_id, grant, now
        )
        if not created:
            raise StateError(
                "the approval could not be consumed atomically (expired, replayed or "
                "already used); the network grant was NOT created"
            )
        record = self.store.get_grant(grant.grant_id)
        if record is None:  # pragma: no cover - storage contract violation
            raise StateError("the network grant was not persisted")
        self._emit(
            record.task_id,
            "grant_created",
            {
                "grant_id": record.grant_id,
                "task_id": record.task_id,
                "host": record.host,
                "port": record.port,
                "protocol": record.protocol,
                "method": record.method,
                "path_prefix": record.path_prefix,
                "profile": record.competition_profile,
                "expires_at": record.expires_at,
                "max_calls": record.max_calls,
                "approval_id": record.approval_id,
                "confirmation_id": record.confirmation_id,
                "confirmation_os_user": record.confirmation_os_user,
                "approver": record.approver,
            },
        )
        return record

    # ------------------------------------------------------------------
    # Grant lifecycle / queries
    # ------------------------------------------------------------------

    def revoke_grant(self, grant_id: str) -> GrantRecord:
        grant = self.store.get_grant(grant_id)
        if grant is None:
            raise NotFoundError(f"unknown grant: {grant_id}")
        if grant.status is GrantStatus.REVOKED:
            return grant
        updated = self.store.set_grant_status(grant_id, GrantStatus.REVOKED)
        self._emit(
            updated.task_id,
            "grant_revoked",
            {
                "grant_id": updated.grant_id,
                "task_id": updated.task_id,
                "host": updated.host,
                "port": updated.port,
                "protocol": updated.protocol,
                "method": updated.method,
                "expires_at": updated.expires_at,
                "max_calls": updated.max_calls,
                "approval_id": updated.approval_id,
                "confirmation_id": updated.confirmation_id,
                "confirmation_os_user": updated.confirmation_os_user,
                "reason": "revoked_by_user",
            },
        )
        return updated

    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]:
        return self.store.list_approvals(task_id=task_id)

    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]:
        return self.store.list_grants(task_id=task_id)

    # ------------------------------------------------------------------
    # Human-readable summary shown on the console
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(record: ApprovalRecord) -> str:
        """Deterministic description of exactly what the human is approving.

        Round 2 P0-1: for a network authorization the human must see the full
        scope (destination, port, protocol, action, path prefix, competition
        profile, grant duration and maximum calls), not just a hostname. Every
        field comes from the same normalized payload that participates in the
        action digest; unsafe/raw caller text cannot reach this summary.
        """

        parts = [
            f"approval={record.approval_id}",
            f"task={record.task_id}",
            f"kind={record.action_kind}",
        ]
        payload = record.payload or {}
        if record.action_kind == _REMOTE_TARGET and isinstance(payload, Mapping):
            target = payload.get("target")
            if isinstance(target, Mapping):
                parts.append(
                    "target="
                    f"{target.get('host')}:{target.get('port')} "
                    f"{str(target.get('protocol', '')).lower()} "
                    f"{str(target.get('method', '')).upper()} "
                    f"{target.get('path_prefix', '/')}"
                )
            profile = payload.get("profile")
            if profile is not None:
                parts.append(f"profile={profile}")
            parts.append(f"grant_ttl_s={payload.get('grant_ttl_s')}")
            parts.append(f"max_calls={payload.get('max_calls')}")
        else:
            from ..security.textsafe import terminal_safe

            details = terminal_safe(canonical_json(payload), max_length=_SUMMARY_DETAIL_CHARS)
            if len(details) > _SUMMARY_DETAIL_CHARS:
                details = details[:_SUMMARY_DETAIL_CHARS] + "..."
            parts.append(f"details={details}")
        if record.expires_at is not None:
            parts.append(f"approval_expires_at={record.expires_at}")
        return "  ".join(parts)

def _grant_digest(grant: GrantRecord, approval: ApprovalRecord) -> str:
    """Integrity digest binding a grant to its Task, scope and human approval."""

    return sha256_hex(
        canonical_json(
            {
                "grant_id": grant.grant_id,
                "task_id": grant.task_id,
                "profile": grant.competition_profile,
                "host": grant.host,
                "port": grant.port,
                "protocol": grant.protocol,
                "method": grant.method,
                "path_prefix": grant.path_prefix,
                "expires_at": grant.expires_at,
                "max_calls": grant.max_calls,
                "approver": grant.approver,
                "approval_id": approval.approval_id,
                "approval_digest": approval.action_digest,
                "confirmation_id": approval.confirmation_id,
                "confirmation_os_user": approval.confirmation_os_user,
                # Target digest in policy canonicalization form (defence in depth).
                "target_digest": target_digest(
                    NetworkTarget.from_mapping(
                        {
                            "host": grant.host,
                            "port": grant.port,
                            "protocol": grant.protocol,
                            "method": grant.method,
                            "path": grant.path_prefix,
                        }
                    )
                ),
            }
        ).encode("utf-8")
    )


__all__ = [
    "ApprovalGrantService",
    "canonical_approval_details",
    "canonical_remote_target_details",
    "remote_target_action_digest",
]
