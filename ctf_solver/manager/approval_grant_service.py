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
from ..core.errors import NotFoundError, StateError, ValidationError
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
    normalize_protocol,
    target_digest,
)
from ..security.confirmation import (
    CHANNEL_LOCAL_CONSOLE,
    ConfirmationError,
    ConsoleConfirmationChannel,
    HumanConfirmation,
)
from .store import ManagerStore

_REMOTE_TARGET = ApprovalAction.REMOTE_TARGET.value

#: Maximum number of payload characters echoed in a human-readable summary.
_SUMMARY_DETAIL_CHARS = 400


# ---------------------------------------------------------------------------
# Canonical remote-target binding helpers (also reusable by the local CLI)
# ---------------------------------------------------------------------------


def canonical_remote_target_details(
    *,
    host: str,
    port: int,
    protocol: str = "tcp",
    method: str = "GET",
    path: str = "/",
    competition_profile: str,
) -> dict[str, Any]:
    """Return the canonical ``remote_target`` approval details mapping.

    The mapping is::

        {"target": {"host", "port", "protocol", "method", "path"}, "profile": str}

    This is the exact shape requested through :meth:`request_approval` and the
    exact shape re-derived from grant arguments when a grant is created, so an
    independent verifier reproduces the same digest. Raises ``ValueError`` for
    an invalid destination/profile (callers convert it to ``ValidationError``).
    """

    profile = str(competition_profile or "").strip()
    if not profile:
        raise ValueError("a remote_target approval requires a competition profile")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("network target host must be a non-empty string")
    if not isinstance(protocol, str) or not protocol.strip():
        raise ValueError("network target protocol must be a non-empty string")
    if method is None:
        method = ""
    if not isinstance(method, str):
        raise ValueError("network target method must be a string")
    if not isinstance(path, str):
        raise ValueError("network target path must be a string")
    if isinstance(port, bool):
        raise ValueError("network target port must be an integer")
    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("network target port must be an integer") from exc
    try:
        target = NetworkTarget.from_mapping(
            {
                "host": host,
                "port": port_int,
                "protocol": protocol,
                "method": method,
                "path": normalize_path(path),
            }
        )
    except ValueError as exc:  # pragma: no cover - message varies by Python version
        raise ValueError(f"invalid network target: {exc}") from exc
    if not 1 <= int(target.port) <= 65535:
        raise ValueError("network target port must be within 1..65535")
    normalized_protocol = normalize_protocol(target.protocol)
    if normalized_protocol not in ALLOWED_NETWORK_PROTOCOLS:
        raise ValueError(f"unsupported network protocol: {target.protocol!r}")
    normalized_method = normalize_method(target.method)
    if len(normalized_method) > 64:
        raise ValueError("network target method is too long")
    if normalized_protocol in METHOD_REQUIRED_PROTOCOLS and not normalized_method:
        raise ValueError(f"protocol {normalized_protocol!r} requires an action/method")
    return {
        "target": {
            "host": normalize_host(target.host),
            "port": int(target.port),
            "protocol": normalized_protocol,
            "method": normalized_method,
            "path": normalize_path(target.path),
        },
        "profile": profile,
    }


def remote_target_action_digest(
    *,
    host: str,
    port: int,
    protocol: str = "tcp",
    method: str = "GET",
    path: str = "/",
    competition_profile: str,
) -> str:
    """Digest binding one concrete network destination/profile to an approval."""

    return action_digest(
        _REMOTE_TARGET,
        canonical_remote_target_details(
            host=host,
            port=port,
            protocol=protocol,
            method=method,
            path=path,
            competition_profile=competition_profile,
        ),
    )


def canonical_approval_details(
    action_kind: str, details: Mapping[str, Any]
) -> dict[str, Any]:
    """Canonicalize caller-supplied approval details for the given action kind.

    Only ``remote_target`` has a frozen machine-checkable shape today; every
    other action kind keeps the caller's mapping verbatim (the Broker recomputes
    its own digest from the typed execution request).
    """

    if not isinstance(details, Mapping):
        raise ValidationError("approval details must be a JSON object")
    if action_kind != _REMOTE_TARGET:
        return {str(key): value for key, value in details.items()}

    target = details.get("target")
    profile = details.get("profile")
    if not isinstance(target, Mapping):
        raise ValidationError(
            "a remote_target approval requires details={'target': {...}, 'profile': ...}"
        )
    if profile is None or not str(profile).strip():
        raise ValidationError(
            "a remote_target approval requires a non-empty competition profile"
        )
    try:
        return canonical_remote_target_details(
            host=target.get("host"),  # type: ignore[arg-type]
            port=target.get("port"),  # type: ignore[arg-type]
            protocol=target.get("protocol", "tcp"),
            method=target.get("method", "GET"),
            path=target.get("path", "/"),
            competition_profile=str(profile),
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
        canonical = canonical_approval_details(kind.value, details)

        expires_at: int | None = None
        if ttl_s is not None:
            try:
                ttl = int(ttl_s)
            except (TypeError, ValueError) as exc:
                raise ValidationError("approval ttl_s must be a positive integer") from exc
            if ttl <= 0:
                raise ValidationError("approval ttl_s must be a positive integer")
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
        self._emit(
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
        return decided

    # ------------------------------------------------------------------
    # Grant creation (only from a confirmed approval)
    # ------------------------------------------------------------------

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
        ttl_s: int = 3600,
        max_calls: int = 10,
    ) -> GrantRecord:
        """Mint one Task-scoped network grant from a human-confirmed approval.

        The requested destination/profile must reproduce exactly the target the
        human approved; any mismatch, expiry, prior consumption, missing
        confirmation or tampered payload fails closed *before* consumption.
        """

        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise NotFoundError(f"unknown approval: {approval_id}")
        if approval.action_kind != _REMOTE_TARGET:
            raise StateError(
                f"approval {approval_id} is {approval.action_kind!r}, not a "
                "'remote_target' approval; it cannot authorize a network grant"
            )
        if approval.status is not ApprovalStatus.APPROVED:
            raise StateError(
                f"approval {approval_id} is {approval.status.value}; a network grant "
                "requires an APPROVED human-confirmed approval"
            )
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

        # 1. Validate the requested grant target and profile.
        try:
            requested = canonical_remote_target_details(
                host=host,
                port=port,
                protocol=protocol,
                method=method,
                path=path_prefix,
                competition_profile=competition_profile,
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"invalid network grant target/profile: {exc}") from exc
        try:
            ttl = int(ttl_s)
            calls = int(max_calls)
        except (TypeError, ValueError) as exc:
            raise ValidationError("grant ttl_s and max_calls must be positive integers") from exc
        if ttl <= 0 or calls <= 0:
            raise ValidationError("grant ttl_s and max_calls must be positive integers")

        # 2. Re-derive the approved target from the stored payload and require it
        #    to reproduce the recorded approval digest (tamper detection).
        try:
            payload_details = canonical_approval_details(
                _REMOTE_TARGET, approval.payload or {}
            )
        except ValidationError as exc:
            raise StateError(
                "the stored approval payload is not a valid remote_target action; "
                "refusing to create a grant from a tampered approval"
            ) from exc
        recomputed = action_digest(_REMOTE_TARGET, payload_details)
        stored_digest = str(approval.action_digest or "").strip().lower()
        if not stored_digest or recomputed != stored_digest:
            raise StateError(
                "approval payload does not match its recorded digest; refusing to "
                "create a grant from a tampered approval"
            )

        # 3. Require the requested destination/profile to equal the approved one.
        if requested != payload_details:
            raise StateError(
                "the requested network target/profile does not match the human-approved "
                "target; the grant was NOT created"
            )
        approved_target = NetworkTarget.from_mapping(payload_details["target"])

        grant = GrantRecord(
            grant_id=new_id("grant"),
            task_id=approval.task_id,
            competition_profile=requested["profile"],
            host=approved_target.host,
            port=int(approved_target.port),
            protocol=approved_target.protocol,
            method=approved_target.method,
            path_prefix=normalize_path(approved_target.path),
            expires_at=now + ttl * 1000,
            max_calls=calls,
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
        """Deterministic one-line description of exactly what is being approved."""

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
                    f"{target.get('path', '/')}"
                )
            profile = payload.get("profile")
            if profile is not None:
                parts.append(f"profile={profile}")
        else:
            details = canonical_json(payload)
            if len(details) > _SUMMARY_DETAIL_CHARS:
                details = details[:_SUMMARY_DETAIL_CHARS] + "..."
            parts.append(f"details={details}")
        if record.expires_at is not None:
            parts.append(f"expires_at={record.expires_at}")
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
