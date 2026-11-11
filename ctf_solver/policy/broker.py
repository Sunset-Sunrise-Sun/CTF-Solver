"""Execution Broker: fail-closed policy enforcement for typed ``ctf-exec``.

The Broker is the trusted policy enforcement point (docs/INTERFACES.md
section 5.2). It validates, in order:

1. structural sanity of the request (ids, argv limits, no shell metacharacters
   in ``argv[0]``, path/limit shapes);
2. the worker bearer token (exists, bound to the same task, ready/running,
   matching ``request.worker_id``);
3. the task (exists, runnable status, bound worker/session/workspace);
4. the tool allowlist, installation state and approved version;
5. the execution tier (challenge code and Tier 2 are denied while isolation is
   unavailable);
6. the tool argv schema, cwd containment and input/output path policy;
7. approval existence, task/action/digest binding, status, expiry, prior use;
8. network target/grant matching (task, profile, host, port, protocol, method,
   path prefix, status, expiry, call count), then grant-call consumption;
9. timeout/output resource limits.

Nothing is consumed until every check has passed. Every expected failure
returns a :class:`BrokerDecision` with a stable :class:`DenyReason`; unexpected
exceptions are converted to ``internal_error`` denials rather than escaping.
"""

from __future__ import annotations

import enum
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..core.canonical import file_sha256
from ..core.errors import CtfSolverError, DenyReason
from ..core.ids import is_valid_id, is_valid_step_id
from ..core.paths import ensure_relative_safe, is_within, resolve_path
from ..core.protocols import Clock, SystemClock
from ..core.types import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    BrokerDecision,
    ExecutionTier,
    ExecRequest,
    GrantRecord,
    GrantStatus,
    NetworkTarget,
    TaskRecord,
    WorkerRecord,
    WorkerStatus,
)
from ..runtime.catalog import ResolvedTool, RuntimeCatalog
from .models import (
    ALLOWED_NETWORK_PROTOCOLS,
    METHOD_REQUIRED_PROTOCOLS,
    action_digest,
    approval_action_digest,
    grant_allows_private,
    hosts_match,
    is_loopback_host,
    is_private_host,
    is_private_ip,
    normalize_method,
    normalize_path,
    normalize_path_prefix,
    normalize_protocol,
    parse_ip,
    path_prefix_matches,
)

__all__ = ["Broker", "BrokerConfig"]

#: Characters that could start shell expansion/command separation. They are
#: rejected in ``argv[0]`` (docs/INTERFACES.md 5.2 step 1); the runtime never
#: uses a shell, so this is a defence-in-depth rejection.
SHELL_METACHARACTERS: frozenset[str] = frozenset({"|", "&", ";", "<", ">", "$", "`", "\n", "\r", "\x00"})

_TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

#: Task states in which execution is allowed (slot-occupying + runnable).
_RUNNABLE_TASK_STATUSES = frozenset({"running", "paused", "awaiting_approval"})

_RUNNABLE_WORKER_STATUSES = frozenset({WorkerStatus.READY, WorkerStatus.RUNNING})

REASON_ALLOWED = "allowed"



def _has_control_or_nul(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _has_traversal(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(part == ".." for part in normalized.split("/"))


def _status_value(status: Any) -> str:
    if isinstance(status, enum.Enum):
        return str(status.value)
    return str(status).strip().lower()


def _action_kind_text(value: Any) -> str:
    if isinstance(value, enum.Enum):
        return str(value.value)
    return str(value)


def _same_destination(left: NetworkTarget | None, right: NetworkTarget) -> bool:
    if not isinstance(left, NetworkTarget):
        return False
    return (
        hosts_match(left.host, right.host)
        and int(left.port) == int(right.port)
        and normalize_protocol(left.protocol) == normalize_protocol(right.protocol)
        and normalize_method(left.method) == normalize_method(right.method)
        and normalize_path(left.path) == normalize_path(right.path)
    )


@dataclass(frozen=True)
class BrokerConfig:
    """Policy limits for one Broker instance.

    ``network_enabled`` is ``False`` in Round 1: no network tool is functional
    until an accepted isolated runtime and target policy exist. Network grant
    matching is still fully implemented and testable (tests/Manager may enable
    it explicitly for synthetic policy exercises), but the shipped default
    fails closed.
    """

    #: ``None`` means "use the runtime catalogue's available tiers".
    available_tiers: frozenset[ExecutionTier] | None = None
    network_enabled: bool = False
    max_argv_args: int = 64
    max_argv_arg_chars: int = 8192
    max_argv0_chars: int = 4096
    max_tool_name_chars: int = 128
    max_id_chars: int = 128
    max_input_files: int = 32
    max_output_paths: int = 32
    max_path_chars: int = 4096
    min_timeout_s: float = 0.1
    max_timeout_s: float = 600.0
    max_output_bytes: int = 4 * 1024 * 1024
    max_network_path_chars: int = 2048


class Broker:
    """Fail-closed policy engine for typed ``ctf-exec`` requests."""

    def __init__(
        self,
        repository: Any,
        catalog: RuntimeCatalog,
        clock: Clock | None = None,
        *,
        config: BrokerConfig | None = None,
    ) -> None:
        if repository is None:
            raise ValueError("Broker requires a PolicyRepository implementation")
        if not isinstance(catalog, RuntimeCatalog):
            raise ValueError("Broker requires a RuntimeCatalog")
        self.repository = repository
        self.catalog = catalog
        self.clock: Clock = clock or SystemClock()
        self.config = config or BrokerConfig()
        configured = self.config.available_tiers
        catalog_tiers = frozenset(catalog.available_tiers)
        if configured is None:
            self._available_tiers = catalog_tiers
        else:
            # Configuration may only narrow what the catalogue advertises.
            self._available_tiers = frozenset(set(configured) & set(catalog_tiers))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def available_tiers(self) -> frozenset[ExecutionTier]:
        return self._available_tiers

    def authorize(self, request: ExecRequest, worker_token: str) -> BrokerDecision:
        """Authorize one execution request; never raises for expected failures."""

        try:
            return self._authorize(request, worker_token)
        except CtfSolverError as exc:
            return BrokerDecision.deny(
                DenyReason.INTERNAL_ERROR, f"policy repository failure: {exc}"
            )
        except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
            return BrokerDecision.deny(
                DenyReason.INTERNAL_ERROR,
                f"unexpected broker failure: {type(exc).__name__}: {exc}",
            )

    def validate_redirect(
        self,
        grant: GrantRecord | Any,
        original_target: NetworkTarget,
        redirect_target: NetworkTarget,
    ) -> BrokerDecision:
        """Revalidate a redirect against the authorized grant scope.

        A redirect to the same destination is always in scope. A different
        destination must match the grant and must not be a private/loopback
        address unless the grant scope explicitly carries ``allow_private``.
        """

        try:
            return self._validate_redirect(grant, original_target, redirect_target)
        except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
            return BrokerDecision.deny(
                DenyReason.INTERNAL_ERROR,
                f"unexpected redirect validation failure: {type(exc).__name__}: {exc}",
            )

    def validate_resolved_address(
        self,
        grant: GrantRecord | Any,
        target: NetworkTarget,
        resolved_ips: list[str] | tuple[str, ...] | Any,
    ) -> BrokerDecision:
        """Revalidate injected DNS results against the authorized grant scope.

        No real DNS lookup is performed by policy code; callers pass synthetic
        or already-resolved addresses. Empty, unparseable or private/loopback
        answers fail closed unless the grant explicitly allows private scope.
        """

        try:
            return self._validate_resolved_address(grant, target, resolved_ips)
        except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
            return BrokerDecision.deny(
                DenyReason.INTERNAL_ERROR,
                f"unexpected DNS validation failure: {type(exc).__name__}: {exc}",
            )

    # ------------------------------------------------------------------
    # Main authorization pipeline
    # ------------------------------------------------------------------

    def _authorize(self, request: ExecRequest, worker_token: str) -> BrokerDecision:
        if not isinstance(request, ExecRequest):
            return self._deny(
                DenyReason.INVALID_REQUEST,
                f"request must be an ExecRequest, got {type(request).__name__}",
            )

        # 1. Structural sanity -------------------------------------------------
        decision = self._validate_structure(request)
        if decision is not None:
            return decision
        now_ms = self.clock.now_ms()

        # 2. Worker token / identity ------------------------------------------
        decision, worker = self._check_worker(request, worker_token)
        if decision is not None:
            return decision
        assert worker is not None

        # 3. Task, runnable state, session and workspace binding --------------
        decision, task, worker_workspace = self._check_task(request, worker)
        if decision is not None:
            return decision
        assert task is not None and worker_workspace is not None

        # 4. Tool allowlist / installation / version ---------------------------
        decision, spec, resolved = self._check_tool(request)
        if decision is not None:
            return decision
        assert spec is not None and resolved is not None

        # 5. Execution tier ----------------------------------------------------
        decision, effective_tier = self._check_tier(request, spec)
        if decision is not None:
            return decision
        assert effective_tier is not None

        # 6. argv schema, cwd, inputs, outputs ---------------------------------
        decision = self._check_arguments_and_paths(request, spec, worker_workspace)
        if decision is not None:
            return decision

        # 7. Approval binding (validate only; consumption happens last) -------
        decision, approval = self._check_approval(request, spec, now_ms)
        if decision is not None:
            return decision

        # 8. Network target / grant scope -------------------------------------
        decision, grant = self._check_network(request, spec, task, now_ms)
        if decision is not None:
            return decision

        # 9. Resource limits ---------------------------------------------------
        decision = self._check_limits(request, spec)
        if decision is not None:
            return decision

        # Consume sensitive tokens only after every check has passed. A failed
        # atomic consumption (race/revocation/expiry) fails closed.
        decision = self._consume_tokens(approval, grant, now_ms)
        if decision is not None:
            return decision

        tool_version = resolved.version or (request.tool_version or spec.version or None)
        return BrokerDecision(
            allowed=True,
            reason_code=REASON_ALLOWED,
            reason="",
            tool={
                "name": spec.name,
                "display_name": spec.display_name,
                "tier": int(spec.tier),
                "version": tool_version,
                "executable": resolved.executable,
                "network": bool(spec.network),
                "executes_challenge_code": bool(spec.executes_challenge_code),
                "requires_approval": (
                    spec.requires_approval.value if spec.requires_approval else None
                ),
            },
            effective_tier=effective_tier,
            approval_id=approval.approval_id if approval is not None else None,
            network_grant_id=grant.grant_id if grant is not None else None,
            grant_call_consumed=grant is not None,
        )

    # ------------------------------------------------------------------
    # Step 1: structural sanity
    # ------------------------------------------------------------------

    def _deny(self, reason: DenyReason, message: str) -> BrokerDecision:
        return BrokerDecision.deny(reason, message)

    def _validate_structure(self, request: ExecRequest) -> BrokerDecision | None:
        if not is_valid_id(request.task_id):
            return self._deny(DenyReason.INVALID_REQUEST, f"invalid task_id: {request.task_id!r}")
        if not is_valid_id(request.worker_id):
            return self._deny(
                DenyReason.INVALID_REQUEST, f"invalid worker_id: {request.worker_id!r}"
            )
        if not is_valid_step_id(request.step_id):
            return self._deny(DenyReason.INVALID_REQUEST, f"invalid step_id: {request.step_id!r}")

        tool_name = request.tool_name
        if not isinstance(tool_name, str) or not _TOOL_NAME_PATTERN.match(tool_name):
            return self._deny(
                DenyReason.INVALID_REQUEST, f"invalid tool_name: {tool_name!r}"
            )

        argv = request.argv
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            return self._deny(DenyReason.INVALID_REQUEST, "argv must be an array of strings")
        if len(argv) > self.config.max_argv_args:
            return self._deny(
                DenyReason.INVALID_REQUEST,
                f"argv exceeds {self.config.max_argv_args} arguments",
            )
        for index, item in enumerate(argv):
            if len(item) > self.config.max_argv_arg_chars:
                return self._deny(
                    DenyReason.INVALID_REQUEST,
                    f"argv[{index}] exceeds {self.config.max_argv_arg_chars} characters",
                )
            if _has_control_or_nul(item):
                return self._deny(
                    DenyReason.INVALID_REQUEST,
                    f"argv[{index}] contains a NUL/control character",
                )
        if argv and any(char in SHELL_METACHARACTERS for char in argv[0]):
            return self._deny(
                DenyReason.SHELL_EXPANSION_REJECTED,
                "argv[0] contains shell metacharacters; only argv arrays are accepted",
            )

        cwd = request.cwd
        if not isinstance(cwd, str) or not cwd.strip():
            return self._deny(DenyReason.INVALID_REQUEST, "cwd is required")
        if len(cwd) > self.config.max_path_chars or _has_control_or_nul(cwd):
            return self._deny(DenyReason.INVALID_REQUEST, "cwd is not a valid path string")
        if not os.path.isabs(cwd):
            return self._deny(DenyReason.INVALID_REQUEST, f"cwd must be absolute: {cwd!r}")

        tier = request.tier
        if not isinstance(tier, ExecutionTier):
            return self._deny(DenyReason.INVALID_REQUEST, f"invalid execution tier: {tier!r}")

        timeout = request.timeout_s
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            return self._deny(DenyReason.INVALID_REQUEST, "timeout_s must be a number")
        if not self.config.min_timeout_s <= float(timeout) <= self.config.max_timeout_s:
            return self._deny(
                DenyReason.RESOURCE_LIMIT,
                f"timeout_s must be within [{self.config.min_timeout_s}, "
                f"{self.config.max_timeout_s}]",
            )

        max_output = request.max_output_bytes
        if max_output is not None:
            if isinstance(max_output, bool) or not isinstance(max_output, int):
                return self._deny(DenyReason.INVALID_REQUEST, "max_output_bytes must be an int")
            if max_output <= 0 or max_output > 64 * 1024 * 1024:
                return self._deny(
                    DenyReason.RESOURCE_LIMIT,
                    "max_output_bytes must be within (0, 64 MiB]",
                )

        if not isinstance(request.input_files, list):
            return self._deny(DenyReason.INVALID_REQUEST, "input_files must be an array")
        if len(request.input_files) > self.config.max_input_files:
            return self._deny(
                DenyReason.INVALID_REQUEST,
                f"input_files exceeds {self.config.max_input_files} entries",
            )
        for item in request.input_files:
            if not isinstance(item, Mapping):
                return self._deny(DenyReason.INVALID_REQUEST, "input_files entries must be objects")
            raw_path = item.get("path")
            digest = item.get("sha256")
            if not isinstance(raw_path, str) or not raw_path.strip():
                return self._deny(
                    DenyReason.INVALID_REQUEST, "input_files entries need a non-empty path"
                )
            if len(raw_path) > self.config.max_path_chars or _has_control_or_nul(raw_path):
                return self._deny(DenyReason.INVALID_REQUEST, "input file path is invalid")
            if not isinstance(digest, str) or not _SHA256_PATTERN.match(digest.strip()):
                return self._deny(
                    DenyReason.INVALID_REQUEST,
                    f"input file {raw_path!r} needs a 64-hex SHA-256 digest",
                )

        if not isinstance(request.output_paths, list):
            return self._deny(DenyReason.INVALID_REQUEST, "output_paths must be an array")
        if len(request.output_paths) > self.config.max_output_paths:
            return self._deny(
                DenyReason.INVALID_REQUEST,
                f"output_paths exceeds {self.config.max_output_paths} entries",
            )
        for raw_path in request.output_paths:
            if not isinstance(raw_path, str) or not raw_path.strip():
                return self._deny(
                    DenyReason.INVALID_REQUEST, "output_paths entries must be non-empty strings"
                )
            if len(raw_path) > self.config.max_path_chars or _has_control_or_nul(raw_path):
                return self._deny(DenyReason.INVALID_REQUEST, "output path is invalid")

        for label, value in (
            ("network_grant_id", request.network_grant_id),
            ("approval_id", request.approval_id),
        ):
            if value is None:
                continue
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > self.config.max_id_chars
                or _has_control_or_nul(value)
            ):
                return self._deny(DenyReason.INVALID_REQUEST, f"{label} is invalid")

        if request.network_target is not None:
            problem = self._network_target_problem(request.network_target)
            if problem is not None:
                return self._deny(
                    DenyReason.INVALID_REQUEST, f"invalid network_target: {problem}"
                )
        return None

    def _network_target_problem(self, target: Any) -> str | None:
        if not isinstance(target, NetworkTarget):
            return f"expected a NetworkTarget object, got {type(target).__name__}"
        host = target.host
        if not isinstance(host, str) or not host.strip():
            return "host is required"
        if len(host) > 253 or _has_control_or_nul(host) or " " in host:
            return "host is not a valid hostname/IP literal"
        if "://" in host or "/" in host:
            return "host must be a bare hostname or IP literal"
        normalized = host.strip().strip("[]")
        if ":" in normalized and parse_ip(normalized) is None:
            return "host must not embed a port; use the port field"
        port = target.port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return f"invalid port: {port!r}"
        protocol = normalize_protocol(target.protocol)
        if protocol not in ALLOWED_NETWORK_PROTOCOLS:
            return f"unsupported protocol {target.protocol!r}"
        method = target.method
        if not isinstance(method, str):
            return "method must be a string"
        normalized_method = normalize_method(method)
        if len(normalized_method) > 64 or _has_control_or_nul(method):
            return "method is invalid"
        if protocol in METHOD_REQUIRED_PROTOCOLS and not normalized_method:
            return f"protocol {protocol!r} requires a method"
        path = target.path
        if not isinstance(path, str):
            return "path must be a string"
        if not path.startswith("/"):
            return "path must start with '/'"
        if len(path) > self.config.max_network_path_chars or _has_control_or_nul(path):
            return "path is invalid"
        return None

    # ------------------------------------------------------------------
    # Step 2: worker token
    # ------------------------------------------------------------------

    def _check_worker(
        self, request: ExecRequest, worker_token: str
    ) -> tuple[BrokerDecision | None, WorkerRecord | None]:
        if (
            not isinstance(worker_token, str)
            or not worker_token.strip()
            or len(worker_token) > 512
            or _has_control_or_nul(worker_token)
        ):
            return self._deny(DenyReason.UNKNOWN_WORKER, "a valid worker token is required"), None
        worker = self.repository.get_worker_by_token(worker_token)
        if worker is None:
            return self._deny(DenyReason.UNKNOWN_WORKER, "unknown worker token"), None
        if worker.worker_id != request.worker_id:
            return (
                self._deny(
                    DenyReason.WORKER_MISMATCH,
                    "worker token does not belong to request.worker_id",
                ),
                None,
            )
        if worker.task_id != request.task_id:
            return (
                self._deny(
                    DenyReason.WORKER_MISMATCH,
                    "worker token is scoped to a different task",
                ),
                None,
            )
        if worker.status not in _RUNNABLE_WORKER_STATUSES:
            return (
                self._deny(
                    DenyReason.WORKER_NOT_RUNNING,
                    f"worker status {worker.status.value!r} is not runnable",
                ),
                None,
            )
        return None, worker

    # ------------------------------------------------------------------
    # Step 3: task binding
    # ------------------------------------------------------------------

    def _check_task(
        self, request: ExecRequest, worker: WorkerRecord
    ) -> tuple[BrokerDecision | None, TaskRecord | None, Path | None]:
        task = self.repository.get_task(request.task_id)
        if task is None:
            return self._deny(DenyReason.UNKNOWN_TASK, f"unknown task {request.task_id!r}"), None, None
        status = _status_value(task.status)
        if status not in _RUNNABLE_TASK_STATUSES:
            return (
                self._deny(
                    DenyReason.TASK_NOT_RUNNABLE,
                    f"task status {status!r} is not runnable",
                ),
                None,
                None,
            )
        if not task.worker_id or task.worker_id != worker.worker_id:
            return (
                self._deny(
                    DenyReason.WORKER_MISMATCH,
                    "task is not bound to the token's worker",
                ),
                None,
                None,
            )
        if not task.acp_session_id or task.acp_session_id != worker.acp_session_id:
            return (
                self._deny(
                    DenyReason.SESSION_MISMATCH,
                    "worker ACP session does not match the task's session",
                ),
                None,
                None,
            )
        try:
            task_workspace = resolve_path(task.workspace_path)
            worker_workspace = resolve_path(worker.workspace_path)
        except (OSError, ValueError) as exc:
            return (
                self._deny(DenyReason.WORKER_MISMATCH, f"invalid workspace path: {exc}"),
                None,
                None,
            )
        if os.path.normcase(str(task_workspace)) != os.path.normcase(str(worker_workspace)):
            return (
                self._deny(
                    DenyReason.WORKER_MISMATCH,
                    "worker workspace does not match the task workspace",
                ),
                None,
                None,
            )
        return None, task, worker_workspace

    # ------------------------------------------------------------------
    # Step 4: tool allowlist / version
    # ------------------------------------------------------------------

    def _check_tool(
        self, request: ExecRequest
    ) -> tuple[BrokerDecision | None, Any, ResolvedTool | None]:
        spec = self.catalog.get(request.tool_name)
        if spec is None:
            return (
                self._deny(
                    DenyReason.TOOL_NOT_ALLOWED,
                    f"tool {request.tool_name!r} is not in the Manager allowlist",
                ),
                None,
                None,
            )
        resolved = self.catalog.resolve(request.tool_name)
        if resolved is None or not resolved.installed:
            return (
                self._deny(
                    DenyReason.TOOL_NOT_INSTALLED,
                    f"tool {request.tool_name!r} is not installed/available",
                ),
                None,
                None,
            )
        requested_version = request.tool_version
        if requested_version:
            expected = resolved.version
            if not expected or str(requested_version).strip() != str(expected).strip():
                return (
                    self._deny(
                        DenyReason.TOOL_VERSION_MISMATCH,
                        f"tool version {requested_version!r} does not match resolved "
                        f"version {expected!r}",
                    ),
                    None,
                    None,
                )
        return None, spec, resolved

    # ------------------------------------------------------------------
    # Step 5: execution tier
    # ------------------------------------------------------------------

    def _check_tier(
        self, request: ExecRequest, spec: Any
    ) -> tuple[BrokerDecision | None, ExecutionTier | None]:
        tiers = self._available_tiers
        requested = ExecutionTier(int(request.tier))
        effective = requested if int(requested) >= int(spec.tier) else spec.tier
        if spec.executes_challenge_code:
            if ExecutionTier.TIER2_ISOLATED not in tiers:
                return (
                    self._deny(
                        DenyReason.UNTRUSTED_CODE_REQUIRES_TIER2,
                        "executing challenge-provided code requires an accepted Tier 2 "
                        "OS isolation runtime; approval alone is not sufficient",
                    ),
                    None,
                )
        if effective not in tiers:
            return (
                self._deny(
                    DenyReason.TIER_NOT_AVAILABLE,
                    f"execution tier {effective.name} is not available "
                    f"(available: {sorted(int(tier) for tier in tiers)})",
                ),
                None,
            )
        return None, effective

    # ------------------------------------------------------------------
    # Step 6: argv / cwd / paths
    # ------------------------------------------------------------------

    def _check_arguments_and_paths(
        self, request: ExecRequest, spec: Any, worker_workspace: Path
    ) -> BrokerDecision | None:
        if spec.arg_validator is not None:
            try:
                problem = spec.arg_validator(list(request.argv))
            except Exception as exc:  # pragma: no cover - validator contract violation
                problem = f"argument validator failed: {type(exc).__name__}: {exc}"
            if problem:
                return self._deny(DenyReason.ARGV_SCHEMA_VIOLATION, problem)

        if spec.internal is None and not spec.executable:
            return self._deny(
                DenyReason.TOOL_NOT_ALLOWED,
                "tool has no runnable implementation in this runtime",
            )

        try:
            cwd_resolved = resolve_path(request.cwd)
        except (OSError, ValueError) as exc:
            return self._deny(DenyReason.INVALID_REQUEST, f"invalid cwd: {exc}")
        if not is_within(cwd_resolved, worker_workspace):
            return self._deny(
                DenyReason.CWD_OUTSIDE_ROOT,
                f"cwd {request.cwd!r} is outside the authorized worker workspace",
            )
        if not cwd_resolved.is_dir():
            return self._deny(
                DenyReason.INVALID_REQUEST, f"cwd does not exist: {request.cwd!r}"
            )

        for item in request.input_files:
            raw_path = str(item.get("path"))
            expected_digest = str(item.get("sha256", "")).strip().lower()
            if _has_traversal(raw_path):
                return self._deny(
                    DenyReason.PATH_TRAVERSAL,
                    f"input path contains traversal: {raw_path!r}",
                )
            candidate = (
                Path(raw_path) if os.path.isabs(raw_path) else cwd_resolved / Path(raw_path)
            )
            try:
                resolved = resolve_path(candidate)
            except (OSError, ValueError) as exc:
                return self._deny(DenyReason.INVALID_REQUEST, f"invalid input path: {exc}")
            if not is_within(resolved, worker_workspace):
                return self._deny(
                    DenyReason.INPUT_OUTSIDE_ROOT,
                    f"input path is outside the worker workspace: {raw_path!r}",
                )
            if not resolved.is_file():
                return self._deny(
                    DenyReason.INPUT_MISSING, f"input file does not exist: {raw_path!r}"
                )
            actual_digest = file_sha256(resolved)
            if actual_digest != expected_digest:
                return self._deny(
                    DenyReason.INPUT_HASH_MISMATCH,
                    f"input file SHA-256 mismatch for {raw_path!r}",
                )

        seen_outputs: set[str] = set()
        for raw_path in request.output_paths:
            if _has_traversal(raw_path) or os.path.isabs(raw_path):
                return self._deny(
                    DenyReason.PATH_TRAVERSAL,
                    f"output path must be workspace-relative without traversal: {raw_path!r}",
                )
            try:
                relative = ensure_relative_safe(raw_path)
            except ValueError as exc:
                return self._deny(DenyReason.PATH_TRAVERSAL, f"invalid output path: {exc}")
            candidate = resolve_path(os.path.join(str(cwd_resolved), relative))
            if not is_within(candidate, worker_workspace) or not is_within(
                candidate, cwd_resolved
            ):
                return self._deny(
                    DenyReason.OUTPUT_OUTSIDE_ROOT,
                    f"output path is outside the authorized workspace: {raw_path!r}",
                )
            key = os.path.normcase(str(candidate))
            if key in seen_outputs:
                return self._deny(
                    DenyReason.OUTPUT_CONFLICT, f"duplicate output path: {raw_path!r}"
                )
            seen_outputs.add(key)
            if candidate.exists() and candidate.is_dir():
                return self._deny(
                    DenyReason.OUTPUT_CONFLICT,
                    f"output path is an existing directory: {raw_path!r}",
                )
        return None

    # ------------------------------------------------------------------
    # Step 7: approval
    # ------------------------------------------------------------------

    def _required_approval_action(self, spec: Any) -> ApprovalAction | None:
        if spec.requires_approval is not None:
            return spec.requires_approval
        if spec.executes_challenge_code:
            return ApprovalAction.UNTRUSTED_CODE
        return None

    def _expected_approval_digests(self, action_kind: str, request: ExecRequest) -> set[str]:
        digests = {approval_action_digest(action_kind, request)}
        # Tolerate a Manager that binds the approval digest to the full request
        # document instead of the canonical approval details. Both forms bind
        # the approval to exactly this request, so either is acceptable.
        try:
            digests.add(action_digest(action_kind, request.to_dict()))
        except Exception:  # pragma: no cover - non-serialisable defensive path
            pass
        return {digest.strip().lower() for digest in digests}

    def _check_approval(
        self, request: ExecRequest, spec: Any, now_ms: int
    ) -> tuple[BrokerDecision | None, ApprovalRecord | None]:
        required = self._required_approval_action(spec)
        approval_id = request.approval_id
        if approval_id is None:
            if required is not None:
                return (
                    self._deny(
                        DenyReason.APPROVAL_MISSING,
                        f"tool {request.tool_name!r} requires an approved "
                        f"{required.value!r} approval",
                    ),
                    None,
                )
            return None, None
        approval = self.repository.get_approval(approval_id)
        if approval is None:
            return (
                self._deny(DenyReason.APPROVAL_MISSING, f"approval {approval_id!r} not found"),
                None,
            )
        if approval.task_id != request.task_id:
            return (
                self._deny(
                    DenyReason.APPROVAL_MISMATCH,
                    "approval is scoped to a different task",
                ),
                None,
            )
        action_kind = _action_kind_text(approval.action_kind)
        if required is not None and action_kind != required.value:
            return (
                self._deny(
                    DenyReason.APPROVAL_MISMATCH,
                    f"approval action kind {action_kind!r} does not match required "
                    f"{required.value!r}",
                ),
                None,
            )
        status = _status_value(approval.status)
        if status != ApprovalStatus.APPROVED.value:
            if status == ApprovalStatus.EXPIRED.value:
                return (
                    self._deny(DenyReason.APPROVAL_EXPIRED, "approval has expired"),
                    None,
                )
            return (
                self._deny(
                    DenyReason.APPROVAL_INVALID,
                    f"approval status {status!r} is not approved",
                ),
                None,
            )
        if approval.consumed_at is not None:
            return (
                self._deny(
                    DenyReason.APPROVAL_ALREADY_USED,
                    "approval has already been consumed by another action",
                ),
                None,
            )
        if approval.expires_at is not None and int(approval.expires_at) <= now_ms:
            return self._deny(DenyReason.APPROVAL_EXPIRED, "approval has expired"), None
        digest = str(approval.action_digest or "").strip().lower()
        if not digest:
            return (
                self._deny(DenyReason.APPROVAL_INVALID, "approval has no action digest"),
                None,
            )
        expected = self._expected_approval_digests(action_kind, request)
        if digest not in expected:
            return (
                self._deny(
                    DenyReason.APPROVAL_MISMATCH,
                    "approval digest does not match this exact execution request",
                ),
                None,
            )
        return None, approval

    # ------------------------------------------------------------------
    # Step 8: network target / grant
    # ------------------------------------------------------------------

    def _check_network(
        self, request: ExecRequest, spec: Any, task: TaskRecord, now_ms: int
    ) -> tuple[BrokerDecision | None, GrantRecord | None]:
        target = request.network_target
        grant_id = request.network_grant_id
        if target is None:
            if spec.network:
                return (
                    self._deny(
                        DenyReason.NETWORK_TARGET_MISSING,
                        f"network tool {request.tool_name!r} requires an authorized target",
                    ),
                    None,
                )
            if grant_id is not None:
                return (
                    self._deny(
                        DenyReason.NETWORK_TARGET_MISSING,
                        "network_grant_id was supplied without a network_target",
                    ),
                    None,
                )
            return None, None
        if not spec.network:
            return (
                self._deny(
                    DenyReason.INVALID_REQUEST,
                    f"tool {request.tool_name!r} does not accept a network target",
                ),
                None,
            )
        if grant_id is None:
            return (
                self._deny(
                    DenyReason.GRANT_MISSING,
                    "network target access requires a Task-scoped network grant",
                ),
                None,
            )
        grant = self.repository.get_grant(grant_id)
        if grant is None:
            return (
                self._deny(DenyReason.GRANT_MISSING, f"network grant {grant_id!r} not found"),
                None,
            )
        denial = self._grant_scope_denial(grant, target, request.task_id, task, now_ms)
        if denial is not None:
            return denial, None
        if not self.config.network_enabled:
            return (
                self._deny(
                    DenyReason.TIER_NOT_AVAILABLE,
                    "network target execution is disabled until an accepted isolated "
                    "runtime and target policy are available",
                ),
                None,
            )
        return None, grant

    def _grant_scope_denial(
        self,
        grant: GrantRecord | Any,
        target: NetworkTarget,
        task_id: str,
        task: TaskRecord,
        now_ms: int,
    ) -> BrokerDecision | None:
        if getattr(grant, "task_id", None) != task_id:
            return self._deny(
                DenyReason.GRANT_TASK_MISMATCH,
                "network grant is scoped to a different task",
            )
        task_profile = str(getattr(task, "scope_profile", "") or "")
        grant_profile = str(getattr(grant, "competition_profile", "") or "")
        if task_profile != grant_profile:
            return self._deny(
                DenyReason.GRANT_PROFILE_MISMATCH,
                f"grant profile {grant_profile!r} does not match task profile "
                f"{task_profile!r}",
            )
        active_denial = self._grant_active_denial(grant, now_ms)
        if active_denial is not None:
            return active_denial
        max_calls = int(getattr(grant, "max_calls", 0))
        calls_used = int(getattr(grant, "calls_used", 0))
        if max_calls <= 0:
            return self._deny(DenyReason.GRANT_INVALID, "grant has no call budget")
        if calls_used >= max_calls:
            return self._deny(
                DenyReason.GRANT_EXHAUSTED,
                f"grant call budget exhausted ({calls_used}/{max_calls})",
            )
        return self._grant_target_denial(grant, target, DenyReason.GRANT_HOST_MISMATCH)

    def _grant_active_denial(
        self, grant: GrantRecord | Any, now_ms: int
    ) -> BrokerDecision | None:
        status = _status_value(getattr(grant, "status", GrantStatus.ACTIVE))
        if status != GrantStatus.ACTIVE.value:
            if status == GrantStatus.EXPIRED.value:
                return self._deny(DenyReason.GRANT_EXPIRED, "network grant has expired")
            if status == GrantStatus.EXHAUSTED.value:
                return self._deny(DenyReason.GRANT_EXHAUSTED, "network grant is exhausted")
            return self._deny(
                DenyReason.GRANT_INVALID, f"network grant status {status!r} is not active"
            )
        try:
            expires_at = int(getattr(grant, "expires_at"))
        except (TypeError, ValueError):
            return self._deny(DenyReason.GRANT_INVALID, "network grant has no valid expiry")
        if expires_at <= now_ms:
            return self._deny(DenyReason.GRANT_EXPIRED, "network grant has expired")
        return None

    def _grant_target_denial(
        self,
        grant: GrantRecord | Any,
        target: NetworkTarget,
        host_reason: DenyReason,
    ) -> BrokerDecision | None:
        if not hosts_match(str(getattr(grant, "host", "")), target.host):
            return self._deny(
                host_reason,
                f"target host {target.host!r} does not match granted host "
                f"{getattr(grant, 'host', '')!r}",
            )
        if int(getattr(grant, "port", -1)) != int(target.port):
            return self._deny(
                DenyReason.GRANT_PORT_MISMATCH,
                f"target port {target.port} does not match granted port "
                f"{getattr(grant, 'port', -1)}",
            )
        if normalize_protocol(str(getattr(grant, "protocol", ""))) != normalize_protocol(
            target.protocol
        ):
            return self._deny(
                DenyReason.GRANT_PROTOCOL_MISMATCH,
                "target protocol does not match the granted protocol",
            )
        if normalize_method(str(getattr(grant, "method", ""))) != normalize_method(
            target.method
        ):
            return self._deny(
                DenyReason.GRANT_ACTION_MISMATCH,
                "target method/action does not match the granted action",
            )
        granted_path_prefix = normalize_path_prefix(str(getattr(grant, "path_prefix", "/")))
        if not path_prefix_matches(target.path, granted_path_prefix):
            return self._deny(
                DenyReason.GRANT_PATH_MISMATCH,
                f"target path {target.path!r} is outside the granted path prefix "
                f"{granted_path_prefix!r}",
            )
        return None

    # ------------------------------------------------------------------
    # Step 9 + consumption
    # ------------------------------------------------------------------

    def _check_limits(self, request: ExecRequest, spec: Any) -> BrokerDecision | None:
        timeout = float(request.timeout_s)
        if timeout > self.config.max_timeout_s:
            return self._deny(
                DenyReason.RESOURCE_LIMIT,
                f"timeout_s {timeout} exceeds the policy maximum "
                f"{self.config.max_timeout_s}",
            )
        requested_output = request.max_output_bytes
        if requested_output is not None:
            if requested_output > self.config.max_output_bytes:
                return self._deny(
                    DenyReason.RESOURCE_LIMIT,
                    f"max_output_bytes exceeds the policy cap "
                    f"{self.config.max_output_bytes}",
                )
            if requested_output > int(spec.max_output_bytes):
                return self._deny(
                    DenyReason.RESOURCE_LIMIT,
                    f"max_output_bytes exceeds the tool cap {spec.max_output_bytes}",
                )
        return None

    def _consume_tokens(
        self,
        approval: ApprovalRecord | None,
        grant: GrantRecord | None,
        now_ms: int,
    ) -> BrokerDecision | None:
        if approval is not None:
            consumed = self.repository.consume_approval(approval.approval_id, now_ms)
            if not consumed:
                return self._deny(
                    DenyReason.APPROVAL_ALREADY_USED,
                    "approval could not be consumed atomically "
                    "(expired, revoked or already used)",
                )
        if grant is not None:
            consumed = self.repository.consume_grant_call(grant.grant_id, now_ms)
            if not consumed:
                return self._deny(
                    DenyReason.GRANT_INVALID,
                    "network grant call could not be consumed atomically "
                    "(expired, revoked or exhausted)",
                )
        return None

    # ------------------------------------------------------------------
    # Redirect / DNS revalidation
    # ------------------------------------------------------------------

    def _validate_redirect(
        self,
        grant: GrantRecord | Any,
        original_target: NetworkTarget,
        redirect_target: NetworkTarget,
    ) -> BrokerDecision:
        if not isinstance(original_target, NetworkTarget):
            return self._deny(
                DenyReason.INVALID_REQUEST, "original_target must be a NetworkTarget"
            )
        problem = self._network_target_problem(redirect_target)
        if problem is not None:
            return self._deny(DenyReason.INVALID_REQUEST, f"invalid redirect_target: {problem}")
        if not self._is_grant_like(grant):
            return self._deny(DenyReason.GRANT_INVALID, "a network grant scope is required")
        now_ms = self.clock.now_ms()
        active_denial = self._grant_active_denial(grant, now_ms)
        if active_denial is not None:
            return active_denial
        scope_denial = self._grant_target_denial(
            grant, redirect_target, DenyReason.REDIRECT_SCOPE_VIOLATION
        )
        if scope_denial is not None:
            return BrokerDecision.deny(
                DenyReason.REDIRECT_SCOPE_VIOLATION,
                f"redirect target is outside the granted scope: {scope_denial.reason}",
            )
        if _same_destination(original_target, redirect_target):
            return self._allow_network(grant)
        if is_private_host(redirect_target.host) or is_loopback_host(redirect_target.host):
            if not grant_allows_private(grant):
                return self._deny(
                    DenyReason.REDIRECT_SCOPE_VIOLATION,
                    "redirect to a private/loopback destination requires an explicit "
                    "allow_private grant scope flag",
                )
        return self._allow_network(grant)

    def _validate_resolved_address(
        self,
        grant: GrantRecord | Any,
        target: NetworkTarget,
        resolved_ips: list[str] | tuple[str, ...] | Any,
    ) -> BrokerDecision:
        problem = self._network_target_problem(target)
        if problem is not None:
            return self._deny(DenyReason.INVALID_REQUEST, f"invalid network target: {problem}")
        if not self._is_grant_like(grant):
            return self._deny(DenyReason.GRANT_INVALID, "a network grant scope is required")
        now_ms = self.clock.now_ms()
        active_denial = self._grant_active_denial(grant, now_ms)
        if active_denial is not None:
            return active_denial
        scope_denial = self._grant_target_denial(
            grant, target, DenyReason.DNS_SCOPE_VIOLATION
        )
        if scope_denial is not None:
            return BrokerDecision.deny(
                DenyReason.DNS_SCOPE_VIOLATION,
                f"resolved destination is outside the granted scope: {scope_denial.reason}",
            )
        if not isinstance(resolved_ips, (list, tuple)) or not resolved_ips:
            return self._deny(
                DenyReason.DNS_SCOPE_VIOLATION,
                "no resolved addresses were provided; refusing to trust an unvalidated DNS answer",
            )
        parsed_ips = []
        for value in resolved_ips:
            parsed = parse_ip(str(value))
            if parsed is None:
                return self._deny(
                    DenyReason.DNS_SCOPE_VIOLATION,
                    f"resolved value {value!r} is not an IP address",
                )
            parsed_ips.append(parsed)
        literal = parse_ip(normalize_host_for_literal(target.host))
        if literal is not None:
            literal_text = str(literal)
            if not any(str(parsed) == literal_text for parsed in parsed_ips):
                return self._deny(
                    DenyReason.DNS_SCOPE_VIOLATION,
                    f"resolved addresses do not include the granted IP literal "
                    f"{literal_text}",
                )
        private_ips = [str(parsed) for parsed in parsed_ips if is_private_ip(str(parsed))]
        if private_ips and not grant_allows_private(grant):
            return self._deny(
                DenyReason.DNS_SCOPE_VIOLATION,
                "DNS answer contains private/loopback address(es) "
                f"{private_ips!r}; an explicit allow_private grant scope flag is required",
            )
        return self._allow_network(grant)

    @staticmethod
    def _is_grant_like(grant: Any) -> bool:
        return all(
            hasattr(grant, attribute)
            for attribute in ("grant_id", "task_id", "host", "port", "protocol", "method", "expires_at")
        )

    def _allow_network(self, grant: Any) -> BrokerDecision:
        return BrokerDecision(
            allowed=True,
            reason_code=REASON_ALLOWED,
            reason="",
            effective_tier=ExecutionTier.TIER1_TRUSTED,
            network_grant_id=str(getattr(grant, "grant_id", "")),
            grant_call_consumed=False,
        )


def normalize_host_for_literal(host: str) -> str:
    """Normalize an IP-literal target host (brackets removed) for comparison."""

    value = str(host).strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value
