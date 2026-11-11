"""Error types and stable failure reason codes for CTF-Solver.

All failures that cross a module boundary carry a machine-readable
``reason_code`` so Manager, Broker, Runtime and the evidence pipeline can
distinguish "denied before execution" from "executed but failed" without
string matching.
"""

from __future__ import annotations

import enum
from typing import Any


class CtfSolverError(Exception):
    """Base class for every expected CTF-Solver failure."""

    reason_code = "internal_error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": type(self).__name__,
            "reason_code": self.reason_code,
            "message": self.message,
            "details": self.details,
        }


class ConfigError(CtfSolverError):
    reason_code = "config_error"


class ValidationError(CtfSolverError):
    """A caller-supplied payload is structurally invalid."""

    reason_code = "invalid_request"


class NotFoundError(CtfSolverError):
    reason_code = "not_found"


class StateError(CtfSolverError):
    """An operation is not valid for the current durable state."""

    reason_code = "invalid_state"


class StorageError(CtfSolverError):
    reason_code = "storage_error"


class ChainIntegrityError(StorageError):
    reason_code = "chain_integrity_error"


class EvidenceError(CtfSolverError):
    reason_code = "evidence_error"


class UnsupportedCompressionError(EvidenceError):
    reason_code = "compression_unsupported"


class RuntimeDenied(CtfSolverError):
    """Raised when a policy decision denies a request before execution."""

    reason_code = "denied"


class ToolExecutionError(CtfSolverError):
    reason_code = "tool_execution_error"


class AcpError(CtfSolverError):
    reason_code = "acp_error"


class AcpUnavailableError(AcpError):
    """The Manager cannot start a Worker because ACP is unavailable.

    Callers (CLI/MCP) must surface this instead of creating a Task that can
    never leave the queue.
    """

    reason_code = "acp_unavailable"


class AcpStateError(AcpError):
    reason_code = "acp_state_error"


class AcpProtocolError(AcpError):
    reason_code = "acp_protocol_error"


class AcpTimeout(AcpError):
    reason_code = "acp_timeout"


class AcpProcessExited(AcpError):
    reason_code = "acp_process_exited"


class AcpRemoteError(AcpError):
    reason_code = "acp_remote_error"

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        data: Any = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        merged = dict(details or {})
        merged.setdefault("rpc_code", code)
        merged.setdefault("rpc_data", data)
        super().__init__(message, details=merged)
        self.code = code
        self.data = data


class ModelCallNotAuthorized(AcpError):
    """Raised when Round 1 code attempts an unauthorized model prompt."""

    reason_code = "model_call_not_authorized"


class IpcError(CtfSolverError):
    reason_code = "ipc_error"

    def __init__(
        self,
        message: str,
        *,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        if reason_code:
            self.reason_code = reason_code


class CaptureError(CtfSolverError):
    reason_code = "capture_error"


class DeliveryError(CtfSolverError):
    reason_code = "delivery_error"


class PreflightError(CtfSolverError):
    reason_code = "preflight_error"


class DenyReason(str, enum.Enum):
    """Stable Broker denial codes (fail-closed decisions)."""

    INVALID_REQUEST = "invalid_request"
    UNKNOWN_TASK = "unknown_task"
    TASK_NOT_RUNNABLE = "task_not_runnable"
    UNKNOWN_WORKER = "unknown_worker"
    WORKER_MISMATCH = "worker_mismatch"
    WORKER_NOT_RUNNING = "worker_not_running"
    SESSION_MISMATCH = "session_mismatch"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    TOOL_NOT_INSTALLED = "tool_not_installed"
    TOOL_VERSION_MISMATCH = "tool_version_mismatch"
    ARGV_SCHEMA_VIOLATION = "argv_schema_violation"
    SHELL_EXPANSION_REJECTED = "shell_expansion_rejected"
    CWD_OUTSIDE_ROOT = "cwd_outside_root"
    INPUT_OUTSIDE_ROOT = "input_outside_root"
    INPUT_HASH_MISMATCH = "input_hash_mismatch"
    INPUT_MISSING = "input_missing"
    OUTPUT_OUTSIDE_ROOT = "output_outside_root"
    PATH_TRAVERSAL = "path_traversal"
    OUTPUT_CONFLICT = "output_conflict"
    TIER_NOT_AVAILABLE = "tier_not_available"
    UNTRUSTED_CODE_REQUIRES_TIER2 = "untrusted_code_requires_tier2"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_MISMATCH = "approval_mismatch"
    APPROVAL_ALREADY_USED = "approval_already_used"
    GRANT_MISSING = "grant_missing"
    GRANT_INVALID = "grant_invalid"
    GRANT_EXPIRED = "grant_expired"
    GRANT_EXHAUSTED = "grant_exhausted"
    GRANT_TASK_MISMATCH = "grant_task_mismatch"
    GRANT_PROFILE_MISMATCH = "grant_profile_mismatch"
    GRANT_HOST_MISMATCH = "grant_host_mismatch"
    GRANT_PORT_MISMATCH = "grant_port_mismatch"
    GRANT_PROTOCOL_MISMATCH = "grant_protocol_mismatch"
    GRANT_ACTION_MISMATCH = "grant_action_mismatch"
    GRANT_PATH_MISMATCH = "grant_path_mismatch"
    GRANT_PRIVATE_DESTINATION = "grant_private_destination"
    REDIRECT_SCOPE_VIOLATION = "redirect_scope_violation"
    DNS_SCOPE_VIOLATION = "dns_scope_violation"
    RESOURCE_LIMIT = "resource_limit"
    NETWORK_TARGET_MISSING = "network_target_missing"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    INTERNAL_ERROR = "internal_error"


DENIAL_STATUS = "denied"
