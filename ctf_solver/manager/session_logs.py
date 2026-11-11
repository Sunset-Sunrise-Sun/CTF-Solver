"""Manager-registry-only resolution of Harness session logs (Round 2 section 3.1).

The Manager never accepts a model- or caller-supplied path for evidence
ingestion. ``SessionLogResolver`` maps a **registered** ``task_id`` (and
optionally a registered ``worker_id``) to the exact Harness session log using
the audited on-disk layout only:

    <sessions_root>/<cwd-slug>/<sessionId>/session.v4.jsonl.zstd

Two log roots exist and are deliberately separate:

* ``sessions_root`` — the managed, isolated Harness home that only ever holds
  Worker sessions;
* ``lead_sessions_root`` — the live Harness sessions root used for a Task's
  one-time, explicit Lead-session binding. It is configured explicitly (never
  derived from the managed home) and must already exist.

Security rules implemented here (fail closed, stable ``reason_code`` values):

* only the Manager registry selects the path (there is no path argument at all);
* the sessions root must exist and must not itself be a link;
* every path component between the root and the log must be a real directory
  (symlinks *and* NTFS junctions/reparse points are rejected);
* the resolved path must stay inside the root (``realpath`` containment);
* exactly one log must match (zero -> ``log_missing``, many -> ``ambiguous_session_log``);
* the log content must prove its identity: the first decoded JSON record must be
  the Harness session header whose ``data.id`` (or top-level ``id``) equals the
  registered ``sessionId``. Nothing about the payload is trusted before that;
* a Lead log additionally has to be bound to the Task (``no_binding``) and its
  header ``cwd`` has to realpath-equal the Manager workspace root
  (``lead_cwd_mismatch``) whenever that root is supplied.

The registration data itself is untrusted input from the resolver's point of
view: a registered/bound ``sessionId`` must be a single safe path component, so
a tampered registry row cannot traverse directories or address system files.

``source="auto"`` follows the clarified Round 1 rule: an explicit Lead binding
wins over the shell-only Worker session that a Lead-bound Task may also own; a
Worker log is used only when the Task has no Lead binding. ``source="worker"``
keeps the pre-existing worker-only behaviour exactly.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.errors import ConfigError, CtfSolverError, ValidationError
from ..core.protocols import Clock
from ..evidence.zstd_frames import decode_all, iter_payload_segments, parse_json_lines
from .store import ManagerStore

#: Exact file name written by the audited Harness version (v4 JSONL, multi-frame zstd).
SESSION_LOG_FILENAME = "session.v4.jsonl.zstd"

#: Stable reason codes (docs/ROUND_2_INTERFACES.md section 3.1 + Round 1 Lead binding).
REASON_UNKNOWN_TASK = "unknown_task"
REASON_NO_WORKER = "no_worker"
REASON_UNKNOWN_SESSION = "unknown_session"
REASON_LOG_MISSING = "log_missing"
REASON_AMBIGUOUS_SESSION_LOG = "ambiguous_session_log"
REASON_SYMLINK_REJECTED = "symlink_rejected"
REASON_PATH_ESCAPE = "path_escape"
REASON_HEADER_MISMATCH = "header_mismatch"
REASON_SESSIONS_ROOT_MISSING = "sessions_root_missing"
REASON_NO_BINDING = "no_binding"
REASON_LEAD_CWD_MISMATCH = "lead_cwd_mismatch"
REASON_LEAD_ROOT_MISSING = "lead_sessions_root_missing"

#: All stable reason codes (useful to callers building a diagnostics surface).
REASON_CODES: frozenset[str] = frozenset(
    {
        REASON_UNKNOWN_TASK,
        REASON_NO_WORKER,
        REASON_UNKNOWN_SESSION,
        REASON_LOG_MISSING,
        REASON_AMBIGUOUS_SESSION_LOG,
        REASON_SYMLINK_REJECTED,
        REASON_PATH_ESCAPE,
        REASON_HEADER_MISMATCH,
        REASON_SESSIONS_ROOT_MISSING,
        REASON_NO_BINDING,
        REASON_LEAD_CWD_MISMATCH,
        REASON_LEAD_ROOT_MISSING,
    }
)

#: Accepted ``source`` selectors for :meth:`SessionLogResolver.resolve`.
RESOLVE_SOURCES: frozenset[str] = frozenset({"auto", "worker", "lead"})

#: Session ids are UUIDs / synthetic test ids: one safe path component only.
_MAX_SESSION_COMPONENT = 128


class SessionLogError(CtfSolverError):
    """A session log could not be resolved safely.

    ``reason_code`` is one of :data:`REASON_CODES`; the base exception's
    ``to_dict`` exposes it for MCP/IPC callers without string matching.
    """

    reason_code = "session_log_error"

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        if reason_code not in REASON_CODES:  # pragma: no cover - internal misuse
            raise ValueError(f"unknown session-log reason code: {reason_code!r}")
        super().__init__(message, details=details)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ResolvedSessionLog:
    """The single registered session log for a Task (Worker or Lead source)."""

    task_id: str
    worker_id: str | None
    session_id: str
    path: Path
    source: str = "worker"

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "session_id": self.session_id,
            "path": str(self.path),
            "source": self.source,
        }


def _is_link_like(path: Path) -> bool:
    """True for symlinks and Windows junction/reparse points.

    ``Path.is_symlink`` is False for NTFS junctions, so the resolver also checks
    ``Path.is_junction`` (Python >= 3.12 on Windows) to keep junction escapes
    from being treated as ordinary directories.
    """

    try:
        if path.is_symlink():
            return True
    except OSError:  # pragma: no cover - defensive
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:  # pragma: no cover - defensive
            return True
    return False


def _component_is_safe(value: Any) -> bool:
    """Return True when ``value`` is a single safe path component (no traversal)."""

    if not isinstance(value, str) or not value:
        return False
    if len(value) > _MAX_SESSION_COMPONENT:
        return False
    if value in (".", ".."):
        return False
    if value != value.strip():
        return False
    if any(char in value for char in ("/", "\\", "\x00", ":")):
        return False
    if os.path.isabs(value) or os.path.splitdrive(value)[0]:
        return False
    return not any(ord(char) < 0x20 for char in value)


def _contained_within_root(root: Path, candidate: Path) -> bool:
    """``realpath`` containment check used before any file is read."""

    try:
        root_real = os.path.normcase(os.path.realpath(root))
        candidate_real = os.path.normcase(os.path.realpath(candidate))
        return os.path.commonpath([root_real, candidate_real]) == root_real
    except (OSError, ValueError):  # pragma: no cover - different drives etc.
        return False


def _symlink_in_path(root: Path, candidate: Path) -> Path | None:
    """Return the first link-like component from ``root`` down, else ``None``."""

    if _is_link_like(root):
        return root
    try:
        relative = candidate.relative_to(root)
    except ValueError:  # pragma: no cover - containment is checked separately
        return candidate
    current = root
    for part in relative.parts:
        current = current / part
        if _is_link_like(current):
            return current
    return None


def _header_session_id(record: dict[str, Any]) -> Any:
    """Extract the header session id from the real v4 envelope or a flat header."""

    data = record.get("data")
    if isinstance(data, dict) and "id" in data:
        return data.get("id")
    return record.get("id")


def _header_cwd(record: dict[str, Any]) -> Any:
    """Extract the header ``cwd`` from the real v4 envelope or a flat header."""

    data = record.get("data")
    if isinstance(data, dict) and "cwd" in data:
        return data.get("cwd")
    return record.get("cwd")


def _optional_absolute_path(value: Path | str | None) -> Path | None:
    """Normalise an optional config path; blanks and ``None`` stay ``None``."""

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return Path(os.path.abspath(os.fspath(text)))


class SessionLogResolver:
    """Resolve one registered Task session log without model-supplied paths.

    ``sessions_root`` is ``<DSH_HOME>/sessions`` of the *managed, isolated*
    Harness home (Worker logs). ``lead_sessions_root`` is the explicitly
    configured live Harness sessions root used for a Task's one-time Lead
    binding; ``workspace_root`` is the Manager root that a Lead header ``cwd``
    has to match. ``store`` is the authoritative Manager registry. ``clock`` is
    accepted for interface symmetry and does not influence resolution.
    """

    def __init__(
        self,
        sessions_root: Path | str,
        store: ManagerStore,
        *,
        lead_sessions_root: Path | str | None = None,
        workspace_root: Path | str | None = None,
        clock: Clock | None = None,
    ) -> None:
        if sessions_root is None or not str(sessions_root).strip():
            raise ConfigError("SessionLogResolver requires a non-empty sessions_root")
        self.sessions_root = Path(os.path.abspath(os.fspath(sessions_root)))
        self.store = store
        self.clock = clock
        self.lead_sessions_root = _optional_absolute_path(lead_sessions_root)
        self.workspace_root = _optional_absolute_path(workspace_root)

    # -- public API -----------------------------------------------------

    def resolve(
        self, task_id: str, *, worker_id: str | None = None, source: str = "auto"
    ) -> ResolvedSessionLog:
        """Resolve the single session log for ``task_id`` from a registry choice.

        ``source="worker"`` is the pre-existing worker-only behaviour,
        ``source="lead"`` uses only the Task's one-time Lead binding, and
        ``source="auto"`` prefers a Lead binding when present (explicit opt-in)
        and otherwise falls back to the registered Worker log. An unknown
        source is a caller error (:class:`ValidationError`).

        Raises :class:`SessionLogError` with a stable ``reason_code`` on any
        registry, filesystem or content-identity failure. The API deliberately
        has **no** path parameter: callers cannot point the resolver at an
        arbitrary file.
        """

        if source not in RESOLVE_SOURCES:
            raise ValidationError(
                f"unsupported session log source {source!r}; expected one of "
                f"{', '.join(sorted(RESOLVE_SOURCES))}"
            )
        if source == "worker":
            return self._resolve_worker(task_id, worker_id=worker_id)
        if source == "lead":
            return self._resolve_lead(task_id)

        # auto: an explicit Lead binding wins over the shell-only Worker that a
        # Lead-bound Task may also own; an explicit worker_id keeps the caller's
        # worker-only selection.
        task = self._require_task(task_id)
        binding = self._get_binding(task.task_id)
        if binding is not None and worker_id is None:
            return self._resolve_lead(task.task_id, task=task, binding=binding)
        return self._resolve_worker(task.task_id, worker_id=worker_id)

    def validate_lead_candidate(
        self, session_id: str
    ) -> tuple[str, Path, str | None]:
        """Validate a Lead-supplied session id **before** it is bound.

        The candidate must be a single safe path component, exactly one log must
        exist for it under :attr:`lead_sessions_root`, every component must be a
        real directory inside that root, and the decoded session header must
        identify ``session_id`` and (when ``workspace_root`` is configured) real
        path-equal the Manager root.

        Returns ``(session_id, path, log_sha256)`` where ``log_sha256`` is the
        SHA-256 of the current raw log bytes. No binding is read or required:
        callers persist the returned digest *after* validating, and the binding
        checks themselves live in the resolution helpers.
        """

        if not _component_is_safe(session_id):
            raise SessionLogError(
                "Lead session id is not a safe path component",
                reason_code=REASON_UNKNOWN_SESSION,
                details={"session_id": session_id},
            )
        root = self._require_lead_sessions_root()
        path = self._locate_unique_log(root, session_id)
        data = self._verify_header(path, session_id, lead=True)
        return session_id, path, hashlib.sha256(data).hexdigest()

    # -- resolution branches --------------------------------------------

    def _resolve_worker(
        self, task_id: str, *, worker_id: str | None = None
    ) -> ResolvedSessionLog:
        task = self._require_task(task_id)
        worker = self._require_worker(task_id, worker_id=worker_id)
        session_id = self._require_session_id(task, worker)
        root = self._require_sessions_root()
        path = self._locate_unique_log(root, session_id)

        self._verify_header(path, session_id)
        return ResolvedSessionLog(
            task_id=task.task_id,
            worker_id=worker.worker_id,
            session_id=session_id,
            path=path,
            source="worker",
        )

    def _resolve_lead(
        self, task_id: str, *, task: Any = None, binding: Any = None
    ) -> ResolvedSessionLog:
        task = task if task is not None else self._require_task(task_id)
        root = self._require_lead_sessions_root()
        binding = binding if binding is not None else self._get_binding(task.task_id)
        if binding is None:
            raise SessionLogError(
                f"Task {task.task_id} has no bound Lead session",
                reason_code=REASON_NO_BINDING,
                details={"task_id": task.task_id},
            )
        session_id = binding.session_id
        if not _component_is_safe(session_id):
            raise SessionLogError(
                "bound Lead session id is not a safe path component",
                reason_code=REASON_UNKNOWN_SESSION,
                details={"session_id": session_id},
            )
        path = self._locate_unique_log(root, session_id)
        self._verify_header(path, session_id, lead=True)
        return ResolvedSessionLog(
            task_id=task.task_id,
            worker_id=None,
            session_id=session_id,
            path=path,
            source="lead",
        )

    def _get_binding(self, task_id: str) -> Any:
        get_lead_binding = getattr(self.store, "get_lead_binding", None)
        return get_lead_binding(task_id) if callable(get_lead_binding) else None

    # -- registry -------------------------------------------------------

    def _require_task(self, task_id: str):
        if not isinstance(task_id, str) or not task_id:
            raise SessionLogError(
                "a session log can only be resolved for an existing Task",
                reason_code=REASON_UNKNOWN_TASK,
                details={"task_id": task_id},
            )
        task = self.store.get_task(task_id)
        if task is None:
            raise SessionLogError(
                f"unknown task: {task_id}",
                reason_code=REASON_UNKNOWN_TASK,
                details={"task_id": task_id},
            )
        return task

    def _require_worker(self, task_id: str, *, worker_id: str | None):
        get_worker_for_task = getattr(self.store, "get_worker_for_task", None)
        worker = get_worker_for_task(task_id) if callable(get_worker_for_task) else None
        if worker is None:
            raise SessionLogError(
                f"Task {task_id} has no registered Worker mapping",
                reason_code=REASON_NO_WORKER,
                details={"task_id": task_id},
            )
        if worker.task_id != task_id:  # pragma: no cover - registry consistency guard
            raise SessionLogError(
                f"registered Worker {worker.worker_id} does not belong to Task {task_id}",
                reason_code=REASON_NO_WORKER,
                details={"task_id": task_id, "worker_id": worker.worker_id},
            )
        if worker_id is not None and worker.worker_id != worker_id:
            raise SessionLogError(
                f"Task {task_id} is not mapped to Worker {worker_id!r}",
                reason_code=REASON_NO_WORKER,
                details={
                    "task_id": task_id,
                    "requested_worker_id": worker_id,
                    "registered_worker_id": worker.worker_id,
                },
            )
        return worker

    def _require_session_id(self, task, worker) -> str:
        session_id = worker.acp_session_id
        if not isinstance(session_id, str) or not session_id:
            raise SessionLogError(
                f"Worker {worker.worker_id} has no registered ACP session id",
                reason_code=REASON_UNKNOWN_SESSION,
                details={"task_id": task.task_id, "worker_id": worker.worker_id},
            )
        if not _component_is_safe(session_id):
            raise SessionLogError(
                "registered ACP session id is not a safe path component",
                reason_code=REASON_UNKNOWN_SESSION,
                details={"session_id": session_id},
            )
        task_session = getattr(task, "acp_session_id", None)
        if task_session is not None and task_session != session_id:
            raise SessionLogError(
                "Task and Worker registries disagree on the ACP session id",
                reason_code=REASON_UNKNOWN_SESSION,
                details={
                    "task_id": task.task_id,
                    "task_session_id": task_session,
                    "worker_session_id": session_id,
                },
            )
        return session_id

    # -- filesystem -----------------------------------------------------

    def _require_sessions_root(self) -> Path:
        root = self.sessions_root
        if _is_link_like(root):
            raise SessionLogError(
                "the sessions root is a symlink or junction; refusing to resolve",
                reason_code=REASON_SYMLINK_REJECTED,
                details={"sessions_root": str(root)},
            )
        try:
            exists = root.exists()
            is_dir = root.is_dir()
        except OSError as exc:  # pragma: no cover - defensive
            raise SessionLogError(
                "the sessions root cannot be inspected",
                reason_code=REASON_SESSIONS_ROOT_MISSING,
                details={"sessions_root": str(root), "error": str(exc)},
            ) from exc
        if not exists or not is_dir:
            raise SessionLogError(
                "the configured sessions root does not exist or is not a directory",
                reason_code=REASON_SESSIONS_ROOT_MISSING,
                details={"sessions_root": str(root), "exists": exists, "is_dir": is_dir},
            )
        return root

    def _require_lead_sessions_root(self) -> Path:
        root = self.lead_sessions_root
        if root is None:
            raise SessionLogError(
                "no Lead sessions root is configured",
                reason_code=REASON_LEAD_ROOT_MISSING,
                details={"lead_sessions_root": None},
            )
        if _is_link_like(root):
            raise SessionLogError(
                "the Lead sessions root is a symlink or junction; refusing to resolve",
                reason_code=REASON_SYMLINK_REJECTED,
                details={"lead_sessions_root": str(root)},
            )
        try:
            exists = root.exists()
            is_dir = root.is_dir()
        except OSError as exc:  # pragma: no cover - defensive
            raise SessionLogError(
                "the Lead sessions root cannot be inspected",
                reason_code=REASON_LEAD_ROOT_MISSING,
                details={"lead_sessions_root": str(root), "error": str(exc)},
            ) from exc
        if not exists or not is_dir:
            raise SessionLogError(
                "the configured Lead sessions root does not exist or is not a directory",
                reason_code=REASON_LEAD_ROOT_MISSING,
                details={
                    "lead_sessions_root": str(root),
                    "exists": exists,
                    "is_dir": is_dir,
                },
            )
        return root

    def _locate_unique_log(self, root: Path, session_id: str) -> Path:
        """Find and prove the single log for ``session_id`` under ``root``."""

        matches, link_hits = self._scan(root, session_id)
        if link_hits:
            raise SessionLogError(
                "session log path contains a symlink or junction; refusing to resolve",
                reason_code=REASON_SYMLINK_REJECTED,
                details={"paths": [str(path) for path in link_hits]},
            )
        if not matches:
            raise SessionLogError(
                f"no session log for registered session {session_id!r} under the sessions root",
                reason_code=REASON_LOG_MISSING,
                details={"session_id": session_id, "sessions_root": str(root)},
            )
        if len(matches) > 1:
            raise SessionLogError(
                f"registered session {session_id!r} has multiple on-disk logs",
                reason_code=REASON_AMBIGUOUS_SESSION_LOG,
                details={"session_id": session_id, "paths": [str(path) for path in matches]},
            )

        path = matches[0]
        if not _contained_within_root(root, path):
            raise SessionLogError(
                "resolved session log escapes the sessions root",
                reason_code=REASON_PATH_ESCAPE,
                details={"sessions_root": str(root), "path": str(path)},
            )
        escaped_component = _symlink_in_path(root, path)
        if escaped_component is not None:
            raise SessionLogError(
                "resolved session log path contains a symlink or junction",
                reason_code=REASON_SYMLINK_REJECTED,
                details={"component": str(escaped_component), "path": str(path)},
            )
        return path

    def _scan(self, root: Path, session_id: str) -> tuple[list[Path], list[Path]]:
        """Find exact ``<root>/<slug>/<session_id>/session.v4.jsonl.zstd`` files."""

        try:
            children = sorted(root.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            raise SessionLogError(
                "the sessions root cannot be enumerated",
                reason_code=REASON_SESSIONS_ROOT_MISSING,
                details={"sessions_root": str(root), "error": str(exc)},
            ) from exc

        matches: list[Path] = []
        link_hits: list[Path] = []

        for slug in children:
            if _is_link_like(slug):
                through_link = slug / session_id / SESSION_LOG_FILENAME
                if os.path.lexists(through_link):
                    link_hits.append(through_link)
                continue
            try:
                if not slug.is_dir():
                    continue
            except OSError:  # pragma: no cover - defensive
                continue

            session_dir = slug / session_id
            if _is_link_like(session_dir):
                if os.path.lexists(session_dir):
                    link_hits.append(session_dir)
                continue
            try:
                if not session_dir.is_dir():
                    continue
            except OSError:  # pragma: no cover - defensive
                continue

            log_path = session_dir / SESSION_LOG_FILENAME
            if _is_link_like(log_path):
                link_hits.append(log_path)
                continue
            try:
                if log_path.is_file():
                    matches.append(log_path)
            except OSError:  # pragma: no cover - defensive
                continue

        return matches, link_hits

    # -- content identity ----------------------------------------------

    def _verify_header(self, path: Path, session_id: str, *, lead: bool = False) -> bytes:
        """Require the first decoded session header to identify ``session_id``.

        For a Lead log (``lead=True``) the header ``cwd`` must additionally
        realpath-equal the configured Manager workspace root; when no workspace
        root was supplied the cwd check is skipped (the caller is expected to
        supply it in production wiring). Returns the raw log bytes so callers
        can hash exactly what was verified.
        """

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SessionLogError(
                "the registered session log became unreadable",
                reason_code=REASON_LOG_MISSING,
                details={"path": str(path), "error": str(exc)},
            ) from exc

        # ``UnsupportedCompressionError`` (no zstd backend) intentionally
        # propagates: that is an environment BLOCKED state, not a forged log.
        report = decode_all(data)
        if not report.frames:
            raise SessionLogError(
                "the registered session log contains no zstd frames",
                reason_code=REASON_HEADER_MISMATCH,
                details={"path": str(path)},
            )

        first_record: dict[str, Any] | None = None
        for segment in iter_payload_segments(report):
            records, _gaps = parse_json_lines(segment.payload)
            if records:
                first_record = records[0]
                break
        if first_record is None:
            raise SessionLogError(
                "the registered session log has no parsable JSON-Lines header",
                reason_code=REASON_HEADER_MISMATCH,
                details={"path": str(path)},
            )

        record_type = first_record.get("type")
        if record_type not in (None, "session"):
            raise SessionLogError(
                f"first session-log record is {record_type!r}, not the session header",
                reason_code=REASON_HEADER_MISMATCH,
                details={"path": str(path), "record_type": record_type},
            )
        header_id = _header_session_id(first_record)
        if not isinstance(header_id, str) or header_id != session_id:
            raise SessionLogError(
                "session-log header id does not match the registered ACP session id",
                reason_code=REASON_HEADER_MISMATCH,
                details={
                    "path": str(path),
                    "registered_session_id": session_id,
                    "header_session_id": header_id,
                },
            )
        if lead and self.workspace_root is not None:
            header_cwd = _header_cwd(first_record)
            if not _cwd_matches(header_cwd, self.workspace_root):
                raise SessionLogError(
                    "Lead session header cwd does not match the Manager workspace root",
                    reason_code=REASON_LEAD_CWD_MISMATCH,
                    details={
                        "path": str(path),
                        "header_cwd": header_cwd,
                        "workspace_root": str(self.workspace_root),
                    },
                )
        return data


def _cwd_matches(header_cwd: Any, workspace_root: Path) -> bool:
    """True when ``header_cwd`` realpath-equals ``workspace_root`` (normcase)."""

    if not isinstance(header_cwd, str) or not header_cwd.strip():
        return False
    try:
        header_real = os.path.normcase(os.path.realpath(header_cwd))
        workspace_real = os.path.normcase(os.path.realpath(workspace_root))
    except (OSError, ValueError):  # pragma: no cover - defensive
        return False
    return header_real == workspace_real
