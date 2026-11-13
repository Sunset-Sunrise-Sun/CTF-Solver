"""Authoritative evidence store: append-only hash-chained events + CAS metadata.

``EvidenceStore`` is the single authoritative event/state store for evidence.
Every appended event is linked into a per-record SHA-256 hash chain::

    record_hash = chain_hash(prev_hash, record_payload)

where ``prev_hash`` is the protected chain head before the append and the new
head is written to ``meta`` **in the same SQLite transaction** as the event row.
The chain is tamper-evident relative to that protected head — it is not a
digital signature (see docs/SECURITY.md §8). ``chain_status()`` recomputes the
whole chain from ``GENESIS_HASH`` and reports the first broken sequence.

``export_events_jsonl`` derives the deterministic JSONL export from committed
rows only; it never writes SQLite, so there is no dual-write race between the
database and a second authority.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.canonical import (
    GENESIS_HASH,
    canonical_json,
    chain_hash,
    sha256_hex,
)
from ..core.config import SolverPaths
from ..core.errors import NotFoundError, StorageError, ValidationError
from ..core.protocols import SystemClock
from ..core.types import ArtifactRef, ChainStatus, ExportInfo, ScreenshotRecord
from ..storage.db import (
    META_CHAIN_HEAD,
    META_CHAIN_HEAD_SEQ,
    get_meta,
    open_database,
    set_meta,
    transaction,
)
from .cas import Cas

_TASK_PATH_RE = re.compile(r"[\\/]tasks[\\/]([^\\/]+)[\\/]")

#: Column order used by the deterministic JSONL export.
_EVENT_COLUMNS = (
    "seq",
    "record_id",
    "task_id",
    "worker_id",
    "session_id",
    "source",
    "source_id",
    "source_seq",
    "event_type",
    "timestamp",
    "payload_json",
    "prev_hash",
    "record_hash",
    "ingested_at",
)

#: Fields that must match when the same ``record_id`` is appended again.
_SEMANTIC_FIELDS = (
    "task_id",
    "worker_id",
    "session_id",
    "source",
    "source_id",
    "source_seq",
    "event_type",
    "timestamp",
)


def _event_row_to_dict(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a SQLite ``events`` row into the public dict form."""

    payload = row["payload_json"]
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:  # pragma: no cover - corruption is surfaced by chain_status
            payload = {"__invalid_payload_json__": payload}
    return {
        "seq": int(row["seq"]),
        "record_id": row["record_id"],
        "task_id": row["task_id"],
        "worker_id": row["worker_id"],
        "session_id": row["session_id"],
        "source": row["source"],
        "source_id": row["source_id"],
        "source_seq": row["source_seq"],
        "event_type": row["event_type"],
        "timestamp": int(row["timestamp"]),
        "payload": payload,
        "prev_hash": row["prev_hash"],
        "record_hash": row["record_hash"],
        "ingested_at": int(row["ingested_at"]),
    }


def _chain_payload(
    *,
    seq: int,
    record_id: str,
    task_id: str,
    worker_id: str | None,
    session_id: str | None,
    source: str,
    source_id: str,
    source_seq: int | None,
    event_type: str,
    timestamp: int,
    payload: dict[str, Any],
    ingested_at: int,
) -> dict[str, Any]:
    """Canonical record payload hashed into the chain (no hash fields).

    Keeping ``seq`` inside the hashed payload binds record ordering: moving or
    deleting a row changes the recomputed chain at the affected sequence.
    """

    return {
        "seq": seq,
        "record_id": record_id,
        "task_id": task_id,
        "worker_id": worker_id,
        "session_id": session_id,
        "source": source,
        "source_id": source_id,
        "source_seq": source_seq,
        "event_type": event_type,
        "timestamp": timestamp,
        "payload": payload,
        "ingested_at": ingested_at,
    }


def _row_chain_payload(row: Mapping[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    return _chain_payload(
        seq=int(row["seq"]),
        record_id=row["record_id"],
        task_id=row["task_id"],
        worker_id=row["worker_id"],
        session_id=row["session_id"],
        source=row["source"],
        source_id=row["source_id"],
        source_seq=row["source_seq"],
        event_type=row["event_type"],
        timestamp=int(row["timestamp"]),
        payload=payload,
        ingested_at=int(row["ingested_at"]),
    )


class EvidenceStore(AbstractContextManager["EvidenceStore"]):
    """SQLite-backed append-only evidence store implementing ``EvidenceSink``."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        cas_root: str | os.PathLike[str],
        clock: Any | None = None,
    ) -> None:
        if not str(db_path):
            raise ValidationError("evidence database path is required")
        if not str(cas_root):
            raise ValidationError("evidence CAS root is required")
        self._db_path = Path(os.path.abspath(os.fspath(db_path)))
        self._cas = Cas(cas_root)
        self._clock = clock if clock is not None else SystemClock()
        self._conn = open_database(self._db_path)

    # -- construction / lifecycle ---------------------------------------

    @classmethod
    def from_root(cls, root: str | os.PathLike[str], *, clock: Any | None = None) -> "EvidenceStore":
        """Create a store for a CTF-Solver project root (creates the layout)."""

        paths: SolverPaths = SolverPaths.for_root(root)
        paths.ensure()
        return cls(paths.db_path, paths.cas_dir, clock=clock)

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def cas(self) -> Cas:
        return self._cas

    @property
    def connection(self) -> sqlite3.Connection:
        """Underlying connection (read-only use by tests/tooling)."""

        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None  # type: ignore[assignment]

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
        return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"EvidenceStore(db_path={str(self._db_path)!r}, cas_root={str(self._cas.root)!r})"

    # -- validation / row building --------------------------------------

    def _next_seq(self) -> int:
        row = self._conn.execute("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM events").fetchone()
        return int(row["max_seq"]) + 1

    def _build_row(self, event: Mapping[str, Any], *, ingested_at: int) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            raise ValidationError("evidence event must be a mapping")
        task_id = event.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise ValidationError("evidence event requires a non-empty task_id")
        source = event.get("source")
        if not isinstance(source, str) or not source:
            raise ValidationError("evidence event requires a non-empty source")
        event_type = event.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            raise ValidationError("evidence event requires a non-empty event_type")
        payload = event.get("payload")
        if payload is None:
            payload = {}
        if not isinstance(payload, Mapping):
            raise ValidationError("evidence event payload must be a mapping")
        payload_dict = dict(payload)
        try:
            canonical_json(payload_dict)
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                f"evidence event payload is not JSON-serializable: {exc}"
            ) from exc

        worker_id = event.get("worker_id")
        session_id = event.get("session_id")
        source_id = event.get("source_id")
        if source_id is None:
            source_id = f"{source}:{task_id}"
        if not isinstance(source_id, str) or not source_id:
            raise ValidationError("evidence event source_id must be a non-empty string")
        source_seq = event.get("source_seq")
        if source_seq is not None:
            if isinstance(source_seq, bool) or not isinstance(source_seq, int):
                raise ValidationError("evidence event source_seq must be an integer or None")
        timestamp = event.get("timestamp")
        if timestamp is None:
            timestamp = int(self._clock.now_ms())
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise ValidationError("evidence event timestamp must be an integer")

        record_id = event.get("record_id")
        if record_id is not None and (not isinstance(record_id, str) or not record_id):
            raise ValidationError("evidence event record_id must be a non-empty string or None")
        if record_id is None:
            record_id = "ev-" + sha256_hex(
                canonical_json(
                    {
                        "kind": "event",
                        "task_id": task_id,
                        "worker_id": worker_id,
                        "session_id": session_id,
                        "source": source,
                        "source_id": source_id,
                        "source_seq": source_seq,
                        "event_type": event_type,
                        "payload_sha256": sha256_hex(canonical_json(payload_dict).encode("utf-8")),
                    }
                ).encode("utf-8")
            )[:24]

        return {
            "record_id": record_id,
            "task_id": task_id,
            "worker_id": worker_id,
            "session_id": session_id,
            "source": source,
            "source_id": source_id,
            "source_seq": source_seq,
            "event_type": event_type,
            "timestamp": int(timestamp),
            "payload": payload_dict,
            "ingested_at": int(ingested_at),
        }

    @staticmethod
    def _row_matches(existing: sqlite3.Row, row: Mapping[str, Any]) -> bool:
        for field in _SEMANTIC_FIELDS:
            if existing[field] != row[field]:
                return False
        existing_payload = existing["payload_json"]
        return existing_payload == canonical_json(row["payload"])

    # -- append ---------------------------------------------------------

    def append_event(
        self,
        *,
        task_id: str,
        worker_id: str | None = None,
        session_id: str | None = None,
        source: str,
        source_id: str | None = None,
        source_seq: int | None = None,
        event_type: str,
        payload: dict[str, Any],
        timestamp: int | None = None,
        record_id: str | None = None,
    ) -> str:
        """Append one event to the hash chain and return its ``record_id``.

        Re-appending an identical event (same ``record_id`` and same semantic
        content) is idempotent and returns the existing id. Re-using a
        ``record_id`` or ``(source_id, source_seq)`` for different content fails
        closed with :class:`StorageError`.
        """

        ingested_at = int(self._clock.now_ms())
        row = self._build_row(
            {
                "task_id": task_id,
                "worker_id": worker_id,
                "session_id": session_id,
                "source": source,
                "source_id": source_id,
                "source_seq": source_seq,
                "event_type": event_type,
                "payload": payload,
                "timestamp": timestamp,
                "record_id": record_id,
            },
            ingested_at=ingested_at,
        )
        self._insert_rows([row], skip_duplicates=False)
        return row["record_id"]

    def append_events(
        self, events: Sequence[Mapping[str, Any]], *, skip_duplicates: bool = False
    ) -> list[str]:
        """Append a batch of event dicts in one transaction.

        Returns the ids that were actually appended (skipped duplicates are not
        included). With ``skip_duplicates=True`` an event whose
        ``(source_id, source_seq)`` was already ingested is skipped, which is
        what makes session-log re-ingestion idempotent.
        """

        if not events:
            return []
        ingested_at = int(self._clock.now_ms())
        rows = [self._build_row(event, ingested_at=ingested_at) for event in events]
        appended, _skipped = self._insert_rows(rows, skip_duplicates=skip_duplicates)
        return appended

    def _insert_rows(
        self, rows: Sequence[dict[str, Any]], *, skip_duplicates: bool
    ) -> tuple[list[str], list[str]]:
        appended: list[str] = []
        skipped: list[str] = []
        if not rows:
            return appended, skipped
        with transaction(self._conn):
            head = get_meta(self._conn, META_CHAIN_HEAD, GENESIS_HASH) or GENESIS_HASH
            head_seq = int(get_meta(self._conn, META_CHAIN_HEAD_SEQ, "0") or 0)
            next_seq = self._next_seq()
            for row in rows:
                existing = self._conn.execute(
                    "SELECT * FROM events WHERE record_id = ?", (row["record_id"],)
                ).fetchone()
                if existing is not None:
                    if self._row_matches(existing, row):
                        skipped.append(row["record_id"])
                        continue
                    raise StorageError(
                        "evidence record_id collision with different content; refusing to "
                        "overwrite evidence",
                        details={"record_id": row["record_id"]},
                    )
                if row["source_seq"] is not None:
                    conflicting = self._conn.execute(
                        "SELECT record_id FROM events WHERE source_id = ? AND source_seq = ?",
                        (row["source_id"], row["source_seq"]),
                    ).fetchone()
                    if conflicting is not None:
                        if skip_duplicates:
                            skipped.append(row["record_id"])
                            continue
                        raise StorageError(
                            "evidence (source_id, source_seq) already ingested with a "
                            "different record_id; refusing to append ambiguous evidence",
                            details={
                                "source_id": row["source_id"],
                                "source_seq": row["source_seq"],
                                "existing_record_id": conflicting["record_id"],
                            },
                        )
                chain_input = _chain_payload(
                    seq=next_seq,
                    record_id=row["record_id"],
                    task_id=row["task_id"],
                    worker_id=row["worker_id"],
                    session_id=row["session_id"],
                    source=row["source"],
                    source_id=row["source_id"],
                    source_seq=row["source_seq"],
                    event_type=row["event_type"],
                    timestamp=row["timestamp"],
                    payload=row["payload"],
                    ingested_at=row["ingested_at"],
                )
                record_hash = chain_hash(head, chain_input)
                self._conn.execute(
                    "INSERT INTO events("
                    "seq, record_id, task_id, worker_id, session_id, source, source_id, "
                    "source_seq, event_type, timestamp, payload_json, prev_hash, record_hash, "
                    "ingested_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        next_seq,
                        row["record_id"],
                        row["task_id"],
                        row["worker_id"],
                        row["session_id"],
                        row["source"],
                        row["source_id"],
                        row["source_seq"],
                        row["event_type"],
                        row["timestamp"],
                        canonical_json(row["payload"]),
                        head,
                        record_hash,
                        row["ingested_at"],
                    ),
                )
                appended.append(row["record_id"])
                head = record_hash
                head_seq = next_seq
                next_seq += 1
            # The protected chain head is updated in the SAME transaction as the
            # rows that extend it; a crash cannot separate the two.
            set_meta(self._conn, META_CHAIN_HEAD, head)
            set_meta(self._conn, META_CHAIN_HEAD_SEQ, str(head_seq))
        return appended, skipped

    # -- artifacts ------------------------------------------------------

    def record_artifact(self, ref: ArtifactRef, *, source: str = "") -> None:
        """Record CAS object metadata; identical rows are kept once."""

        if not isinstance(ref, ArtifactRef):
            raise ValidationError("record_artifact requires an ArtifactRef")
        self._conn.execute(
            "INSERT INTO artifacts(sha256, size, media_type, source, created_at) "
            "VALUES(?,?,?,?,?) ON CONFLICT(sha256) DO NOTHING",
            (ref.sha256, int(ref.size), ref.media_type, source, int(self._clock.now_ms())),
        )

    def store_artifact(
        self,
        data: bytes | bytearray | memoryview | str | os.PathLike[str],
        *,
        media_type: str = "application/octet-stream",
        source: str = "",
    ) -> ArtifactRef:
        """Store raw bytes (or a file path) in CAS and record its metadata."""

        if isinstance(data, (bytes, bytearray, memoryview)):
            ref = self._cas.put_bytes(bytes(data), media_type=media_type)
        elif isinstance(data, (str, os.PathLike)):
            ref = self._cas.put_file(data, media_type=media_type)
        else:
            raise ValidationError(
                f"store_artifact requires bytes or a path, not {type(data).__name__}"
            )
        self.record_artifact(ref, source=source)
        return ref

    def store_artifact_file(
        self,
        path: str | os.PathLike[str],
        *,
        media_type: str = "application/octet-stream",
        source: str = "",
    ) -> ArtifactRef:
        """Convenience wrapper: ``store_artifact`` for an existing file path."""

        return self.store_artifact(path, media_type=media_type, source=source)

    def get_artifact(self, sha256: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM artifacts WHERE sha256 = ?", (sha256,)).fetchone()
        if row is None:
            return None
        return {
            "sha256": row["sha256"],
            "size": int(row["size"]),
            "media_type": row["media_type"],
            "source": row["source"],
            "created_at": int(row["created_at"]),
        }

    def read_artifact(self, sha256: str) -> bytes:
        """Return the CAS bytes for a digest (used by the Delivery bundle builder).

        ``NotFoundError`` when the object is absent; callers decide whether a
        missing object is a hard failure or an explicit evidence gap.
        """

        return self._cas.get_bytes(sha256)

    def list_artifacts(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM artifacts ORDER BY created_at, sha256"
        ).fetchall()
        return [
            {
                "sha256": row["sha256"],
                "size": int(row["size"]),
                "media_type": row["media_type"],
                "source": row["source"],
                "created_at": int(row["created_at"]),
            }
            for row in rows
        ]

    # -- queries --------------------------------------------------------

    def list_events(
        self,
        task_id: str | None = None,
        after_seq: int | None = None,
        limit: int | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return committed events ordered by ``seq`` (payload as an object)."""

        clauses: list[str] = []
        params: list[Any] = []
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if after_seq is not None:
            clauses.append("seq > ?")
            params.append(int(after_seq))
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        if limit is not None:
            if int(limit) < 0:
                raise ValidationError("limit must be >= 0")
            sql += " LIMIT ?"
            params.append(int(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [_event_row_to_dict(row) for row in rows]

    def get_event(self, record_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return None
        return _event_row_to_dict(row)

    def count_events(self, task_id: str | None = None) -> int:
        if task_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS count FROM events").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS count FROM events WHERE task_id = ?", (task_id,)
            ).fetchone()
        return int(row["count"])

    def get_task_events_for_writeup(self, task_id: str) -> list[dict[str, Any]]:
        """Convenience for the Writeup generator: task events ordered by seq."""

        return self.list_events(task_id=task_id)

    # -- chain integrity ------------------------------------------------

    def chain_head(self) -> tuple[int, str]:
        """Return the protected ``(head_seq, head_hash)`` from ``meta``."""

        head = get_meta(self._conn, META_CHAIN_HEAD, GENESIS_HASH) or GENESIS_HASH
        head_seq = int(get_meta(self._conn, META_CHAIN_HEAD_SEQ, "0") or 0)
        return head_seq, head

    def verify_chain_anchor(self, anchor_hash: str) -> bool:
        """Return True iff ``anchor_hash`` is a record in the current intact chain.

        ``chain_head()`` is the global append position. Historic Task completion
        snapshots store the hash of their own completion event; later events may
        advance the global head, but the anchor must still exist in the valid
        chain. The chain itself is fully recomputed before accepting an anchor.
        """

        text = str(anchor_hash or "").strip().lower()
        if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
            return False
        row = self._conn.execute(
            "SELECT seq FROM events WHERE record_hash = ?", (text,)
        ).fetchone()
        if row is None:
            return False
        return bool(self.chain_status().ok)

    def chain_status(self) -> ChainStatus:
        """Recompute the whole chain and compare it with the protected head."""

        rows = self._conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        previous = GENESIS_HASH
        expected_seq = 1
        records = 0
        first_error: str = ""
        broken_at: int | None = None
        for row in rows:
            seq = int(row["seq"])
            records += 1
            payload = row["payload_json"]
            try:
                payload_obj = json.loads(payload) if isinstance(payload, str) else payload
            except json.JSONDecodeError:
                payload_obj = {"__invalid_payload_json__": payload}
            if first_error:
                previous = row["record_hash"]
                expected_seq = seq + 1
                continue
            if seq != expected_seq:
                first_error = (
                    f"sequence discontinuity at seq {seq}: expected {expected_seq} "
                    "(records were deleted or reordered)"
                )
                broken_at = seq
                previous = row["record_hash"]
                expected_seq = seq + 1
                continue
            computed = chain_hash(previous, _row_chain_payload(row, payload_obj))
            if row["prev_hash"] != previous:
                first_error = (
                    f"prev_hash mismatch at seq {seq}: stored {str(row['prev_hash'])[:12]}… "
                    f"does not link to previous record hash {previous[:12]}…"
                )
                broken_at = seq
            elif row["record_hash"] != computed:
                first_error = (
                    f"record_hash mismatch at seq {seq}: stored {str(row['record_hash'])[:12]}… "
                    f"does not match recomputed {computed[:12]}…"
                )
                broken_at = seq
            previous = row["record_hash"]
            expected_seq = seq + 1

        computed_head = previous
        meta_seq, meta_head = self.chain_head()
        last_seq = int(rows[-1]["seq"]) if rows else 0
        head_error: str = ""
        if meta_head != computed_head:
            if meta_seq > last_seq:
                head_error = (
                    f"chain head mismatch: protected meta head is at seq {meta_seq} but the "
                    f"events table ends at seq {last_seq} (records were truncated)"
                )
            else:
                head_error = (
                    "chain head mismatch: protected meta head "
                    f"{meta_head[:12]}… does not match recomputed head {computed_head[:12]}…"
                )
        elif meta_seq != last_seq:
            head_error = (
                f"chain head sequence mismatch: protected meta seq {meta_seq} but events "
                f"table ends at seq {last_seq}"
            )
        if not first_error and head_error:
            first_error = head_error
        ok = not first_error
        return ChainStatus(
            ok=ok,
            records=records,
            head_hash=computed_head,
            error=first_error,
            broken_at_seq=broken_at,
        )

    # -- deterministic export ------------------------------------------

    def export_events_jsonl(
        self,
        *,
        task_id: str,
        out_path: str | os.PathLike[str],
        privacy_filtered: bool = True,
    ) -> ExportInfo:
        """Write a deterministic ``events.jsonl`` export for one task.

        Rows are read from committed SQLite state only, rendered as canonical
        JSON (sorted keys, compact separators) in ``seq`` order with a trailing
        LF. The same database state always produces byte-identical output, and
        this method performs **no SQLite writes**.

        By default the export is the delivery privacy projection
        (:func:`ctf_solver.delivery.privacy.filter_events`): model reasoning,
        passthrough payloads and Skill bodies never reach the file. Passing
        ``privacy_filtered=False`` exports the raw committed rows and is reserved
        for internal tests/tooling; it is not a delivery surface.
        """

        if not isinstance(task_id, str) or not task_id:
            raise ValidationError("export_events_jsonl requires a task_id")
        target = Path(os.path.abspath(os.fspath(out_path)))
        target.parent.mkdir(parents=True, exist_ok=True)
        rows = self.list_events(task_id=task_id)
        if privacy_filtered:
            # Lazy import: ``delivery`` imports the evidence types, so a
            # module-level import would create an import cycle.
            from ..delivery.privacy import filter_events

            rows = filter_events(rows)
        chunks: list[str] = []
        for row in rows:
            chunks.append(canonical_json(row))
            chunks.append("\n")
        data = "".join(chunks).encode("utf-8")
        tmp_path = target.parent / f".{target.name}.{os.getpid()}.tmp"
        try:
            with open(tmp_path, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
        except OSError as exc:  # pragma: no cover - disk failure path
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise StorageError(f"failed to write events export: {exc}") from exc
        return ExportInfo(
            kind="events_jsonl",
            path=str(target),
            sha256=sha256_hex(data),
            size=len(data),
            entries=len(rows),
        )

    # -- screenshots / exports / ingestion watermarks -------------------

    def record_screenshot(self, record: ScreenshotRecord) -> None:
        if not isinstance(record, ScreenshotRecord):
            raise ValidationError("record_screenshot requires a ScreenshotRecord")
        try:
            self._conn.execute(
                "INSERT INTO screenshots("
                "screenshot_id, task_id, worker_id, step_id, session_id, scope, captured_at, "
                "sha256, width, height, status, failure_reason, media_type, execution_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(screenshot_id) DO UPDATE SET "
                "task_id=excluded.task_id, worker_id=excluded.worker_id, "
                "step_id=excluded.step_id, session_id=excluded.session_id, "
                "scope=excluded.scope, captured_at=excluded.captured_at, "
                "sha256=excluded.sha256, width=excluded.width, height=excluded.height, "
                "status=excluded.status, failure_reason=excluded.failure_reason, "
                "media_type=excluded.media_type, execution_id=excluded.execution_id",
                (
                    record.screenshot_id,
                    record.task_id,
                    record.worker_id,
                    record.step_id,
                    record.session_id,
                    record.scope,
                    int(record.captured_at),
                    record.sha256,
                    record.width,
                    record.height,
                    record.status.value,
                    record.failure_reason or "",
                    record.media_type,
                    record.execution_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StorageError(
                f"cannot record screenshot {record.screenshot_id!r} for task "
                f"{record.task_id!r}: {exc}",
                details={"screenshot_id": record.screenshot_id, "task_id": record.task_id},
            ) from exc

    def list_screenshots(self, task_id: str) -> list[ScreenshotRecord]:
        rows = self._conn.execute(
            "SELECT * FROM screenshots WHERE task_id = ? "
            "ORDER BY captured_at, screenshot_id",
            (task_id,),
        ).fetchall()
        return [ScreenshotRecord.from_row(row) for row in rows]

    def get_screenshot(self, screenshot_id: str) -> ScreenshotRecord | None:
        row = self._conn.execute(
            "SELECT * FROM screenshots WHERE screenshot_id = ?", (screenshot_id,)
        ).fetchone()
        return ScreenshotRecord.from_row(row) if row is not None else None

    @staticmethod
    def _derive_task_id(path: str) -> str:
        match = _TASK_PATH_RE.search(path.replace("\\", "/"))
        return match.group(1) if match else ""

    def record_export(self, info: ExportInfo, *, task_id: str | None = None) -> str:
        """Record one generated deliverable in the ``exports`` ledger."""

        if not isinstance(info, ExportInfo):
            raise ValidationError("record_export requires an ExportInfo")
        path = os.path.abspath(info.path)
        resolved_task = task_id if task_id is not None else self._derive_task_id(path)
        export_id = "exp-" + sha256_hex(
            f"{info.kind}|{path}|{info.sha256}".encode("utf-8")
        )[:24]
        self._conn.execute(
            "INSERT INTO exports(export_id, task_id, kind, path, sha256, created_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(export_id) DO UPDATE SET "
            "task_id=excluded.task_id, kind=excluded.kind, path=excluded.path, "
            "sha256=excluded.sha256, created_at=excluded.created_at",
            (
                export_id,
                resolved_task,
                info.kind,
                path,
                info.sha256,
                int(self._clock.now_ms()),
            ),
        )
        return export_id

    def list_exports(self, task_id: str | None = None) -> list[dict[str, Any]]:
        if task_id is None:
            rows = self._conn.execute(
                "SELECT * FROM exports ORDER BY created_at, export_id"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM exports WHERE task_id = ? ORDER BY created_at, export_id",
                (task_id,),
            ).fetchall()
        return [
            {
                "export_id": row["export_id"],
                "task_id": row["task_id"],
                "kind": row["kind"],
                "path": row["path"],
                "sha256": row["sha256"],
                "created_at": int(row["created_at"]),
            }
            for row in rows
        ]

    def record_ingestion(
        self,
        source_id: str,
        *,
        task_id: str,
        session_id: str | None = None,
        last_seq: int = -1,
        sha256: str = "",
        raw_sha256: str | None = None,
        frames: int = 0,
        records: int = 0,
        gaps: int = 0,
    ) -> None:
        """Upsert the ``ingestion_sources`` watermark for one source.

        ``last_seq`` is monotonic: a re-ingestion never lowers the watermark.
        """

        if not source_id:
            raise ValidationError("source_id is required")
        now = int(self._clock.now_ms())
        with transaction(self._conn):
            existing = self._conn.execute(
                "SELECT * FROM ingestion_sources WHERE source_id = ?", (source_id,)
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO ingestion_sources("
                    "source_id, task_id, session_id, last_seq, sha256, raw_sha256, frames, "
                    "records, gaps, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        source_id,
                        task_id,
                        session_id,
                        int(last_seq),
                        sha256,
                        raw_sha256,
                        int(frames),
                        int(records),
                        int(gaps),
                        now,
                    ),
                )
                return
            new_last_seq = max(int(existing["last_seq"]), int(last_seq))
            self._conn.execute(
                "UPDATE ingestion_sources SET task_id = ?, session_id = ?, last_seq = ?, "
                "sha256 = ?, raw_sha256 = ?, frames = ?, records = ?, gaps = ?, "
                "updated_at = ? WHERE source_id = ?",
                (
                    task_id,
                    session_id,
                    new_last_seq,
                    sha256,
                    raw_sha256,
                    int(frames),
                    int(records),
                    int(gaps),
                    now,
                    source_id,
                ),
            )

    def ingest_state(self, source_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM ingestion_sources WHERE source_id = ?", (source_id,)
        ).fetchone()
        if row is None:
            return None
        return self._ingestion_row_to_dict(row)

    def ingestion_sources(self, task_id: str) -> list[dict[str, Any]]:
        """Return ingestion watermarks for one Task (used by the evidence bundle)."""

        rows = self._conn.execute(
            "SELECT * FROM ingestion_sources WHERE task_id = ? ORDER BY updated_at, source_id",
            (task_id,),
        ).fetchall()
        return [self._ingestion_row_to_dict(row) for row in rows]

    @staticmethod
    def _ingestion_row_to_dict(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "source_id": row["source_id"],
            "task_id": row["task_id"],
            "session_id": row["session_id"],
            "last_seq": int(row["last_seq"]),
            "sha256": row["sha256"],
            "raw_sha256": row["raw_sha256"],
            "frames": int(row["frames"]),
            "records": int(row["records"]),
            "gaps": int(row["gaps"]),
            "updated_at": int(row["updated_at"]),
        }

    # -- ingestion delegates (implement INTERFACES §4.5) -----------------

    def ingest_session_log_bytes(
        self,
        *,
        task_id: str,
        worker_id: str | None,
        session_id: str | None,
        data: bytes,
        source_id: str,
        path: str | None = None,
        boundary: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Ingest raw ``.jsonl.zstd`` bytes; returns a JSON-serializable report."""

        from .ingest import Ingestor

        report = Ingestor(self, self._cas).ingest_session_log_bytes(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            data=data,
            source_id=source_id,
            path=path,
            boundary=boundary,
        )
        return report.to_dict()

    def ingest_session_log_file(
        self,
        *,
        task_id: str,
        worker_id: str | None,
        session_id: str | None,
        path: str | os.PathLike[str],
        source_id: str | None = None,
        boundary: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Ingest a session-log file; returns a JSON-serializable report."""

        from .ingest import Ingestor

        report = Ingestor(self, self._cas).ingest_session_log_file(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            path=path,
            source_id=source_id,
            boundary=boundary,
        )
        return report.to_dict()


__all__ = ["EvidenceStore"]
