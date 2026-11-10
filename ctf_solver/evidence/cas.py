"""SHA-256 content-addressed artifact store.

Layout: ``<root>/<sha[:2]>/<sha256>`` so every object path is derived from its
own content hash. Objects are immutable: an existing object is never rewritten,
and a put that finds a corrupt object fails closed instead of silently keeping
bad evidence. The store itself is plain filesystem state; SQLite metadata
(``artifacts``) is owned by :mod:`ctf_solver.evidence.store`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

from ..core.canonical import sha256_hex
from ..core.errors import NotFoundError, StorageError, ValidationError
from ..core.types import ArtifactRef

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MEDIA_TYPE = "application/octet-stream"


def validate_sha256(value: str) -> str:
    """Return ``value`` when it is a canonical lowercase SHA-256 hex digest."""

    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise ValidationError(f"invalid SHA-256 digest: {value!r}")
    return value


class Cas:
    """Content-addressed store for raw evidence and artifact bytes."""

    def __init__(self, root_dir: str | os.PathLike[str]) -> None:
        if root_dir is None or str(root_dir) == "":
            raise ValidationError("CAS root directory is required")
        self.root = Path(os.path.abspath(os.fspath(root_dir)))

    # -- layout ---------------------------------------------------------

    def path_for(self, sha256: str) -> Path:
        """Return the object path for a digest (no existence requirement)."""

        digest = validate_sha256(sha256)
        return self.root / digest[:2] / digest

    def exists(self, sha256: str) -> bool:
        try:
            path = self.path_for(sha256)
        except ValidationError:
            return False
        return path.is_file()

    def size_for(self, sha256: str) -> int:
        path = self.path_for(sha256)
        if not path.is_file():
            raise NotFoundError(f"CAS object not found: {sha256}")
        return path.stat().st_size

    # -- writes ---------------------------------------------------------

    def put_bytes(
        self, data: bytes | bytearray | memoryview, media_type: str = DEFAULT_MEDIA_TYPE
    ) -> ArtifactRef:
        """Store ``data`` and return its content-addressed reference.

        Identical bytes deduplicate to one object; an existing object is never
        mutated. If the on-disk object no longer matches its digest the write
        fails closed with :class:`StorageError` (corruption must be surfaced,
        not overwritten).
        """

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"CAS put_bytes requires bytes, not {type(data).__name__}")
        raw = bytes(data)
        digest = sha256_hex(raw)
        path = self.path_for(digest)
        media = media_type or DEFAULT_MEDIA_TYPE

        if path.is_file():
            # Dedup: never rewrite an existing object, but never trust it either.
            existing = path.read_bytes()
            if existing != raw:
                raise StorageError(
                    "CAS object content does not match its digest; refusing to "
                    "silently overwrite corrupt evidence",
                    details={"sha256": digest, "path": str(path)},
                )
            return ArtifactRef(
                sha256=digest, size=len(raw), media_type=media, cas_path=str(path)
            )

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.parent / f".{digest}.{os.getpid()}.tmp"
        try:
            with open(tmp_path, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            # ``os.replace`` is atomic; an existing object would only be replaced
            # by identical bytes (checked above), so this cannot mutate evidence.
            os.replace(tmp_path, path)
        except OSError as exc:  # pragma: no cover - disk failure path
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise StorageError(
                f"failed to write CAS object: {exc}", details={"sha256": digest}
            ) from exc
        return ArtifactRef(sha256=digest, size=len(raw), media_type=media, cas_path=str(path))

    def put_file(
        self,
        path: str | os.PathLike[str],
        media_type: str = DEFAULT_MEDIA_TYPE,
        *,
        source_path: str | os.PathLike[str] | None = None,
    ) -> ArtifactRef:
        """Store the bytes of an existing file.

        ``source_path`` is accepted for call-site clarity; the object is keyed by
        the file's own bytes, never by its path.
        """

        target = Path(os.fspath(path if source_path is None else source_path))
        if not target.is_file():
            raise NotFoundError(f"artifact file not found: {target}")
        try:
            data = target.read_bytes()
        except OSError as exc:  # pragma: no cover - permission/disk failure
            raise StorageError(f"failed to read artifact file {target}: {exc}") from exc
        return self.put_bytes(data, media_type=media_type)

    def put_stream(
        self, chunks: Iterator[bytes], media_type: str = DEFAULT_MEDIA_TYPE
    ) -> ArtifactRef:
        """Store an iterable of byte chunks (convenience; buffered for hashing)."""

        buffer = bytearray()
        for chunk in chunks:
            buffer.extend(bytes(chunk))
        return self.put_bytes(bytes(buffer), media_type=media_type)

    def get_bytes(self, sha256: str) -> bytes:
        """Return the object bytes; ``NotFoundError`` when missing."""

        path = self.path_for(sha256)
        if not path.is_file():
            raise NotFoundError(f"CAS object not found: {sha256}")
        return path.read_bytes()

    def open_path(self, sha256: str) -> Path:
        """Return an existing object path (``NotFoundError`` when missing)."""

        path = self.path_for(sha256)
        if not path.is_file():
            raise NotFoundError(f"CAS object not found: {sha256}")
        return path

    # -- verification ---------------------------------------------------

    def verify(self, sha256: str) -> bool:
        """Recompute the digest of the stored object; False when missing/corrupt."""

        try:
            path = self.path_for(sha256)
        except ValidationError:
            return False
        if not path.is_file():
            return False
        try:
            from ..core.canonical import file_sha256

            return file_sha256(path) == sha256
        except OSError:  # pragma: no cover - permission failure
            return False

    def verify_all(self) -> dict[str, bool]:
        """Verify every object under the CAS root, keyed by digest."""

        result: dict[str, bool] = {}
        for digest, path in self._iter_object_paths():
            result[digest] = sha256_hex(path.read_bytes()) == digest if path.is_file() else False
        return result

    # -- iteration ------------------------------------------------------

    def _iter_object_paths(self) -> Iterator[tuple[str, Path]]:
        if not self.root.is_dir():
            return
        for shard in sorted(self.root.iterdir()):
            if not shard.is_dir():
                continue
            for object_path in sorted(shard.iterdir()):
                if object_path.is_file() and _SHA256_PATTERN.fullmatch(object_path.name):
                    yield object_path.name, object_path

    def iter_objects(self) -> Iterator[ArtifactRef]:
        """Yield one :class:`ArtifactRef` per stored object, sorted by digest."""

        for digest, path in self._iter_object_paths():
            if not path.is_file():
                continue
            yield ArtifactRef(
                sha256=digest,
                size=path.stat().st_size,
                media_type=DEFAULT_MEDIA_TYPE,
                cas_path=str(path),
            )

    def count_objects(self) -> int:
        return sum(1 for _ in self._iter_object_paths())

    def remove_object(self, sha256: str) -> bool:
        """Delete one object (only used by tests/repair tooling)."""

        path = self.path_for(sha256)
        if not path.is_file():
            return False
        try:
            path.unlink()
        except OSError as exc:  # pragma: no cover - permission failure
            raise StorageError(f"failed to remove CAS object: {exc}") from exc
        return True

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Cas({str(self.root)!r})"


__all__ = ["Cas", "DEFAULT_MEDIA_TYPE", "validate_sha256"]
