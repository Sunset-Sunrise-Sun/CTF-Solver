"""Deterministic canonical serialization and hashing helpers.

Every hash in the evidence chain and every manifest entry is produced from
these helpers so that independent verification reproduces exactly the same
bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Iterator

GENESIS_HASH = "0" * 64
HASH_ALGORITHM = "sha256"


def canonical_json(value: Any) -> str:
    """Return a stable, key-sorted JSON representation.

    ``ensure_ascii=False`` keeps UTF-8 payloads readable and, combined with
    ``sort_keys`` and fixed separators, byte-identical across runs and
    platforms. Trailing whitespace is never emitted.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def file_sha256(path: str | Path, *, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def chain_hash(prev_hash: str, record_payload: Any) -> str:
    """Hash one evidence record into the append-only chain."""

    digest = hashlib.sha256()
    digest.update(prev_hash.encode("ascii"))
    digest.update(b"\n")
    digest.update(canonical_bytes(record_payload))
    return digest.hexdigest()


def hash_manifest(entries: Iterable[tuple[str, str]]) -> str:
    """Render ``<sha256>  <relpath>`` lines in sorted path order."""

    lines = [f"{digest}  {rel}" for rel, digest in sorted(entries, key=lambda item: item[0])]
    return "\n".join(lines) + "\n"


def iter_file_hashes(root: str | Path) -> Iterator[tuple[str, str]]:
    """Yield ``(posix_relpath, sha256)`` for every regular file under root."""

    base = Path(root)
    for path in sorted(base.rglob("*")):
        if path.is_file():
            yield path.relative_to(base).as_posix(), file_sha256(path)
