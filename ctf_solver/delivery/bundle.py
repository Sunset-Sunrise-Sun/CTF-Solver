"""Evidence ZIP assembly and independent manifest verification.

The ZIP is deterministic: fixed member order (sorted paths), fixed timestamps
(1980-01-01 00:00:00), normalized permissions and deflate compression. The same
committed evidence therefore produces byte-identical archives, and every member
is covered by ``manifest.sha256`` inside the archive.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Iterable

from ..core.canonical import file_sha256, sha256_hex
from ..core.errors import DeliveryError
from ..core.types import ExportInfo, ScreenshotRecord, TaskRecord
from .writeup import WriteupBuilder, _as_event_dict, _payload

ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
MANIFEST_NAME = "manifest.sha256"


def write_manifest(files: Iterable[tuple[str, str]], out_path: str | Path) -> ExportInfo:
    """Write ``<sha256>  <relpath>`` lines sorted by relative path."""

    entries = sorted(files, key=lambda item: item[0])
    text = "".join(f"{digest}  {rel}\n" for rel, digest in entries)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return ExportInfo(
        kind="manifest",
        path=str(target),
        sha256=sha256_hex(text.encode("utf-8")),
        size=len(text.encode("utf-8")),
        entries=len(entries),
    )


def verify_manifest(manifest_path: str | Path, root: str | Path) -> dict[str, Any]:
    """Independently verify every manifest entry against files under ``root``."""

    manifest_file = Path(manifest_path)
    base = Path(root)
    problems: list[str] = []
    checked = 0
    if not manifest_file.is_file():
        raise DeliveryError(f"manifest not found: {manifest_file}")
    manifest_relpaths: set[str] = set()
    for line_number, line in enumerate(
        manifest_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            problems.append(f"line {line_number}: malformed manifest entry")
            continue
        expected, relpath = parts
        manifest_relpaths.add(relpath)
        target = base / relpath
        if not target.is_file():
            problems.append(f"missing file: {relpath}")
            continue
        actual = file_sha256(target)
        checked += 1
        if actual != expected:
            problems.append(f"hash mismatch: {relpath} (expected {expected}, actual {actual})")
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if rel == MANIFEST_NAME:
            continue
        if rel not in manifest_relpaths:
            problems.append(f"unlisted extra file: {rel}")
    return {
        "ok": not problems,
        "checked": checked,
        "problems": problems,
        "manifest": str(manifest_file),
    }


class EvidenceBundleBuilder:
    """Build ``writeup.md`` + selected evidence + screenshots + ZIP per Task."""

    def __init__(self, evidence: Any, paths: Any) -> None:
        self.evidence = evidence
        self.paths = paths
        self.writeup = WriteupBuilder(evidence)

    @staticmethod
    def _read_artifact(evidence: Any, sha256: str) -> bytes:
        """Read a CAS object through any supported evidence/CAS accessor."""

        cas = getattr(evidence, "cas", None)
        if cas is not None and callable(getattr(cas, "get_bytes", None)):
            return bytes(cas.get_bytes(sha256))
        for name in ("read_artifact", "get_artifact", "read_bytes"):
            reader = getattr(evidence, name, None)
            if callable(reader):
                result = reader(sha256)
                if isinstance(result, (bytes, bytearray)):
                    return bytes(result)
                data = getattr(result, "data", None)
                if isinstance(data, (bytes, bytearray)):
                    return bytes(data)
        raise DeliveryError("evidence store exposes no readable CAS accessor")

    # -- staging ------------------------------------------------------

    def _writeup_text(self, task: TaskRecord) -> str:
        return self.writeup.render(task)

    def _collect_screenshots(self, task: TaskRecord, staging: Path) -> list[dict[str, Any]]:
        included: list[dict[str, Any]] = []
        shots_dir = staging / "screenshots"
        screenshots = self.writeup._screenshots(task.task_id)  # noqa: SLF001 - same package
        for shot in screenshots:
            if shot.status.value != "ok" or not shot.sha256:
                continue
            try:
                data = self._read_artifact(self.evidence, shot.sha256)
            except Exception:  # noqa: BLE001 - missing CAS object becomes an explicit gap
                included.append(
                    {"screenshot_id": shot.screenshot_id, "included": False, "reason": "CAS object missing"}
                )
                continue
            shots_dir.mkdir(parents=True, exist_ok=True)
            member = f"screenshots/{shot.screenshot_id}.png"
            (staging / member).write_bytes(data)
            included.append(
                {
                    "screenshot_id": shot.screenshot_id,
                    "included": True,
                    "member": member,
                    "sha256": shot.sha256,
                }
            )
        return included

    def _collect_outputs(self, task: TaskRecord, staging: Path) -> list[dict[str, Any]]:
        included: list[dict[str, Any]] = []
        events = [_as_event_dict(item) for item in self.evidence.list_events(task_id=task.task_id)]
        events.sort(key=lambda item: int(item.get("seq") or 0))
        out_dir = staging / "outputs"
        for event in events:
            if event.get("event_type") not in {
                "execution_completed",
                "execution_failed",
                "execution_denied",
            }:
                continue
            payload = _payload(event)
            execution_id = str(payload.get("execution_id", "execution"))
            for key, suffix in (("stdout_sha256", "stdout.txt"), ("stderr_sha256", "stderr.txt")):
                sha = payload.get(key)
                if not sha:
                    continue
                try:
                    data = self._read_artifact(self.evidence, str(sha))
                except Exception:  # noqa: BLE001
                    included.append({"execution_id": execution_id, "included": False, "reason": f"{key} CAS missing"})
                    continue
                if not data:
                    continue
                out_dir.mkdir(parents=True, exist_ok=True)
                member = f"outputs/{execution_id}-{suffix}"
                (staging / member).write_bytes(data)
                included.append(
                    {"execution_id": execution_id, "included": True, "member": member, "sha256": sha}
                )
        return included

    def _collect_raw_sources(self, task: TaskRecord, staging: Path) -> list[dict[str, Any]]:
        """Copy raw ingested session logs referenced by ingestion sources, when exposed."""

        included: list[dict[str, Any]] = []
        sources = getattr(self.evidence, "ingestion_sources", None)
        if not callable(sources):
            return included
        try:
            rows = sources(task.task_id)
        except Exception:  # noqa: BLE001
            return included
        for row in rows or []:
            raw_sha = None
            if isinstance(row, dict):
                raw_sha = row.get("raw_sha256")
            else:
                raw_sha = getattr(row, "raw_sha256", None)
            if not raw_sha:
                continue
            try:
                data = self._read_artifact(self.evidence, raw_sha)
            except Exception:  # noqa: BLE001
                continue
            raw_dir = staging / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            member = f"raw/session-{raw_sha[:16]}.jsonl.zstd"
            (staging / member).write_bytes(data)
            included.append({"member": member, "sha256": raw_sha})
        return included

    # -- build --------------------------------------------------------

    def build(self, task: TaskRecord) -> ExportInfo:
        task_dir = self.paths.task_dir(task.task_id)
        task_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir = self.paths.task_evidence_dir(task.task_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        staging = task_dir / "bundle"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)

        writeup_path = self.paths.writeup_path(task.task_id)
        writeup_info = self.writeup.build(task, writeup_path)
        (staging / "writeup.md").write_bytes(Path(writeup_path).read_bytes())

        events_path = evidence_dir / "events.jsonl"
        export_info = self.evidence.export_events_jsonl(task_id=task.task_id, out_path=events_path)
        if Path(events_path).is_file():
            (staging / "events.jsonl").write_bytes(Path(events_path).read_bytes())

        screenshots = self._collect_screenshots(task, staging)
        outputs = self._collect_outputs(task, staging)
        raw_sources = self._collect_raw_sources(task, staging)

        manifest_entries: list[tuple[str, str]] = []
        for path in sorted(staging.rglob("*")):
            if path.is_file() and path.name != MANIFEST_NAME:
                manifest_entries.append((path.relative_to(staging).as_posix(), file_sha256(path)))
        manifest_info = write_manifest(manifest_entries, staging / MANIFEST_NAME)

        zip_path = self.paths.evidence_zip_path(task.task_id)
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        if zip_path.exists():
            zip_path.unlink()
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for relpath in sorted(
                [rel for rel, _ in manifest_entries] + [MANIFEST_NAME]
            ):
                info = zipfile.ZipInfo(relpath, date_time=ZIP_DATE_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                data = (staging / relpath).read_bytes()
                archive.writestr(info, data)
        zip_sha = file_sha256(zip_path)
        verify_dir = Path(tempfile.mkdtemp(prefix="ctf-solver-bundle-verify-"))
        try:
            report = self.verify_zip(zip_path, verify_dir / "extract")
            if not report.get("ok"):
                problems = "; ".join(report.get("problems", [])[:5])
                raise DeliveryError(
                    "evidence ZIP failed internal verification: "
                    + (problems or "manifest does not verify")
                )
        finally:
            shutil.rmtree(verify_dir, ignore_errors=True)
        info = ExportInfo(
            kind="evidence_zip",
            path=str(zip_path),
            sha256=zip_sha,
            size=zip_path.stat().st_size,
            entries=len(manifest_entries) + 1,
        )
        try:
            record_export = getattr(self.evidence, "record_export", None)
            if callable(record_export):
                record_export(info)
                record_export(
                    ExportInfo(
                        kind="writeup",
                        path=str(writeup_path),
                        sha256=writeup_info["sha256"],
                        size=int(writeup_info["size"]),
                        entries=1,
                    )
                )
                record_export(
                    ExportInfo(
                        kind="events_jsonl",
                        path=str(events_path),
                        sha256=export_info.sha256,
                        size=export_info.size,
                        entries=export_info.entries,
                    )
                )
        except Exception:  # noqa: BLE001 - export recording is best effort; the ZIP is returned
            pass
        return info

    # -- verification -------------------------------------------------

    @staticmethod
    def verify_zip(zip_path: str | Path, extract_to: str | Path) -> dict[str, Any]:
        target = Path(extract_to)
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as archive:
            names = archive.namelist()
            archive.extractall(target)
        report = verify_manifest(target / MANIFEST_NAME, target)
        report["zip_sha256"] = file_sha256(zip_path)
        report["members"] = names
        return report


def deterministic_zip_sha(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
