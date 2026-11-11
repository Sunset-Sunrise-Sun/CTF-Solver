"""Deliverable facade used by the Manager (Writeup + evidence ZIP)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.canonical import sha256_hex
from ..core.errors import DeliveryError
from ..core.types import ExportInfo, TaskRecord
from .bundle import EvidenceBundleBuilder
from .writeup import WriteupBuilder


class Deliverables:
    def __init__(self, evidence: Any, paths: Any) -> None:
        self.evidence = evidence
        self.paths = paths
        self.writeup = WriteupBuilder(evidence)
        self.bundles = EvidenceBundleBuilder(evidence, paths)

    def build_writeup(self, task: TaskRecord) -> ExportInfo:
        if not isinstance(task, TaskRecord):
            raise DeliveryError("build_writeup requires a TaskRecord")
        out_path = self.paths.writeup_path(task.task_id)
        result = self.writeup.build(task, out_path)
        payload = Path(out_path).read_bytes()
        info = ExportInfo(
            kind="writeup",
            path=str(out_path),
            sha256=sha256_hex(payload),
            size=len(payload),
            entries=1,
        )
        record_export = getattr(self.evidence, "record_export", None)
        if callable(record_export):
            record_export(info)
        return info

    def export_evidence_zip(self, task: TaskRecord) -> ExportInfo:
        if not isinstance(task, TaskRecord):
            raise DeliveryError("export_evidence_zip requires a TaskRecord")
        return self.bundles.build(task)
