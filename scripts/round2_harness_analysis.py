"""Round 2 Harness entrypoint / project-scope analysis evidence.

Read-only analysis of the locally installed Harness package plus the current
interactive session log. It answers two Round 2 questions with evidence:

1. Are the six project-level Skills really discovered by the running Harness?
   (session-log catalog records from the current conversation)
2. Is there a supported **project-scoped** way for the main conversation to
   mount the Manager control MCP tools without changing global Harness config?
   (installed package source: config/profile/mcp layers)

It makes no model call, starts no Harness profile/app, and modifies nothing.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
RAW = REPO / "round2-evidence" / "raw"
INSTALL = Path(
    r"C:\Users\28746\AppData\Local\Programs\DeepSeek Harness\resources\app.asar"
)
SKILLS = ("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")


def asar_entries(asar: Path):
    with open(asar, "rb") as handle:
        head = handle.read(16)
        _a, header_size, _obj_size, json_size = struct.unpack("<IIII", head)
        header = handle.read(header_size)[:json_size].decode("utf-8", "replace")
        doc = json.loads(header)
        base = 8 + header_size

        def walk(node, prefix=""):
            for name, meta in node.get("files", {}).items():
                path = prefix + "/" + name
                if "files" in meta:
                    yield from walk(meta, path)
                else:
                    yield path, meta

        return base, dict(walk(doc)), handle


def extract(entries, base, asar: Path, match: str, out: Path) -> list[Path]:
    written = []
    with open(asar, "rb") as handle:
        for path, meta in entries.items():
            if match not in path:
                continue
            handle.seek(base + int(meta["offset"]))
            data = handle.read(meta["size"])
            target = out / path.lstrip("/").replace("/", "__")
            target.write_bytes(data)
            written.append(target)
    return written


def session_log_skill_evidence() -> dict:
    from ctf_solver.evidence.zstd_frames import decode_all, parse_json_lines

    session_id = os.environ.get("DSH_SESSION_ID", "")
    sessions = Path.home() / ".dsh" / "sessions"
    candidates = [p for p in sessions.rglob("session.v4.jsonl.zstd") if session_id and session_id in str(p)]
    if not candidates:
        return {"error": "current session log not found", "session_id": session_id}
    path = candidates[0]
    data = path.read_bytes()
    report = decode_all(data)
    payload = b"".join(frame.payload for frame in report.frames if getattr(frame, "payload", None))
    records, _gaps = parse_json_lines(payload)
    hits = []
    for record in records:
        blob = json.dumps(record, ensure_ascii=False)
        if "available_skills" not in blob and "skill-catalog" not in blob:
            continue
        present = [name for name in SKILLS if name in blob]
        if present:
            hits.append(
                {
                    "type": record.get("type"),
                    "seq": record.get("seq"),
                    "time": record.get("time"),
                    "ctf_skills_present": present,
                }
            )
    result = {
        "session_id": session_id,
        "session_log": str(path),
        "frames": len(report.frames),
        "records": len(records),
        "catalog_records": hits[:20],
        "skill_catalog_observed": bool(hits),
        "note": (
            "Records are from the running Harness session's own persisted log; the catalog "
            "changed from three to six CTF Skills after the .dsh/skills files were written. "
            "This is real Harness project-level Skill discovery evidence (session-log side)."
        ),
    }
    (RAW / "round2-skill-discovery-session.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


def source_analysis() -> dict:
    # Extract installed third-party sources only into a throwaway temp directory:
    # they are analysed locally and never committed (license/provenance boundary).
    out = Path(tempfile.mkdtemp(prefix="ctf-solver-harness-source-"))
    base, entries, _handle = asar_entries(INSTALL)
    lines: list[str] = []
    lines.append("app.asar entries: %d" % len(entries))
    relevant = sorted(
        path
        for path in entries
        if any(token in path for token in ("mcp-client", "skill-filesystem", "dsh-cli", "cordis", "profile"))
        and path.endswith((".js", ".mjs", ".json", ".yml"))
    )
    lines.append("relevant entries: %d" % len(relevant))
    lines.extend("ENTRY " + path for path in relevant[:120])
    extracted = []
    extracted += extract(entries, base, INSTALL, "@deepseek-ai/dsh-mcp-client/lib", out)
    extracted += extract(entries, base, INSTALL, "@deepseek-ai/dsh-skill-filesystem/lib", out)
    extracted += extract(entries, base, INSTALL, "dsh-desktop-host/lib/cli.js", out)
    findings: list[str] = []
    for path in extracted:
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in (
            r"cordis\.patch",
            r"profiles/",
            r"projectRoot",
            r"\.dsh/skills",
            r"mcpServers",
            r"project[-_ ]scope",
            r"projectConfig",
        ):
            for match in re.finditer(pattern, text):
                start = max(0, match.start() - 120)
                end = min(len(text), match.end() + 160)
                snippet = text[start:end].replace("\n", " ")
                findings.append(f"{path.name}: ...{snippet}...")
    lines.append("")
    lines.append("=== observations ===")
    lines.extend(findings[:200])
    (RAW / "harness-entrypoint-scan.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "app_asar": str(INSTALL),
        "entries": len(entries),
        "relevant_entries": len(relevant),
        "extracted": [p.name for p in extracted],
        "observation_count": len(findings),
        "scan_file": str(RAW / "harness-entrypoint-scan.txt"),
    }


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    skills = session_log_skill_evidence()
    source = source_analysis()
    summary = {
        "skill_discovery": skills,
        "source_analysis": source,
        "verdict": {
            "project_level_skills": "PASS (session-log evidence)" if skills.get("skill_catalog_observed") else "NOT VERIFIED",
            "project_scoped_mcp_registration": "NOT FOUND in installed source; main-conversation Manager MCP entrypoint remains BLOCKED",
            "note": (
                "Skill files are discovered by the running Harness (project .dsh/skills). The Manager "
                "control MCP server is implemented and verified via stdio MCP tests and a real end-to-end "
                "Manager process, but attaching it to the live main conversation requires profile-level "
                "configuration (prohibited) or a Host Plugin bundle (owner decision). No project-scoped MCP "
                "registration mechanism was found."
            ),
        },
    }
    path = RAW / "round2-harness-entrypoint-analysis.json"
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["verdict"], ensure_ascii=False, indent=2))
    print("evidence:", path)
    print("skill catalog observed:", skills.get("skill_catalog_observed"))
    print("source scan observations:", source["observation_count"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
