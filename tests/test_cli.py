"""Tests for the CLI entry points and offline evidence decode helper."""

from __future__ import annotations

import json
from pathlib import Path

from tests.support.proc import PROJECT_ROOT, run_module
from tests.support.session_events import standard_session
from tests.support.zstd_fixtures import build_session_log


def test_version_command() -> None:
    result = run_module("ctf_solver", "version")
    assert result.returncode == 0, result.stderr
    assert "ctf-solver" in result.stdout


def test_preflight_quiet_command() -> None:
    result = run_module("ctf_solver", "preflight", "--root", str(PROJECT_ROOT), "--quiet")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""


def test_skills_command_json() -> None:
    result = run_module("ctf_solver", "skills", "--root", str(PROJECT_ROOT))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert set(payload["found"]) == {
        "ctf-solver",
        "ctf-web",
        "ctf-misc",
        "ctf-crypto",
        "ctf-reverse",
        "ctf-pwn",
    }


def test_evidence_decode_command(tmp_path: Path) -> None:
    log_path = tmp_path / "session.v4.jsonl.zstd"
    records = standard_session()
    build_session_log(records, frames=4)
    log_path.write_bytes(build_session_log(records, frames=4))
    result = run_module("ctf_solver", "evidence", "decode", str(log_path))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["decoded_records"] == len(records)
    assert payload["frames"] >= 4
    assert payload["complete"] is True


def test_task_command_help_exposes_isolated_dsh_home_option() -> None:
    result = run_module("ctf_solver", "task", "--help")
    assert result.returncode == 0, result.stderr
    assert "--dsh-home" in result.stdout
    assert "isolated" in result.stdout.lower()


def test_default_isolated_dsh_home_never_uses_live_home(tmp_path: Path) -> None:
    from ctf_solver.wiring import default_isolated_dsh_home

    home = Path(default_isolated_dsh_home(tmp_path))
    assert home == tmp_path / ".ctf-solver-data" / "dsh-home"
    assert home.is_dir()
    assert Path.home() / ".dsh" != home
    assert ".dsh" not in [part for part in home.parts if part == ".dsh"]


def test_cli_reports_domain_errors_without_traceback(tmp_path: Path) -> None:
    result = run_module(
        "ctf_solver",
        "manager",
        "serve",
        "--root",
        str(tmp_path),
        "--capture-mode",
        "real-window",
    )
    assert result.returncode == 1
    assert "ctf-solver error:" in result.stderr
    assert "Traceback" not in result.stderr
