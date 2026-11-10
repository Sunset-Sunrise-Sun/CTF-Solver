"""Tests for :mod:`ctf_solver.acp.launch` (Round 2 section 3.3).

The launch builder is the only place that knows the audited ACP entrypoint
``dsh --profile acp``. These tests never start the real Harness server and never
call a model: the only process executed is a temporary ``.cmd`` fixture that
records the argv it received and exits 0.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from ctf_solver.acp import launch
from ctf_solver.core.errors import ConfigError

COMSPEC = os.environ.get("COMSPEC") or "cmd.exe"


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return token[1:-1]
    return token


# ---------------------------------------------------------------------------
# build_acp_command: exact argv shapes
# ---------------------------------------------------------------------------


def test_executable_launcher_gets_audited_profile_args() -> None:
    assert launch.build_acp_command([r"C:\tools\dsh.exe"]) == [
        r"C:\tools\dsh.exe",
        "--profile",
        "acp",
    ]
    assert launch.build_acp_command(["dsh"]) == ["dsh", "--profile", "acp"]


def test_extra_launcher_arguments_follow_the_profile_flag() -> None:
    command = launch.build_acp_command([r"C:\tools\dsh.exe", "--foo", "bar"])
    assert command == [r"C:\tools\dsh.exe", "--foo", "bar", "--profile", "acp"]
    assert command[-2:] == ["--profile", "acp"]


@pytest.mark.parametrize("suffix", [".cmd", ".CMD", ".bat", ".Bat"])
def test_cmd_launcher_is_wrapped_by_comspec(suffix: str) -> None:
    executable = rf"C:\tools\dsh{suffix}"
    command = launch.build_acp_command([executable])
    assert command == [COMSPEC, "/c", executable, "--profile", "acp"]
    assert command[0] == COMSPEC
    assert command[1] == "/c"


def test_cmd_wrapper_keeps_extra_arguments_after_profile_args() -> None:
    command = launch.build_acp_command([r"C:\tools\dsh.cmd", "--extra", "1"])
    assert command == [COMSPEC, "/c", r"C:\tools\dsh.cmd", "--extra", "1", "--profile", "acp"]


def test_build_acp_command_uses_environment_comspec(monkeypatch) -> None:
    monkeypatch.setenv("COMSPEC", r"X:\synthetic\cmd.exe")
    command = launch.build_acp_command([r"C:\tools\dsh.cmd"])
    assert command[0] == r"X:\synthetic\cmd.exe"
    assert command[2] == r"C:\tools\dsh.cmd"


def test_build_acp_command_does_not_mutate_launcher() -> None:
    launcher = [r"C:\tools\dsh.cmd", "--extra"]
    snapshot = list(launcher)
    launch.build_acp_command(launcher)
    assert launcher == snapshot


# ---------------------------------------------------------------------------
# build_acp_command: rejection of invalid launchers (never a shell string)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "launcher",
    [
        [],
        (),
        "",
        "dsh --profile acp",
        r"C:\tools\dsh.cmd --profile acp",
        None,
        42,
        [""],
        ["dsh.exe", ""],
        [None],
        ["dsh.exe", 5],
    ],
)
def test_invalid_launcher_raises_config_error(launcher) -> None:
    with pytest.raises(ConfigError):
        launch.build_acp_command(launcher)  # type: ignore[arg-type]


def test_string_launcher_is_never_split_by_a_shell() -> None:
    with pytest.raises(ConfigError):
        launch.build_acp_command("dsh --profile acp")
    with pytest.raises(ConfigError):
        launch.build_acp_command(f'"{shutil.which("cmd")}" /c dsh')


def test_builder_returns_an_argv_list_of_strings() -> None:
    command = launch.build_acp_command([r"C:\tools\dsh.exe"])
    assert isinstance(command, list)
    assert all(isinstance(part, str) and part for part in command)
    assert "--profile" in command and "acp" in command


# ---------------------------------------------------------------------------
# End-to-end argv delivery through the COMSPEC wrapper (deterministic, offline)
# ---------------------------------------------------------------------------


def test_temp_cmd_launcher_receives_profile_args_through_wrapper(tmp_path: Path) -> None:
    script_dir = tmp_path / "dir with space"
    script_dir.mkdir(parents=True)
    script = script_dir / "dsh.cmd"
    script.write_bytes(
        b"@echo off\r\n"
        b'echo %* > "%~dp0received-args.txt"\r\n'
        b"exit /b 0\r\n"
    )
    received = script_dir / "received-args.txt"
    command = launch.build_acp_command([str(script)])
    assert command[:3] == [COMSPEC, "/c", str(script)]

    completed = _run(command, cwd=tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert received.is_file(), "the .cmd launcher was not executed through the wrapper"
    arguments = received.read_text(encoding="utf-8", errors="replace").strip()
    # The script's %* must receive exactly the ACP profile flag (not the wrapper).
    assert arguments == "--profile acp"


def _run(command: list[str], *, cwd: Path):
    import subprocess

    return subprocess.run(
        command,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# ---------------------------------------------------------------------------
# build_default_acp_command: discovery + composition
# ---------------------------------------------------------------------------


def test_build_default_returns_none_when_no_launcher_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
    env = {"LOCALAPPDATA": str(tmp_path / "no-harness"), "CTF_SOLVER_ACP_COMMAND": ""}
    assert launch.build_default_acp_command(env) is None


def test_build_default_uses_discovered_local_harness_launcher(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
    launcher = (
        tmp_path
        / "Programs"
        / "DeepSeek Harness"
        / "resources"
        / "runtime"
        / "cli"
        / "bin"
        / "dsh.cmd"
    )
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"@echo off\r\n")
    env = {"LOCALAPPDATA": str(tmp_path), "CTF_SOLVER_ACP_COMMAND": ""}

    command = launch.build_default_acp_command(env)

    assert command is not None
    assert command[0] == COMSPEC
    assert command[1] == "/c"
    assert command[2] == str(launcher)
    assert command[3:] == ["--profile", "acp"]


def test_build_default_honours_environment_override(tmp_path: Path) -> None:
    executable = tmp_path / "custom-dsh.exe"
    executable.write_bytes(b"MZ-synthetic")
    env = {"CTF_SOLVER_ACP_COMMAND": str(executable), "LOCALAPPDATA": str(tmp_path)}

    command = launch.build_default_acp_command(env)

    assert command is not None
    assert _unquote(command[0]) == str(executable)
    assert command[1:] == ["--profile", "acp"]


def test_build_default_wraps_override_cmd_with_env_comspec(tmp_path: Path) -> None:
    script = tmp_path / "dsh.cmd"
    script.write_bytes(b"@echo off\r\n")
    env = {
        "CTF_SOLVER_ACP_COMMAND": str(script),
        "COMSPEC": r"X:\synthetic\cmd.exe",
        "LOCALAPPDATA": str(tmp_path),
    }
    command = launch.build_default_acp_command(env)
    assert command == [r"X:\synthetic\cmd.exe", "/c", str(script), "--profile", "acp"]


def test_build_default_composes_discovery_result(monkeypatch) -> None:
    monkeypatch.setattr(launch, "discover_acp_command", lambda env=None: [r"C:\discovered\dsh.exe"])
    assert launch.build_default_acp_command({}) == [
        r"C:\discovered\dsh.exe",
        "--profile",
        "acp",
    ]


def test_build_default_returns_none_for_missing_discovery(monkeypatch) -> None:
    monkeypatch.setattr(launch, "discover_acp_command", lambda env=None: None)
    assert launch.build_default_acp_command({}) is None


def test_build_default_propagates_invalid_discovered_launcher(monkeypatch) -> None:
    monkeypatch.setattr(launch, "discover_acp_command", lambda env=None: [])
    with pytest.raises(ConfigError):
        launch.build_default_acp_command({})


# ---------------------------------------------------------------------------
# Round 2 P0-3: project privacy patch composition (absolute --patch argument)
# ---------------------------------------------------------------------------


def _project_patch(tmp_path: Path) -> Path:
    patch = tmp_path / "config" / "acp" / "cordis.patch.yml"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_text("- id: session-log-deepseek\n  config:\n    enabled: false\n", encoding="utf-8")
    return patch


def test_privacy_patch_is_absolute_and_follows_profile(tmp_path: Path) -> None:
    patch = _project_patch(tmp_path)
    command = launch.build_acp_command(
        [r"C:\tools\dsh.cmd"], privacy_patch=str(patch)
    )
    assert command == [
        COMSPEC,
        "/c",
        r"C:\tools\dsh.cmd",
        "--profile",
        "acp",
        "--patch",
        str(patch.resolve()),
    ]
    patch_index = command.index("--patch")
    assert command[patch_index - 2 : patch_index] == ["--profile", "acp"]
    assert Path(command[patch_index + 1]).is_absolute()


def test_privacy_patch_missing_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing-patch.yml"
    with pytest.raises(ConfigError):
        launch.build_acp_command(
            [r"C:\tools\dsh.cmd"], privacy_patch=str(missing)
        )
    with pytest.raises(ConfigError):
        launch.build_privacy_patch_args(missing)


def test_privacy_patch_relative_path_is_rejected(tmp_path: Path, monkeypatch) -> None:
    patch = _project_patch(tmp_path)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError):
        launch.build_privacy_patch_args("config/acp/cordis.patch.yml")
    # Absolute input is accepted even from another cwd.
    assert launch.build_privacy_patch_args(str(patch.resolve())) == [
        "--patch",
        str(patch.resolve()),
    ]


def test_build_default_composes_privacy_patch(tmp_path: Path, monkeypatch) -> None:
    patch = _project_patch(tmp_path)
    monkeypatch.setattr(launch, "discover_acp_command", lambda env=None: [r"C:\discovered\dsh.exe"])
    command = launch.build_default_acp_command({}, privacy_patch=str(patch))
    assert command == [
        r"C:\discovered\dsh.exe",
        "--profile",
        "acp",
        "--patch",
        str(patch.resolve()),
    ]
