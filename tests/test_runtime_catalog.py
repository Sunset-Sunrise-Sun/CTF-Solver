"""Runtime catalogue tests: builtin trust set and cached version resolution.

Version probing runs only the tool's fixed ``version_probe`` argv. Tests skip
the ``git`` probe only when git is genuinely absent from the host (documented),
using an injected ``which`` rather than touching the network.
"""

from __future__ import annotations

import json
import shutil
import sys

import pytest

from ctf_solver.core.canonical import canonical_json
from ctf_solver.core.errors import ConfigError
from ctf_solver.core.types import ApprovalAction, ExecutionTier
from ctf_solver.runtime.catalog import ResolvedTool, RuntimeCatalog
from ctf_solver.runtime.tools import ToolSpec, build_builtin_tools

EXPECTED_INTERNAL = {
    "internal.archive_list",
    "internal.file_hash",
    "internal.file_metadata",
    "internal.hex_preview",
    "internal.strings_scan",
    "internal.text_search",
}
EXPECTED_PROBES = {"tool.git_version", "tool.python_version"}


def test_default_catalog_contains_builtin_trusted_tools() -> None:
    catalog = RuntimeCatalog.default()
    names = set(catalog.names())
    assert EXPECTED_INTERNAL <= names
    assert EXPECTED_PROBES <= names
    assert "tool.remote_probe" in names
    assert names == EXPECTED_INTERNAL | EXPECTED_PROBES | {"tool.remote_probe"}
    for name in EXPECTED_INTERNAL:
        spec = catalog.get(name)
        assert spec is not None
        assert spec.tier is ExecutionTier.TIER0_STATIC
        assert spec.internal is not None
        assert spec.executes_challenge_code is False
        assert spec.network is False
        assert spec.requires_approval is None
    for name in EXPECTED_PROBES:
        spec = catalog.get(name)
        assert spec is not None
        assert spec.tier is ExecutionTier.TIER1_TRUSTED
        assert spec.version_probe == ["--version"]
        assert spec.internal is None
        assert spec.executes_challenge_code is False


def test_default_catalog_network_stub_is_always_policy_only() -> None:
    catalog = RuntimeCatalog.default()
    spec = catalog.get("tool.remote_probe")
    assert spec is not None
    assert spec.network is True
    assert spec.tier is ExecutionTier.TIER2_ISOLATED
    assert spec.requires_approval is ApprovalAction.REMOTE_TARGET
    assert spec.internal is None
    assert spec.executes_challenge_code is False
    resolved = catalog.resolve("tool.remote_probe")
    assert resolved is not None and resolved.installed is True
    assert resolved.executable is None  # never runnable


def test_list_tools_is_deterministic_and_sorted() -> None:
    catalog = RuntimeCatalog.default()
    names = [spec.name for spec in catalog.list_tools()]
    assert names == sorted(names)
    assert catalog.names() == names


def test_get_unknown_tool_returns_none() -> None:
    catalog = RuntimeCatalog.default()
    assert catalog.get("internal.nope") is None
    assert catalog.get("") is None
    assert catalog.resolve("internal.nope") is None


def test_internal_tools_have_static_versions() -> None:
    catalog = RuntimeCatalog.default()
    for name in EXPECTED_INTERNAL:
        assert catalog.is_installed(name) is True
        assert catalog.version_of(name) == "1"
        assert catalog.executable_of(name) is None


def test_python_version_probe_runs_and_is_cached() -> None:
    catalog = RuntimeCatalog.default()
    first = catalog.resolve("tool.python_version")
    second = catalog.resolve("tool.python_version")
    assert first is not None and second is not None
    assert first is second  # cached probe result
    assert first.installed is True
    assert first.version and "python" in first.version.lower()
    assert first.executable == sys.executable


def test_git_version_probe_runs_when_git_present() -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed on this host; fixed-argv git probe not verified")
    catalog = RuntimeCatalog.default()
    resolved = catalog.resolve("tool.git_version")
    assert resolved is not None
    assert resolved.installed is True
    assert resolved.version and "git" in resolved.version.lower()
    assert resolved.executable and resolved.executable.lower().endswith("git.exe") or resolved.executable


def test_missing_executable_is_not_installed() -> None:
    spec = ToolSpec(
        name="synth.missing",
        display_name="Missing executable",
        description="probe tool",
        tier=ExecutionTier.TIER1_TRUSTED,
        version_probe=["--version"],
        executable="ctf-solver-no-such-binary-xyz",
    )
    catalog = RuntimeCatalog(tools=[spec])
    resolved = catalog.resolve("synth.missing")
    assert resolved is not None
    assert resolved.installed is False
    assert resolved.version is None


def test_failing_version_probe_does_not_crash() -> None:
    spec = ToolSpec(
        name="synth.failing_probe",
        display_name="Failing probe",
        description="probe tool",
        tier=ExecutionTier.TIER1_TRUSTED,
        version_probe=["-c", "import sys; sys.exit(3)"],
        executable=sys.executable,
    )
    catalog = RuntimeCatalog(tools=[spec])
    resolved = catalog.resolve("synth.failing_probe")
    assert resolved is not None
    assert resolved.installed is True
    assert resolved.version is None


def test_hanging_probe_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ToolSpec(
        name="synth.slow_probe",
        display_name="Slow probe",
        description="probe tool",
        tier=ExecutionTier.TIER1_TRUSTED,
        version_probe=["-c", "import time; time.sleep(5)"],
        executable=sys.executable,
    )
    catalog = RuntimeCatalog(tools=[spec], probe_timeout_s=0.2)
    resolved = catalog.resolve("synth.slow_probe")
    assert resolved is not None
    assert resolved.installed is True
    assert resolved.version is None


def test_probe_uses_injected_which() -> None:
    spec = ToolSpec(
        name="synth.path_tool",
        display_name="Path tool",
        description="probe tool",
        tier=ExecutionTier.TIER1_TRUSTED,
        version_probe=["--version"],
        executable="fake-tool",
    )
    catalog = RuntimeCatalog(tools=[spec], which=lambda name: None)
    assert catalog.is_installed("synth.path_tool") is False


def test_duplicate_tool_names_rejected() -> None:
    first = build_builtin_tools()[0]
    with pytest.raises(ConfigError):
        RuntimeCatalog(tools=[first, first])


def test_empty_catalogue_rejected() -> None:
    with pytest.raises(ConfigError):
        RuntimeCatalog(tools=[])


def test_invalid_spec_rejected() -> None:
    invalid = ToolSpec(
        name="synth.no_impl",
        display_name="No implementation",
        description="no implementation and no network intent",
        tier=ExecutionTier.TIER1_TRUSTED,
    )
    with pytest.raises(ConfigError):
        RuntimeCatalog(tools=[invalid])


def test_internal_and_probe_spec_rejected() -> None:
    from ctf_solver.core.types import ExecutionStatus, RuntimeOutcome

    invalid = ToolSpec(
        name="synth.both",
        display_name="Both",
        description="both internal and probe",
        tier=ExecutionTier.TIER0_STATIC,
        version_probe=["--version"],
        internal=lambda invocation: RuntimeOutcome(status=ExecutionStatus.COMPLETED),
        executable=sys.executable,
    )
    with pytest.raises(ConfigError):
        RuntimeCatalog(tools=[invalid])


def test_available_tiers_default_and_override() -> None:
    catalog = RuntimeCatalog.default()
    assert catalog.available_tiers == frozenset(
        {ExecutionTier.TIER0_STATIC, ExecutionTier.TIER1_TRUSTED}
    )
    assert catalog.supports_tier(ExecutionTier.TIER1_TRUSTED) is True
    assert catalog.supports_tier(ExecutionTier.TIER2_ISOLATED) is False
    all_tiers = frozenset(
        {ExecutionTier.TIER0_STATIC, ExecutionTier.TIER1_TRUSTED, ExecutionTier.TIER2_ISOLATED}
    )
    extended = RuntimeCatalog.default(available_tiers=all_tiers)
    assert extended.supports_tier(ExecutionTier.TIER2_ISOLATED) is True
    assert extended.supports_tier(99) is False  # type: ignore[arg-type]


def test_describe_is_json_serialisable_and_complete() -> None:
    catalog = RuntimeCatalog.default()
    entries = catalog.describe()
    assert len(entries) == len(catalog.list_tools())
    assert [entry["name"] for entry in entries] == catalog.names()
    for entry in entries:
        assert isinstance(entry, dict)
        assert "installed" in entry
        assert "tier" in entry
    encoded = canonical_json(entries)
    assert json.loads(encoded) == entries


def test_resolved_tool_reports_frozen_public_fields() -> None:
    catalog = RuntimeCatalog.default()
    resolved = catalog.resolve("internal.file_hash")
    assert isinstance(resolved, ResolvedTool)
    assert resolved.name == "internal.file_hash"
    assert resolved.spec.internal is not None
    assert set(resolved.to_dict()) >= {
        "name",
        "tier",
        "installed",
        "version",
        "network",
        "executes_challenge_code",
        "max_output_bytes",
    }
