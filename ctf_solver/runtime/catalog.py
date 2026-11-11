"""Trusted-tool catalogue with cached version resolution.

The catalogue is Manager-owned: Workers cannot add tools or choose arbitrary
executables. Version resolution is cached and never raises:

- internal tools use their static ``ToolSpec.version``;
- Tier 1 probe tools run only their fixed ``version_probe`` argv, with a
  timeout and a minimal environment; a missing executable or failing probe
  marks the tool unavailable/unknown instead of crashing.

``RuntimeCatalog.default()`` returns the builtin trusted tools described in
docs/INTERFACES.md section 5.1. Tests may pass an explicit ``tools`` list.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

from ..core.errors import ConfigError
from ..core.types import ExecutionTier
from .tools import ToolSpec, build_builtin_tools

__all__ = ["ResolvedTool", "RuntimeCatalog"]

_PROBE_ENV_KEYS = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
)

DEFAULT_AVAILABLE_TIERS: frozenset[ExecutionTier] = frozenset(
    {ExecutionTier.TIER0_STATIC, ExecutionTier.TIER1_TRUSTED}
)

DEFAULT_PROBE_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class ResolvedTool:
    """A catalogue entry plus its resolved availability/version/executable."""

    spec: ToolSpec
    installed: bool
    version: str | None
    executable: str | None

    @property
    def name(self) -> str:
        return self.spec.name

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.spec.name,
            "display_name": self.spec.display_name,
            "description": self.spec.description,
            "tier": int(self.spec.tier),
            "installed": self.installed,
            "version": self.version,
            "executable": self.executable,
            "network": self.spec.network,
            "executes_challenge_code": self.spec.executes_challenge_code,
            "requires_approval": (
                self.spec.requires_approval.value if self.spec.requires_approval else None
            ),
            "default_timeout_s": self.spec.default_timeout_s,
            "max_output_bytes": self.spec.max_output_bytes,
        }


def _minimal_probe_env() -> dict[str, str]:
    env = {key: os.environ[key] for key in _PROBE_ENV_KEYS if key in os.environ}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


class RuntimeCatalog:
    """Immutable catalogue of trusted tools with cached probe results."""

    def __init__(
        self,
        tools: Iterable[ToolSpec] | None = None,
        *,
        available_tiers: Iterable[ExecutionTier] | None = None,
        probe_timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
        probe_env: Mapping[str, str] | None = None,
        which: Callable[[str], str | None] | None = None,
    ) -> None:
        if tools is None:
            tools = build_builtin_tools()
        specs: dict[str, ToolSpec] = {}
        for spec in tools:
            self._validate_spec(spec)
            if spec.name in specs:
                raise ConfigError(f"duplicate tool name in catalogue: {spec.name!r}")
            specs[spec.name] = spec
        if not specs:
            raise ConfigError("runtime catalogue must contain at least one tool")
        self._tools = specs
        tiers = (
            frozenset(available_tiers)
            if available_tiers is not None
            else DEFAULT_AVAILABLE_TIERS
        )
        if not tiers:
            raise ConfigError("runtime catalogue must expose at least one execution tier")
        self._available_tiers = tiers
        self._probe_timeout_s = float(probe_timeout_s)
        if not 0.1 <= self._probe_timeout_s <= 60.0:
            raise ConfigError("version probe timeout must be within [0.1, 60] seconds")
        self._probe_env = dict(probe_env) if probe_env is not None else _minimal_probe_env()
        self._which = which or shutil.which
        self._resolved: dict[str, ResolvedTool] = {}

    # -- validation ---------------------------------------------------------

    @staticmethod
    def _validate_spec(spec: ToolSpec) -> None:
        if not isinstance(spec, ToolSpec):
            raise ConfigError(f"catalogue entries must be ToolSpec instances, got {type(spec)!r}")
        if not spec.name or not isinstance(spec.name, str):
            raise ConfigError("catalogue tool name must be a non-empty string")
        if not isinstance(spec.tier, ExecutionTier):
            raise ConfigError(f"tool {spec.name!r} has an invalid execution tier")
        if spec.max_output_bytes <= 0:
            raise ConfigError(f"tool {spec.name!r} max_output_bytes must be positive")
        if spec.default_timeout_s <= 0:
            raise ConfigError(f"tool {spec.name!r} default_timeout_s must be positive")
        if spec.version_probe is not None:
            if not isinstance(spec.version_probe, list) or not all(
                isinstance(item, str) for item in spec.version_probe
            ):
                raise ConfigError(f"tool {spec.name!r} version_probe must be a list of strings")
            if spec.internal is not None:
                raise ConfigError(
                    f"tool {spec.name!r} cannot be both internal and subprocess-based"
                )
            if not spec.executable:
                raise ConfigError(
                    f"tool {spec.name!r} has a version probe but no executable"
                )
        if spec.internal is not None and not callable(spec.internal):
            raise ConfigError(f"tool {spec.name!r} internal implementation is not callable")
        if spec.arg_validator is not None and not callable(spec.arg_validator):
            raise ConfigError(f"tool {spec.name!r} arg_validator is not callable")
        if spec.internal is None and not spec.executable and not spec.version_probe:
            if not spec.network:
                raise ConfigError(
                    f"tool {spec.name!r} has no implementation, executable or network intent"
                )

    # -- construction -------------------------------------------------------

    @classmethod
    def default(cls, **kwargs: object) -> "RuntimeCatalog":
        """Build the builtin catalogue.

        Probe tools resolve their executable through PATH (``git``) or use the
        interpreter running the Manager (``python --version``); no caller input
        ever influences an executable path.
        """

        return cls(build_builtin_tools(), **kwargs)  # type: ignore[arg-type]

    # -- queries ------------------------------------------------------------

    @property
    def available_tiers(self) -> frozenset[ExecutionTier]:
        return self._available_tiers

    def supports_tier(self, tier: ExecutionTier) -> bool:
        try:
            normalized = ExecutionTier(int(tier))
        except (TypeError, ValueError):
            return False
        return normalized in self._available_tiers

    def get(self, name: str) -> ToolSpec | None:
        if not isinstance(name, str):
            return None
        return self._tools.get(name)

    def list_tools(self) -> list[ToolSpec]:
        return [self._tools[name] for name in sorted(self._tools)]

    def names(self) -> list[str]:
        return sorted(self._tools)

    def resolve(self, name: str) -> ResolvedTool | None:
        """Return cached availability/version/executable for one tool."""

        spec = self.get(name)
        if spec is None:
            return None
        cached = self._resolved.get(name)
        if cached is not None:
            return cached
        resolved = self._resolve_spec(spec)
        self._resolved[name] = resolved
        return resolved

    def is_installed(self, name: str) -> bool:
        resolved = self.resolve(name)
        return bool(resolved is not None and resolved.installed)

    def version_of(self, name: str) -> str | None:
        resolved = self.resolve(name)
        return resolved.version if resolved is not None else None

    def executable_of(self, name: str) -> str | None:
        """Resolved executable path used for subprocess execution."""

        resolved = self.resolve(name)
        return resolved.executable if resolved is not None else None

    # -- probing ------------------------------------------------------------

    def _resolve_spec(self, spec: ToolSpec) -> ResolvedTool:
        if spec.internal is not None:
            return ResolvedTool(
                spec=spec,
                installed=True,
                version=(spec.version or "1"),
                executable=None,
            )
        executable = spec.executable
        if executable is None:
            if spec.network and spec.version_probe is None and spec.internal is None:
                # Declared policy-only network stub: reported installed so the
                # Broker reaches its Tier 2 / network denial, but it has no
                # runnable implementation and the executor refuses it.
                return ResolvedTool(
                    spec=spec,
                    installed=True,
                    version=spec.version or None,
                    executable=None,
                )
            return ResolvedTool(spec=spec, installed=False, version=None, executable=None)
        resolved_executable = self._resolve_executable(executable)
        if spec.version_probe is None:
            if spec.network:
                return ResolvedTool(
                    spec=spec, installed=True, version=spec.version or None, executable=None
                )
            return ResolvedTool(
                spec=spec,
                installed=resolved_executable is not None,
                version=(spec.version or None) if resolved_executable else None,
                executable=resolved_executable,
            )
        if resolved_executable is None:
            return ResolvedTool(spec=spec, installed=False, version=None, executable=None)
        version = self._probe_version(resolved_executable, list(spec.version_probe))
        return ResolvedTool(
            spec=spec,
            installed=True,
            version=version,
            executable=resolved_executable,
        )

    def _resolve_executable(self, executable: str) -> str | None:
        try:
            if os.path.isabs(executable):
                return executable if os.path.isfile(executable) else None
            found = self._which(executable)
        except (OSError, ValueError):  # pragma: no cover - defensive
            return None
        return found or None

    def _probe_version(self, executable: str, probe_argv: list[str]) -> str | None:
        command = [executable, *probe_argv]
        try:
            completed = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                timeout=self._probe_timeout_s,
                env=dict(self._probe_env),
                check=False,
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
        text = self._first_version_line(completed.stdout, completed.stderr)
        if completed.returncode != 0 and text is None:
            return None
        return text

    @staticmethod
    def _first_version_line(stdout: bytes, stderr: bytes) -> str | None:
        for blob in (stdout, stderr):
            if not blob:
                continue
            text = blob.decode("utf-8", errors="replace")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped:
                    return stripped[:200]
        return None

    def describe(self) -> list[dict[str, object]]:
        """Return a deterministic, JSON-friendly catalogue report."""

        return [self.resolve(name).to_dict() for name in self.names() if self.resolve(name)]
