"""Typed trusted-tool catalogue and execution runtime.

Submodules:

- :mod:`ctf_solver.runtime.tools` — ``ToolSpec``/``ToolInvocation`` and the
  builtin trusted tools;
- :mod:`ctf_solver.runtime.catalog` — ``RuntimeCatalog`` (allowlist + cached
  version resolution);
- :mod:`ctf_solver.runtime.executor` — ``RuntimeExecutor`` (in-process or
  fixed-argv ``shell=False`` subprocess execution with bounded capture);
- :mod:`ctf_solver.runtime.pipeline` — ``ExecutionPipeline`` (Broker decision →
  execution → executions row + hash-chained evidence events).

Imports are intentionally lazy in this package initialiser to keep the
``policy`` ↔ ``runtime`` dependency direction (Broker validates catalogue
entries; the pipeline calls the Broker) free of import cycles.
"""

from __future__ import annotations

__all__ = [
    "ExecutionPipeline",
    "ResolvedTool",
    "RuntimeCatalog",
    "RuntimeExecutor",
    "ToolInvocation",
    "ToolSpec",
]


def __getattr__(name: str):  # pragma: no cover - convenience re-exports
    if name == "ToolSpec" or name == "ToolInvocation":
        from .tools import ToolInvocation, ToolSpec

        return {"ToolSpec": ToolSpec, "ToolInvocation": ToolInvocation}[name]
    if name == "RuntimeCatalog" or name == "ResolvedTool":
        from .catalog import ResolvedTool, RuntimeCatalog

        return {"RuntimeCatalog": RuntimeCatalog, "ResolvedTool": ResolvedTool}[name]
    if name == "RuntimeExecutor":
        from .executor import RuntimeExecutor

        return RuntimeExecutor
    if name == "ExecutionPipeline":
        from .pipeline import ExecutionPipeline

        return ExecutionPipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
