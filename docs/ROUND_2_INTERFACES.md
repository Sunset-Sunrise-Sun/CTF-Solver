# Round 2 Module Interfaces — Security Fixes, Integration and Packaging

**Status:** frozen for Round 2 implementation on branch `feat/round2-harness-integration`
**Authority:** `docs/ROUND_2_INTEGRATION_TASK.md` + the owner's Round 2 remediation instructions.
**Baseline:** Round 1 HEAD `e40f76f317ec3f3186e0120744af2f5924d32721`; Round 2 recovery commit
`8615af6` restores the previously ignored `ctf_solver/evidence/` package.

This file fixes the *new* interfaces introduced by the Round 2 security remediation. The frozen
Round 1 product architecture and the Round 1 `docs/INTERFACES.md` contracts remain authoritative
unless explicitly superseded here.

## 0. Repository / branch rules

- Round 1 branch `feat/round1-complete-product-core` at `e40f76f` is frozen; never modify it.
- All Round 2 work happens on `feat/round2-harness-integration`; no push/PR/merge.
- No software installation; no Harness global config changes; no WSL/Docker start; synthetic data
  only; **no `session/prompt` / model calls are authorized**.
- Do not touch `D:\CTFworker`; keep `D:\CTF-SOLVER` runtime data out of Git.
- UTF-8 without BOM; LF for source; all tests deterministic/offline unless explicitly marked.

## 1. Schema v1.1 (Lead-owned, already committed)

`ctf_solver/__init__.py` → `SCHEMA_VERSION = "1.1"`; `ctf_solver/storage/db.py` migrates 1.0 → 1.1.

New columns:
- `approvals`: `confirmation_channel`, `confirmation_id`, `confirmation_os_user`, `confirmation_note`
- `network_grants`: `approval_id`, `confirmation_id`, `confirmation_os_user`
- new table `task_inputs(task_id, rel_path, sha256, size, media_type, source_rel_path, imported_at)`

`ctf_solver/core/types.py`:
- `ApprovalRecord` gained the four confirmation fields.
- `GrantRecord` gained `approval_id`, `confirmation_id`, `confirmation_os_user`.
- new `ImportedInput` dataclass (`rel_path, sha256, size, media_type, source_rel_path, imported_at`).
`ctf_solver/core/config.py`: `SolverConfig.dsh_home`, `session_log_root`, `intake_root`, `ensure_runtime_dirs()`.

## 2. `ctf_solver/security/` + approval/grant service (teammate A)

New package `ctf_solver/security/` (+ `ctf_solver/manager/approval_grant_service.py`), teammate A owns:
`ctf_solver/security/**`, `ctf_solver/manager/store.py`, `ctf_solver/manager/approval_grant_service.py`,
`tests/test_security_*.py`.

### 2.1 Human confirmation channel (`security/confirmation.py`)

```python
@dataclass(frozen=True)
class HumanConfirmation:
    channel: str            # must be "local_console"
    os_user: str
    confirmed_at: int
    confirmation_id: str    # uuid
    approval_digest: str    # digest of the exact proposed action
    note: str = ""

class ConfirmationError(CtfSolverError):  # reason_code="confirmation_error"/"confirmation_unavailable"
    ...

class ConsoleConfirmationChannel:
    def __init__(self, clock, *, input_fn=None, output_fn=None, is_tty=None,
                 os_user=None, max_attempts=3) -> None: ...
    def available(self) -> bool: ...
    def confirm(self, *, approval_digest: str, summary: str) -> HumanConfirmation: ...
    def reject(self, *, approval_digest: str, summary: str) -> HumanConfirmation:
        """Records an explicit human rejection (same TTY rules)."""
```

Hard rules:
- only works when `sys.stdin.isatty()` (or injected `is_tty` in tests) **and** the process is the
  local console (no stdio-pipe/MCP context). Non-interactive → `ConfirmationError` (fail closed).
- always displays the action summary + `approval_digest[:8]`; requires the human to type an exact
  confirmation phrase (`CONFIRM <digest[:8]>`); wrong phrase/attempts exhausted → error, never approve.
- never accept an `approver` string supplied by a caller; `os_user` comes from `getpass.getuser()`.

### 2.2 Approval/grant use cases (`manager/approval_grant_service.py`)

```python
class ApprovalGrantService:
    def __init__(self, store: ManagerStore, evidence: EvidenceSink, clock, config: SolverConfig): ...
    def request_approval(self, task_id: str, *, action_kind: str,
                         details: dict[str, Any], ttl_s: int | None = None) -> ApprovalRecord
    def confirm_approval(self, approval_id: str, *, channel: ConsoleConfirmationChannel,
                         reject: bool = False, note: str = "") -> ApprovalRecord
    def create_grant_from_approval(self, approval_id: str, *,
        competition_profile: str, host: str, port: int, protocol: str = "tcp",
        method: str = "GET", path_prefix: str = "/", ttl_s: int = 3600,
        max_calls: int = 10) -> GrantRecord
    def revoke_grant(self, grant_id: str) -> GrantRecord
    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]
    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]
```

Rules:
- `request_approval`: creates PENDING with `action_digest = policy.models.action_digest(action_kind, details)`,
  TTL, payload details; emits `approval_requested` evidence. No caller-supplied identity.
- `confirm_approval`: the **only** decision path; requires the console channel; approval must be PENDING,
  not expired, digest must equal the digest echoed by the human confirmation; records
  `confirmation_*` fields, `approver=os_user`, `decided_at`; APPROVED or REJECTED; replay/consumed/
  cross-task/expired/mismatched → fail closed. Emits `approval_decided` evidence with channel/os user.
- `create_grant_from_approval`: requires an APPROVED, unexpired, unconsumed `remote_target` approval
  for the same Task; recomputes the target digest from `(host, port, protocol, method, path_prefix,
  competition_profile)` using `policy.models.target_digest`-style canonicalization and requires it to
  equal the approval's recorded target digest (approvals are requested with
  `details={"target": {...}, "profile": ...}`); atomically consumes the approval; grant stores
  `approval_id`, `confirmation_id`, `confirmation_os_user`, `approver`; emits `grant_created`.
  Any mismatch/expiry/consumed/other Task → fail closed.
- There is **no** method that accepts a raw `approver` string, and no MCP tool may approve or create
  a grant (Lead removes `ctf_approval_decide` and `ctf_grant_create` from the MCP surface).

### 2.3 `ManagerStore` changes (teammate A owns this file)

Keep all existing Round 1 behavior and add/extend:
- `create_approval`, `get_approval`, `list_approvals`, `decide_approval` → replaced by a
  confirmation-based atomic method (e.g. `record_approval_confirmation(approval_id, *, approved,
  confirmation: HumanConfirmation-like fields, decided_at) -> ApprovalRecord`); `consume_approval`
  must require an APPROVED approval with confirmation fields; `_approval_from_row` maps the new columns.
- `create_grant`/`_grant_from_row` map new grant columns; `consume_grant_call` unchanged in behavior.
- Add `get_worker_by_session(session_id: str) -> WorkerRecord | None`.
- Add `record_task_inputs(task_id: str, inputs: list[ImportedInput]) -> None` and
  `list_task_inputs(task_id: str) -> list[ImportedInput]` (upsert; used by Lead's ManagerService intake wiring).
- Existing Round 1 manager tests that call `decide_approval(..., approver=...)` /
  `create_network_grant(..., approver=...)` are **expected to be updated by the Lead**, not by you;
  report the breaking changes precisely.

### 2.4 A's tests (minimum)

Console channel: non-TTY fails; wrong phrase fails; TTY phrase approves/rejects; os_user recorded.
Approval: replay fails; expired fails; cross-Task fails; digest mismatch fails; `approved`/`approver`
strings supplied by a caller are impossible via the API; grant creation requires confirmed approval;
grant cannot be created directly (no API path); replay consumption fails; no self-approval path.
Wire fake `input_fn/output_fn/is_tty` through the constructor; never touch a real TTY in tests.

## 3. Session-log resolver + MCP schema + ACP launch (teammate B)

Teammate B owns: `ctf_solver/manager/session_logs.py`, `ctf_solver/mcp/schema.py`,
`ctf_solver/acp/launch.py`, tests `tests/test_session_log_resolver.py`,
`tests/test_mcp_schema.py`, `tests/test_acp_launch.py`.

### 3.1 `SessionLogResolver` (`manager/session_logs.py`)

```python
class SessionLogError(CtfSolverError):
    # reason codes: unknown_task, no_worker, unknown_session, log_missing,
    # ambiguous_session_log, symlink_rejected, path_escape, header_mismatch, sessions_root_missing

@dataclass(frozen=True)
class ResolvedSessionLog:
    task_id: str; worker_id: str; session_id: str; path: Path

class SessionLogResolver:
    def __init__(self, sessions_root: Path, store: ManagerStore, *, clock=None): ...
    def resolve(self, task_id: str, *, worker_id: str | None = None) -> ResolvedSessionLog: ...
```

Rules:
- Task must exist; Worker mapping must exist; optional `worker_id` must match the Task's Worker.
- Locate the log **only** by Manager registry: `<sessions_root>/*/<sessionId>/session.v4.jsonl.zstd`
  (the real Harness layout verified by the audit is `sessions/<cwd-slug>/<session-uuid>/session.v4.jsonl.zstd`).
  Reject: missing sessions root, zero matches, more than one match (ambiguous), any symlink in the
  resolved path/ancestors, resolved path outside `sessions_root`.
- Verify content identity: first zstd frame's session header `id` must equal the registered
  `sessionId` (use `ctf_solver.evidence.zstd_frames.decode_all` + `parse_json_lines`; no model input).
- Never accept a caller path; the resolver takes only `task_id` (+ optional `worker_id` check).

### 3.2 MCP schema validator (`mcp/schema.py`)

```python
class SchemaValidationError(ValueError): ...
def validate_schema(schema: dict[str, Any], value: Any, *, path: str = "$") -> list[dict[str, Any]]: ...
def validate_or_raise(schema: dict[str, Any], value: Any) -> None: ...
```

Support at least: `type` (single or list; object/array/string/integer/number/boolean/null),
`enum`, `const`, `required`, `properties`, `additionalProperties` (bool; false rejects extras),
`items` (single schema), `minItems`, `maxItems`, `minLength`, `maxLength`, `pattern`, `minimum`,
`maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `anyOf` (minimal). Error dicts:
`{"path": "$.argv[1]", "message": "..."}`. Unknown schema keywords are ignored, not trusted.
Malformed JSON-Schema input → `SchemaValidationError("invalid schema")`.

### 3.3 ACP launch command builder (`acp/launch.py`)

```python
def build_acp_command(launcher: list[str]) -> list[str]:
    """Return the exact argv for the audited ACP server: dsh --profile acp (cmd wrapper for .cmd/.bat)."""

def build_default_acp_command(env: dict[str,str] | None = None) -> list[str] | None:
    """discover_acp_command() + build_acp_command(); None if the launcher is absent."""
```

Rules: never a shell string; `.cmd`/`.bat` wrapped as `[COMSPEC, "/c", exe, "--profile", "acp", *rest]`;
other executables `[exe, "--profile", "acp", *rest]`; empty launcher → `ConfigError`.
Tests: builder output for .cmd vs .exe; a temp `.cmd` that records `%*` to a file executed through
the wrapper receives `--profile acp`; `build_default_acp_command` returns the discovered launcher path.

## 4. Challenge-file intake + packaging (teammate C)

Teammate C owns: `ctf_solver/intake.py`, `pyproject.toml`, `tooling/wheelbuild.py`,
`scripts/build_wheel.py`, `scripts/fresh_clone_check.py`, tests `tests/test_intake.py`,
`tests/test_wheel_build.py`.

### 4.1 `IntakeService` (`ctf_solver/intake.py`)

```python
class IntakeError(CtfSolverError): ...
class IntakeService:
    def __init__(self, intake_root: Path, *, max_files: int = 100,
                 max_total_bytes: int = 256 * 1024 * 1024, clock=None): ...
    def import_files(self, *, task_id: str, workspace: Path,
                     supplied_files: list[str]) -> list[ImportedInput]: ...
```

Rules:
- `intake_root` is the only source root (`<project>/challenge-uploads/`); must exist, be a directory,
  not a symlink.
- Each supplied entry is a **relative POSIX/Windows path** under `intake_root`: reject absolute paths,
  drive-qualified paths, `..` traversal, NUL/control chars, empty entries; resolve with
  `os.path.realpath` and require containment in `intake_root`.
- Reject symlinks (including symlink ancestors) and non-regular files; enforce file-count/total-size
  limits; reject duplicate target rel_paths.
- Copy to `<workspace>/inputs/<rel_path>` (mkdir parents); compute SHA-256, size, media type
  (`mimetypes.guess_type` with `application/octet-stream` fallback); return `ImportedInput` list with
  `source_rel_path`; never expose arbitrary host paths to the model. No shell.
- Tests: traversal/absolute/symlink/outside/intake-missing/limits/duplicates; multi-file; two Tasks
  receive separate copies and cannot see each other's files; hashes/metadata correct; writeup data
  shape (`ImportedInput.to_dict`) stable.

### 4.2 Wheel build (in-tree PEP 517 backend, no installation)

Because `setuptools`/`wheel` are **not installed** and installation is forbidden, change
`pyproject.toml` to use an in-tree stdlib backend:

```toml
[build-system]
requires = []
build-backend = "wheelbuild"
backend-path = ["tooling"]
```

Implement `tooling/wheelbuild.py` with PEP 517 hooks (`get_requires_for_build_wheel` → `[]`,
`build_wheel`, `prepare_metadata_for_build_wheel`, optional `build_sdist`) that builds a valid
`ctf_solver-0.1.0-py3-none-any.whl` from `[project]` metadata + all `ctf_solver/**/*.py` packages
(including `security/`, `intake.py`, `wiring.py`), `.dist-info/METADATA`, `WHEEL`
(`Root-Is-Purelib: true`, tag `py3-none-any`), `entry_points.txt` (`ctf-solver=ctf_solver.cli:main`),
and a correct `RECORD` (SHA-256, base64url, no padding; RECORD entry itself unhashed). Deterministic
zip timestamps. Keep `[project]` metadata authoritative; ignore/describe legacy `[tool.setuptools]`.

`scripts/build_wheel.py`: builds via `python -m pip wheel . --no-deps --no-build-isolation -w dist`
(or invokes the backend directly if pip refuses), then verifies: wheel file exists, all `ctf_solver`
packages present (at least `core, storage, acp, evidence, policy, runtime, mcp, manager, delivery,
preflight, security` once A lands), extract to temp and successfully import
`ctf_solver.evidence.store`, `ctf_solver.manager.service`, `ctf_solver.intake`, and run
`python -m ctf_solver version` with `PYTHONPATH=<extract>`.

`scripts/fresh_clone_check.py`: `git clone --no-hardlinks --branch <current> <repo> <temp>` (read-only
on the source), run `python -m pytest tests -q` inside the clone with the existing interpreter, then
build+import the wheel from the clone; print JSON summary + raw logs to `round2-evidence/`.

## 5. Lead-owned integration (do not edit)

`ctf_solver/manager/service.py`, `ctf_solver/manager/store.py` is A-owned but integration callers are
Lead's; `ctf_solver/mcp/protocol.py`, `ctf_solver/mcp/manager_server.py`, `ctf_solver/cli.py`,
`ctf_solver/wiring.py`, `docs/`, integration tests and evidence are Lead-owned.

Round 2 MCP surface changes (Lead):
- remove `ctf_approval_decide` and `ctf_grant_create` (model can propose, never approve/authorize);
- `ctf_session_ingest` takes only `task_id` (+ optional `worker_id`), never a path;
- `ctf_task_create` accepts `supplied_files` relative to the project intake root;
- `ctf_approval_list`, `ctf_grant_list`, `ctf_grant_revoke` remain;
- local human confirmation is performed by a **local TTY CLI**, not through MCP.

## 6. Definition of done for teammates

- Only files in your scope changed; no installs; no global Harness config; no model call; no target;
  synthetic fixtures/tmp paths only.
- Your tests pass (`pytest tests/<your files> -q`) and are negative-case heavy; report exact command,
  counts, raw log under `round2-evidence/raw/`, and any contract gap or breakage to the Lead.
- Do not edit other teammates' scopes or the shared files listed in §5; message the Lead instead.
