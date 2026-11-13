# Module Interfaces (Frozen Contract)

**Status:** frozen interface contract for the current release.
**Authority:** the accepted product docs. This file only fixes module boundaries so
parallel work composes; it does not change product scope.

Every module imports the frozen contracts from `ctf_solver.core` and `ctf_solver.storage.db`.
Do not redefine them. If a contract is genuinely insufficient, report it to the Lead instead
of silently editing shared files.

## 0. Ground rules

- Python 3.11+ syntax, but the existing interpreter is **Python 3.14.7**; standard library
  only, except: `zstandard` (already installed) may be imported *optionally* as a zstd
  backend. Never install anything.
- All file writes are UTF-8; source files use LF line endings; Skill files must be
  **UTF-8 without BOM**.
- Tests use `pytest` (already installed). Test data lives in `tmp_path`; never write runtime
  data into the repository tree. Tests must be deterministic, offline, and must not spawn
  real Harness ACP sessions or model calls (except the explicitly marked opt-in
  zero-model-call smoke test).
- No shell strings: only argv arrays. `subprocess` calls use `shell=False`.
- Never claim PASS for blocked/unverified behaviour.
- Every process started by a test/Manager must be cleaned up (no orphans).
- Write scopes are advisory but enforced by the Lead in review. Stay inside your directories.

## 1. Shared core (Lead-owned, do not edit)

`ctf_solver/core/types.py`, `errors.py`, `canonical.py`, `config.py`, `ids.py`, `paths.py`,
`protocols.py`; `ctf_solver/storage/db.py`; `tests/support/*`.

Key helpers:

- `canonical_json(value)`, `canonical_bytes(value)`, `sha256_hex(bytes)`, `file_sha256(path)`,
  `chain_hash(prev_hash, record_payload)`, `hash_manifest(entries)`, `GENESIS_HASH`.
- `SolverPaths.for_root(root)` / `SolverConfig(root=...)` (`ensure_layout()` creates
  `.ctf-solver-data/`, `tasks/`, `exports/`, `captures/`).
- `SolverConfig.max_active_workers` is 1 or 2 (default 2); `allow_model_calls` may never be
  true in Round 1 (`ConfigError` otherwise).
- `ctf_solver.core.errors`: `ValidationError`, `NotFoundError`, `StateError`, `StorageError`,
  `ChainIntegrityError`, `EvidenceError`, `AcpError` family, `ModelCallNotAuthorized`,
  `IpcError`, `CaptureError`, `DeliveryError`, `DenyReason` (stable denial codes).
- Types: `TaskRecord`, `WorkerRecord`, `ApprovalRecord`, `GrantRecord`, `ArtifactRef`,
  `ExecRequest`, `NetworkTarget`, `BrokerDecision`, `RuntimeOutcome`, `ExecutionResult`,
  `ScreenshotRecord`, `CaptureResult`, `ChainStatus`, `ExportInfo`, plus enums
  (`Category`, `TaskStatus`, `WorkerStatus`, `ExecutionTier`, `ExecutionStatus`,
  `ApprovalStatus`, `GrantStatus`, `FlagState`, `CaptureStatus`, `ApprovalAction`).
- `TaskStatus`/`TASK_TRANSITIONS`: use `can_transition()` for every status change.
  `PAUSED` is an implementation-level non-terminal state for the control-API "pause"
  capability; terminal states are `CANCELLED/COMPLETED/PARTIAL/FAILED`.
  `SLOT_OCCUPYING_TASK_STATUSES` = starting/running/paused/awaiting_approval/blocked/
  cancel_requested.
- Clock: `ctf_solver.core.protocols.SystemClock().now_ms()` returns int ms; tests may inject a
  fake clock with the same `now_ms()` method.
- Protocols in `ctf_solver.core.protocols`: `AcpSessionClient`, `AcpClientFactory`,
  `EvidenceSink`, `PolicyRepository`, `ExecutionPipelineProtocol`, `ScreenCapturer`,
  `DeliverablesProtocol`, `ManagerControl`, `Clock`.

## 2. SQLite schema (shared, Lead-owned DDL)

`ctf_solver/storage/db.py` creates every table. Modules must not run their own DDL. Relevant
tables:

| table | owner | purpose |
|---|---|---|
| `tasks` | Manager | Task registry and lifecycle |
| `workers` | Manager | one Worker per Task, ACP session + workspace + token |
| `approvals` | Manager | Task-scoped human approvals |
| `network_grants` | Manager | Task-scoped target grants |
| `executions` | Runtime pipeline | one row per ctf-exec call (allowed or denied) |
| `events` | Evidence | append-only hash-chained normalized events |
| `artifacts` | Evidence | CAS object metadata |
| `screenshots` | Evidence/Delivery | screenshot metadata |
| `ingestion_sources` | Evidence | idempotent ingestion watermarks |
| `exports` | Delivery | generated deliverable records |
| `meta` | shared | `schema_version`, `events_chain_head`, `events_chain_head_seq` |

Helpers: `open_database(path)`, `initialize_schema(conn)`, `transaction(conn)`,
`get_meta/set_meta`. `events` has BEFORE UPDATE/DELETE triggers that abort; type/text
columns must match the DDL exactly (see the file).

## 3. `ctf_solver/acp` — ACP Client (teammate A)

Files: `transport.py`, `client.py`, `models.py`, `fake_server.py` (+ tests `tests/test_acp_*.py`).

### 3.1 Transport (`transport.py`)

`JsonRpcStdioTransport` over a subprocess' stdio pipes:

- Single reader thread parses **ND-JSON**: one JSON-RPC 2.0 message per line; handles partial
  reads, several messages per chunk, CRLF/LF, arbitrary message size (e.g. 1 MiB+), invalid
  JSON (surfaced as `AcpProtocolError` diagnostics; must not kill the reader permanently).
- `send_request(method, params, timeout_s) -> result` correlates by generated request id;
  supports event/response interleaving, out-of-order responses, duplicate ids, timeouts
  (`AcpTimeout`), process exit (`AcpProcessExited`).
- `send_notification(method, params)`; `notify(method, params)`; server→client requests are
  dispatched to registered handlers (`session/request_permission`).
- stderr drained to a bounded in-memory buffer and optional file, never mixed into stdout.
- Round 1 is a **client** only; do not add a server beyond `fake_server.py`.

### 3.2 Client (`client.py`)

`AcpClient` implements `ctf_solver.core.protocols.AcpSessionClient`:

```python
AcpClient(command: list[str], *, env: dict[str,str] | None = None, cwd: str | None = None,
          startup_timeout_s: float = 20.0, request_timeout_s: float = 30.0,
          stderr_path: str | None = None, allow_model_calls: bool = False)
```

- `start()` spawns `Popen(command, shell=False)` then calls `initialize`
  (`protocolVersion` must be 1; store `agentInfo`, `mcpCapabilities`,
  `sessionCapabilities`).
- Lifecycle state machine: `stopped -> starting -> ready -> closing -> stopped` plus
  `failed`/`crashed`; `diagnostics()` returns a dict with at least `state`, `pid`,
  `command`, `protocol_version`, `pending_requests`, `last_error`, `stderr_tail`,
  `started_at`, `request_count`, `response_count`, `malformed_lines`.
- `new_session(cwd, mcp_servers=None)` → raw result dict (must contain `sessionId`; keep
  `configOptions`). `cwd` must be absolute; a relative/nonexistent cwd is a
  `ValidationError` before sending.
- `list_sessions(cwd=None)`, `resume_session(session_id, cwd)`, `close_session(session_id)`.
- `cancel_session(session_id)` sends the `session/cancel` **notification** (never described as
  an OS kill).
- `prompt(session_id, content)`: Round 1 must raise `ModelCallNotAuthorized` unless
  `allow_model_calls=True`; tests assert the default. When allowed, send
  `session/prompt` and return the raw result.
- `set_permission_handler(cb)`: cb receives the raw `session/request_permission` params and
  returns the exact response payload (`{"outcome": {"outcome": "selected",
  "optionId": "allow-once"}}` or `{"outcome": {"outcome": "cancelled"}}`).
- `set_session_update_handler(cb)`: cb receives `session/update` params.
- `stop()`: graceful stdin EOF / terminate, reaps the process, records diagnostics; one
  `stop()` must be idempotent.
- Crash: if the process dies, pending requests fail with `AcpProcessExited`, state becomes
  `crashed`, and the exit code is preserved in diagnostics.

### 3.3 Fake ACP server (`fake_server.py`)

Executable module: `python -m ctf_solver.acp.fake_server --scenario <name> [--log-dir DIR]`.
It must speak the same ND-JSON JSON-RPC protocol on stdio and support, at minimum:

- `initialize` (v1 capabilities), `session/new` (validate absolute cwd; optional mcpServers),
  `session/list` (exclude active sessions, newest-first), `session/close`,
  `session/resume` (cwd canonical match), `session/cancel` (notification), `session/prompt`
  (scripted echo result; the *client* gate is what prevents use in Round 1).
- Scenarios: `normal`, `slow` (delayed responses), `malformed` (emit non-JSON line),
  `crash-after-init`, `exit-on-cancel`, `permission-request` (server→client
  `session/request_permission`, waits for the client answer and records it), `partial-flush`
  (write responses in tiny chunks), plus a `--session-log DIR` option that writes a realistic
  multi-frame zstd `session.v4.jsonl.zstd` for `session/new` using
  `tests.support.session_events`/`zstd_fixtures`, and a `--record DIR` option that writes
  `session-new.json` (list of recorded `session/new` params incl. returned sessionId, cwd and
  `mcpServers` env) so Lead integration tests can obtain the per-Worker IPC URL/token exactly
  as a real Harness session would receive them.
- Tests: transport framing/correlation/timeouts/malformed/EOF/process-exit; lifecycle states;
  session isolation; permission round trip; graceful stop; no orphan processes.

## 4. `ctf_solver/evidence` — evidence pipeline (teammate B)

Files: `zstd_frames.py`, `cas.py`, `normalize.py`, `store.py`, `ingest.py`, `manifest.py`
(+ tests `tests/test_evidence_*.py`, `tests/test_zstd_*.py`).

### 4.1 Multi-frame decoding (`zstd_frames.py`)

- `scan_frames(data: bytes) -> list[FrameSpan]` by zstd magic `28 B5 2F FD`; identify truncated
  tail frames.
- `decode_all(data: bytes) -> DecodeReport` with `frames: list[FrameDecode]`
  (`index, offset, length, payload: bytes, error`), `gaps: list[DecodeGap]`,
  `complete: bool`. Decode **every** concatenated frame, including frames without a content
  size header (streaming decompressor). Try `zstandard` first, fall back to stdlib
  `compression.zstd`; if neither exists raise `UnsupportedCompressionError` (BLOCKED, never
  silently single-frame).
- `parse_json_lines(payload: bytes) -> (list[dict], list[GapInfo])`: torn/invalid JSON lines
  become explicit gaps, never silently dropped. A line may span frame boundaries.

### 4.2 CAS (`cas.py`)

`Cas(root_dir)` with `put_bytes(data, media_type="application/octet-stream") -> ArtifactRef`,
`put_file(path, ...)`, `get_bytes(sha256)`, `path_for(sha256)`, `exists`, `verify(sha256)`,
`iter_objects()`. Layout: `<root>/<aa>/<sha256>` (root = `.ctf-solver-data/cas/sha256`).
Dedup identical bytes; never mutate existing objects.

### 4.3 Normalization (`normalize.py`)

`normalize_session_records(*, task_id, worker_id, session_id, raw_records, cas) ->
NormalizedBatch(events: list[dict], gaps: list[dict], stats: dict)`.
Each normalized event is a dict with:
`record_id` (deterministic), `task_id`, `worker_id`, `session_id`, `source`
(`"session_log"`), `source_id`, `source_seq` (raw `seq`), `event_type`, `timestamp`,
`payload`.

Required normalization:
- `tool/call` ↔ `tool/result` correlated by `callId`; result content text → CAS
  (`application/octet-stream`) with bounded preview (e.g. 4096 chars) and `is_error`, exit
  code parsed from `exit code: N` when present.
- Preserve job `registered/settled` (status, cause, detail), approvals
  (`approval/asked|decided`), command events, turn/step boundaries, and unknown event types
  as generic `passthrough` events (full `data` preserved).
- Unmatched call/result → explicit `evidence_gap` events with reason
  `unmatched_call`/`unmatched_result`; sequence gaps → `evidence_gap` with
  `sequence_gap` (include missing range).
- `record_id` deterministic: `ev-<sha256(canonical identity)[:24]>` so re-ingestion is
  idempotent.

### 4.4 Store (`store.py`) — implements `EvidenceSink` + evidence queries

`EvidenceStore(db_path, cas_root, clock=None)` using `storage/db.py`:

- `append_event(...) -> str` (exact signature from `EvidenceSink`) — chain insert:
  `prev_hash` = current `meta.events_chain_head`; `record_hash = chain_hash(prev_hash,
  record_payload)`; update chain head **in the same transaction**; return record_id.
- `append_events(list[dict])`, `ingest_session_log_bytes(...)`, `ingest_session_log_file(...)`
  implement §4.5.
- `store_artifact(data|path, media_type, source) -> ArtifactRef` (CAS + `artifacts` row).
- `list_events(task_id=None, after_seq=None, limit=None, event_type=None)`,
  `get_event(record_id)`, `count_events(task_id)`.
- `chain_status() -> ChainStatus`: recompute the entire chain in `seq` order from
  `GENESIS_HASH`, compare with recomputed record hashes and with the protected head in
  `meta`; report first broken seq.
- `chain_head() -> tuple[int, str]`.
- `export_events_jsonl(*, task_id, out_path) -> ExportInfo`: deterministic export from
  committed rows only (canonical JSON per row sorted by `seq`, full row incl. payload object);
  same DB state ⇒ byte-identical file; must not write SQLite.
- `record_screenshot(record: ScreenshotRecord) -> None`, `list_screenshots(task_id)`,
  `get_task_events_for_writeup(task_id)` (convenience, ordered by seq).
- `ingest_state(source_id)`; `record_export(ExportInfo)`.

### 4.5 Ingestion (`ingest.py`)

`Ingestor(store, cas)`:
- `ingest_session_log_bytes(*, task_id, worker_id, session_id, data, source_id, path=None) ->
  IngestReport(frames, decoded_records, appended, skipped_duplicates, gaps, raw_sha256,
  complete)`.
- Stores the **raw bytes** in CAS; decodes all frames; normalizes; appends records with
  `UNIQUE(source_id, source_seq)` idempotency (re-ingesting the same bytes appends 0);
  updates `ingestion_sources` watermark; gaps are recorded as gap events (not dropped).
- Partial re-ingestion (a longer log that starts with previously ingested records) appends
  only new sequence numbers.
- Truncated last frame / corrupt frame / torn line → explicit gap entries, `complete=False`.

### 4.6 Canonical normalized event types and payload keys (frozen)

To let delivery generate the Writeup from evidence deterministically, the following event
type names and payload keys are frozen. Extra keys are allowed; these must be present.

| event_type | source | payload keys (minimum) |
|---|---|---|
| `tool_call` | session_log | `call_id`, `tool_name`, `arguments`, `turn`, `step` |
| `tool_result` | session_log | `call_id`, `is_error`, `content_preview`, `content_sha256`, `content_size`, `exit_code`, `cwd`, `turn`, `step` |
| `job_registered` | session_log | `job_id`, `tool_call_id`, `kind`, `label` |
| `job_settled` | session_log | `job_id`, `tool_call_id`, `status`, `cause`, `detail` |
| `harness_approval_asked` | session_log | `approval_id`, `call_id`, `tool_name`, `reason` |
| `harness_approval_decided` | session_log | `approval_id`, `outcome` |
| `command_run` / `command_done` | session_log | `command`, plus `exit_code` on done |
| `turn_start`, `turn_end`, `step_start`, `step_end`, `assistant_message`, `passthrough` | session_log | raw `data` under `data` (bounded) |
| `evidence_gap` | any | `reason` (`unmatched_call`, `unmatched_result`, `sequence_gap`, `torn_line`, `frame_decode_error`, `truncated_frame`), `detail` |
| `execution_started` | runtime | `execution_id`, `tool_name`, `tool_version`, `argv`, `cwd`, `tier`, `step_id` |
| `execution_completed` / `execution_failed` / `execution_denied` | runtime | `execution_id`, `status`, `exit_code`, `reason_code`, `stdout_sha256`, `stderr_sha256`, `stdout_preview`, `stderr_preview` |
| `task_created` | manager | `title`, `category`, `conversation_id` |
| `task_started` | manager | `worker_id`, `session_id`, `workspace` |
| `task_paused` / `task_cancelled` / `task_interrupted` | manager | `reason`, optional `quiescent` |
| `model_call_suppressed` | manager | `message_length` |
| `approval_requested` / `approval_decided` | manager | `approval_id`, `action_kind`, `action_digest`, `approved`, `approver` |
| `grant_created` / `grant_revoked` | manager | `grant_id`, `host`, `port`, `protocol`, `method`, `expires_at`, `max_calls` |
| `flag_candidate` | manager | `flag_sha256`, `source`, `flag_state` (never the raw Flag) |
| `screenshot_captured` / `screenshot_failed` | manager | `screenshot_id`, `sha256`, `width`, `height`, `scope`, `status`, `failure_reason` |
| `task_cancel_requested`, `task_failed` | manager | `reason`, optional `phase` |
| `evidence_ingested` | manager | `path`, `frames`, `records`, `gaps`, `raw_sha256` |
| `acp_permission_rejected` | manager | `session_id`, `tool_call` (Round 1 rejects ACP host-tool permission requests) |

### 4.7 Manifest (`manifest.py`)

`write_manifest(entries: list[tuple[str, str]], out_path) -> ExportInfo` (sorted
`<sha256>  <relpath>` lines, LF) and `verify_manifest(manifest_path, root) -> ManifestReport`
(missing/mismatched/extra detection, independently recomputed).

### 4.7 Tests (minimum)

Multi-frame decode (including >1 frame with mid-line splits), single-frame regression,
truncated frame, corrupt frame, torn line; call/result correlation; unmatched pair; sequence
gap; idempotent re-ingestion; longer-log incremental ingestion; CAS dedup/integrity; chain
verify clean; tamper detection (drop triggers → mutate row → `chain_status().ok is False`);
chain-head mismatch; deterministic JSONL export (twice → identical bytes); export has no
SQLite side effects; manifest generate/verify and tamper cases.

## 5. `ctf_solver/policy` + `ctf_solver/runtime` (teammate C)

Files: `policy/broker.py`, `policy/models.py`, `runtime/catalog.py`, `runtime/executor.py`,
`runtime/tools.py`, `runtime/pipeline.py` (+ tests `tests/test_broker_*.py`,
`tests/test_runtime_*.py`).

### 5.1 Runtime (`runtime/`)

`ToolSpec` dataclass: `name, display_name, description, tier: ExecutionTier, version: str`,
`version_probe: list[str] | None`, `executes_challenge_code: bool`,
`arg_validator: Callable[[list[str]], str | None]` (None = valid, else message),
`internal: Callable[[ToolInvocation], RuntimeOutcome] | None`, `default_timeout_s`,
`max_output_bytes`, `requires_approval: ApprovalAction | None`,
`network: bool = False`.

`RuntimeCatalog.default()` returns builtin trusted tools (all deterministic, no challenge
code execution):
- Tier 0 internal: `internal.file_hash`, `internal.file_metadata`, `internal.archive_list`
  (zip/tar metadata only), `internal.text_search` (bounded), `internal.hex_preview`,
  `internal.strings_scan` (bounded).
- Tier 1 fixed-argv probes: `tool.git_version` (`["--version"]`), `tool.python_version`
  (`["--version"]`) — subprocess, argv fixed, `shell=False`.
- No network tools are functional in Round 1; a `tool.remote_probe` entry may exist only to
  prove the Broker denies it (`network=True`, requires grant + Tier 2).
Catalog is extensible in tests via `RuntimeCatalog(tools=[...])`.

`RuntimeExecutor.execute(spec, invocation) -> RuntimeOutcome`: internal ops run in-process;
subprocess ops use `subprocess.run([...], cwd=..., timeout=..., shell=False,
env=minimal_env)`, cap stdout/stderr at `max_output_bytes` (truncate flag), never raise for
non-zero exit (return `ExecutionStatus.FAILED` with exit code); timeout →
`TIMED_OUT`; spawn failure → `FAILED` with error text.

### 5.2 Broker (`policy/broker.py`)

`Broker(repository: PolicyRepository, catalog: RuntimeCatalog, clock, *, config)`
with `authorize(request: ExecRequest, worker_token: str) -> BrokerDecision`. Fail-closed in
this order (deny with `DenyReason` codes):
1. structural sanity (ids, step_id pattern, argv limits: <= 64 args, each <= 8192 chars, no
   NUL/control chars, no shell metacharacters in argv[0]);
2. worker token → `WorkerRecord`; require worker exists, is bound to the same task, status
   `ready/running`, and request.worker_id matches;
3. task exists, status is slot-occupying and runnable (`running/paused/awaiting_approval`),
   workspace path matches worker workspace;
4. tool allowlisted; not installed → `TOOL_NOT_INSTALLED`; requested version must equal the
   catalog version when supplied;
5. `executes_challenge_code` / `tier >= TIER2` or Tier2 unavailable → deny
   `UNTRUSTED_CODE_REQUIRES_TIER2` / `TIER_NOT_AVAILABLE`;
6. argv validator; cwd absolute and inside worker workspace; input files inside workspace,
   exist, SHA-256 matches; output paths inside workspace, no traversal/absolute;
7. approval: if `requires_approval` or `approval_id` supplied, approval must exist for the
   task, match action digest, be approved, unexpired, unused; then `consume_approval`;
8. network: if `network_target` present, `network_grant_id` required; grant must match task,
   profile, host, port, protocol, method, path prefix, be active/unexpired, `calls_used <
   max_calls`; loopback/private destinations require an explicit grant (same checks); then
   `consume_grant_call`. If the tool is network-capable but no target/grant → deny
   `NETWORK_TARGET_MISSING`.
9. timeout/resource limits within policy.
`Broker.validate_redirect(grant, original_target, redirect_target)` and
`Broker.validate_resolved_address(grant, target, resolved_ips)` implement redirect/DNS scope
revalidation: same in-scope destination OK; private/loopback IPs require an explicit
`allow_private` grant payload flag; otherwise deny `REDIRECT_SCOPE_VIOLATION` /
`DNS_SCOPE_VIOLATION`. Tests use injected/synthetic resolver data only (no real DNS).

Grant/approval helpers (`policy/models.py` or `broker.py`): `target_digest(target)`,
`action_digest(action_kind, details)`, `is_private_host(host)`, `is_loopback_host(host)`,
call-count consumption is delegated to the repository (`consume_grant_call`,
`consume_approval` must be atomic in SQLite).

### 5.3 Execution pipeline (`runtime/pipeline.py`)

`ExecutionPipeline(repository: PolicyRepository, evidence: EvidenceSink, broker: Broker,
executor: RuntimeExecutor, clock)` implements `ExecutionPipelineProtocol`:
`execute(request, worker_token) -> ExecutionResult`.

- Denied: status `DENIED`, no process started, `reason_code` from decision; write
  `executions` row and evidence event (`execution_denied`); **never** call the executor.
- Allowed: write `executions` `running` row + evidence `execution_started`; run; store
  stdout/stderr bytes in CAS through `EvidenceSink.store_artifact`; write final row/result +
  `execution_completed|execution_failed` evidence; output files hashed into
  `output_files`.
- Response matches docs/EXECUTION_CONTRACT.md (including `started_at/ended_at/exit_code/
  stdout/stderr refs/previews`), distinguishes denied vs started-and-failed.
- Allowed events use source `"runtime"`, source_id like `execution:<execution_id>`,
  source_seq 1/2 for start/finish.

### 5.4 Tests (minimum)

Allow/deny matrix for every rule above; cross-task worker token denial; wrong tool/version;
argv shell-injection attempts; path traversal and cwd escape; input hash mismatch; approval
missing/expired/cross-task/already-used; grant missing/expired/exhausted/wrong
task/host/port/protocol/method/path; private/loopback target denial; redirect and DNS
mismatch; tier2 denial; denied-before-exec is distinguishable (no executor call, spy
executor) from executed-but-failed (real internal tool returning non-zero) and timed out;
runtime output caps; subprocess fixed-argv tools work; pipeline writes executions + evidence
and returns the contract fields.

## 6. `ctf_solver/manager` — Manager core (teammate D)

Files: `store.py`, `scheduler.py`, `service.py`, `ipc.py` (+ tests `tests/test_manager_*.py`,
`tests/test_scheduler.py`, `tests/test_manager_recovery.py`).

### 6.1 Store (`store.py`) — implements `PolicyRepository`

`ManagerStore(db_path, clock)` using `storage/db.py`: create/read/update Task and Worker
rows, FIFO queue queries (`queued` ordered by `created_at, task_id`), approval/grant CRUD,
execution row insert/update, token lookup, slot counting (`workers` joined with
`SLOT_OCCUPYING_WORKER_STATUSES`), atomic `consume_grant_call`/`consume_approval`
(transactional check+update; return False when invalid/expired/exhausted/used).
All status changes go through a helper that enforces `can_transition` and raises
`StateError` on illegal transitions.

### 6.2 Scheduler (`scheduler.py`)

Pure, clock-injected `Scheduler(capacity=2)`:
`admit(active_count, queued_tasks) -> list[TaskRecord]` (FIFO order, capacity-respecting),
`queue_position(task_id, queued_tasks)`, slot accounting helpers. No DB writes; unit tests
cover 2 active + 3rd queued, promotion after release, capacity validation.

### 6.3 Service (`service.py`) — implements `ManagerControl`

`ManagerService(config: SolverConfig, store: ManagerStore, acp_factory: AcpClientFactory,
evidence: EvidenceStore, pipeline: ExecutionPipeline, deliverables: DeliverablesProtocol,
capturer: ScreenCapturer, clock)`.

Additional lifecycle surface required by the Lead-owned control server:

- `start() -> dict`: start the loopback IPC server first, then start the managed ACP client
  (if not already started), then run `recover()`; return a status dict. Idempotent.
- `ipc_url` property: loopback IPC base URL (`http://127.0.0.1:<port>` is not implied; the
  IPC uses raw TCP ND-JSON, so expose `ipc_url` as `tcp://127.0.0.1:<port>`). `None` before
  `start()`.
- Calls to ManagerControl methods before `start()` start the service lazily (tests may also
  construct fakes and call directly).

Behaviour requirements:

- `create_task`: validate title/category/conversation, create `tasks/<task_id>/work`, durable
  Task (status `queued`), then `pump()` to start up to capacity.
- `pump()`: while slots free and queued tasks exist → `start_task`: create Worker id/token,
  call `acp_client.new_session(cwd=workspace, mcp_servers=[worker ctf-exec spec])`, persist
  **before** marking ready/running (Task.acp_session_id, worker row with session id, token,
  status ready, task status running, started_at). Any failure → task `failed`/`interrupted`,
  slot released, other active tasks unaffected (failure isolation). One Worker per Task; no
  workspace/session reuse.
- max 2 active Workers; queued order FIFO; promotion after slot release.
- Manager owns the active registry (never calls `session/list` to decide state).
- `pause_task`: running → `paused` + `acp.cancel_session`; records event;
  `cancel_task`: set `cancel_requested`, send ACP cancel notification, then attempt
  `close_session`; only after close success (or confirmed quiescence) transition
  `cancelled` and free the slot; if close fails, remain `cancel_requested` with diagnostics
  (truthful cancellation; ACP cancel is not an OS kill).
- Unexpected ACP process exit/crash: mark affected tasks `interrupted` (never `completed`),
  mark workers crashed, free slots, and do not corrupt other tasks.
- `recover()`: reload durable tasks; tasks in `starting/running/...` without a live ACP
  session mapping become `interrupted` with diagnostics; **never create duplicate sessions**
  for tasks that already have an `acp_session_id`; queued tasks resume FIFO.
- `continue_task`: records a continuation evidence event; Round 1 must NOT issue
  `session/prompt` (no model call); return `model_call_suppressed=True` and the active task
  summary. Task must be non-terminal.
- approvals (`request_approval`, `decide_approval`, `list_approvals`): Task-scoped;
  `decide_approval` records approver/timestamp; agent cannot approve its own sensitive
  action (approver string required, tests use a human label; no auto-approval path).
- network grants (`create_network_grant`, `revoke_grant`, `list_grants`): write grant with
  digest/expiry/max_calls; Task-scoped; `fresh grant` starts `calls_used=0`.
- `record_candidate_flag`: only `candidate`; never submits; returns flag state.
- `take_screenshot`: explicit capture via injected `ScreenCapturer`, store bytes in CAS via
  evidence, record screenshot row (ok/blank/failed), bind task/worker/step/session/time;
  blank/failed captures recorded honestly.
- `ingest_session_log`: delegate to evidence ingestion for the task's worker session;
  return report dict.
- `export_events` / `build_writeup` / `export_evidence_zip`: delegate to
  `EvidenceStore`/`DeliverablesProtocol`, record exports.
- `get_task_status`: task + worker + queue position + approvals + grants + last executions
  + screenshot count + evidence chain head.
- `runtime_status`: ACP client diagnostics, active count, queue length, chain head.
- `shutdown()`: stop IPC, stop ACP client, reap children; no orphan processes.

### 6.4 IPC (`ipc.py`)

Loopback TCP JSON-RPC server used by the Worker `ctf-exec` MCP server:
- bind `127.0.0.1:0`, expose `url` and a per-Worker bearer token (token issued by Manager at
  Worker start, passed to the MCP server via env).
- request: `{"id": int, "method": "ctf_exec", "token": str, "params": {...ExecRequest...}}`
  → response `{"id": ..., "result": {...ExecutionResult...}}` or `{"error": {...}}`.
  Also `"ping"` and `"worker_info"` methods.
- unknown/invalid token → fail closed (`denied`/`ipc_error`), never executes.
- tests: direct socket client; MCP server integration test in Lead scope.

### 6.5 Manager fake-ACP + MCP test wiring

The Manager service must accept an injected `acp_factory`, so tests can start a fake ACP
client in-process. For end-to-end tests the Lead wires `AcpClient` against the fake ACP
server process (`python -m ctf_solver.acp.fake_server`) through
`AcpClientFactory`.

## 7. Lead-owned modules (reference only; do not edit)

- `ctf_solver/mcp/protocol.py`: minimal ND-JSON MCP stdio server (`server/discover`,
  `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`).
- `ctf_solver/mcp/manager_server.py`: `python -m ctf_solver.mcp.manager_server` — exposes
  `ManagerControl` as MCP tools `ctf_task_create`, `ctf_task_list`, `ctf_task_status`,
  `ctf_task_continue`, `ctf_task_pause`, `ctf_task_cancel`, `ctf_approval_request`,
  `ctf_approval_decide`, `ctf_approval_list`, `ctf_grant_create`, `ctf_grant_revoke`,
  `ctf_grant_list`, `ctf_flag_candidate`, `ctf_screenshot_capture`,
  `ctf_session_ingest`, `ctf_events_export`, `ctf_writeup_build`, `ctf_evidence_zip`,
  `ctf_runtime_status`.
- `ctf_solver/mcp/exec_server.py`: `python -m ctf_solver.mcp.exec_server` — one Worker-scoped
  MCP server exposing exactly one typed tool `ctf_exec`; identity comes from env
  `CTF_SOLVER_IPC_URL` / `CTF_SOLVER_WORKER_TOKEN` (never from tool arguments); forwards to
  Manager IPC; returns the `ExecutionResult` as JSON text.
- `ctf_solver/delivery/*`: screenshots (`ScreenCapturer` implementations, blank detection),
  Markdown Writeup, evidence ZIP + manifest.
- `ctf_solver/preflight/doctor.py`: read-only first-run report.
- `.dsh/skills/*`: six Skill files (UTF-8, no BOM, frontmatter `name` + `description`).
- CLI `ctf_solver/cli.py` / `python -m ctf_solver`: `preflight`, `manager serve`,
  `worker-mcp`, `fake-acp` (delegates), evidence helper commands.
- Integration tests + acceptance report + docs.

## 8. Definition of done per teammate

1. All files in your write scope implemented (no stubs marked TODO).
2. `python -m pytest tests/<your tests> -q` passes; include negative/failure cases.
3. No writes outside your write scope; no dependency installation; no real Harness session.
4. Report to Lead: files, test command, raw result counts, PASS/FAIL/BLOCKED per requirement,
   and any contract gaps. Do not edit `ctf_solver/core`, `ctf_solver/storage/db.py`,
   `docs/INTERFACES.md`, `pyproject.toml`, or other teammates' directories.
