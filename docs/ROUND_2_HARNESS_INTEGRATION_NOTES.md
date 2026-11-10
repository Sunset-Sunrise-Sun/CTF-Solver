# Round 2 Harness Integration Notes

**Status:** Round 2 integration candidate (not final acceptance; ChatGPT independent
review pending).
**Date:** 2026-11-10
**Evidence:** `round2-evidence/raw/` (integration log/summary, Harness analysis scan).

Round 2 does not redesign the product. It fixes the Round 1 delivery/security defects,
then integrates the unchanged architecture with the real, locally installed Harness
installation. No software was installed, no Harness global profile/config/plugin was
modified, no WSL/Docker was started, no real CTF target was contacted, no challenge code
was executed, and **no `session/prompt`/model call was made**.

## 1. Real Harness ACP integration (30/30 checks PASS, zero model calls)

`python scripts/round2_integration.py` starts the real installed Harness ACP server with
an isolated temporary `DSH_HOME` under the project (`.ctf-solver-data/r2-dsh-home`) and
verifies (`round2-evidence/raw/round2-integration.log`,
`round2-integration-summary.json`):

| Check | Result |
|---|---|
| Real ACP client ready, protocolVersion 1 | PASS |
| Launch argv is the audited `dsh --profile acp` (cmd wrapper) | PASS |
| Two active Workers + third FIFO queued Task | PASS |
| Distinct real ACP sessions and workspaces | PASS |
| Real ACP **per-session ctf-exec MCP mount** (both sessions) | PASS |
| MCP server handshake identity == Worker token hash | PASS |
| Direct MCP `tools/call` through the Worker-scoped exec server | PASS |
| Denied typed execution fails closed (`tier_not_available`) | PASS |
| Real Harness multi-frame session logs written | PASS (2 files) |
| Registry-derived real session-log ingestion | PASS (frames/records decoded, 4 appended) |
| Session-log ingestion idempotent | PASS (0 appended on re-ingest) |
| Real project-owned window screenshot (PrintWindow flag 2) | PASS (1104×689 PNG, CAS stored) |
| Writeup + evidence ZIP + independently verified manifest | PASS |
| Cancel confirms quiescence; FIFO Task promoted with its own session/MCP mount | PASS |
| Synthetic end-to-end challenge (intake → typed tools → candidate flag → screenshot → Writeup → ZIP) | PASS (writeup/zip/screenshot copied to `round2-evidence/end-to-end/`) |
| Restart recovery marks active Tasks interrupted, never completed | PASS |
| Restart recovery creates no duplicate sessions | PASS |
| Isolated-profile session-log privacy mechanism (config only) | PASS |

**Important correction discovered by integration:** ACP v1 `session/new.mcpServers`
environment must be an ordered **array of `{name, value}` entries**. With a plain JSON
object the installed Harness accepted `session/new` but silently did not mount the MCP
server. The Manager now emits the standard entry array, and the real mount/discovery
handshake is verified per session. This was a genuine Round 1 integration defect.

Worker tool calls in the synthetic end-to-end run are executed by the script through the
same typed MCP `ctf_exec` interface a model-driven Worker uses. They are **not**
model-mediated; the script and generated Writeup state this explicitly.

## 2. Skill discovery and the `/ctf-solver` main-conversation entrypoint

- Six project-level Skills exist under `.dsh/skills/` (UTF-8, no BOM, frontmatter with
  `name`/`description`), validated by deterministic tests and preflight.
- **Real Harness Skill discovery: PASS (session-log evidence).** The running Harness
  session's own persisted log records catalog updates from three to all six CTF Skills
  after the files were written
  (`round2-evidence/raw/round2-skill-discovery-session.json`,
  `round2-harness-entrypoint-analysis.json`). The installed `dsh-skill-filesystem`
  source confirms project roots: nearest `.git` ancestor → `<projectRoot>/.dsh/skills`
  (`harness-entrypoint-scan.txt`).
- **Main-conversation Manager MCP entrypoint: BLOCKED.** No supported project-scoped MCP
  server/plugin registration mechanism was found in the installed source. MCP servers
  come from profile-level configuration (`cordis.patch.yml` bundle layers / user patch)
  or from per-ACP-session `session/new.mcpServers`. The Manager control MCP server is
  implemented and verified as a real stdio MCP process (end-to-end stack test + real
  Manager process), and each Worker session receives its own `ctf-exec` MCP server via
  the audited per-session mechanism (verified above); but attaching the control server to
  the **live main conversation** without a Harness global/profile change is not possible
  with the supported project-scoped surface. `/ctf-solver` is therefore **not** claimed
  functional as a live Harness command entrypoint.
  Smallest owner options remain: (a) authorize a dedicated profile-scoped MCP
  registration; (b) authorize a thin Cordis Host Plugin bundle that registers the
  Manager tools (explicit owner decision; this was not made mandatory silently);
  (c) accept a user-launched local Manager connected out-of-band.

## 3. Model-mediated Worker gate — BLOCKED

`session/prompt` and all model calls remain unauthorized for this round (ADR-020). The
ACP client gate raises `ModelCallNotAuthorized` before sending anything, and the
integration run makes zero prompts. Model-mediated Worker reasoning, live MCP
`tools/call` by a model, and permission round-trips under a real turn remain BLOCKED for
Round 2 acceptance and require separate owner authorization after the privacy gate.

## 4. Session-log privacy gate — mechanism PASS, negative canary BLOCKED

The full local audit (SHA-256 `955136d1…fe5373`, read-only) was used to identify the
supported mechanism: disable `dsh-session-log-deepseek` via a profile `cordis.patch.yml`
entry (`config: { enabled: false }`). Round 2 re-verified this in a dedicated temporary
`DSH_HOME` with `dsh --profile acp --patch config/acp/cordis.patch.yml --dump-config`
(exit 0, composed config contains `enabled: false`, only the temp home written).
Evidence: `round2-evidence/raw/round2-privacy-gate-*.{json,txt}`.

The required **negative outbound-delivery canary test** requires an official API request
(a model call). No model call is authorized in this round, so that test is **BLOCKED**
and real CTF content must not be processed. A configuration file stating
`enabled: false` is not reported as delivery-verified.

## 5. Screenshots

`delivery/screenshot.py` gained `WindowCapturer` (PrintWindow `PW_RENDERFULLCONTENT`,
DPI-aware) that captures only an explicitly selected **project-owned window** by PID, so
no personal desktop content is recorded. Two synthetic Tk windows (checkerboard + text)
were captured live during integration; both PNGs are non-blank, bound to
Task/Worker/Step/session/time, stored in CAS and included in the evidence ZIP
(`round2-evidence/end-to-end/screenshot.png`). The full-desktop `DesktopCapturer`
remains implemented but is not used for evidence collection.

## 6. Real session-log ingestion layout

Real Harness sessions in the isolated home produced logs under
`<DSH_HOME>/sessions/<cwd-slug>/<sessionId>/session.v4.jsonl.zstd`; the resolver found
them from the Manager registry (no caller path), verified the first-frame session header
and ingested all frames. The Manager never accepts a model-supplied path, and the
control-tool response does not echo local paths.

## 7. Environment boundary evidence

- `D:\CTFworker` untouched: git-status porcelain fingerprint unchanged from start to end
  of this round; protected local audit report unchanged (size 46,444 B, SHA-256
  `955136d1…fe5373`).
- Live `~/.dsh` profiles unchanged (775 files, max mtime `2026-11-10T01:52:31`); isolated
  `DSH_HOME` used for every real ACP run; no stray global `profiles` directory.
- No installs, no Harness global config change, no WSL/Docker start, no real target,
  no challenge-provided code execution, zero model calls.
- Runtime data (`.ctf-solver-data/`, `tasks/`, `challenge-uploads/`) remains git-ignored
  and was removed from the working tree after the evidence run.

## 8. Remaining limits / Round 2 NOT VERIFIED

1. Main-conversation `/ctf-solver` → Manager control tools (BLOCKED; see §2).
2. Session-log negative outbound-delivery canary (BLOCKED; needs model call + owner
   authorization).
3. Model-mediated Worker / live MCP tool call by a model (BLOCKED by design).
4. Real physical-console approval TTY interaction (positive path is injected in tests;
   non-TTY/agent-context fail-closed paths are tested).
5. Real CTF target access, Tier 2 isolation and challenge-code execution (out of scope).
6. Real Skill-discovery proof inside a *model-driven* ACP Worker turn (discovery is
   proven by the live session log; without a model turn the ACP session log does not
   contain the catalog).

---

## 9. Final acceptance remediation evidence (2026-11-10)

- **43/43** zero-model-call real-Harness integration checks PASS on the remediation
  branch (2 Workers + FIFO, protocol-level MCP mount, real session-log ingestion,
  project-owned window screenshot, Writeup/evidence ZIP, restart recovery, privacy
  evidence, and a synthetic end-to-end Task that completes normally).
- **Privacy patch is now in the actual Manager launch**: the live ACP argv is
  `[COMSPEC, /c, dsh.cmd, --profile, acp, --patch, <D:\CTF-SOLVER\config\acp\cordis.patch.yml>]`
  (evidence A), and running that same argv with `--dump-config` in the same isolated
  `DSH_HOME` shows `dsh-session-log-deepseek` disabled (evidence B). The external-delivery
  canary remains **BLOCKED** (requires a model request); config evidence is not reported
  as delivery verification.
- **MCP mount evidence is protocol-level**: the actual ACP-spawned `ctf-exec` child writes
  a handshake only after answering MCP `initialize`, then records `tools/list` tool names
  (`["ctf_exec"]`), PID, Task, Worker-token SHA-256 and protocol version. Integration
  verifies the handshake PID's OS ancestor chain contains the ACP server PID. The
  synthetic E2E `tools/call` is executed by an **independent** MCP stdio process using the
  real Worker token; same-child `tools/call` remains **NOT VERIFIED** under the
  zero-model-call gate and is not reported as such.
- **Completion lifecycle**: the E2E Task final state is `completed` with a concrete
  `result_state` (`solved_flag_candidate`), real `ended_at`, stopped Worker, closed
  session, intact evidence and a Writeup that shows `Status: completed` (never `running`
  or `unknown`). Normal completion and restart-recovery are separate checks; the
  completed Task remains completed after restart, while the still-running FIFO Task is
  interrupted without duplicate sessions.
- Raw logs: `round2-evidence/raw/round2-integration.log`,
  `round2-integration-summary.json`, `round2-privacy-gate-result.json`.
