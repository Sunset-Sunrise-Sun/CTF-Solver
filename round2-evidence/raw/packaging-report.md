# Round 2 Packaging + Challenge-File Intake — Delivery Report

**Owner:** `verifier-round1` (task-8, Round 2 work stream)
**Branch:** `feat/round2-harness-integration` (HEAD `8615af6f552813d50ed2f429b45ef4bdfe65e326`; no commits made by this task — Lead owns Git)
**Date:** 2026-11-10 (Asia/Shanghai / UTC+8)
**Scope delivered:** `ctf_solver/intake.py`, `pyproject.toml`, `tooling/wheelbuild.py`,
`scripts/build_wheel.py`, `scripts/fresh_clone_check.py`, `tests/test_intake.py`,
`tests/test_wheel_build.py`, `round2-evidence/raw/packaging-*` (all written files are
UTF-8 without BOM and LF).

No installation, no network, no model call, no ACP session, no real target, and no
`D:\CTFworker` modification was performed. All build/test outputs stay in `tmp_path`,
`dist/` (git-ignored) and `round2-evidence/raw/`.

---

## 1. Command results (raw evidence in `round2-evidence/raw/`)

| # | Command | Result | Exit | Raw log |
|---|---|---|---|---|
| 1 | `python -m pytest tests\test_intake.py tests\test_wheel_build.py -q -p no:cacheprovider` | **60 passed, 2 skipped** (15–17 s) | 0 | [`packaging-pytest.txt`](packaging-pytest.txt) |
| 2 | `python scripts\build_wheel.py` | **PASS** — pip PEP 517 build + structure/RECORD/import verification (3.2 s) | 0 | [`packaging-build-wheel.txt`](packaging-build-wheel.txt), JSON [`wheel-build.json`](wheel-build.json) |
| 3 | `python scripts\fresh_clone_check.py --overlay-working-tree` | clone ✓, **pytest 924 passed / 5 failed / 4 skipped**, **wheel build from clone PASS** | 1 (pytest failures, see §4) | [`packaging-fresh-clone.txt`](packaging-fresh-clone.txt), [`fresh-clone-20261110T115032Z.json`](fresh-clone-20261110T115032Z.json), [`fresh-clone-20261110T115032Z.log`](fresh-clone-20261110T115032Z.log) |
| 4 | `python scripts\fresh_clone_check.py` (strict committed HEAD) | **BLOCKED**: HEAD lacks `scripts/build_wheel.py`; 6 skill tests also fail (CRLF, §4) | 1 | [`packaging-fresh-clone-strict.txt`](packaging-fresh-clone-strict.txt), [`fresh-clone-20261110T114904Z.json`](fresh-clone-20261110T114904Z.json) |
| 5 | determinism / RECORD / tamper / package-discovery / metadata tests inside #1 | PASS | 0 | included in #1 |

Two skips in #1 are documented environment limits, not passes: Windows cannot create
**file** symlinks without elevation/Developer Mode on this host (junction/directory-reparse
cases *do* run and pass via `mklink /J`). Skip reasons are printed by pytest.

### Final wheel (repository working tree)

```
filename : ctf_solver-0.1.0-py3-none-any.whl
size     : 203,956 bytes
sha256   : b446888d3744fb5e01bc17e1c2ed13502ca282755e10f0898d5da42a86d57c1c
builder  : pip wheel (--no-deps --no-build-isolation); in-tree PEP 517 backend "wheelbuild"
members  : 63 (62 files + RECORD)
```

Packages in the wheel (all current `ctf_solver/**` packages, discovered from the tree —
new packages such as `security/` are picked up automatically):

```
ctf_solver, ctf_solver.acp, ctf_solver.core, ctf_solver.delivery, ctf_solver.evidence,
ctf_solver.manager, ctf_solver.mcp, ctf_solver.policy, ctf_solver.preflight,
ctf_solver.runtime, ctf_solver.security, ctf_solver.storage
```

Also included: `ctf_solver/intake.py`, `ctf_solver/wiring.py`, `ctf_solver/cli.py`,
`ctf_solver-0.1.0.dist-info/{METADATA,WHEEL,entry_points.txt,RECORD}`. Verification
confirmed: RECORD covers exactly every archive member, all SHA-256 digests are
urlsafe-base64-unpadded and sizes match; metadata Name/Version/Requires-Python/
Description-Content-Type/Provides-Extra match authoritative `[project]`; console script
`ctf-solver = ctf_solver.cli:main`; fixed 1980-01-01 zip timestamps and mode 0644;
extracted wheel imports `ctf_solver.evidence.store`, `ctf_solver.manager.service`,
`ctf_solver.intake` and runs `python -m ctf_solver version` with
`PYTHONPATH=<extract>` from a directory outside the repo.

Note: the wheel SHA changes whenever teammates edit `ctf_solver/**` (observed during this
task); determinism is proven on a frozen snapshot (build twice → byte-identical). The SHA
above is the artifact produced at the final run.

---

## 2. What was implemented

### `ctf_solver/intake.py` — `IntakeService` (ROUND_2_INTERFACES §4.1)
- `IntakeError(CtfSolverError)` (`reason_code="intake_error"`), structured `details["code"]`.
- `IntakeService(intake_root, *, max_files=100, max_total_bytes=256 MiB, clock=None)` with
  `import_files(*, task_id, workspace, supplied_files) -> list[ImportedInput]`.
- Intake root must exist, be a directory, and not be a symlink/reparse point; it is the only
  source root. Entries are relative POSIX/Windows paths: absolute, drive-qualified, UNC,
  `..`, NUL/control, empty/`.`/`//`, leading/trailing whitespace, trailing-dot/space and
  Windows reserved device names are rejected; symlinks/reparse points are rejected for the
  file **and every ancestor**; non-regular files rejected; resolved source must remain
  inside `realpath(intake_root)`; duplicates (case-insensitively) rejected; count/byte
  limits enforced before any copy; copies go to `<workspace>/inputs/<rel_path>` with
  parents, hash/size/media-type (`mimetypes.guess_type` fallback octet-stream) computed
  from the copied bytes; `ImportedInput.source_rel_path` preserved; partial copies removed
  on failure. No shell, no subprocess, no host reads outside the intake root.

### `pyproject.toml` (ROUND_2_INTERFACES §4.2)
- `[build-system] requires = []`, `build-backend = "wheelbuild"`,
  `backend-path = ["tooling"]`; `[project]` metadata remains authoritative (zero runtime
  dependencies, entry point unchanged); Round 1 `[tool.setuptools]` retained only as a
  documented legacy hint that the in-tree backend ignores.

### `tooling/wheelbuild.py` — stdlib-only PEP 517 backend
`get_requires_for_build_wheel`/`_sdist` → `[]`, `prepare_metadata_for_build_wheel`,
`build_wheel`, optional `build_sdist`, plus explicit-root helpers
(`build_wheel_for_repo`, `prepare_metadata_for_repo`, `build_sdist_for_repo`) used by the
scripts/tests. Reads `[project]` + README from the root it belongs to, discovers all
`ctf_solver/**` files, writes deterministic wheels and a correct RECORD (RECORD row
itself unhashed). No non-stdlib imports (asserted by a test).

### `scripts/build_wheel.py`
Real build through `python -m pip wheel . --no-deps --no-build-isolation
--disable-pip-version-check --no-input --no-cache-dir -w dist`, with a direct
`build_wheel_for_repo` fallback if pip refuses; independent wheel structure/RECORD/metadata
verification, extraction + import of the three required modules + `python -m ctf_solver
version` with `PYTHONPATH=<extract>`, JSON evidence written to
`round2-evidence/raw/wheel-build.json` (always written, including failure reports), exit
non-zero on failure.

### `scripts/fresh_clone_check.py`
`git clone --no-hardlinks --branch <branch> <repo> <temp>` (source read-only), optional
`--overlay-working-tree` for the pre-commit candidate (tracked modifications/deletions +
untracked files; runtime/evidence directories skipped and listed), then
`python -m pytest tests -q -p no:cacheprovider` and the clone's
`scripts/build_wheel.py` inside the clone; writes timestamped
`fresh-clone-<utc>.{json,log}` + `fresh-clone-wheel-build-<utc>.json` raw evidence and exits
non-zero on failure. Records `core.autocrlf` of source/clone for line-ending diagnosis.

### Tests
- `tests/test_intake.py` (48 cases): happy path multi-file/nested metadata/hashes/media
  types/to_dict; Windows separator normalisation; absolute/drive/UNC/traversal/empty/
  control/reserved-name rejection; missing file; directory; symlink file (skips if the OS
  cannot create it), symlink/junction ancestor escape, symlinked intake root, symlinked
  destination; intake-root validation; count/byte limits before copy; duplicates
  (case-insensitive); two-Task isolation; re-import; `SolverConfig.intake_root` wiring;
  no shell/network imports.
- `tests/test_wheel_build.py` (14 cases): in-tree PEP 517 configuration; deterministic
  wheel name/bytes; METADATA/WHEEL/entry_points content; every source package file and
  baseline package present; RECORD digest/size/padding/coverage; tampered/missing RECORD
  detection; prepare-metadata hook; extracted-wheel imports + version CLI; backend direct
  build/verify; end-to-end `scripts/build_wheel.py` on the repository; non-zero failure on
  an unbuildable tree; sdist determinism; stdlib-only/no-install/no-network scan; fresh
  clone helper/overlay unit test in a throw-away temp git repo.

---

## 3. Contract gaps / notes

1. `ROUND_2_INTERFACES.md` §4.1 says the intake root must "not be a symlink"; on Windows
   **junctions** and other reparse points are not `Path.is_symlink()` in every Python
   version, so the implementation additionally checks
   `st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`. This is a hardening superset of the
   written rule, not a deviation.
2. `ImportedInput.imported_at` is a single `clock.now_ms()` value for one import call (all
   files share it) — deterministic and consistent for one user action.
3. Re-importing the same `rel_path` into the same workspace overwrites the earlier copy
   (after full re-validation); cross-Task workspaces stay isolated. No cross-Task data is
   visible.
4. `[tool.setuptools]` remains in `pyproject.toml` as documentation only; the in-tree
   backend ignores it. `pip`/`python -m build` cannot use it without setuptools, and the
   wheel is built correctly from `[project]` alone.
5. Symlink/junction unit tests skip only where Windows cannot create the link without
   elevation/Developer Mode; junction-based ancestor/root escapes are exercised.

---

## 4. Fresh-clone findings (reported, not fixed — outside this task's scope)

### F1 — BLOCKED until Lead commits: strict clean clone cannot build the wheel
`git clone` of committed HEAD `8615af6` does not contain the Round 2 packaging files
(`tooling/`, `scripts/`, `ctf_solver/intake.py`, `pyproject.toml` change — all currently
uncommitted). Strict run therefore stops with the explicit error
`clone has no scripts/build_wheel.py (branch HEAD does not contain the Round 2 packaging
work; run with --overlay-working-tree or commit first)`.
→ Once the Lead commits the working tree, rerun `python scripts/fresh_clone_check.py`
without the overlay flag.

### F2 — Clean-clone line-ending defect (Lead-owned `.gitattributes`/git config)
With the machine's `core.autocrlf=true`, a fresh clone checks out text files as CRLF, so
`tests/test_skills.py::test_skill_is_utf8_without_bom_and_has_frontmatter` fails for the
skill files that were not overlaid (`---\r\n` instead of `---\n`) — 5 failures in the
overlay run, all 6 in the strict run. Repository working tree files are LF.
→ Recommended fix (Lead scope): add a root `.gitattributes` forcing LF for source/Skill
files (e.g. `* text=auto eol=lf` or `*.md text eol=lf` + `*.py text eol=lf`) and/or run the
fresh-clone check with `core.autocrlf=false`. This is a real clean-clone acceptance defect,
not a transient in-flight edit.

### F3 — In-flight integration failures observed earlier in the clone (now resolved in tree)
Earlier overlay runs showed `tests/test_mcp_exec_server.py` failures
(`McpRemoteError: arguments do not match the schema for tool ctf_exec` for the
`worker_token` extra property and for non-array argv) while the Lead/B MCP schema
integration was in progress; a subsequent overlay run passed those tests. They are noted
for the Lead's change tracking, not attributed to the intake/packaging work. The latest
overlay run has only the F2 failures (924 passed / 5 failed / 4 skipped).

All new intake/packaging tests passed in every fresh-clone overlay run.

---

## 5. Files and evidence index

Delivered files (untracked / modified in this task only):

```
ctf_solver/intake.py            (new)
pyproject.toml                  (modified: in-tree PEP 517 backend, legacy hint documented)
tooling/wheelbuild.py           (new)
scripts/build_wheel.py          (new)
scripts/fresh_clone_check.py    (new)
tests/test_intake.py            (new)
tests/test_wheel_build.py       (new)
```

Raw evidence (`round2-evidence/raw/`):

```
packaging-pytest.txt                          packaging test run (60 passed, 2 skipped)
packaging-build-wheel.txt                     build_wheel.py run (exit 0)
wheel-build.json                              machine-readable wheel build/verification report
packaging-build-wheel-probe.txt               earlier probe run (superseded, kept)
packaging-fresh-clone.txt                     overlay fresh-clone run (latest)
packaging-fresh-clone-strict.txt              strict committed-HEAD fresh-clone run (BLOCKED)
fresh-clone-20261110T115032Z.json/.log        overlay run evidence
fresh-clone-wheel-build-20261110T115032Z.json clone wheel build evidence
fresh-clone-20261110T114904Z.json/.log        strict run evidence
fresh-clone-20261110T114549Z.json/.log        earlier overlay run evidence
fresh-clone-20261110T114752Z.json/.log        earlier overlay run evidence
```

`dist/ctf_solver-0.1.0-py3-none-any.whl` is the built artifact (git-ignored by `dist/`).
