# Session-log privacy gate — Round 1 evidence summary

**Audit source (read-only):** `D:\CTFworker\docs\HARNESS_INTEGRATION_CAPABILITY_AUDIT.md`
(size 46,444 B, SHA-256 `955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373`,
verified before reading).

The audit found `dsh-session-log-deepseek` enabled by default and observed a
`session-log-deepseek/delivery-accepted` event; incremental normalized session data is
sent as the request field `dsh_session_log` with official API requests. This is a P0
blocker for real CTF content.

## What Round 1 verified

Mechanism: disable the plugin in a dedicated profile through a `cordis.patch.yml` entry
(`config: { enabled: false }`). Project sample:
`config/acp/cordis.patch.yml`.

Verification command (isolated temporary `DSH_HOME`, zero model calls, no transport):

```powershell
$env:DSH_HOME = "<temporary-empty-directory>"
& cmd /c '"C:\Users\28746\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd" --profile acp --patch "D:\CTF-SOLVER\config\acp\cordis.patch.yml" --dump-config'
```

Result: exit code 0; the composed configuration contains:

```yaml
- id: session-log-deepseek
  name: '@deepseek-ai/dsh-session-log-deepseek'
  config:
    enabled: false
```

Only the temporary `DSH_HOME` was written (`profiles/acp/*`). The live
`C:\Users\28746\.dsh\profiles\desktop` profile was not modified, and no global
`profiles` directory remained after verification. Raw output:
`round1-evidence/raw/privacy-gate-dump-config.txt`,
`round1-evidence/raw/privacy-gate-result.txt`,
`round1-evidence/raw/privacy-gate-home-path.txt`.

## What remains BLOCKED

The required **negative outbound-delivery canary test** — proving a synthetic canary
from a CTF session is absent from real `dsh_session_log` delivery — requires an official
API request (a model call). Round 1 does not authorize `session/prompt` or any model call
(ADR-020), so this test is BLOCKED and real CTF content must not be processed in Round 1.

## Verdict

- Supported disable mechanism identified and composed in an isolated profile: **PASS**
  (zero-model-call evidence).
- Global Harness configuration untouched: **PASS**.
- Negative outbound delivery canary: **BLOCKED** (requires a model call; Round 2 gate
  after separate owner authorization).
- Real CTF content processing in Round 1: **NOT AUTHORIZED**.
