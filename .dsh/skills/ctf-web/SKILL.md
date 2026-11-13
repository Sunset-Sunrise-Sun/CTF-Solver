---
name: ctf-web
description: Web challenge reasoning for CTF-Solver; source/configuration and protocol analysis first, active requests only through a Task-scoped target grant, evidence-first, human-approval rules inherited from ctf-solver.
---

# Web Challenges

## Order of work

1. **Reconnaissance from provided material** — read source code, configuration, routes,
   templates, dependency manifests, Dockerfiles, `.env` samples, frontend bundles,
   API descriptions and supplied screenshots before touching any remote target.
2. **Model the request surface** — enumerate endpoints, parameters, authentication
   boundaries, sessions, uploads, deserialization, templating, SSRF-like sinks,
   middleware and trust boundaries. Write a hypothesis list with evidence for each.
3. **Local reproduction first** — if a runnable copy is provided, favor static reading
   and local analysis inside the Task workspace; remember challenge-provided code must
   not be executed on the host while Tier 2 isolation is unavailable.
4. **Target requests only with a grant** — active probing/sending requests to a remote
   target requires a Task-scoped `network_grant` matching host, port, protocol, method,
   path prefix, TTL and call count. Request the approval through the Manager; never
   assume a generic approval authorizes a target.

## Flows to check (checklist, not a blind scanner)

- authentication and authorization (IDOR, missing checks, role confusion, JWT/claims,
  session fixation, CSRF);
- injection sinks (SQL/NoSQL/LDAP/command/template/expression) and how input reaches
  them;
- file handling (path traversal, upload validation, archive handling, exposed backups);
- SSRF and URL-fetching components including loopback/private-address policy;
- deserialization, prototype pollution, misconfigured headers/cookies, debug endpoints,
  source-map and `.git`/backup exposure;
- client-side logic only when it protects a server-side asset.

## Evidence requirements

- Record the exact HTTP method, URL/path, relevant headers and body (bounded), status
  code, response excerpt, timestamps and the grant used.
- Prefer reproducible request scripts placed in the Task workspace; record every actual
  request made through approved tooling.
- Screenshots only for important GUI/program-running steps; HTTP evidence is textual.

## Safety and honesty

- Public writeups/documentation are research only; do not attack the public source.
- No out-of-scope hosts, ports or actions; no automatic exploitation of anything beyond
  the authorized challenge scope.
- Do not claim a working exploit, a Flag or a solved challenge without the recorded
  request/response evidence.
- A candidate Flag is recorded as `candidate`; the user submits it.

## Evidence recording (native tools)

- Native Lead tool calls are recorded automatically from the Lead session log; never hand-write or copy evidence.
- Capture screenshots only at real checkpoints, with `step_id` = `turn{N}-step{S}`.
- Distinguish 未执行 / 执行失败 / 未记录 honestly; never state an unrecorded step as a fact.
