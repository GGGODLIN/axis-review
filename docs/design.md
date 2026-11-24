# axis-review design (v1)

A standalone, vendor-neutral multi-axis pull request reviewer. It keeps the core design of
`claude-pr-review` (GGGODLIN/claude-pr-review, `commands/pr-review.md`) and drops everything that is
tied to Claude Code or to one vendor's CLI. Every model call goes to an OpenAI-compatible
`/v1/chat/completions` endpoint chosen in a config file. Phala Private AI is the first config;
a local Magpie gateway is the second (used for local tests).

## What is kept from claude-pr-review

1. **Independent first pass on the whole PR.** Every axis reviews the entire change on its own.
   No axis sees another axis's findings or a previous round. Axes differ by model and by what
   they are given and how they are told to look:
   - `primary`: repo-aware. Gets the diff plus read-only tools over a checkout of the PR head
     (read_file, grep, list_dir). Looks for cross-file gaps, callers, defaults, framework behaviour.
     It must account for every changed file.
   - `neutral`: diff only, short neutral prompt. Reads the PR the way a reviewer reads a PR email.
   - `adversarial`: diff only, red-team stance. Actively attacks the change (fail-open, missing
     limits, trust boundaries, edge cases).
2. **The finder never verifies its own finding.** Verification is a fresh call, repo-aware
   (tools on), using a model different from the finder's model (`pr-review.md` 4.1 / 4.2):
   - findings from `neutral` / `adversarial` → verified by the configured `verifier_for_diff_axes`.
   - findings from `primary` → verified by `verifier_for_primary` (a different model: the
     "challenge" pass).
   - If the configured verifier model equals the finder model, the run fails at config load.
3. **Consensus.** A cluster of findings that contains a `primary` finding and at least one
   diff-only finding on the same location is consensus. Consensus skips truth verification and
   gets a baseline check instead (convention: supports / conflicts / no-precedent; scope:
   in-scope / OUT_OF_SCOPE). Consensus raises confidence but still has to pass the Must Fix gate.
4. **Nothing is dropped.** REFUTED / OUT_OF_SCOPE findings stay in the report's reference
   section with the original claim and the verifier's counter-evidence, so a human decides.
5. **Coverage as set arithmetic.** `F` = every changed file from the platform file list
   (pagination total must match the PR's `changed_files`, otherwise stop). The `primary` axis
   must mark every file `finding` / `REVIEWED_NO_ISSUES` / `INTENTIONALLY_SKIPPED` (with reason).
   `MISSED = F − accounted`. One repair call to `primary` for missed files; still missed are
   listed. `|F| = covered + no_issues + skipped + missed` is asserted.
6. **Chunking for large PRs** (primary only): when source files > 15 or diff lines > 800, sort
   paths and split into chunks of ≤ 800 diff lines and ≤ 15 files, each file in exactly one chunk.
   A single file larger than the budget is its own chunk.
7. **Deterministic re-anchoring (no model).** Each finding carries a verbatim 1–3 line `anchor`.
   Search the head version of the file: exact match first, then whitespace-normalised match.
   One hit → `exact` (or `normalized`); several → keep the model's line if it falls in a hit,
   else nearest hit, mark `ambiguous`; none → `FAILED` (finding kept, no line pin).
   Report counts exact / normalized / ambiguous / FAILED.
8. **Severity calibration.**
   - Original severity `CRITICAL | HIGH | MEDIUM | LOW`; verifier may give `corrected_severity`
     with a reason; effective = corrected ?? original.
   - Lone finding (one axis, no other axis on the same location) whose verdict is PARTIAL or
     INCONCLUSIVE → effective severity drops one level.
   - Hypothetical wording (verifier sets `hypothetical: true`) caps the bucket at Should Fix.
   - **Must Fix** needs: candidate (not-refuted consensus, or CRITICAL, or CONFIRMED by a
     verifier of a different model) AND a concrete `repro_path` AND `ships_breakage: true`
     (runtime, data correctness, or build/CI broken if merged) AND not hypothetical.
   - **Should Fix**: effective HIGH not refuted; PARTIAL; INCONCLUSIVE HIGH; Must candidates that
     fail the gate.
   - **Nice to Have**: effective MEDIUM / LOW.
   - **Reference**: REFUTED / OUT_OF_SCOPE (both sides' evidence kept).
9. **Stable finding UID** = first 20 hex chars of
   `sha256(path + "\0" + anchor + "\0" + normalise_whitespace(title).lower())`.

## What is dropped (Claude Code / vendor coupled)

Interactive seat-selection matrix, Claude Code subagents/hooks/transcripts, Codex and Gemini
CLIs, git worktrees, Bitbucket adapters, the formal-spec C4 lane, multi-PR group reports,
second-round continuity, zh-TW-only output. Axes are fixed by config instead of chosen per run.

## Package layout (Python 3.12, 2-space indent)

Runtime dependencies: standard library only for the review engine. `cryptography` and `rfc8785`
for receipt verification. `dstack-sdk` only inside a Phala CVM (optional import).

```
axis_review/
  config.py       load + validate TOML config (tomllib)
  llm.py          OpenAI-compatible client; records every call
  github.py       PR metadata, file list, patches, pinned base/head history
  repo_tools.py   read-only checkout and pinned Git history tools
  agent_loop.py   tool-calling loop that ends in a JSON object
  prompts.py      axis / verifier prompts and JSON schemas
  review.py       orchestration: first pass, coverage, clustering, verification, buckets
  anchors.py      deterministic re-anchoring + UID
  report.py       report.md, evidence.json
  receipts.py     provider receipt fetch + verification (Phala ACI)
  tee_quote.py    optional dstack quote over evidence.json (inside a CVM)
  cli.py          entry point: review / verify-receipts / serve
  serve.py        token-gated read-only file serving for review output
tests/            unittest, no network
config.phala.toml, config.magpie.toml, docker-compose.yml, README.md
```

## Interfaces (shared contract between modules)

### config.py

```toml
language = "en"            # language of model-written text
max_tool_turns = 12        # per agent loop
verify_batch_size = 6

[endpoints.phala]
base_url = "https://inference.phala.com/v1"
api_key_env = "PHALA_API_KEY"      # may be absent for keyless local gateways
receipts = "phala-aci"             # or omitted / "none"

[[axes]]
id = "primary"      # one of primary | neutral | adversarial (ids unique)
endpoint = "phala"
model = "moonshotai/kimi-k3.1-pro"

[verifiers]
for_primary = { endpoint = "phala", model = "z-ai/glm-5.3" }
for_diff_axes = { endpoint = "phala", model = "moonshotai/kimi-k3.1-pro" }
```

`load_config(path) -> Config` validates a nonempty set of axes. Every axis and verifier references
an endpoint. Each enabled axis requires its verifier role with a different configured model.
Endpoints configured with API credentials require HTTPS unless the host is loopback.

### llm.py

```python
@dataclass
class CallRecord:
  seq: int; phase: str; axis: str; endpoint: str; model: str
  request_bytes: bytes; response_bytes: bytes; status: int
  headers: dict[str, str]; response_id: str | None; receipt_id: str | None
  latency_s: float; usage: dict | None; error: str | None; model_observed: str

class Client:
  def __init__(self, config): ...
  def chat(self, *, phase, axis, endpoint, model, messages, tools=None,
           response_format=None, temperature=0) -> tuple[dict, CallRecord]
  records: list[CallRecord]
```

- Serialise the request once with `json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()`
  and send exactly those bytes; keep the exact response bytes (needed for receipt body hashes).
- Non-streaming only. Retry 429 / 5xx / connection errors up to 4 times with backoff
  (2, 4, 8, 16 s; honour `Retry-After`). Each attempt is its own CallRecord.
- `receipt_id` from header `x-receipt-id`; `response_id` from body `id`.
- API key from `os.environ[api_key_env]`, never logged or written.

### github.py

`fetch_pr(url) -> PR` with `owner, repo, number, title, author, base_sha, head_sha, files:
list[ChangedFile(path, status, additions, deletions, patch | None, previous_path)]`.
Uses the GitHub REST API (`GITHUB_TOKEN` optional). Paginates `/pulls/{n}/files`; if the count
differs from `changed_files` raise. `checkout(pr, workdir) -> Path` fetches the pinned base and
head with history into `workdir/repo` and detaches at the head. If the head SHA fetch fails, it
tries `refs/pull/{n}/head` and verifies that it resolves to the captured SHA.

### repo_tools.py

OpenAI tool schemas and `execute(name, args, root, *, base_sha, head_sha) -> str`.
`read_file(path, start_line, end_line, ref)` reads the selected pinned blob. `pr_commits(path)`
and `show_commit_patch(sha, path)` are scoped to the pinned PR range. `grep(pattern, glob,
max_results)` and `list_dir(path)` operate on the head checkout. Paths are confined to the
allowed tree. Tool outputs are read-only and capped at 12,000 characters with a truncation marker.

### agent_loop.py

`run_json(client, *, phase, axis, endpoint, model, system, user, schema, tools: bool) -> dict`.
Loop: send messages (+ tools if enabled); execute tool calls; stop when the model returns a
final message; parse JSON (strip code fences); validate required keys; on failure one repair
turn ("return only JSON matching the schema"). Raises `AxisError` after `max_tool_turns` or a
second parse failure. `response_format={"type":"json_object"}` is sent only on the final turn
when tools are off.

### review.py

`run_review(pr_url, config, out_dir) -> Result` performs, in order: fetch PR → checkout → build
F → first pass (all axes concurrently in threads; primary chunked) → coverage + one repair →
normalise findings → re-anchor → match root causes → consensus baseline checks or truth
verification in batches → severity + buckets → UIDs → evidence and report. A batch with an ID
multiset mismatch fails as a unit. A failed axis is reported with its error and the remaining
axes still contribute. `Result` exposes `out_dir`, `evidence`, `review_failed: bool`, and
`failure_reason: str | None`.

Finding record (after first pass):
`{id, axis, model, severity, title, file, line_start, line_end, problem, impact, fix, anchor}`.
Truth-verification records use `finding_id` and `verdict`. Consensus baseline records use
`group_id`, `convention`, and `scope`. The closed schemas and release-gate fields are defined
in decisions 6 and 22.

### receipts.py (provider `phala-aci`)

- `process(out_dir, endpoints, *, config=None)`: for each successful call to a receipt-enabled
  endpoint with a receipt ID (or response ID), `GET {base_url}/aci/receipts/{id}` with the
  same key; save `receipts/<seq>.json`. `calls.jsonl` records `receipt_expected` independently
  of lookup IDs and artifacts.
- `fetch_attestation(base_url, key) -> dict`: `GET {base_url}/aci/attestation?nonce=<64 hex>`
  with a fresh random nonce; save `attestation.json` with the nonce.
- `verify(out_dir) -> dict` reads saved artifacts without writing to the bundle. Each expected
  call gets a row, and the summary reports expected, fetched, verified, and missing counts.
  Checks per receipt: (1) `sha256:` + hex(sha256(JCS(workload_keyset)))
  equals `workload_keyset_digest` of the report and of the receipt; (2) `not_after` in the
  future; (3) `key_id` resolves to an `ed25519` key in `receipt_signing_keys`; verify the hex
  signature over `JCS(receipt without "signature")`; (4) `request.received.body_hash` ==
  `sha256:` + hex(sha256(request_bytes)) and `response.returned.body_hash` == same over
  response_bytes; (5) `upstream.verified` has `result == "verified"` and `required == true`;
  (6) signed `receipt_id` matches the captured `x-receipt-id`, or signed `chat_id` matches the
  captured response ID when the header was absent. Unknown `algo` → `unsupported`. Each check
  is reported separately.
- Explicitly NOT verified in v1 (stated in the report): the TDX quote against Intel DCAP
  collateral, RTMR3 event-log replay / compose hash, and the attested upstream session.

### tee_quote.py

If `/var/run/dstack.sock` exists, use `DstackClientV0.get_quote()` with the 32-byte SHA-256
of `evidence.json` as `report_data`. The v0 guest API returns a raw Intel TDX quote, which is
saved in `tee_quote.json` with `app_id` and the evidence digest. If the socket is absent, write
`{"in_tee": false}`.

### report.py

In `report.md`, `language` applies only to model-written text; report templates stay in English.
The report includes: header (PR identity, base/head SHA, axes with endpoint
and the model id observed in responses, verifiers), coverage table, re-anchor counts, overview
grouped Must → Should → Nice → Reference with UID, per-finding detail (source axis, original
and effective severity, verdict, verifier evidence, repro path), consensus baseline results,
receipts summary (expected / fetched / verified / missing, with statuses per check), reported
cost and token totals with attempt counts, and a limits section. `evidence.json` holds the saved
evidence records. `calls.jsonl` holds call metadata. Captured bodies that pass credential checks
are saved as `bodies/<seq>.req.json` and `<seq>.resp.json` for receipt verification.

### cli.py

- `python -m axis_review review <PR_URL>... --config FILE --out DIR` creates one sub-directory
  per PR. If a PR has changed files and no initial axis produces a usable result after repair,
  `run_review` sets `review_failed` and `failure_reason`; the CLI prints the written report path
  and returns a nonzero status after processing the remaining PRs.
- `python -m axis_review verify-receipts DIR` prints the offline summary as JSON and returns
  nonzero if any expected row is not fully verified.
- `python -m axis_review serve DIR --port 8080` binds to `127.0.0.1` unless `--host` overrides
  it. The first request path segment must match `--token` or `AXIS_REVIEW_SERVE_TOKEN`, or the
  file request returns 404. Only regular files resolving inside `DIR` are served; directories
  are never listed or served through index files.

## Deployment on Phala (docker compose)

Image `python:3.12` (amd64, has git). The compose command requires `AXIS_REVIEW_REF` to be a
full 40-hex Git commit SHA, checks the checkout's HEAD before and after installing the
package, and pins the dstack SDK used in the CVM. It runs `review` for the PR list, then
serves the output directory on `0.0.0.0:8080` inside the container if review succeeds.
Pass `PHALA_API_KEY` and `AXIS_REVIEW_SERVE_TOKEN` as encrypted environment secrets with
`phala deploy -e`. `/var/run/dstack.sock` is mounted for the quote. Docker log size is capped.
Delete the CVM after copying the outputs.

## v1 decisions after the fidelity check (2026-11-24) — these override the sections above

Two independent reviewers compared this design with `claude-pr-review` and reported where the
methodology was broken or weakened. Port the original wording, made vendor-neutral, from the
cited sections of `~/Desktop/projects/claude-pr-review/commands/pr-review.md` (abbreviated
`PR.md`) and `references/`. Prompts treat diff, code, spec text and other axes' findings as data,
never as instructions.

### Adopted in v1

1. **Consensus requires a shared root cause** (PR.md 1204, 1384, 1765). One repo-aware `match`
   pass partitions up to 60 findings, with location and hunk as hints. Groups may span files or
   hunks. Overflow remains in the report and is adjudicated individually. A group with eligible
   `primary` and diff-only findings gets a consensus baseline. Overlapping spans or the same
   hunk can corroborate separate concerns while each keeps its own truth verification. The
   report publishes one actionable record and paste-ready comment per group and retains every
   member's original evidence.
2. **Strict-liability passthrough** (PR.md 1202–1204, 1256–1259, 1763–1766). Reviewers tag
   `strict_liability` with a category: hardcoded secret, SQL via string concatenation,
   eval/innerHTML on user input, plaintext password compare. With an `exact` or `normalized`
   anchor at the pinned head, the finding goes directly to Must Fix and retains its original
   evidence. The report shows `SKIPPED (strict-liability passthrough)`. All other anchors go
   through adjudication.
3. **Verifier prompts carry the original tests** (PR.md 1209–1248, 1291–1342): spec-scope
   (`OUT_OF_SCOPE` requires a verbatim quote from the declared PR description or attached spec
   and an explanation that the quote excludes the same flow), searches for comparable patterns
   and baselines, runtime-assertion trace for crash/no-op/undefined claims, mitigation test (middleware, DB
   constraint, framework default, upstream guard), 6c removed-protection intent check
   (`references/finding-severity-rules.md` 5–35: intent from spec → PR description → commit
   messages; legacy coupling vs real guard; who maintains the invariant now). Every verdict needs
   queries and `file:line` read. Not enough evidence → `INCONCLUSIVE`.
4. **Spec context**: the PR description (verbatim) always; plus files matching config
   `spec_globs` at the head SHA, passed verbatim up to `spec_max_chars` (default 60,000);
   anything cut is disclosed in the report. Never summarise spec text (PR.md 345–355).
5. **Verifier failure is final** (PR.md 1248, 1342, 1361). Transport retries are fine; once a
   verifier returns a final message, no repair turn. Parse error, schema error, tool-turn
   exhaustion, timeout, or an ID multiset mismatch → that batch is `FAILED`, every finding in it
   gets `INCONCLUSIVE`, the reason is in the report, other batches continue. Initial axes may get
   one repair turn for malformed JSON.
6. **Closed verdict contract.** Verdict ∈ {CONFIRMED, REFUTED, PARTIAL, OUT_OF_SCOPE,
   INCONCLUSIVE}; severity ∈ {CRITICAL, HIGH, MEDIUM, LOW}. Every row must have `finding_id`,
   `verdict`, `corrected_severity` (or null), `severity_reason`, `evidence`, `queries`,
   `scope_quote`, `scope_source`, `scope_explanation`, `repro_path`, `repro_path_verified`,
   `ships_breakage`, `hypothetical`, `fix_is_local`, `unverified_premises`,
   `blind_spot_explanation`, `confirmed_claim`, `security_facts`, and `security_matrix_severity`.
   Inapplicable nullable fields use null. Baseline rows use `group_id`, `convention`
   (supports/conflicts/no-precedent), and `scope` (in-scope/OUT_OF_SCOPE), with the same fields
   for scope, source evidence, severity, security, and the release gate. Missing or invalid
   baseline rows leave findings in the report and mark the baseline incomplete.
7. **Lone rule** (PR.md 1382–1393). Apply lone calibration only when at least two axes actually
   reviewed the finding's file. A primary `MISSED` or `INTENTIONALLY_SKIPPED` file is not counted
   as reviewed. Same-root-cause, overlapping, or same-hunk corroboration rules out lone status.
   CONFIRMED keeps severity and records any supported blind spot. PARTIAL or INCONCLUSIVE drops
   one level if `blind_spot_explanation` is null.
8. **Security matrix only lowers** (PR.md 1384–1391, `references/severity-calibration.md`).
   Security findings carry the four facts (attack vector, auth scope, input control,
   reachability). The verifier or baseline returns a matrix severity that can only lower the
   effective severity. Missing facts or matrix severity make calibration incomplete and close
   the Must Fix gate for the finding or consensus group.
9. **Hypothetical / unverified premises** (6d, `finding-severity-rules.md` 37–55): for Should
   or above, remove unverified premises and regrade; hypothetical wording caps at Should.
10. **Buckets are exclusive, evaluated in this order**: Reference (REFUTED, OUT_OF_SCOPE) →
    Must (strict-liability passthrough; or candidate that passes the gate) → Should (effective
    HIGH; any PARTIAL; INCONCLUSIVE HIGH; Must candidate failing the gate) → Nice (everything
    else). Each finding also gets `action` ∈ {auto-fix, ask-user, no-op} + one-line reason.
11. **Observed-model independence governs truth verdicts.** The configured finder and verifier
    model names must differ. Use the `model` values from their final replies to judge actual
    independence. If they are the same, retain the reported verdict for inspection and use
    `INCONCLUSIVE` with reason `same observed model` for adjudication. If either model is
    missing, record `UNAVAILABLE` and withhold cross-model confirmation. Consensus baselines
    check shared evidence and follow their own gate.
12. **Primary is optional.** Any non-empty set of axes. Without `primary`, coverage is
    `N-A (primary not selected)`; diff-only findings still go to the repo-aware verifier.
13. **Coverage ownership.** F paths are the only keys. Each chunk owns its files; entries for
    files outside the chunk are ignored. A file with a finding counts as covered even if also
    marked no-issues. Repair covers only MISSED files with the same shared prompt; new findings
    from repair join verification.
14. **Chunk budget applies to source file count and total patch length** (PR.md 546–569).
    Each chunk allows up to 15 source files and 800 patch lines, including context and hunk
    headers. If a patch is unavailable, use additions plus deletions for its estimate. Docs,
    lockfiles and generated files still belong to a chunk. Known generated names or markers in
    the head blob exempt a file from the source count. An oversized file gets its own chunk.
15. **Diff completeness.** If a file's `patch` is null, fetch the full PR diff
    (`Accept: application/vnd.github.v3.diff`) and take that file's section; if still missing,
    mark the material incomplete for every axis in the report.
16. **Anchors follow Git line numbering.** Match against the pinned head blob using LF line
    boundaries and normalize CRLF. Missing-code findings use anchor `<none>` plus the enclosing
    symbol and line, and require manual placement.
17. **UID uses a separate `root_cause` field**, not the title:
    `sha256(path\0anchor\0normalise(root_cause).lower())[:20]`.
18. **Initial prompts** port PR.md 777–794 (+ shared checklist 467–528) for primary (search
    before reporting a missing guard, trace callers/defaults/framework mechanisms, scope check,
    per-file accounting, 1–3 line verbatim anchor, evidence: queries, file:line, why it still
    holds), PR.md 934–936 / 965–976 for neutral, PR.md 997–1009 for adversarial.
19. **Version binding and drift.** Record base/head SHA at fetch; verify the checkout HEAD equals
    head SHA. Save the evidence and request the application quote before fetching the current
    versions. Record that last observation in Markdown and the returned evidence immediately
    before publication. The saved evidence and its quote predate the observation.
20. **Report shape** (PR.md 1560–1648, 1696–1810): header; spec basis; per-file change summary
    and coverage; overview table with one column per enabled axis (hit + original severity),
    verification, final bucket, action, reason; per-finding detail with both sides' evidence and
    a paste-ready inline comment; reference section with verdicts; receipts; limits / not done.
21. **Deterministic self-check before publishing** (subset of PR.md 1827–1851 R1–R10): every F
    file accounted or primary N-A; every finding in exactly one bucket; every axis has a state;
    every verdict in the enum; unique report UIDs; every Must passes the release gate or meets
    strict-liability passthrough; counts in the header match the body. The report lists failures.
22. **Must Fix requires a verified failure path.** For a qualifying candidate, the verifier or
    consensus baseline must supply search queries, `file:line` evidence, a concrete `repro_path`,
    `repro_path_verified: true`, and `ships_breakage: true`. Set `repro_path_verified` only when
    first-hand evidence still supports the path after removing unverified premises. A usable
    decision and `hypothetical: false` are also required. An `INCONCLUSIVE` verdict or an
    incomplete baseline cannot open the gate.
23. **Repository tools use pinned inputs.** `read_file` defaults to `head` and accepts `base` for
    the earlier version. Both read regular Git blobs. `pr_commits(path)` lists messages and SHAs
    of commits touching the path in `base_sha..head_sha`. `show_commit_patch(sha, path)` takes one
    full SHA from that range and returns the path's patch. `grep` and `list_dir` work on the head
    checkout. Attached specs come from regular head blobs with their original line endings.
24. **PARTIAL comments use the confirmed scope.** The nullable `confirmed_claim` contains the
    verified failure and impact for the supported paths, with a fix only if that scope supports
    it. If it is null, the paste-ready comment uses the verified evidence and says the original
    scope and fix need confirmation. The original finding remains in the detailed evidence.
25. **An unusable initial review still publishes.** If there are changed files, a valid diff-only
    reply counts even with zero findings. Primary must account for at least one changed file
    across the initial pass and coverage repair to count. If neither yields a usable reply,
    `Result` and the report record failure and its reason. The review CLI prints the report path,
    processes the remaining PRs, and exits nonzero.
26. **Serving requires a token.** The default bind is `127.0.0.1`. `--host` overrides it, and
    `--token` takes precedence over `AXIS_REVIEW_SERVE_TOKEN`. A nonempty path-safe token must
    match the first URL segment. Requests without a matching token get 404. The server offers
    visible regular files resolving beneath the output directory with no directory indexes or
    request URL logging. The Compose service binds `0.0.0.0` with the encrypted token provided
    through the environment after a successful review.
27. **Receipt verification binds identity and counts missing artifacts.** Match the signed
    `receipt_id` with the captured `x-receipt-id`. If the header was absent, match signed `chat_id`
    with the captured response ID. Every successful receipt-enabled call gets a verification row
    even without a lookup ID or artifact. The Markdown and JSON summaries show expected, fetched,
    verified, and missing. The offline command exits nonzero when an expected row fails any check
    and leaves the bundle untouched.
28. **Saved bodies preserve bytes when safe.** Preserve the exact request and response bodies
    when they pass credential checks, including checks on decoded JSON strings. If a body is
    withheld, retain its call metadata and record that its hash cannot be checked. Usage sums
    report the number of attempts contributing to each field so an omitted token count remains
    distinguishable from zero.

### Deferred (stated in the report's limits section)

- Formal-spec (C4) compliance lane.
- Previous-round continuity (FIXED / STILL_OPEN / STALE).
- Author calibration file.
- Authored vs inherited provenance (hotfix → staging); v1 treats every changed file as authored.
- Multi-PR group mode.
- Model-based report Self-Verify auditor (v1 runs the deterministic self-check only).
- Skipping 4.2 for claims already CONFIRMED in 4.1.

### Known limits after review round 1 (2026-11-24)

A targeted recheck of the 37 review findings marked 32 fixed and 5 partially fixed. The four
below rest on model judgment that the program cannot verify on its own; the code narrows them
but does not close them.

- **Strict-liability classification (S09).** Passthrough now needs an exact or normalized head
  anchor, which proves the cited text exists but not that it really is a secret or an injection.
  A reviewer that misclassifies text with a valid anchor still skips verification, as in the
  original tool.
- **Scope exclusion (S10).** An `OUT_OF_SCOPE` quote must appear verbatim in the PR description
  or attached spec and carry a reason. Whether that passage really excludes the same flow is
  still the verifier's reading.
- **Release-gate premises (F04).** Must Fix needs `repro_path_verified: true`. The program trusts
  that flag; it does not detect a verifier that lists a premise as unverified yet marks the
  path verified.
- **Cross-location root causes (F06).** All findings go to the root-cause matcher, so findings
  in different hunks can corroborate each other. If the matcher splits them or fails, they are
  treated as separate, and the lone rule may apply.

S08 (missing receipts visible in the summary) is complete for bundles written by this version.
Bundles without the `receipt_expected` field predate it; none were ever produced.

Optional evidence steps (receipt fetch, dstack quote) catch every exception type, because all
model calls have finished by then and a library failure must cost only that section.
