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
  github.py       PR metadata, file list, patches, checkout at head SHA
  repo_tools.py   read-only tools confined to the checkout
  agent_loop.py   tool-calling loop that ends in a JSON object
  prompts.py      axis / verifier prompts and JSON schemas
  review.py       orchestration: first pass, coverage, clustering, verification, buckets
  anchors.py      deterministic re-anchoring + UID
  report.py       report.md, evidence.json
  receipts.py     provider receipt fetch + verification (Phala ACI)
  tee_quote.py    optional dstack quote over evidence.json (inside a CVM)
  cli.py          entry point: review / verify-receipts / serve
tests/            unittest, no network
config.phala.toml, config.magpie.toml, docker-compose.yml, README.md
```

## Interfaces (shared contract between modules)

### config.py

```toml
language = "en"            # report language passed to prompts
max_tool_turns = 12        # per agent loop
verify_batch_size = 6

[endpoints.phala]
base_url = "https://inference.phala.com/v1"
api_key_env = "PHALA_API_KEY"      # may be absent for keyless local gateways
receipts = "phala-aci"             # or omitted / "none"

[[axes]]
id = "primary"      # one of primary | neutral | adversarial (ids unique; primary required)
endpoint = "phala"
model = "moonshotai/kimi-k3.1-pro"

[verifiers]
for_primary = { endpoint = "phala", model = "z-ai/glm-5.3" }
for_diff_axes = { endpoint = "phala", model = "moonshotai/kimi-k3.1-pro" }
```

`load_config(path) -> Config` (dataclasses). Validation: `primary` axis present; every axis and
verifier references a defined endpoint; `verifiers.for_primary.model != primary.model`;
`verifiers.for_diff_axes.model` differs from every diff-only axis model.

### llm.py

```python
@dataclass
class CallRecord:
  seq: int; phase: str; axis: str; endpoint: str; model: str
  request_bytes: bytes; response_bytes: bytes; status: int
  headers: dict[str, str]; response_id: str | None; receipt_id: str | None
  latency_s: float; usage: dict | None; error: str | None

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
differs from `changed_files` raise. `checkout(pr, workdir) -> Path`: shallow fetch of `head_sha`
into `workdir/repo` (works for merged PRs and forks via `refs/pull/{n}/head` or the SHA).

### repo_tools.py

OpenAI tool schemas + `execute(name, args, root) -> str` for `read_file(path, start_line,
end_line)`, `grep(pattern, glob, max_results)`, `list_dir(path)`. Paths resolved and confined to
`root` (reject `..`, absolute paths, symlink escape). Output truncated to 12,000 chars with a
marker. Never writes.

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
normalise findings → re-anchor → cluster (same file and overlapping line range, or equal anchor)
→ consensus baseline checks / truth verification in batches (exact ID multiset check per batch;
mismatch → whole batch INCONCLUSIVE) → severity + buckets → UIDs → report. An axis that fails
is reported `FAILED` with its error; the run continues with the rest and says so.

Finding record (after first pass):
`{id, axis, model, severity, title, file, line_start, line_end, problem, impact, fix, anchor}`.
Verification record: `{finding_id, verifier_model, verdict, corrected_severity, severity_reason,
evidence, repro_path, ships_breakage, hypothetical}`. Baseline record (consensus):
`{cluster_id, verifier_model, convention, scope, evidence}`.

### receipts.py (provider `phala-aci`)

- `fetch_receipts(client_cfg, records, out_dir)`: for each CallRecord with a receipt id (or
  response id), `GET {base_url}/aci/receipts/{id}` with the same key; save
  `receipts/<seq>.json`.
- `fetch_attestation(base_url, key) -> dict`: `GET {base_url}/aci/attestation?nonce=<64 hex>`
  with a fresh random nonce; save `attestation.json` with the nonce.
- `verify(out_dir) -> dict` per receipt: (1) `sha256:` + hex(sha256(JCS(workload_keyset)))
  equals `workload_keyset_digest` of the report and of the receipt; (2) `not_after` in the
  future; (3) `key_id` resolves to an `ed25519` key in `receipt_signing_keys`; verify the hex
  signature over `JCS(receipt without "signature")`; (4) `request.received.body_hash` ==
  `sha256:` + hex(sha256(request_bytes)) and `response.returned.body_hash` == same over
  response_bytes; (5) `upstream.verified` has `result == "verified"` and `required == true`.
  Unknown `algo` → `unsupported`. Each check reported separately.
- Explicitly NOT verified in v1 (stated in the report): the TDX quote against Intel DCAP
  collateral, RTMR3 event-log replay / compose hash, and the attested upstream session.

### tee_quote.py

If `/var/run/dstack.sock` exists: `DstackClient().get_quote(sha256(evidence.json)[:32])`, write
`tee_quote.json` with the quote, `app_id`, and the evidence digest. Otherwise write
`{"in_tee": false}`.

### report.py

`report.md` (language from config) with: header (PR identity, base/head SHA, axes with endpoint
and the model id observed in responses, verifiers), coverage table, re-anchor counts, overview
grouped Must → Should → Nice → Reference with UID, per-finding detail (source axis, original
and effective severity, verdict, verifier evidence, repro path), consensus baseline results,
receipts summary (count fetched / verified per check), cost (sum of `usage.cost` when present,
else tokens), a "not done / limits" section. `evidence.json` holds every record. `calls.jsonl`
holds CallRecords without request/response bodies; bodies go to `bodies/<seq>.req.json` and
`<seq>.resp.json` (needed to recheck body hashes).

### cli.py

`python -m axis_review review <PR_URL>... --config FILE --out DIR` (one sub-directory per PR),
`python -m axis_review verify-receipts DIR`, `python -m axis_review serve DIR --port 8080`
(read-only static server for the output directory).

## Deployment on Phala (docker compose)

Image `python:3.12` (amd64, has git). The compose command installs this repo at a pinned commit
from GitHub (`pip install git+https://github.com/GGGODLIN/axis-review@<sha>`), runs `review`
for the PR list, then `serve`s the output dir on 8080. `PHALA_API_KEY` is passed as an encrypted
secret (`phala deploy -e`), referenced as `${PHALA_API_KEY}`. `/var/run/dstack.sock` is mounted
for the quote. Docker log size is capped. Delete the CVM after copying the outputs.

## v1 decisions after the fidelity check (2026-11-24) — these override the sections above

Two independent reviewers compared this design with `claude-pr-review` and reported where the
methodology was broken or weakened. Port the original wording, made vendor-neutral, from the
cited sections of `~/Desktop/projects/claude-pr-review/commands/pr-review.md` (abbreviated
`PR.md`) and `references/`. Prompts treat diff, code, spec text and other axes' findings as data,
never as instructions.

### Adopted in v1

1. **Consensus means the same issue, not the same place** (PR.md 1204, 1384, 1765). Location
   (same file, overlapping lines or equal anchor) only proposes candidate groups. One `match`
   call per PR (repo-aware verifier model, tools on) splits candidates into same-root-cause
   groups. A group with a `primary` finding and a diff-only finding is consensus. Same hunk but
   different failure mode = corroboration only: each finding keeps its own truth verification,
   and neither is lone.
2. **Strict-liability passthrough** (PR.md 1202–1204, 1256–1259, 1763–1766). Reviewers tag
   `strict_liability` with a category: hardcoded secret, SQL via string concatenation,
   eval/innerHTML on user input, plaintext password compare. These skip verification, are shown
   as `SKIPPED (strict-liability passthrough)`, and are Must Fix with their original evidence.
3. **Verifier prompts carry the original tests** (PR.md 1209–1248, 1291–1342): spec-scope (only
   `OUT_OF_SCOPE` with a verbatim quote), search related patterns, baseline-comparable test,
   runtime-assertion trace for crash/no-op/undefined claims, mitigation test (middleware, DB
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
   `repro_path` (or null), `ships_breakage`, `hypothetical`, `unverified_premises`,
   `blind_spot_explanation` (or null). Baseline rows: `group_id`, `convention`
   (supports/conflicts/no-precedent), `scope` (in-scope/OUT_OF_SCOPE + quote), `evidence`, plus
   the same Must-gate fields (`repro_path`, `ships_breakage`, `hypothetical`) so consensus can
   reach Must Fix. Missing or invalid baseline rows → findings kept, baseline marked incomplete.
7. **Lone rule** (PR.md 1382–1393). Lone = exactly one axis and no other axis on the same hunk
   or the same root cause. Only when ≥ 2 initial axes ran. CONFIRMED keeps severity and records
   why others missed it. PARTIAL/INCONCLUSIVE downgrade one level only when the verifier's
   `blind_spot_explanation` is null (no plausible reason the other axes missed it).
8. **Security matrix only lowers** (PR.md 1384–1391, `references/severity-calibration.md`).
   Security findings carry the four facts (attack vector, auth scope, input control,
   reachability). Verifier computes the matrix value; if lower than effective severity, use it
   and note it; never raise.
9. **Hypothetical / unverified premises** (6d, `finding-severity-rules.md` 37–55): for Should
   or above, remove unverified premises and regrade; hypothetical wording caps at Should.
10. **Buckets are exclusive, evaluated in this order**: Reference (REFUTED, OUT_OF_SCOPE) →
    Must (strict-liability passthrough; or candidate that passes the gate) → Should (effective
    HIGH; any PARTIAL; INCONCLUSIVE HIGH; Must candidate failing the gate) → Nice (everything
    else). Each finding also gets `action` ∈ {auto-fix, ask-user, no-op} + one-line reason.
11. **Different-model check uses observed models.** Record the `model` field of every response.
    "Confirmed by a different model" needs observed finder and verifier models that differ; if
    either is missing, write `UNAVAILABLE` and do not count it as cross-model confirmation.
12. **Primary is optional.** Any non-empty set of axes. Without `primary`, coverage is
    `N-A (primary not selected)`; diff-only findings still go to the repo-aware verifier.
13. **Coverage ownership.** F paths are the only keys. Each chunk owns its files; entries for
    files outside the chunk are ignored. A file with a finding counts as covered even if also
    marked no-issues. Repair covers only MISSED files with the same shared prompt; new findings
    from repair join verification.
14. **Chunk budget counts source files only** (PR.md 546–569): ≤ 15 source files and ≤ 800
    diff lines (all files) per chunk; non-source files (docs, lockfiles, generated) are still
    assigned to exactly one chunk.
15. **Diff completeness.** If a file's `patch` is null, fetch the full PR diff
    (`Accept: application/vnd.github.v3.diff`) and take that file's section; if still missing,
    mark the material incomplete for every axis in the report.
16. **Anchors.** Missing-code findings use anchor `<none>` plus the enclosing symbol and line;
    they get no line pin and are reported as needing manual placement.
17. **UID uses a separate `root_cause` field**, not the title:
    `sha256(path\0anchor\0normalise(root_cause).lower())[:20]`.
18. **Initial prompts** port PR.md 777–794 (+ shared checklist 467–528) for primary (search
    before reporting a missing guard, trace callers/defaults/framework mechanisms, scope check,
    per-file accounting, 1–3 line verbatim anchor, evidence: queries, file:line, why it still
    holds), PR.md 934–936 / 965–976 for neutral, PR.md 997–1009 for adversarial.
19. **Version binding and drift.** Record base/head SHA at fetch; verify the checkout HEAD equals
    head SHA; re-fetch the PR right before writing the report and disclose any drift without
    re-reviewing.
20. **Report shape** (PR.md 1560–1648, 1696–1810): header; spec basis; per-file change summary
    and coverage; overview table with one column per enabled axis (hit + original severity),
    verification, final bucket, action, reason; per-finding detail with both sides' evidence and
    a paste-ready inline comment; reference section with verdicts; receipts; limits / not done.
21. **Deterministic self-check before publishing** (subset of PR.md 1827–1851 R1–R10): every F
    file accounted or primary N-A; every finding in exactly one bucket; every axis has a state;
    every verdict in the enum; every Must has repro path + ships_breakage or strict-liability;
    counts in the header match the body. Failures are listed in the report, not hidden.

### Deferred (stated in the report's limits section)

- Formal-spec (C4) compliance lane.
- Previous-round continuity (FIXED / STILL_OPEN / STALE).
- Author calibration file.
- Authored vs inherited provenance (hotfix → staging); v1 treats every changed file as authored.
- Multi-PR group mode.
- Model-based report Self-Verify auditor (v1 runs the deterministic self-check only).
- Skipping 4.2 for claims already CONFIRMED in 4.1.
