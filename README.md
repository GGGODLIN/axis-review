# axis-review

Axis Review runs independent pull request reviews with models behind OpenAI-compatible chat endpoints. It reads GitHub PRs and writes a report and evidence directory for each PR. It leaves GitHub comments and fixes for the operator to apply.

## Review methodology

The three default axes follow [claude-pr-review](https://github.com/GGGODLIN/claude-pr-review). The primary axis reads the diff and can inspect pinned base and head files, path-filtered commit messages, and per-commit patches with read-only tools. The neutral and adversarial axes review the diff independently. When primary runs, it tracks each changed file, splits large PRs into chunks, and gets one repair pass for coverage gaps.

Truth verification checks the model names reported in the final replies. If the finder and verifier report the same model, the verdict becomes `INCONCLUSIVE` and the original verdict stays in the evidence. If a model ID is missing, cross-model confirmation is unavailable. When primary and a diff-only axis find the same root cause, the group gets a consensus baseline and scope check. Strict-liability findings with an exact or whitespace-normalized head anchor go directly to Must Fix.

Other Must Fix findings need a qualifying candidate, source evidence that supports the failure path after unverified premises are removed, and breakage that would ship. Paste-ready `PARTIAL` comments use the verified scope or evidence. Refuted and out-of-scope claims stay in the reference section. The full release gate and report checks are in the [v1 design](docs/design.md#v1-decisions-after-the-fidelity-check-2026-11-24--these-override-the-sections-above).

Deferred in v1 are the formal-spec C4 lane, cross-round continuity, author calibration, authored-versus-inherited provenance, grouped multi-PR reports, a model-based report auditor, and skipping 4.2 after 4.1 already confirmed a finding.

## Configuration and local usage

- [Magpie](/config.magpie.toml) targets a local keyless gateway at `127.0.0.1:18417` with receipt retrieval disabled.
- [Phala Private AI](/config.phala.toml) uses `PHALA_API_KEY` from the environment and enables Phala ACI receipts. `GITHUB_TOKEN` is optional for GitHub API access.
- Endpoints with API credentials must use HTTPS unless the host is loopback.
- In each config, `language` applies only to model-written text; report templates stay in English.

From a checkout with Python 3.11 or newer and Git available, create a virtual environment and start with Magpie running locally:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
axis-review review https://github.com/OWNER/REPO/pull/123 --config config.magpie.toml --out out
```

Use `--config config.phala.toml` after setting `PHALA_API_KEY` to review through Phala. Add more PR URLs before `--config` to produce separate output directories. If a PR has changed files and every axis still lacks a usable result after repair, the CLI writes and prints its diagnostic report, continues reviewing the remaining PRs, and exits nonzero.

Each review bundle contains `report.md`, `evidence.json`, `calls.jsonl`, and the exact request and response bodies that pass credential checks. The call index records any withheld body. Use the PR's output directory to rerun the offline receipt checks.

```bash
axis-review verify-receipts "$PR_OUTPUT_DIR"
export AXIS_REVIEW_SERVE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
axis-review serve out --port 8080
```

`serve` binds to `127.0.0.1` by default. Open `http://127.0.0.1:8080/<token>/<PR_DIRECTORY>/report.md`, replacing `<token>` with `AXIS_REVIEW_SERVE_TOKEN` and `<PR_DIRECTORY>` with the name of the PR output directory. `--token` overrides the environment variable, but the environment keeps the token out of process arguments. All file paths need the token as their first segment; directory listings and automatic index pages are disabled. Use `--host` only if you intend to serve other hosts. For non-local access, put the server behind HTTPS and keep token-bearing URLs out of logs, shared links, and screenshots.

## Deploy on Phala Cloud

Install the [Phala CLI](https://docs.phala.com/phala-cloud/phala-cloud-cli/overview) and authenticate with `phala login`. Set `PHALA_API_KEY` from your secret store, generate `AXIS_REVIEW_SERVE_TOKEN` as above, set `AXIS_REVIEW_REF` to a published full 40-hex commit SHA, and set `PR_URLS` to a space-separated list of GitHub pull request URLs. If GitHub API access needs a token, pass `-e "GITHUB_TOKEN=$GITHUB_TOKEN"` to the same deployment command. The CLI encrypts the environment variables supplied with `-e`; see [Phala secure environment variables](https://docs.phala.com/phala-cloud/cvm/set-secure-environment-variables).

```bash
npm i -g phala
phala login
phala deploy -n axis-review -c docker-compose.yml -t tdx.small --disk-size 20G \
  -e "PHALA_API_KEY=$PHALA_API_KEY" -e "AXIS_REVIEW_REF=$AXIS_REVIEW_REF" \
  -e "AXIS_REVIEW_SERVE_TOKEN=$AXIS_REVIEW_SERVE_TOKEN" -e "PR_URLS=$PR_URLS" --wait
phala cvms get axis-review
phala cvms attestation axis-review
```

The [Compose service](/docker-compose.yml) checks that the checkout matches the requested commit before and after installing it with the `tee` extra. It reads the Phala config from that checkout and writes results to `/data/out`. When review exits successfully, it binds to `0.0.0.0:8080` inside the container and requires the same token-prefixed paths as local serving. The token grants access to raw model payloads and PR material as well as reports. Use the CVM's HTTPS application endpoint for port `8080` to copy the results before deleting it. See [Phala port routing](https://docs.phala.com/phala-cloud/cvm/set-secure-environment-variables#special-environment-variables).

```bash
phala cvms delete axis-review
```

## Receipt verification and its limits

Phase-by-phase call records preserve the exact bytes sent and received. For each successful Phala call, the reviewer looks up the receipt by `x-receipt-id`, falling back to the response ID when the header is absent. It saves the bare receipt under `receipts/` and requests one gateway attestation per endpoint with a fresh nonce.

`receipts/verification.json` records the checks at collection time. The Markdown report shows the same `expected`, `fetched`, `verified`, and `missing` counts. Successful calls to receipt-enabled endpoints count as expected even when no lookup ID or artifact was saved. `verify-receipts` recomputes the JSON summary on stdout, leaves the bundle untouched, and exits nonzero if any expected receipt is not fully verified. Older bundles without `receipt_expected` in `calls.jsonl` infer scope from saved receipts and attestations. If both are absent, the saved bundle cannot establish which calls expected a receipt.

A passing row confirms that:

- The saved workload keyset's SHA-256 over RFC 8785 canonical JSON matches the digest in both the saved report and the receipt, and its `not_after` timestamp is in the future at verification time.
- The receipt selects a supported Ed25519 key in that keyset and the signature verifies over the canonical receipt with only `signature` removed.
- The signed `receipt_id` matches the captured header, or the signed `chat_id` matches the captured response ID when the header is absent.
- The receipt's `request.received` and `response.returned` hashes match the exact saved body bytes.
- The receipt has an `upstream.verified` event with `result: "verified"` and `required: true`.

These checks establish evidence consistency against the saved keyset. Establishing gateway identity requires independently verifying the TDX quote against Intel DCAP collateral and checking that the quote binds the nonce and keyset. RTMR3 event-log replay and the measured compose hash are also unverified. The upstream event is an assertion in the receipt, and the cited upstream session is unverified. [Phala's full verification procedure](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-signature)

The application CVM quote is a separate artifact. With the dstack socket mounted, `tee_quote.json` stores the CVM app ID, the SHA-256 of `evidence.json`, and the quote requested over that digest. Offline receipt verification does not validate this application quote. A local run without the socket writes `{"in_tee": false}`.
