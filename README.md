# axis-review

Axis Review runs independent pull request reviews with models behind OpenAI-compatible chat endpoints. It reads GitHub PRs and writes a report and evidence directory for each PR. It leaves GitHub comments and fixes for the operator to apply.

## Review methodology

The three default axes follow [claude-pr-review](https://github.com/GGGODLIN/claude-pr-review). The primary axis reads the diff and explores a read-only checkout of the PR head. The neutral and adversarial axes review the diff independently. The adversarial prompt focuses on failure modes, trust boundaries, and edge cases. Every changed file is tracked individually when primary runs, with chunking for large PRs and one repair pass for gaps in coverage.

A repo-aware verifier uses a different model from the finder. Findings count as consensus when primary and a diff-only axis identify the same root cause. Consensus gets a baseline and scope check. Findings in the same hunk with distinct root causes still get truth verification. The strict-liability categories in the design bypass that verification and go directly to Must Fix.

The report records coverage, deterministic anchor placement, severity, the reasoning for each action, and both sides' evidence. Outside the strict-liability categories, Must Fix requires a qualifying candidate, a concrete reproduction path, and breakage that would ship. Refuted and out-of-scope claims stay in the reference section. The [v1 design](docs/design.md#v1-decisions-after-the-fidelity-check-2026-11-24--these-override-the-sections-above) defines the full review rules and deterministic report checks.

Deferred in v1 are the formal-spec C4 lane, cross-round continuity, author calibration, authored-versus-inherited provenance, grouped multi-PR reports, a model-based report auditor, and skipping 4.2 after 4.1 already confirmed a finding.

## Configuration and local usage

- [Magpie](config.magpie.toml) targets a local keyless gateway at `127.0.0.1:18417` with receipt retrieval disabled.
- [Phala Private AI](config.phala.toml) uses `PHALA_API_KEY` from the environment and enables Phala ACI receipts. `GITHUB_TOKEN` is optional for GitHub API access.

From a checkout with Python 3.11 or newer and Git available, create a virtual environment and start with Magpie running locally:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
axis-review review https://github.com/OWNER/REPO/pull/123 --config config.magpie.toml --out out
```

Use `--config config.phala.toml` after setting `PHALA_API_KEY` to review through Phala. Add more PR URLs before `--config` to produce separate output directories. Each PR has `report.md`, `evidence.json`, `calls.jsonl`, and exact request and response bodies. Use the PR's output directory to rerun the offline receipt checks.

```bash
axis-review verify-receipts "$PR_OUTPUT_DIR"
axis-review serve out --port 8080
```

## Deploy on Phala Cloud

Install the [Phala CLI](https://docs.phala.com/phala-cloud/phala-cloud-cli/overview) and authenticate with `phala login`. Set `PHALA_API_KEY` from your secret store, `AXIS_REVIEW_REF` to a published commit SHA, and `PR_URLS` to a space-separated list of GitHub pull request URLs. If GitHub API access needs a token, pass `-e "GITHUB_TOKEN=$GITHUB_TOKEN"` to the same deployment command. The CLI encrypts the environment variables supplied with `-e`. [Phala secure environment variables](https://docs.phala.com/phala-cloud/cvm/set-secure-environment-variables)

```bash
npm i -g phala
phala login
phala deploy -n axis-review -c docker-compose.yml -t tdx.small --disk-size 20G \
  -e "PHALA_API_KEY=$PHALA_API_KEY" -e "AXIS_REVIEW_REF=$AXIS_REVIEW_REF" \
  -e "PR_URLS=$PR_URLS" --wait
phala cvms get axis-review
phala cvms attestation axis-review
```

The [Compose service](docker-compose.yml) installs the chosen Git revision with the `tee` extra, reads the Phala config from that checkout, and writes results to `/data/out`. When review exits successfully, it serves that directory on port `8080`. The static server has no authentication, and the directory includes raw model payloads and PR material. Use public PR material when the service is publicly reachable. Copy the results from the CVM's application endpoint for port `8080` before deleting it. [Phala port routing](https://docs.phala.com/phala-cloud/cvm/set-secure-environment-variables#special-environment-variables)

```bash
phala cvms delete axis-review
```

## Receipt verification and its limits

Phase-by-phase call records preserve the exact bytes sent and received. For each successful Phala call, the reviewer looks up the receipt by `x-receipt-id`, falling back to the response ID when the header is absent. It saves the bare receipt under `receipts/` and requests one gateway attestation per endpoint with a fresh nonce.

`receipts/verification.json` records each check per call and counts results per check. A passing row confirms that:

- The saved workload keyset's SHA-256 over RFC 8785 canonical JSON matches the digest in both the saved report and the receipt, and its `not_after` timestamp is in the future at verification time.
- The receipt selects a supported Ed25519 key in that keyset and the signature verifies over the canonical receipt with only `signature` removed.
- The receipt's `request.received` and `response.returned` hashes match the exact saved body bytes.
- The receipt has an `upstream.verified` event with `result: "verified"` and `required: true`.

These checks establish evidence consistency against the saved keyset. Establishing gateway identity requires independently verifying the TDX quote against Intel DCAP collateral and checking that the quote binds the nonce and keyset. RTMR3 event-log replay and the measured compose hash are also unverified. The upstream event is an assertion in the receipt, and the cited upstream session is unverified. [Phala's full verification procedure](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-signature)

The application CVM quote is a separate artifact. With the dstack socket mounted, `tee_quote.json` stores the CVM app ID, the SHA-256 of `evidence.json`, and the quote requested over that digest. Offline receipt verification does not validate this application quote. A local run without the socket writes `{"in_tee": false}`.
