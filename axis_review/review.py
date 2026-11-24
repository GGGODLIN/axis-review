import json
import re
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from . import github, report
from .agent_loop import AxisError, run_json_with_record
from .anchors import anchor_file, finding_uid
from .config import Config, Model, verifier_role
from .github import ChangedFile, PR
from .llm import Client, UNAVAILABLE
from .prompts import SEVERITIES, STRICT_LIABILITY, system_prompt
from .repo_tools import confined, matches_glob
from .selfcheck import ANCHOR_STATES, BUCKETS, PRIMARY_NA, check


NO_ISSUES = "REVIEWED_NO_ISSUES"
SKIPPED = "INTENTIONALLY_SKIPPED"


@dataclass(frozen=True)
class Result:
  out_dir: Path
  evidence: dict


def is_source(file: ChangedFile) -> bool:
  parts = PurePosixPath(file.path.lower()).parts
  name = parts[-1]
  non_source_dirs = {"doc", "docs", "documentation", "vendor", "vendors", "third_party",
                     "third-party", "node_modules", "generated", "__generated__", "dist"}
  lock_names = {"go.sum", "yarn.lock", "gemfile.locked", "npm-shrinkwrap.json",
                "package-lock.json", "pnpm-lock.yaml", "bun.lockb", "uv.lock"}
  return not (non_source_dirs.intersection(parts[:-1]) or name in lock_names
              or name.endswith((".lock", ".md", ".mdx", ".rst", ".adoc", ".txt", ".generated.ts",
                                ".generated.js", ".gen.go", ".pb.go", ".min.js", ".min.css"))
              or name.startswith(("readme", "changelog", "license")))


def chunk_files(files: list[ChangedFile], source_limit: int = 15,
                line_limit: int = 800) -> list[list[ChangedFile]]:
  chunks = []
  current = []
  sources = lines = 0
  for file in sorted(files, key=lambda item: item.path):
    source = int(is_source(file))
    size = file.additions + file.deletions
    if current and (sources + source > source_limit or lines + size > line_limit):
      chunks.append(current)
      current, sources, lines = [], 0, 0
    current.append(file)
    sources += source
    lines += size
  if current:
    chunks.append(current)
  return chunks


def coverage_for(files: list[ChangedFile], assignments: list[tuple[set[str], dict]]) -> dict:
  inventory = {file.path for file in files}
  entries = {path: {"status": "MISSED", "reason": None} for path in sorted(inventory)}
  ranks = {"MISSED": 0, SKIPPED: 1, NO_ISSUES: 2, "covered": 3}
  for owned, reply in assignments:
    rows = [*reply["coverage"], *({"file": row["file"], "status": "covered", "reason": None}
                                 for row in reply["findings"])]
    for row in rows:
      path, status, reason = row["file"], row["status"], row["reason"]
      if path not in inventory or path not in owned or (status == SKIPPED and not reason):
        continue
      if ranks[status] > ranks[entries[path]["status"]]:
        entries[path] = {"status": status, "reason": reason}
  counts = {key: 0 for key in ranks}
  counts.update(Counter(row["status"] for row in entries.values()))
  assert len(inventory) == sum(counts.values())
  return {"status": "APPLICABLE", "files": entries, "counts": counts}


def _spec_context(pr: PR, root: Path, config: Config) -> dict:
  context = {"description": pr.description, "files": [], "notes": []}
  if not config.spec_globs:
    return context
  remaining = config.spec_max_chars
  for path in github.tracked_paths(root):
    if not any(matches_glob(path, pattern) for pattern in config.spec_globs):
      continue
    try:
      source = confined(root, path)
      if source.is_symlink() or not source.is_file() or (root / path).is_symlink():
        raise ValueError
      with source.open(encoding="utf-8", newline="") as file:
        text = file.read(remaining + 1)
    except (OSError, ValueError):
      context["notes"].append(f"Spec file unavailable at head: {path}")
      continue
    truncated = len(text) > remaining
    included = text[:remaining]
    remaining -= len(included)
    if included or not truncated:
      context["files"].append({"path": path, "text": included})
    if truncated:
      context["notes"].append(f"Spec text {'truncated' if included else 'omitted'} by character budget: {path}")
  return context


def _call(client, root, phase, axis, target: Model, prompt, data, *, tools):
  system, schema = system_prompt(prompt, client.config.language)
  reply, record = run_json_with_record(
    client, phase=phase, axis=axis, endpoint=target.endpoint, model=target.model, system=system,
    user=json.dumps(data, ensure_ascii=True, allow_nan=False), schema=schema, tools=tools,
    root=root if tools else None,
  )
  return reply, record.model_observed


def _initial(client, pr, root, spec, axis, chunks, phase="initial"):
  runs = []
  for files in chunks:
    paths = [file.path for file in files]
    data = {"pr": {"title": pr.title, "base_sha": pr.base_sha, "head_sha": pr.head_sha},
            "spec": spec, "changed_files": [asdict(file) for file in files]}
    if axis.id == "primary":
      data["commit_messages"] = pr.commit_messages
    try:
      reply, observed = _call(client, root, phase, axis.id, axis, axis.id, data, tools=axis.id == "primary")
      findings = [dict(item, axis=axis.id, model=axis.model, model_observed=observed)
                  for item in reply["findings"] if item["file"] in paths]
      ignored = len(reply["findings"]) - len(findings)
      reply = dict(reply, findings=findings, coverage=reply.get("coverage", []))
      runs.append({"files": paths, "reply": reply, "observed": observed, "error": None,
                   "ignored_findings": ignored})
    except AxisError as error:
      runs.append({"files": paths, "reply": None, "observed": UNAVAILABLE, "error": str(error),
                   "ignored_findings": 0})
  return runs


def _prepare_findings(root: Path, runs: list[dict], files: list[ChangedFile]) -> list[dict]:
  hunks = {file.path: [(int(start), int(length) if length else 1)
                       for start, length in re.findall(r"(?m)^@@ .*? \+(\d+)(?:,(\d+))? @@", file.patch or "")]
           for file in files}
  findings = []
  for run in runs:
    if run["reply"] is None:
      continue
    for row in run["reply"]["findings"]:
      anchor = anchor_file(root, row["file"], row["anchor"], row["line_start"])
      start = anchor.line_start or row["line_start"]
      end = anchor.line_end or row["line_end"] or start
      related = [index for index, (line, length) in enumerate(hunks[row["file"]])
                 if start is not None and length and max(start, line) <= min(end, line + length - 1)]
      findings.append(dict(row, id=f"finding-{len(findings) + 1}", location=asdict(anchor), hunks=related))
  return findings


def _overlap(left: dict, right: dict) -> bool:
  if left["file"] != right["file"]:
    return False
  if left["anchor"] == right["anchor"] and left["anchor"] != "<none>":
    return True

  def span(finding):
    location = finding.get("location", {})
    start = location.get("line_start") or finding.get("line_start")
    end = location.get("line_end") or finding.get("line_end") or start
    return start, end

  a, b = span(left), span(right)
  return a[0] is not None and b[0] is not None and max(a[0], b[0]) <= min(a[1], b[1])


def _candidate_groups(findings: list[dict]) -> tuple[list[list[dict]], set[str]]:
  groups = []
  corroborated = set()
  for item in findings:
    touching = []
    hunks = set(item.get("hunks", ()))
    for index, group in enumerate(groups):
      overlaps = False
      for other in group:
        overlap = _overlap(item, other)
        overlaps |= overlap
        same_hunk = item["file"] == other["file"] and hunks.intersection(other.get("hunks", ()))
        if item["axis"] != other["axis"] and (overlap or same_hunk):
          corroborated.update((item["id"], other["id"]))
      if overlaps:
        touching.append(index)
    related = [other for index in touching for other in groups[index]]
    for index in reversed(touching):
      del groups[index]
    groups.append([*related, item])
  return groups, corroborated


def _match_candidates(findings: list[dict]) -> list[list[dict]]:
  eligible = [item for item in findings if item.get("strict_liability") not in STRICT_LIABILITY]
  groups, _ = _candidate_groups(eligible)
  return [group for group in groups if len(group) > 1]


def group_findings(findings: list[dict], matched: list[list[str]]) -> list[dict]:
  by_id = {finding["id"]: finding for finding in findings}
  _, corroborated = _candidate_groups(findings)
  candidates = [{item["id"] for item in group} for group in _match_candidates(findings)]
  if (Counter(item for group in matched for item in group) != Counter(item for group in candidates for item in group)
      or any(not group or not any(set(group) <= options for options in candidates) for group in matched)):
    raise AxisError("Match response was not an exact partition of candidate IDs")
  used = {item for group in matched for item in group}
  partitions = [*matched, *([item] for item in by_id if item not in used)]
  groups = []
  order = {item: index for index, item in enumerate(by_id)}
  for ids in sorted(partitions, key=lambda items: min(order[item] for item in items)):
    ids = sorted(ids, key=order.__getitem__)
    axes = {by_id[item]["axis"] for item in ids}
    consensus = "primary" in axes and len(axes) > 1
    groups.append({"id": f"group-{len(groups) + 1}", "finding_ids": ids, "consensus": consensus,
                   "corroborated_ids": [item for item in ids if item in corroborated or len(axes) > 1]})
  return groups


def _match(client, root, findings, spec):
  candidates = _match_candidates(findings)
  if not candidates:
    return group_findings(findings, []), {"state": "N-A", "error": None}
  target = client.config.verifiers.get("for_diff_axes") or client.config.verifiers["for_primary"]
  observed = UNAVAILABLE
  try:
    reply, observed = _call(client, root, "match", "match", target, "match",
                            {"candidates": candidates, "spec": spec}, tools=True)
    groups = group_findings(findings, reply["groups"])
    state = {"state": "PASS", "error": None, "model_observed": observed}
  except AxisError as error:
    # Overlap still establishes corroboration when matching cannot establish consensus.
    singletons = [[row["id"]] for group in candidates for row in group]
    groups = group_findings(findings, singletons)
    state = {"state": "FAILED", "error": str(error), "model_observed": observed}
  return groups, state


def _validate_batch(rows, inputs, field, scope_field, verified_spec):
  if Counter(row[field] for row in rows) != Counter(inputs):
    raise AxisError("Verifier response IDs do not match the input ID multiset")
  for row in rows:
    outcome = row[scope_field]
    if outcome == "OUT_OF_SCOPE":
      quote = row["scope_quote"]
      if not quote or not any(quote in text for text in verified_spec):
        raise AxisError("OUT_OF_SCOPE requires a verbatim quote from supplied spec or PR description")
    elif outcome in {"CONFIRMED", "PARTIAL", "REFUTED"}:
      if not row["queries"] or not re.search(r"\S+:\d+\b", row["evidence"]):
        raise AxisError("Truth verdicts require search queries and file:line evidence")


def _empty_verification(finding_id: str, error: str, observed: str) -> dict:
  return {"finding_id": finding_id, "verdict": "INCONCLUSIVE", "evidence": error,
          "corrected_severity": None, "severity_reason": "No usable verifier result.", "queries": [],
          "scope_quote": None, "repro_path": None, "ships_breakage": False, "hypothetical": False,
          "unverified_premises": [], "blind_spot_explanation": None, "fix_is_local": False,
          "security_facts": None, "security_matrix_severity": None,
          "model_observed": observed, "state": "FAILED", "error": error}


def _verify(client, root, pr, spec, findings, groups, ran_axes):
  verification, baselines, batches = {}, {}, []
  by_id = {item["id"]: item for item in findings}
  consensus = [group for group in groups if group["consensus"]]
  consensus_ids = {item for group in consensus for item in group["finding_ids"]}
  corroborated = {item for group in groups for item in group["corroborated_ids"]}
  targets = {role: [] for role in client.config.verifiers}
  for item in findings:
    if item["strict_liability"] is None and item["id"] not in consensus_ids:
      targets[verifier_role(item["axis"])].append(dict(item, lone=ran_axes >= 2 and item["id"] not in corroborated))
  source = [spec["description"], *(file["text"] for file in spec["files"])]
  common = {"spec": spec, "commit_messages": pr.commit_messages}
  size = client.config.verify_batch_size
  for role, inputs in targets.items():
    for offset in range(0, len(inputs), size):
      batch = inputs[offset:offset + size]
      ids = [item["id"] for item in batch]
      observed = UNAVAILABLE
      error = None
      try:
        reply, observed = _call(client, root, "verify", role, client.config.verifiers[role], "verify",
                                dict(common, findings=batch), tools=True)
        _validate_batch(reply["verdicts"], ids, "finding_id", "verdict", source)
        for row in reply["verdicts"]:
          verification[row["finding_id"]] = dict(row, model_observed=observed, state="PASS")
      except AxisError as exc:
        error = str(exc)
        for item in ids:
          verification[item] = _empty_verification(item, error, observed)
      batches.append({"phase": "verify", "role": role, "ids": ids, "error": error,
                      "state": "FAILED" if error else "PASS", "model_observed": observed})
  for offset in range(0, len(consensus), size):
    batch = consensus[offset:offset + size]
    ids = [group["id"] for group in batch]
    observed = UNAVAILABLE
    error = None
    inputs = [{"group_id": group["id"], "findings": [by_id[item] for item in group["finding_ids"]]}
              for group in batch]
    try:
      reply, observed = _call(client, root, "baseline", "for_diff_axes", client.config.verifiers["for_diff_axes"],
                              "baseline", dict(common, groups=inputs), tools=True)
      _validate_batch(reply["baselines"], ids, "group_id", "scope", source)
      for row in reply["baselines"]:
        baselines[row["group_id"]] = dict(row, state="PASS", model_observed=observed)
    except AxisError as exc:
      error = str(exc)
      for item in ids:
        baselines[item] = {"group_id": item, "state": "INCOMPLETE", "error": error,
                           "model_observed": observed}
    batches.append({"phase": "baseline", "role": "for_diff_axes", "ids": ids, "error": error,
                    "state": "FAILED" if error else "PASS", "model_observed": observed})
  return verification, baselines, batches


def cross_model(finder: str | None, verifier: str | None) -> str:
  if any(not value or value == UNAVAILABLE for value in (finder, verifier)):
    return UNAVAILABLE
  return "DIFFERENT" if finder != verifier else "SAME"


def classify(finding: dict, verification: dict | None = None, baseline: dict | None = None,
             *, consensus: bool = False, corroborated: bool = False, ran_axes: int = 1) -> dict:
  proof = verification if verification is not None else (baseline or {})
  strict = finding.get("strict_liability") in STRICT_LIABILITY
  verdict = proof.get("verdict")
  if proof.get("scope") == "OUT_OF_SCOPE":
    verdict = "OUT_OF_SCOPE"
  relationship = cross_model(finding.get("model_observed"), proof.get("model_observed"))
  effective = proof.get("corrected_severity") or finding["severity"]
  notes = []
  matrix = proof.get("security_matrix_severity")
  if not strict and matrix and SEVERITIES.index(matrix) > SEVERITIES.index(effective):
    notes.append(f"Security matrix lowered {effective} to {matrix}")
    effective = matrix
  lone = ran_axes >= 2 and not corroborated and not consensus
  if lone and not strict and verdict in {"PARTIAL", "INCONCLUSIVE"} and not proof.get("blind_spot_explanation"):
    effective = SEVERITIES[min(SEVERITIES.index(effective) + 1, len(SEVERITIES) - 1)]
    notes.append("Other axes raised no related concern and verification found no plausible blind spot")
  if lone and verdict == "CONFIRMED" and not proof.get("blind_spot_explanation"):
    notes.append("The verifier confirmed the finding and supplied no supported explanation for the other axes' silence")

  candidate = consensus or effective == "CRITICAL" or (verdict == "CONFIRMED" and relationship == "DIFFERENT")
  gate = bool(proof.get("repro_path") and proof.get("ships_breakage") and not proof.get("hypothetical"))
  if verdict in {"REFUTED", "OUT_OF_SCOPE"}:
    bucket, action, reason = "Reference", "no-op", "Verification supplied counter-evidence or an explicit scope exclusion."
  elif strict:
    bucket, action, reason = "Must Fix", "ask-user", "A strict-liability defect requires remediation."
  elif candidate and gate:
    bucket, action, reason = "Must Fix", "ask-user", "The verified failure path affects release behavior."
  elif effective == "HIGH" or verdict == "PARTIAL" or candidate:
    bucket, action, reason = "Should Fix", "ask-user", "The concern merits review with the available evidence."
  else:
    bucket, action, reason = "Nice to Have", "no-op", "The available evidence supports optional follow-up."
  supported_fix = (verdict == "CONFIRMED" and relationship == "DIFFERENT") or (consensus and proof.get("state") == "PASS")
  if (action == "ask-user" and supported_fix and proof.get("fix_is_local")
      and not proof.get("hypothetical") and not proof.get("unverified_premises")):
    action, reason = "auto-fix", "Verification supports a specific local fix with clear ownership."
  verification_status = proof.get("state")
  if strict:
    verification_status = "SKIPPED (strict-liability passthrough)"
  elif consensus:
    verification_status = ("CONSENSUS (baseline)" if proof.get("state") == "PASS"
                           else "CONSENSUS (baseline incomplete)")
  return {"bucket": bucket, "action": action, "action_reason": reason, "verdict": verdict,
          "effective_severity": finding["severity"] if strict else effective, "lone": lone,
          "cross_model": relationship, "calibration_notes": notes,
          "verification_status": verification_status,
          "repro_path": proof.get("repro_path"), "ships_breakage": proof.get("ships_breakage", False),
          "hypothetical": proof.get("hypothetical", False)}


def _adjudicate(findings, groups, verification, baselines, ran_axes):
  by_id = {item["id"]: item for item in findings}
  for group in groups:
    hits = {}
    for item in group["finding_ids"]:
      row = by_id[item]
      values = hits.setdefault(row["axis"], [])
      if row["severity"] not in values:
        values.append(row["severity"])
    for item in group["finding_ids"]:
      row = by_id[item]
      row.update(classify(row, verification.get(item), baselines.get(group["id"]),
                          consensus=group["consensus"], corroborated=item in group["corroborated_ids"],
                          ran_axes=ran_axes))
      row.update(group_id=group["id"], axis_hits=hits,
                 uid=finding_uid(row["file"], row["anchor"], row["root_cause"]))
  return sorted(findings, key=lambda row: BUCKETS.index(row["bucket"]))


def _drift(pr):
  try:
    base, head = github.fetch_versions(pr)
  except github.GitHubError as error:
    return {"state": "UNAVAILABLE", "error": str(error)}
  changed = (base, head) != (pr.base_sha, pr.head_sha)
  return {"state": "DRIFT" if changed else "UNCHANGED", "base_sha": base, "head_sha": head}


def _collect(pr, root, client):
  config = client.config
  spec = _spec_context(pr, root, config)
  primary = next((axis for axis in config.axes if axis.id == "primary"), None)
  chunks = (chunk_files(pr.files) or [[]]) if primary else []
  with ThreadPoolExecutor(max_workers=len(config.axes)) as pool:
    tasks = {axis.id: pool.submit(_initial, client, pr, root, spec, axis,
                                 chunks if axis.id == "primary" else [pr.files]) for axis in config.axes}
    runs = {axis: task.result() for axis, task in tasks.items()}
  states = {axis.id: {"state": "FAILED" if any(run["error"] for run in runs[axis.id]) else "PASS",
                      "endpoint": axis.endpoint, "model_requested": axis.model, "runs": runs[axis.id]}
            for axis in config.axes}
  repairs = []
  coverage = {"status": PRIMARY_NA}
  if primary:
    initial = [(set(run["files"]), run["reply"]) for run in runs["primary"] if run["reply"] is not None]
    coverage = coverage_for(pr.files, initial)
    missed = [file for file in pr.files if coverage["files"][file.path]["status"] == "MISSED"]
    if missed:
      repairs = _initial(client, pr, root, spec, primary, [missed], phase="coverage_repair")
      repair = [(set(run["files"]), run["reply"]) for run in repairs if run["reply"] is not None]
      coverage = coverage_for(pr.files, [*initial, *repair])
  initial_runs = [run for axis_runs in runs.values() for run in axis_runs]
  findings = _prepare_findings(root, [*initial_runs, *repairs], pr.files)
  groups, matching = _match(client, root, findings, spec)
  ran_axes = sum(any(run["reply"] is not None for run in entries) for entries in runs.values())
  verification, baselines, batches = _verify(client, root, pr, spec, findings, groups, ran_axes)
  ordered = _adjudicate(findings, groups, verification, baselines, ran_axes)
  return {"pr": dict(asdict(pr), url=pr.url), "language": config.language, "spec": spec,
          "axes": states, "verifiers": {role: asdict(model) for role, model in config.verifiers.items()},
          "chunks": [[file.path for file in chunk] for chunk in chunks], "coverage": coverage,
          "coverage_repair": repairs, "findings": ordered, "groups": groups, "matching": matching,
          "verification": verification, "baselines": baselines, "verification_batches": batches,
          "incomplete_diff": [file.path for file in pr.files if file.patch is None],
          "counts": {"files": len(pr.files), "findings": len(ordered),
                     "buckets": {name: sum(row["bucket"] == name for row in ordered) for name in BUCKETS},
                     "anchors": {name: sum(row["location"]["status"] == name for row in ordered)
                                 for name in ANCHOR_STATES}}}


def run_review(pr_url: str, config: Config, out_dir: Path) -> Result:
  out_dir = Path(out_dir)
  if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
    raise ValueError("Review output directory must be empty")
  pr = github.fetch_pr(pr_url)
  client = Client(config)
  with tempfile.TemporaryDirectory(prefix="axis-review-") as workdir:
    root = github.checkout(pr, Path(workdir))
    evidence = _collect(pr, root, client)
  out_dir.mkdir(parents=True, exist_ok=True)
  report.write_calls(out_dir, client.records, config)
  endpoints = {name: endpoint for name, endpoint in config.endpoints.items() if endpoint.receipts == "phala-aci"}
  evidence["receipts"] = {"state": "N-A (no receipt-enabled endpoint)"}
  if endpoints:
    try:
      from . import receipts

      evidence["receipts"] = receipts.process(out_dir, {
        name: {"base_url": target.base_url, "api_key": target.api_key()} for name, target in endpoints.items()
      }, config=config)
    except (ImportError, OSError, ValueError, RuntimeError) as error:
      evidence["receipts"] = {"state": f"FAILED ({type(error).__name__})"}
  evidence["drift"] = _drift(pr)
  evidence["calls"] = report.call_rows(client.records)
  evidence["selfcheck_failures"] = check(evidence, tuple(axis.id for axis in config.axes))
  report.write_evidence(out_dir, evidence, config)
  try:
    from . import tee_quote

    tee = tee_quote.write_quote(out_dir, config=config)
  except (ImportError, OSError, ValueError, RuntimeError) as error:
    tee = {"in_tee": False, "error": f"Application quote failed ({type(error).__name__})"}
  report.write_report(out_dir, evidence, tee, config)
  return Result(out_dir, evidence)
