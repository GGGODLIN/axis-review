import json
import math
import re
from pathlib import Path

from .config import Config, ensure_no_credentials
from .llm import CallRecord, UNAVAILABLE
from .selfcheck import BUCKETS


LIMITS = (
  "Formal-spec (C4) compliance and previous-round continuity are deferred.",
  "Author calibration and authored/inherited provenance are deferred. All changed files are treated as authored.",
  "Multi-PR group reports and model-based report auditing are deferred.",
  "Skipping the challenge pass based on prior confirmation is deferred.",
  "Receipt checks do not verify Intel DCAP collateral, RTMR3 event-log replay, the compose hash, or the upstream session.",
  "The application quote is reported separately. Its authenticity is not verified by this command.",
)


def _json(value, **kwargs) -> str:
  # Escaped surrogates preserve unusual Git paths without writing invalid UTF-8 JSON.
  return json.dumps(value, ensure_ascii=True, allow_nan=False, **kwargs)


def call_rows(records: list[CallRecord]) -> list[dict]:
  return [{"seq": row.seq, "phase": row.phase, "axis": row.axis, "endpoint": row.endpoint,
           "model_requested": row.model, "model_observed": row.model_observed, "status": row.status,
           "receipt_id": row.receipt_id, "response_id": row.response_id, "latency_s": row.latency_s,
           "usage": row.usage, "error": row.error, "req_path": f"bodies/{row.seq}.req.json",
           "resp_path": f"bodies/{row.seq}.resp.json"}
          for row in sorted(records, key=lambda record: record.seq)]


def write_calls(out_dir: Path, records: list[CallRecord], config: Config) -> None:
  rows = call_rows(records)
  index = "".join(_json(row, separators=(",", ":")) + "\n" for row in rows).encode()
  ensure_no_credentials(index, config)
  for row in records:
    ensure_no_credentials(row.request_bytes, config)
    ensure_no_credentials(row.response_bytes, config)
  (out_dir / "bodies").mkdir()
  for row in records:
    (out_dir / f"bodies/{row.seq}.req.json").write_bytes(row.request_bytes)
    (out_dir / f"bodies/{row.seq}.resp.json").write_bytes(row.response_bytes)
  (out_dir / "calls.jsonl").write_bytes(index)


def write_evidence(out_dir: Path, evidence: dict, config: Config) -> None:
  data = (_json(evidence, indent=2) + "\n").encode()
  ensure_no_credentials(data, config)
  (out_dir / "evidence.json").write_bytes(data)


def _text(value) -> str:
  text = str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")
  return re.sub(r"([\\`*_{}\[\]()#+.!|<>~&-])", r"\\\1", " ".join(text.split()))


def _block(text: str) -> str:
  runs = re.findall(r"`+", text)
  fence = "`" * max(3, 1 + max(map(len, runs), default=0))
  return f"{fence}text\n{text}\n{fence}"


def _table(headers, rows):
  def row(cells):
    return "| " + " | ".join(_text(cell) for cell in cells) + " |"

  separator = "| " + " | ".join(["---"] * len(headers)) + " |"
  return [row(headers), separator, *(row(cells) for cells in rows)]


def _usage(calls):
  costs = []
  tokens = {key: 0 for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
  reported = 0
  for call in calls:
    usage = call["usage"]
    if not usage:
      continue
    reported += 1
    cost = usage.get("cost")
    if type(cost) is int or (type(cost) is float and math.isfinite(cost)):
      costs.append(cost)
    for key in tokens:
      if type(usage.get(key)) is int:
        tokens[key] += usage[key]
  parts = [f"Usage reported on {reported}/{len(calls)} HTTP attempts."]
  if costs:
    parts.append(f"Reported cost sum: {sum(costs)} ({len(costs)} attempts reported costs).")
  if reported:
    parts.append("Reported token totals: " + ", ".join(f"{key}={value}" for key, value in tokens.items()) + ".")
  return " ".join(parts)


def _axes(evidence):
  rows = []
  calls = evidence["calls"]
  for axis, info in evidence["axes"].items():
    records = [call for call in calls if call["axis"] == axis and call["phase"] in {"initial", "coverage_repair"}]
    observed = sorted({call["model_observed"] for call in records})
    notes = [run["error"] for run in info["runs"] if run["error"]]
    rows.append((axis, info["state"], info["endpoint"], info["model_requested"],
                 ", ".join(observed) if observed else UNAVAILABLE, "; ".join(notes) if notes else "—"))
  for role, info in evidence["verifiers"].items():
    records = [call for call in calls if call["axis"] == role]
    batches = [batch for batch in evidence["verification_batches"] if batch["role"] == role]
    observed = sorted({call["model_observed"] for call in records})
    notes = [batch["error"] for batch in batches if batch["error"]]
    state = "FAILED" if notes else ("PASS" if batches else "N-A")
    rows.append((role, state, info["endpoint"], info["model"],
                 ", ".join(observed) if observed else UNAVAILABLE, "; ".join(notes) if notes else "—"))
  return _table(("Role", "State", "Endpoint", "Requested model", "Observed models", "Errors"), rows)


def _detail(item, evidence, number):
  location = item["location"]
  pinned = location["line_start"]
  if pinned is None:
    symbol, line = item["enclosing_symbol"], item["line_start"]
    where = "Manual placement" + (f" near {symbol}" if symbol else "") + (f" at reported line {line}" if line else "")
  else:
    end = location["line_end"]
    where = str(pinned) if end == pinned else f"{pinned}–{end}"
  proof = evidence["verification"].get(item["id"]) or evidence["baselines"].get(item["group_id"], {})
  rows = [f"### F-{number:02d} {_text(item['title'])}", "",
          f"- UID `{item['uid']}`. Source {_text(item['axis'])} using {_text(item['model_observed'])}.",
          f"- File {_text(item['file'])}. Line {_text(where)} ({_text(location['status'])}).",
          f"- Severity {item['severity']} → {item['effective_severity']}. Bucket {item['bucket']}.",
          f"- Verification {_text(item['verdict'] or item['verification_status'])}. "
          f"Verifier model {_text(proof.get('model_observed', UNAVAILABLE))}. Cross-model {_text(item['cross_model'])}.",
          f"- Root cause {_text(item['root_cause'])}", f"- Problem {_text(item['problem'])}",
          f"- Impact {_text(item['impact'])}", f"- Fix {_text(item['fix'])}",
          f"- Initial evidence {_text(item['evidence'])}"]
  if item["queries"]:
    rows.append(f"- Initial queries {_text(', '.join(item['queries']))}")
  if item["security_facts"]:
    rows.append(f"- Initial security facts {_text(_json(item['security_facts']))}")
  for key, label in (("evidence", "Counter-evidence or verification evidence"), ("queries", "Verifier queries"),
                     ("scope_quote", "Scope quote"), ("severity_reason", "Severity reason"),
                     ("security_facts", "Verified security facts"), ("security_matrix_severity", "Security matrix"),
                     ("unverified_premises", "Unverified premises"), ("blind_spot_explanation", "Blind spot"),
                     ("repro_path", "Failure path"), ("error", "Verification error")):
    if proof.get(key):
      value = ", ".join(proof[key]) if isinstance(proof[key], list) else proof[key]
      rows.append(f"- {label} {_text(value)}")
  rows.extend(f"- {_text(note)}" for note in item["calibration_notes"])
  comment = f"{item['problem']}\n\n{item['impact']}\n\n{item['fix']}"
  if item["bucket"] == "Reference":
    comment = f"Reference ({item['verdict']}). {proof.get('scope_quote') or proof.get('evidence', '')}\n\nOriginal concern: {item['problem']}"
  rows.extend(("", "Paste-ready inline comment", "", _block(comment), ""))
  return rows


def render(evidence: dict, tee: dict) -> str:
  pr = evidence["pr"]
  coverage = evidence["coverage"]
  counts = evidence["counts"]
  axes = list(evidence["axes"])
  spec = evidence["spec"]
  drift = evidence["drift"]
  lines = [f"# PR review · {_text(pr['title'])}", "",
           f"[{_text(pr['owner'] + '/' + pr['repo'])} #{pr['number']}]({pr['url']}) · {_text(pr['author'])}", "",
           f"Base `{pr['base_sha']}` · Head `{pr['head_sha']}`", "",
           f"Files {counts['files']} · Findings {counts['findings']} · " +
           " · ".join(f"{label} {count}" for label, count in counts["buckets"].items()), "",
           "Anchor counts · " + " · ".join(f"{_text(label)} {count}" for label, count in counts["anchors"].items()), "",
           f"Version check {_text(drift['state'])}", ""]
  if drift["state"] == "DRIFT":
    lines.extend((f"Current base `{drift['base_sha']}` · Current head `{drift['head_sha']}`. Review evidence uses the original versions.", ""))
  lines.extend((*_axes(evidence), "", "## Spec basis", "",
                "PR description and selected head-SHA spec text are stored verbatim in [evidence.json](evidence.json).", ""))
  if spec["files"]:
    lines.extend(f"- {_text(file['path'])}" for file in spec["files"])
  else:
    lines.append("No spec file text was attached.")
  lines.extend(("", "## Per-file change and coverage", "", _text(coverage["status"]), ""))
  if "counts" in coverage:
    lines.extend((" · ".join(f"{_text(key)} {value}" for key, value in coverage["counts"].items()), ""))
  missing = set(evidence["incomplete_diff"])
  if missing:
    lines.extend((f"Diff material was incomplete for every enabled axis ({len(missing)} missing file sections).", ""))
  files = coverage.get("files", {})
  lines.extend(_table(("File", "Change", "+", "−", "Diff", "Coverage", "Reason"), [
    (file["path"], file["status"], file["additions"], file["deletions"],
     "Missing" if file["path"] in missing else "Available", files.get(file["path"], {}).get("status", "—"),
     files.get(file["path"], {}).get("reason") or "—") for file in pr["files"]
  ]))
  findings = evidence["findings"]
  lines.extend(("", "## Findings overview", ""))
  lines.extend(_table(("#", "UID", "Finding", *axes, "Verification", "Bucket", "Action", "Reason"), [
    (f"F-{index:02d}", item["uid"], item["title"],
     *(", ".join(item["axis_hits"].get(axis, ())) or "—" for axis in axes),
     item["verdict"] or item["verification_status"], item["bucket"], item["action"], item["action_reason"])
    for index, item in enumerate(findings, 1)
  ]))
  lines.extend(("", "Actions are recommendations for the operator.", ""))
  numbered = list(enumerate(findings, 1))
  for bucket in BUCKETS:
    lines.extend((f"## {bucket}", ""))
    selected = [(index, item) for index, item in numbered if item["bucket"] == bucket]
    if not selected:
      lines.extend(("No findings.", ""))
    for index, item in selected:
      lines.extend(_detail(item, evidence, index))
  lines.extend(("## Consensus baselines", "", f"Root-cause matching {_text(evidence['matching']['state'])}.", ""))
  lines.extend(_table(("Group", "State", "Convention", "Scope", "Evidence"), [
    (key, row["state"], row.get("convention", "—"), row.get("scope", "—"),
     row.get("evidence") or row.get("error") or "—") for key, row in evidence["baselines"].items()
  ]))
  lines.extend(("", "## Receipts and application quote", ""))
  receipts = evidence["receipts"]
  if "checks" in receipts:
    lines.extend((f"Fetched {receipts['fetched']} · Verified {receipts['verified']}", ""))
    lines.extend(_table(("Check", "Statuses"), [(key, ", ".join(f"{state}={count}" for state, count in values.items()))
                                                 for key, values in receipts["checks"].items()]))
  else:
    lines.append(_text(receipts.get("state", "UNAVAILABLE")))
  if tee.get("in_tee"):
    lines.extend(("", f"Application quote saved in [tee_quote.json](tee_quote.json). App {_text(tee.get('app_id', UNAVAILABLE))}."))
  else:
    lines.extend(("", "Application quote unavailable.", *([_text(tee["error"])] if tee.get("error") else [])))
  lines.extend(("", "## Usage", "", _usage(evidence["calls"]), "", "## Limits and self-check", ""))
  limits = [*LIMITS, *pr["material_notes"], *spec["notes"]]
  limits.extend(f"{axis} returned {run['ignored_findings']} out-of-assignment findings"
                for axis, data in evidence["axes"].items() for run in data["runs"] if run["ignored_findings"])
  limits.extend(f"Coverage repair failed: {run['error']}" for run in evidence["coverage_repair"] if run["error"])
  for status in (drift, evidence["matching"]):
    if status.get("error"):
      limits.append(status["error"])
  limits.extend(f"{row['phase']} {row['role']} batch ({', '.join(row['ids'])}) failed: {row['error']}"
                for row in evidence["verification_batches"] if row["error"])
  lines.extend(f"- {_text(note)}" for note in limits)
  failures = evidence["selfcheck_failures"]
  lines.extend(("", f"Deterministic self-check {'FAILED' if failures else 'PASS'}.", ""))
  lines.extend(f"- {_text(failure)}" for failure in failures)
  return "\n".join(lines).rstrip() + "\n"


def write_report(out_dir: Path, evidence: dict, tee: dict, config: Config) -> None:
  data = render(evidence, tee).encode("utf-8", errors="backslashreplace")
  ensure_no_credentials(data, config)
  (out_dir / "report.md").write_bytes(data)
