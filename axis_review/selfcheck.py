import re
from collections import Counter

from .prompts import SEVERITIES, STRICT_LIABILITY, VERDICTS


BUCKETS = ("Must Fix", "Should Fix", "Nice to Have", "Reference")
PRIMARY_NA = "N-A (primary not selected)"
COVERAGE_STATES = ("covered", "REVIEWED_NO_ISSUES", "INTENTIONALLY_SKIPPED", "MISSED")
ANCHOR_STATES = ("exact", "normalized", "ambiguous", "FAILED", "<none>")


def strict_passthrough(finding: dict) -> bool:
  return (finding.get("strict_liability") in STRICT_LIABILITY
          and finding.get("location", {}).get("status") in {"exact", "normalized"})


def has_source_evidence(proof: dict) -> bool:
  return bool(proof.get("queries") and re.search(r"\S+:[1-9]\d*\b", proof.get("evidence", "")))


def release_gate(proof: dict, *, security_calibrated: bool) -> bool:
  return (proof.get("state") == "PASS" and proof.get("verdict") != "INCONCLUSIVE"
          and has_source_evidence(proof) and security_calibrated and bool(proof.get("repro_path"))
          and proof.get("repro_path_verified") is True and proof.get("ships_breakage") is True
          and proof.get("hypothetical") is False)


def check(evidence: dict, axis_ids: tuple[str, ...]) -> list[str]:
  failures = []
  axes = evidence.get("axes", {})
  if set(axes) != set(axis_ids):
    failures.append("Axis inventory differs from the enabled axes")
  for axis in axis_ids:
    if axes.get(axis, {}).get("state") not in {"PASS", "FAILED"}:
      failures.append(f"Axis {axis} has no final state")

  paths = [item["path"] for item in evidence["pr"]["files"]]
  coverage = evidence.get("coverage", {})
  if "primary" in axis_ids:
    entries = coverage.get("files", {})
    states = Counter(row.get("status") for row in entries.values())
    totals = {status: states[status] for status in COVERAGE_STATES}
    if (coverage.get("status") != "APPLICABLE" or Counter(paths) != Counter(entries.keys())
        or set(states) - set(COVERAGE_STATES) or coverage.get("counts") != totals
        or sum(totals.values()) != len(paths)):
      failures.append("Coverage inventory and totals must partition the changed file list")
    if any(row.get("status") == "INTENTIONALLY_SKIPPED" and not row.get("reason") for row in entries.values()):
      failures.append("Intentionally skipped files require a reason")
    missed = sorted(path for path, row in entries.items() if row.get("status") == "MISSED")
    if missed:
      failures.append(f"Primary coverage remains incomplete: {', '.join(missed)}")
  elif coverage != {"status": PRIMARY_NA}:
    failures.append("Coverage must be N-A when primary is disabled")

  findings = evidence["findings"]
  uids = Counter(row.get("uid") for row in findings)
  if any(not uid or count != 1 for uid, count in uids.items()):
    failures.append("Every report finding must have a unique stable UID")
  members = [item for row in findings for item in (row, *row.get("member_findings", []))]
  seen = Counter((row.get("group_id"), row.get("id")) for row in members)
  groups = evidence.get("groups", [])
  inventory = Counter((group["id"], item) for group in groups for item in group["finding_ids"])
  if (seen != inventory or any(not item or count != 1 for (_, item), count in seen.items())
      or len({row.get("id") for row in members}) != len(members)
      or Counter(row.get("group_id") for row in findings) != Counter(group["id"] for group in groups)):
    failures.append("Every group needs one report finding and every finding ID must be retained exactly once")
  for row in evidence.get("verification", {}).values():
    if row.get("verdict") not in VERDICTS:
      failures.append(f"Finding {row.get('finding_id')} has an invalid verification verdict")
  for item in members:
    finding_id = item.get("id")
    bucket = item.get("bucket")
    if bucket not in BUCKETS:
      failures.append(f"Finding {finding_id} does not have exactly one valid bucket")
    if item.get("verdict") is not None and item["verdict"] not in VERDICTS:
      failures.append(f"Finding {finding_id} has an invalid verdict")
    if (item.get("action") not in {"auto-fix", "ask-user", "no-op"} or not item.get("action_reason")
        or item.get("effective_severity") not in SEVERITIES):
      failures.append(f"Finding {finding_id} has invalid severity or action metadata")
    if bucket == "Must Fix" and not strict_passthrough(item):
      proof = evidence.get("verification", {}).get(finding_id) or evidence.get("baselines", {}).get(item.get("group_id"), {})
      if not release_gate(proof, security_calibrated=item.get("security_calibrated") is True):
        failures.append(f"Must Fix finding {finding_id} fails the release gate")

  buckets = Counter(row.get("bucket") for row in findings)
  anchors = Counter(row.get("location", {}).get("status") for row in findings)
  counts = {"files": len(paths), "findings": len(findings),
            "buckets": {key: buckets[key] for key in BUCKETS},
            "anchors": {key: anchors[key] for key in ANCHOR_STATES}}
  if evidence.get("counts") != counts or set(anchors) - set(ANCHOR_STATES):
    failures.append("Header counts differ from the finding, file, bucket, or anchor inventory")
  return failures
