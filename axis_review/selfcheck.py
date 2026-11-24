from collections import Counter

from .prompts import SEVERITIES, STRICT_LIABILITY, VERDICTS


BUCKETS = ("Must Fix", "Should Fix", "Nice to Have", "Reference")
PRIMARY_NA = "N-A (primary not selected)"
COVERAGE_STATES = ("covered", "REVIEWED_NO_ISSUES", "INTENTIONALLY_SKIPPED", "MISSED")
ANCHOR_STATES = ("exact", "normalized", "ambiguous", "FAILED", "<none>")


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
  seen = Counter(row.get("id") for row in findings)
  groups = Counter(item for group in evidence.get("groups", []) for item in group["finding_ids"])
  if None in seen or any(count != 1 for count in seen.values()) or seen != groups:
    failures.append("Every finding ID must appear once in the report and once in the group inventory")
  for row in evidence.get("verification", {}).values():
    if row.get("verdict") not in VERDICTS:
      failures.append(f"Finding {row.get('finding_id')} has an invalid verification verdict")
  for item in findings:
    finding_id = item.get("id")
    bucket = item.get("bucket")
    if bucket not in BUCKETS:
      failures.append(f"Finding {finding_id} does not have exactly one valid bucket")
    if item.get("verdict") is not None and item["verdict"] not in VERDICTS:
      failures.append(f"Finding {finding_id} has an invalid verdict")
    if (item.get("action") not in {"auto-fix", "ask-user", "no-op"} or not item.get("action_reason")
        or item.get("effective_severity") not in SEVERITIES):
      failures.append(f"Finding {finding_id} has invalid severity or action metadata")
    if (bucket == "Must Fix" and item.get("strict_liability") not in STRICT_LIABILITY
        and (not item.get("repro_path") or item.get("ships_breakage") is not True or item.get("hypothetical"))):
      failures.append(f"Must Fix finding {finding_id} fails the release gate")

  buckets = Counter(row.get("bucket") for row in findings)
  anchors = Counter(row.get("location", {}).get("status") for row in findings)
  counts = {"files": len(paths), "findings": len(findings),
            "buckets": {key: buckets[key] for key in BUCKETS},
            "anchors": {key: anchors[key] for key in ANCHOR_STATES}}
  if evidence.get("counts") != counts or set(anchors) - set(ANCHOR_STATES):
    failures.append("Header counts differ from the finding, file, bucket, or anchor inventory")
  return failures
