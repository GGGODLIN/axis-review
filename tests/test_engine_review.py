import json
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from axis_review import report
from axis_review.agent_loop import AxisError, run_json, validate
from axis_review.anchors import Anchor, finding_uid, reanchor
from axis_review.config import Axis, Config, Endpoint, Model
from axis_review.github import ChangedFile, PR
from axis_review.llm import UNAVAILABLE
from axis_review.prompts import INITIAL_SCHEMA
from axis_review.review import (
  BUCKETS, _adjudicate, _collect, _match, _prepare_findings, _spec_context, _verify,
  chunk_files, classify, coverage_for, cross_model, is_source, run_review,
)
from axis_review.selfcheck import check


PROOF = {"corrected_severity": None, "severity_reason": "No change", "evidence": "src.py:1 read",
         "queries": ["source"], "scope_quote": None, "unverified_premises": [], "repro_path": None,
         "ships_breakage": False, "hypothetical": False, "fix_is_local": False,
         "security_facts": None, "security_matrix_severity": None}


def changed(path, size=1, patch="@@ -0,0 +1 @@\n+value = 1"):
  return ChangedFile(path, "modified", size, 0, patch)


def pull(files, description="Scope text\n", commit_messages=()):
  return PR("owner", "repo", 7, "A change", "author", "a" * 40, "b" * 40, files,
            description, commit_messages)


def finding(root_cause="root cause", **changes):
  return dict({"severity": "MEDIUM", "title": "Unexpected value", "root_cause": root_cause,
               "file": "src.py", "line_start": 1, "line_end": 1, "enclosing_symbol": None,
               "problem": "The value has the wrong default.", "impact": "The caller sees the default.",
               "fix": "Preserve the configured value.", "anchor": "value = 1", "evidence": "src.py:1",
               "queries": [], "strict_liability": None, "security_facts": None}, **changes)


def verdict(item, status="CONFIRMED", **changes):
  return dict(PROOF, finding_id=item, verdict=status, blind_spot_explanation=None) | changes


def config(*axes, **options):
  return Config({"test": Endpoint("http://127.0.0.1/v1")},
                tuple(Axis("test", f"requested-{axis}", axis) for axis in axes),
                {"for_primary": Model("test", "primary-judge"), "for_diff_axes": Model("test", "diff-judge")},
                **options)


class ScriptedClient:
  def __init__(self, settings, script):
    self.config = settings
    self.script = script
    self.calls = []
    self.records = []

  def chat(self, **kwargs):
    self.calls.append(dict(kwargs, messages=list(kwargs["messages"])))
    user = kwargs["messages"][1]["content"]
    data = json.loads(user) if user != "input" else {}
    result, model = self.script(kwargs["phase"], kwargs["axis"], data)
    payload = result if isinstance(result, str) else json.dumps(result)
    return {"choices": [{"message": {"content": payload}}]}, SimpleNamespace(model_observed=model)


class AnchorsTests(unittest.TestCase):
  def test_exact_normalized_ambiguous_failed_and_none(self):
    source = "start\n  value = 1\nnext\nstart\n  value = 1\nend\n"
    self.assertEqual(reanchor(source, "  value = 1\nnext", 5), Anchor("exact", 2, 3))
    self.assertEqual(reanchor(source, "value  = 1\nnext", 1), Anchor("normalized", 2, 3))
    self.assertEqual(reanchor(source, "start\n  value = 1", 5), Anchor("ambiguous", 4, 5))
    self.assertEqual(reanchor(source, "  value = 1", 6), Anchor("ambiguous", 5, 5))
    self.assertEqual(reanchor(source, "absent", 1), Anchor("FAILED"))
    self.assertEqual(reanchor(source, "<none>", 1), Anchor("<none>"))

  def test_manual_anchor_requires_reported_symbol_and_line(self):
    row = finding(anchor="<none>", enclosing_symbol="<module>")
    validate({"findings": [row]}, INITIAL_SCHEMA)
    for field in ("line_start", "enclosing_symbol"):
      with self.subTest(field=field), self.assertRaisesRegex(AxisError, field):
        validate({"findings": [{**row, field: None}]}, INITIAL_SCHEMA)

  def test_uid_uses_root_cause(self):
    from hashlib import sha256

    expected = sha256(b"src.py\0value = 1\0shared default").hexdigest()[:20]
    first, second = finding(" Shared  Default "), finding("shared default", title="Different words")
    self.assertEqual([finding_uid(row["file"], row["anchor"], row["root_cause"]) for row in (first, second)],
                     [expected, expected])
    self.assertNotEqual(finding_uid("src.py", "value = 1", "unrelated"), expected)


class CoverageTests(unittest.TestCase):
  def test_source_budget_and_oversized_file(self):
    files = [*(changed(f"src/{index:02d}.py", 30) for index in range(16)),
             *(changed(f"docs/{index:02d}.md", 5) for index in range(17)),
             changed("package-lock.json", 1), changed("wide.py", 801), changed("z.py", 2)]
    chunks = chunk_files(files[::-1])
    self.assertEqual(Counter(row.path for chunk in chunks for row in chunk), Counter(row.path for row in files))
    self.assertEqual([row.path for chunk in chunks for row in chunk], sorted(row.path for row in files))
    self.assertEqual(sum(is_source(row) for row in chunks[0]), 15)
    self.assertGreater(len(chunks[0]), 15)
    self.assertIn([changed("wide.py", 801)], chunks)
    for chunk in chunks:
      self.assertLessEqual(sum(is_source(row) for row in chunk), 15)
      if len(chunk) > 1:
        self.assertLessEqual(sum(row.additions + row.deletions for row in chunk), 800)

  def test_coverage_overrides_no_issues_and_respects_ownership(self):
    files = [changed(path) for path in ["a", "b", "c", "d"]]
    initial = ({"a", "b"}, {"findings": [{"file": "a"}, {"file": "c"}], "coverage": [
      {"file": "a", "status": "REVIEWED_NO_ISSUES", "reason": None},
      {"file": "b", "status": "INTENTIONALLY_SKIPPED", "reason": "Generated"},
      {"file": "outside", "status": "REVIEWED_NO_ISSUES", "reason": None},
    ]})
    self.assertEqual(coverage_for(files, [initial])["counts"],
                     {"covered": 1, "REVIEWED_NO_ISSUES": 0, "INTENTIONALLY_SKIPPED": 1, "MISSED": 2})
    repair = ({"c", "d"}, {"findings": [], "coverage": [
      {"file": "c", "status": "REVIEWED_NO_ISSUES", "reason": None},
      {"file": "d", "status": "INTENTIONALLY_SKIPPED", "reason": None},
    ]})
    result = coverage_for(files, [initial, repair])
    self.assertEqual(set(result["files"]), {"a", "b", "c", "d"})
    self.assertEqual(result["counts"], {"covered": 1, "REVIEWED_NO_ISSUES": 1,
                                       "INTENTIONALLY_SKIPPED": 1, "MISSED": 1})
    self.assertEqual(result["files"]["d"]["status"], "MISSED")

  def test_repair_only_reviews_missed_files_and_verifies_new_findings(self):
    def script(phase, axis, data):
      if phase == "initial":
        self.assertEqual([row["path"] for row in data["changed_files"]], ["docs.md", "src.py"])
        return {"findings": [], "coverage": [{"file": "docs.md", "status": "REVIEWED_NO_ISSUES", "reason": None}]}, "reviewer"
      if phase == "coverage_repair":
        self.assertEqual([row["path"] for row in data["changed_files"]], ["src.py"])
        return {"findings": [finding()], "coverage": []}, "repairer"
      self.assertEqual((phase, axis), ("verify", "for_primary"))
      self.assertEqual([row["file"] for row in data["findings"]], ["src.py"])
      return {"verdicts": [verdict(data["findings"][0]["id"])]}, "checker"

    client = ScriptedClient(config("primary"), script)
    with tempfile.TemporaryDirectory() as work:
      root = Path(work)
      (root / "src.py").write_text("value = 1\n", encoding="utf-8")
      evidence = _collect(pull([changed("src.py"), changed("docs.md")]), root, client)
    self.assertEqual([call["phase"] for call in client.calls], ["initial", "coverage_repair", "verify"])
    self.assertEqual(evidence["coverage"]["counts"], {"covered": 1, "REVIEWED_NO_ISSUES": 1,
                                                     "INTENTIONALLY_SKIPPED": 0, "MISSED": 0})
    self.assertEqual(evidence["findings"][0]["model_observed"], "repairer")

  def test_spec_material_uses_tracked_globs_and_discloses_character_budget(self):
    with tempfile.TemporaryDirectory() as work:
      root = Path(work)
      subprocess.run(["git", "init", "--quiet", "--template="], cwd=root, check=True)
      (root / "spec").mkdir()
      (root / "spec" / "first.md").write_bytes(b"abcd\r\nefgh")
      (root / "spec" / "second.md").write_bytes(b"second")
      (root / "spec" / "untracked.md").write_bytes(b"untracked")
      subprocess.run(["git", "add", "spec/first.md", "spec/second.md"], cwd=root, check=True)
      ctx = _spec_context(pull([]), root, config("primary", spec_globs=("spec/*.md",), spec_max_chars=7))
    self.assertEqual(ctx["description"], "Scope text\n")
    self.assertEqual(ctx["files"], [{"path": "spec/first.md", "text": "abcd\r\ne"}])
    self.assertEqual(len(ctx["notes"]), 2)
    self.assertIn("truncated", ctx["notes"][0])
    self.assertIn("omitted", ctx["notes"][1])


class GroupAndVerificationTests(unittest.TestCase):
  def test_nonoverlapping_lines_in_a_shared_hunk_are_corroborated(self):
    first = dict(finding(), axis="primary")
    second = dict(finding(anchor="other = 2", line_start=3, line_end=3), axis="neutral")
    diff = "@@ -1,3 +1,3 @@\n+value = 1\n unchanged\n+other = 2"
    runs = [{"reply": {"findings": [first, second]}}]
    with tempfile.TemporaryDirectory() as work:
      root = Path(work)
      (root / "src.py").write_text("value = 1\nunchanged\nother = 2\n", encoding="utf-8")
      findings = _prepare_findings(root, runs, [changed("src.py", patch=diff)])
    client = ScriptedClient(config("primary", "neutral"), lambda *args: self.fail("No candidate match expected"))
    groups, state = _match(client, Path.cwd(), findings, {"description": "Scope text\n", "files": []})
    self.assertEqual(state["state"], "N-A")
    self.assertEqual([group["corroborated_ids"] for group in groups], [["finding-1"], ["finding-2"]])
    self.assertFalse(any(group["consensus"] for group in groups))

  def test_same_issue_consensus_distinct_issue_same_hunk_corroboration(self):
    findings = [dict(finding(), id=identifier, axis=axis) for identifier, axis in
                (("p", "primary"), ("n", "neutral"), ("a", "adversarial"))]

    def script(phase, axis, data):
      if phase == "match":
        self.assertEqual(data["spec"]["description"], "Scope text\n")
        self.assertEqual([[row["id"] for row in group] for group in data["candidates"]], [["p", "n", "a"]])
        return {"groups": [["n", "p"], ["a"]]}, "matcher"
      if phase == "baseline":
        row = dict(PROOF, group_id=data["groups"][0]["group_id"], scope="in-scope", convention="supports")
        return {"baselines": [row]}, "baseline-model"
      self.assertEqual([(row["id"], row["lone"]) for row in data["findings"]], [("a", False)])
      return {"verdicts": [verdict("a", "PARTIAL")]}, "verifier"

    client = ScriptedClient(config("primary", "neutral", "adversarial"), script)
    groups, state = _match(client, Path.cwd(), findings, {"description": "Scope text\n", "files": []})
    self.assertEqual(state["state"], "PASS")
    self.assertEqual([(row["finding_ids"], row["consensus"], row["corroborated_ids"]) for row in groups],
                     [(["p", "n"], True, ["p", "n"]), (["a"], False, ["a"])])
    verification, baselines, batches = _verify(client, Path.cwd(), pull([]), {"description": "", "files": []},
                                                findings, groups, 3)
    self.assertEqual(set(verification), {"a"})
    self.assertEqual(set(baselines), {groups[0]["id"]})
    self.assertTrue(all(row["state"] == "PASS" for row in batches))

  def test_strict_liability_skips_matching_and_verification(self):
    def script(phase, axis, data):
      raise AssertionError(f"Unexpected {phase} call")

    client = ScriptedClient(config("neutral"), script)
    row = dict(finding(strict_liability="hardcoded_secret"), id="one", axis="neutral")
    groups, _ = _match(client, Path.cwd(), [row], {"description": "", "files": []})
    verifications, baselines, batches = _verify(client, Path.cwd(), pull([]), {"description": "", "files": []},
                                                 [row], groups, 1)
    self.assertEqual((verifications, baselines, batches, client.calls), ({}, {}, [], []))
    row = _adjudicate([row], groups, verifications, baselines, 1)[0]
    self.assertEqual(row["bucket"], "Must Fix")
    self.assertEqual(row["verification_status"], "SKIPPED (strict-liability passthrough)")
    self.assertEqual(row["evidence"], "src.py:1")

  def test_verifier_batch_id_mismatch_has_no_repair_and_later_batch_runs(self):
    findings = [dict(finding(), id=identifier, axis="neutral") for identifier in ("one", "two", "three")]
    given = []

    def script(phase, axis, data):
      ids = [item["id"] for item in data["findings"]]
      given.append(ids)
      return {"verdicts": [verdict("one"), verdict("one")] if len(ids) == 2 else [verdict("three")]}, "checker"

    client = ScriptedClient(config("neutral", verify_batch_size=2), script)
    rows, _, batches = _verify(client, Path.cwd(), pull([]), {"description": "", "files": []}, findings, [], 1)
    self.assertEqual(given, [["one", "two"], ["three"]])
    self.assertEqual(len(client.calls), 2)
    self.assertEqual([row["state"] for row in batches], ["FAILED", "PASS"])
    self.assertEqual([rows[item]["verdict"] for item in ("one", "two", "three")],
                     ["INCONCLUSIVE", "INCONCLUSIVE", "CONFIRMED"])
    self.assertIn("ID multiset", rows["one"]["error"])

  def test_invalid_consensus_baseline_keeps_both_findings(self):
    findings = [dict(finding(), id=identifier, axis=axis) for identifier, axis in (("p", "primary"), ("n", "neutral"))]
    group = {"id": "g", "finding_ids": ["p", "n"], "consensus": True, "corroborated_ids": ["p", "n"]}
    row = dict(PROOF, group_id="g", scope="OUT_OF_SCOPE", convention="supports", scope_quote="Invented quote")
    client = ScriptedClient(config("primary", "neutral"), lambda *args: ({"baselines": [row]}, "checker"))
    verification, baselines, batches = _verify(client, Path.cwd(), pull([]), {"description": "Scope text", "files": []},
                                                findings, [group], 2)
    self.assertEqual(len(client.calls), 1)
    self.assertEqual(verification, {})
    self.assertEqual(batches[0]["state"], "FAILED")
    self.assertEqual(baselines["g"]["state"], "INCOMPLETE")
    self.assertIn("verbatim quote", baselines["g"]["error"])
    rows = _adjudicate(findings, [group], verification, baselines, 2)
    self.assertEqual([(item["id"], item["bucket"], item["verification_status"]) for item in rows],
                     [(key, "Should Fix", "CONSENSUS (baseline incomplete)") for key in ("p", "n")])

  def test_verifier_does_not_repair_malformed_json(self):
    client = ScriptedClient(config("neutral"), lambda phase, axis, data: ("not JSON", "claimed"))
    with self.assertRaisesRegex(AxisError, "malformed JSON"):
      run_json(client, phase="verify", axis="neutral", endpoint="test", model="x", system="rules",
               user="input", schema=INITIAL_SCHEMA, tools=False)
    self.assertEqual(len(client.calls), 1)

  def test_tool_loop_answers_from_checkout_and_disables_tools_on_last_turn(self):
    calls = []
    tool = {"id": "read-1", "type": "function",
            "function": {"name": "read_file", "arguments": '{"path":"src.py"}'}}

    def chat(**kwargs):
      calls.append(kwargs)
      if len(calls) == 1:
        self.assertIsNotNone(kwargs["tools"])
        self.assertIsNone(kwargs["response_format"])
        return {"choices": [{"message": {"tool_calls": [tool]}}]}, None
      self.assertIsNone(kwargs["tools"])
      self.assertEqual(kwargs["response_format"], {"type": "json_object"})
      self.assertEqual(kwargs["messages"][-1], {"role": "tool", "tool_call_id": "read-1", "content": "1: value = 1"})
      return {"choices": [{"message": {"content": '{"findings": []}'}}]}, None

    client = SimpleNamespace(config=config("neutral", max_tool_turns=1), chat=chat)
    with tempfile.TemporaryDirectory() as work:
      root = Path(work)
      (root / "src.py").write_text("value = 1\n", encoding="utf-8")
      reply = run_json(client, phase="verify", axis="neutral", endpoint="test", model="x", system="rules",
                       user="input", schema=INITIAL_SCHEMA, tools=True, root=root)
    self.assertEqual(reply, {"findings": []})
    self.assertEqual(len(calls), 2)

  def test_initial_loop_retries_invalid_schema_and_keeps_final_model(self):
    outputs = iter([({"findings": [{"severity": "INVALID"}]}, "first"), ('```json\n{"findings": []}\n```', "last")])
    client = ScriptedClient(config("neutral"), lambda *args: next(outputs))
    response = run_json(client, phase="initial", axis="neutral", endpoint="test", model="x", system="rules",
                        user="input", schema=INITIAL_SCHEMA, tools=False)
    self.assertEqual(response, {"findings": []})
    self.assertEqual(len(client.calls), 2)
    self.assertEqual(client.calls[1]["response_format"], {"type": "json_object"})
    self.assertIn("schema", client.calls[1]["messages"][-1]["content"])


class TriageTests(unittest.TestCase):
  def test_lone_rule_with_single_axis_and_blind_spot(self):
    initial = finding(severity="HIGH")
    partial = verdict("x", "PARTIAL")
    self.assertEqual(classify(initial, partial, ran_axes=1)["effective_severity"], "HIGH")
    self.assertEqual(classify(initial, partial, ran_axes=2)["effective_severity"], "MEDIUM")
    self.assertEqual(classify(initial, partial, ran_axes=2, corroborated=True)["effective_severity"], "HIGH")
    self.assertEqual(classify(initial, partial | {"blind_spot_explanation": "Other axis lacked caller context"},
                              ran_axes=2)["effective_severity"], "HIGH")
    self.assertEqual(classify(initial, verdict("x"), ran_axes=2)["effective_severity"], "HIGH")

  def test_observed_cross_model_checks(self):
    finding_row = dict(finding(), model="requested-finder", model_observed="actual")
    proof = verdict("x", repro_path="Open the normal view", ships_breakage=True)
    self.assertEqual(cross_model("actual", "actual"), "SAME")
    self.assertEqual(cross_model("actual", UNAVAILABLE), UNAVAILABLE)
    self.assertEqual(cross_model(None, "actual"), UNAVAILABLE)
    for observed, expected in ((UNAVAILABLE, "Nice to Have"), ("actual", "Nice to Have"), ("other", "Must Fix")):
      with self.subTest(observed=observed):
        self.assertEqual(classify(finding_row, proof | {"model_observed": observed})["bucket"], expected)

  def test_auto_fix_is_advisory_and_requires_a_supported_local_fix(self):
    initial = finding(severity="HIGH", model_observed="finder")
    proof = verdict("x", fix_is_local=True, model_observed="verifier")
    self.assertEqual(classify(initial, proof)["action"], "auto-fix")
    self.assertEqual(classify(initial, proof | {"hypothetical": True})["action"], "ask-user")
    self.assertEqual(classify(initial, proof | {"unverified_premises": ["Unknown caller"]})["action"], "ask-user")
    self.assertEqual(classify(initial, proof | {"verdict": "REFUTED"})["action"], "no-op")

  def test_bucket_order_and_exclusivity(self):
    statuses = [("refuted", "REFUTED", "MEDIUM"), ("nice", "INCONCLUSIVE", "MEDIUM"),
                ("should", "PARTIAL", "MEDIUM"), ("must", "CONFIRMED", "CRITICAL")]
    findings = [dict(finding(severity=severity), id=identifier, axis="neutral")
                for identifier, _, severity in statuses]
    groups = [{"id": identifier, "finding_ids": [identifier], "consensus": False, "corroborated_ids": []}
              for identifier, _, _ in statuses]
    verification = {identifier: verdict(identifier, status, repro_path="ordinary flow", ships_breakage=True)
                    for identifier, status, _ in statuses}
    result = _adjudicate(findings, groups, verification, {}, 1)
    self.assertEqual(tuple(row["bucket"] for row in result), BUCKETS)
    self.assertEqual([row["id"] for row in result], ["must", "should", "nice", "refuted"])
    must = verification["must"]
    critical = finding(severity="CRITICAL")
    self.assertEqual(classify(critical, must | {"hypothetical": True})["bucket"], "Should Fix")
    self.assertEqual(classify(critical, must | {"security_matrix_severity": "LOW"})["effective_severity"], "LOW")
    self.assertEqual(classify(finding(), must | {"security_matrix_severity": "HIGH"})["effective_severity"], "MEDIUM")


class PublicationTests(unittest.TestCase):
  def test_selfcheck_reports_missed_file_after_coverage_repair(self):
    def script(phase, axis, data):
      self.assertIn(phase, {"initial", "coverage_repair"})
      return {"findings": [], "coverage": []}, "reviewer"

    client = ScriptedClient(config("primary"), script)
    with tempfile.TemporaryDirectory() as work:
      evidence = _collect(pull([changed("src.py")]), Path(work), client)
    self.assertEqual([call["phase"] for call in client.calls], ["initial", "coverage_repair"])
    self.assertEqual(evidence["coverage"]["files"]["src.py"]["status"], "MISSED")
    self.assertEqual(check(evidence, ("primary",)), ["Primary coverage remains incomplete: src.py"])

  def test_run_review_receipts_quote_drift_and_selfcheck_output(self):
    pr = pull([changed("src.py"), changed("docs.md", patch=None)])
    settings = config("neutral")
    settings.endpoints["receipted"] = Endpoint("http://127.0.0.1/v1", receipts="phala-aci")

    def script(phase, axis, data):
      self.assertEqual(data["spec"]["description"], "Scope text\n")
      if phase == "initial":
        return {"findings": [finding()]}, "reviewer"
      return {"verdicts": [verdict("finding-1", "REFUTED")]}, "verifier"

    events = []

    def process(out_dir, endpoints, *, config):
      self.assertTrue((out_dir / "calls.jsonl").is_file())
      self.assertTrue((out_dir / "bodies").is_dir())
      self.assertEqual(endpoints, {"receipted": {"base_url": "http://127.0.0.1/v1", "api_key": None}})
      self.assertIs(config, settings)
      events.append("receipts")
      return {"fetched": 1, "verified": 1, "checks": {"signature": {"pass": 1}}}

    def quote(out_dir, *, config):
      self.assertIs(config, settings)
      evidence = json.loads((out_dir / "evidence.json").read_text(encoding="utf-8"))
      self.assertEqual(evidence["receipts"]["verified"], 1)
      self.assertEqual(evidence["drift"]["state"], "DRIFT")
      events.append("tee")
      return {"in_tee": True, "app_id": "synthetic"}

    with tempfile.TemporaryDirectory() as work:
      root = Path(work)
      (root / "src.py").write_text("value = 1\n", encoding="utf-8")
      (root / "checkout").mkdir()
      with (patch("axis_review.review.github.fetch_pr", return_value=pr),
            patch("axis_review.review.github.checkout", return_value=root),
            patch("axis_review.review.github.fetch_versions", return_value=(pr.base_sha, "c" * 40)),
            patch("axis_review.review.Client", return_value=ScriptedClient(settings, script)),
            patch("axis_review.receipts.process", side_effect=process),
            patch("axis_review.tee_quote.write_quote", side_effect=quote)):
        result = run_review(pr.url, settings, root / "output")
      output = (result.out_dir / "report.md").read_text(encoding="utf-8")
    self.assertEqual(events, ["receipts", "tee"])
    self.assertEqual(result.evidence["selfcheck_failures"], [])
    self.assertEqual(result.evidence["coverage"]["status"], "N-A (primary not selected)")
    for phrase in ("Version check DRIFT", "incomplete for every enabled axis", "Fetched 1 · Verified 1",
                   "Application quote saved", "## Reference", "REFUTED", "Deterministic self-check PASS"):
      self.assertIn(phrase, output)

    evidence = result.evidence
    evidence["coverage"] = {"status": "wrong"}
    evidence["axes"]["neutral"]["state"] = "PENDING"
    evidence["verification"]["finding-1"]["verdict"] = "UNKNOWN"
    evidence["findings"][0]["bucket"] = "Must Fix"
    failures = check(evidence, ("neutral",))
    self.assertEqual(len(failures), 5)
    evidence["selfcheck_failures"] = failures
    output = report.render(evidence, {"in_tee": False})
    for reason in ("Coverage must be", "has no final state", "invalid verification verdict",
                   "fails the release gate", "Header counts differ"):
      self.assertIn(reason, output)
