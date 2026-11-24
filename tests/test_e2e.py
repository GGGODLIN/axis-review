import hashlib
import io
import json
import tempfile
import threading
import time
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from axis_review import cli, github, receipts, tee_quote
from axis_review.config import Axis, Config, Endpoint, Model
from axis_review.review import run_review


SOURCE = ("default = 'café'\npassword_check = 'legacy'\nretry_count = 3\nlabel = 'Ready'\n"
          "notifications_enabled = False\n")
BASE_SOURCE = SOURCE.replace("retry_count = 3", "retry_count = 1").replace(
  "notifications_enabled = False", "notifications_enabled = True",
)
FILES = {"src.py": SOURCE, "docs/scope.md": "# Scope\n\nReview the settings change.\n",
         "generated/table.txt": "Generated table\n"}
DESCRIPTION = "Review the settings change.\n\nKeep the display label.\n"
BUCKETS = ("Must Fix", "Should Fix", "Nice to Have", "Reference")


def fixture_pr(root):
  def git(*args):
    return github._git(list(args), root, {
      "user.name": "Fixture", "user.email": "fixture@example.invalid",
    }).decode().strip()

  root.mkdir()
  git("init", "--quiet", "--template=")
  (root / "src.py").write_text(BASE_SOURCE, encoding="utf-8")
  git("add", "src.py")
  base = git("commit-tree", git("write-tree"), "-m", "Prior settings")
  (root / "src.py").write_text(SOURCE, encoding="utf-8")
  git("add", "src.py")
  middle = git("commit-tree", git("write-tree"), "-p", base, "-m", "Update settings")
  for path, text in FILES.items():
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
  git("add", "--", *FILES)
  head = git("commit-tree", git("write-tree"), "-p", middle, "-m", "Document settings")
  git("update-ref", "HEAD", head)
  files = [github.ChangedFile(path, "modified" if path == "src.py" else "added", additions, deletions,
                            git("diff", base, head, "--", path))
           for path, additions, deletions in (("src.py", 2, 2), ("docs/scope.md", 3, 0), ("generated/table.txt", 1, 0))]
  return github.PR("fixture", "settings", 7, "Settings revision", "fixture", base, head, files,
                   DESCRIPTION, ({"sha": middle, "message": "Update settings"},
                                 {"sha": head, "message": "Document settings"}))


def finding(title, line, problem, *, category=None):
  return {"severity": "HIGH", "title": title, "root_cause": title, "file": "src.py",
          "line_start": line, "line_end": line, "enclosing_symbol": None,
          "problem": problem, "impact": "Settings could differ from the expected values.",
          "fix": "Use the documented setting.", "anchor": SOURCE.splitlines()[line - 1],
          "evidence": f"Initial read of src.py:{line}", "queries": [],
          "strict_liability": category, "security_facts": None}


def verdict(item, status, evidence):
  return {"finding_id": item["id"], "verdict": status, "evidence": evidence, "queries": ["settings"],
          "corrected_severity": None, "severity_reason": "Original severity retained.", "scope_quote": None,
          "scope_source": None, "scope_explanation": None, "confirmed_claim": None,
          "repro_path": None, "repro_path_verified": False, "ships_breakage": False, "hypothetical": False, "fix_is_local": False,
          "unverified_premises": [], "blind_spot_explanation": None, "security_facts": None,
          "security_matrix_severity": None}


def tool_request(name, arguments):
  return {"content": None, "tool_calls": [{"id": f"call-{name}", "type": "function",
                                           "function": {"name": name, "arguments": json.dumps(arguments)}}]}


def scripted_message(request):
  role = request["model"]
  messages = request["messages"]
  data = json.loads(messages[1]["content"])
  if role == "primary":
    if len(messages) == 2:
      return tool_request("read_file", {"path": "src.py", "start_line": 1, "end_line": 1})
    output = {"findings": [finding("Default changed unexpectedly", 1, "The default is empty."),
                           finding("Legacy credential check", 2, "The fixture categorizes this check as plaintext.",
                                   category="plaintext_password_compare"),
                           finding("Notifications disabled by default", 5, "The default disables notifications.")],
              "coverage": [{"file": "docs/scope.md", "status": "REVIEWED_NO_ISSUES", "reason": None},
                           {"file": "generated/table.txt", "status": "INTENTIONALLY_SKIPPED",
                            "reason": "Generated output"}]}
  elif role == "neutral":
    output = {"findings": [finding("Retry setting is unsupported", 3, "The configured retry count lacks support."),
                           finding("Label spelling differs", 4, "The displayed label differs from its specification."),
                           finding("Notifications disabled by default", 5, "The change turns notifications off.")]}
  elif role == "adversarial":
    output = {"findings": []}
  elif role == "primary-verifier":
    if len(messages) == 2:
      return tool_request("grep", {"pattern": "default", "glob": "*.py"})
    output = {"verdicts": [verdict(data["findings"][0], "REFUTED", "src.py:1 contains a nonempty default.")]}
  elif role == "diff-verifier":
    if "Partition the supplied findings" in messages[0]["content"]:
      groups = {}
      for item in data["findings"]:
        groups.setdefault(item["root_cause"], []).append(item["id"])
      output = {"groups": list(groups.values())}
    elif "groups" in data:
      group, = data["groups"]
      output = {"baselines": [{
        "group_id": group["group_id"], "convention": "conflicts", "scope": "in-scope",
        "evidence": "src.py:5 disables notifications by default.", "queries": ["notifications_enabled"],
        "scope_quote": None, "scope_source": None, "scope_explanation": None, "unverified_premises": [],
        "repro_path": "Start with default settings and check notifications.", "repro_path_verified": True,
        "ships_breakage": True, "hypothetical": False, "fix_is_local": True,
        "corrected_severity": None, "severity_reason": "Original severity retained.",
        "security_facts": None, "security_matrix_severity": None,
      }]}
    else:
      item, = data["findings"]
      if item["line_start"] == 3:
        if len(messages) == 2:
          return tool_request("read_file", {"path": "src.py", "ref": "base", "start_line": 3, "end_line": 3})
        if messages[-1]["tool_call_id"] == "call-read_file":
          return tool_request("pr_commits", {"path": "src.py"})
        if messages[-1]["tool_call_id"] == "call-pr_commits":
          sha = messages[-1]["content"].splitlines()[0]
          return tool_request("show_commit_patch", {"sha": sha, "path": "src.py"})
        return {"content": "{malformed final JSON"}
      proof = verdict(item, "PARTIAL", "src.py:4 defines the label for one code path.")
      proof["confirmed_claim"] = "The alternate settings view is the only view with the label mismatch."
      output = {"verdicts": [proof]}
  else:
    raise AssertionError("Unexpected model role")
  return {"content": json.dumps(output, ensure_ascii=False)}


def digest(data):
  return "sha256:" + hashlib.sha256(data).hexdigest()


def provider_handler(calls, attestations, message_for=scripted_message):
  signing_key = Ed25519PrivateKey.generate()
  keyset = {"not_after": int(time.time()) + 3600, "receipt_signing_keys": [
    {"key_id": "fixture", "algo": "ed25519",
     "public_key": signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()},
  ]}
  keyset_digest = digest(rfc8785.dumps(keyset))
  lock = threading.Lock()

  class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
      pass

    def send_json(self, raw, receipt_id=None):
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.send_header("Content-Length", str(len(raw)))
      if receipt_id:
        self.send_header("X-Receipt-Id", receipt_id)
      self.end_headers()
      self.wfile.write(raw)

    def do_POST(self):
      if self.path != "/v1/chat/completions":
        self.send_error(404)
        return
      request_bytes = self.rfile.read(int(self.headers["Content-Length"]))
      request = json.loads(request_bytes)
      message = message_for(request)
      with lock:
        response_id = f"chat-{len(calls) + 1}"
        receipt_id = f"receipt-{response_id}"
        response = {"id": response_id, "model": f"observed-{request['model']}",
                    "choices": [{"message": {"role": "assistant", **message}}], "usage": {"total_tokens": 5}}
        response_bytes = (json.dumps(response, ensure_ascii=False, indent=2) + "\n").encode()
        calls[receipt_id] = (request_bytes, response_bytes)
      self.send_json(response_bytes, receipt_id)

    def do_GET(self):
      url = urlsplit(self.path)
      if url.path == "/v1/aci/attestation":
        attestations.append(parse_qs(url.query)["nonce"][0])
        payload = {"workload_keyset_digest": keyset_digest, "attestation": {"workload_keyset": keyset}}
      elif url.path.startswith("/v1/aci/receipts/") and url.path.rsplit("/", 1)[1] in calls:
        request, response = calls[url.path.rsplit("/", 1)[1]]
        payload = {"receipt_id": url.path.rsplit("/", 1)[1], "key_id": "fixture",
                   "workload_keyset_digest": keyset_digest, "event_log": [
          {"type": "request.received", "body_hash": digest(request)},
          {"type": "response.returned", "body_hash": digest(response)},
          {"type": "upstream.verified", "result": "verified", "required": True},
        ]}
        payload["signature"] = signing_key.sign(rfc8785.dumps(payload)).hex()
      else:
        self.send_error(404)
        return
      self.send_json(json.dumps(payload).encode())

  return Handler


class EndToEndTests(unittest.TestCase):
  def test_review_with_checkout_tools_exact_bodies_and_receipts(self):
    calls, attestations = {}, []
    with (tempfile.TemporaryDirectory() as temporary,
          ThreadingHTTPServer(("127.0.0.1", 0), provider_handler(calls, attestations)) as server):
      work = Path(temporary)
      root = work / "checkout"
      pr = fixture_pr(root)
      out = work / "output"
      config = Config(
        {"local": Endpoint(f"http://127.0.0.1:{server.server_port}/v1", receipts="phala-aci")},
        tuple(Axis("local", role, role) for role in ("primary", "neutral", "adversarial")),
        {"for_primary": Model("local", "primary-verifier"), "for_diff_axes": Model("local", "diff-verifier")},
        verify_batch_size=1, spec_globs=("docs/*.md",),
      )
      thread = threading.Thread(target=server.serve_forever)
      thread.start()
      try:
        with (patch.object(github, "fetch_pr", return_value=pr) as fetch,
              patch.object(github, "checkout", return_value=root) as checkout,
              patch.object(github, "fetch_versions", return_value=(pr.base_sha, pr.head_sha)) as versions,
              patch.object(tee_quote, "DSTACK_SOCKET", work / "absent.sock")):
          result = run_review(pr.url, config, out)
      finally:
        server.shutdown()
        thread.join()

      fetch.assert_called_once_with(pr.url)
      self.assertEqual(checkout.call_args.args[0], pr)
      versions.assert_called_once_with(pr)
      self.assertEqual(result.out_dir, out)
      self.assertFalse(result.review_failed)
      self.assertIsNone(result.failure_reason)
      evidence = json.loads((out / "evidence.json").read_bytes())
      text = (out / "report.md").read_text(encoding="utf-8")
      headers = [line for line in text.splitlines() if line.startswith("## ")]
      self.assertEqual(headers, [f"## {name}" for name in (
        "Spec basis", "Per-file change and coverage", "Findings overview", *BUCKETS,
        "Consensus baselines", "Receipts and application quote", "Usage", "Limits and self-check",
      )])
      self.assertIn(f"Base `{pr.base_sha}` · Head `{pr.head_sha}`", text)
      self.assertIn("Version check UNCHANGED", text)
      self.assertIn("Deterministic self-check PASS.", text)
      self.assertEqual(evidence["selfcheck_failures"], [])
      self.assertEqual(evidence["spec"], {
        "description": DESCRIPTION, "files": [{"path": "docs/scope.md", "text": FILES["docs/scope.md"]}], "notes": [],
      })
      self.assertEqual({path: row["status"] for path, row in evidence["coverage"]["files"].items()}, {
        "src.py": "covered", "docs/scope.md": "REVIEWED_NO_ISSUES", "generated/table.txt": "INTENTIONALLY_SKIPPED",
      })
      self.assertEqual(set(evidence["coverage"]["files"]), set(FILES))
      self.assertEqual(evidence["coverage"]["counts"]["MISSED"], 0)

      sections = dict((heading.splitlines()[0], heading) for heading in text.split("\n## ")[1:])
      by_title = {row["title"]: row for row in evidence["findings"]}
      self.assertEqual(set(by_title), {"Default changed unexpectedly", "Legacy credential check",
                                      "Retry setting is unsupported", "Label spelling differs",
                                      "Notifications disabled by default"})
      for row in by_title.values():
        self.assertEqual([bucket for bucket in BUCKETS if f"UID `{row['uid']}`" in sections[bucket]], [row["bucket"]])
      self.assertIn("REFUTED", sections["Reference"])
      self.assertIn("The default is empty", sections["Reference"])
      self.assertIn("contains a nonempty default", sections["Reference"])
      self.assertEqual(by_title["Default changed unexpectedly"]["bucket"], "Reference")
      strict = by_title["Legacy credential check"]
      self.assertEqual(strict["bucket"], "Must Fix")
      self.assertEqual(strict["verification_status"], "SKIPPED (strict-liability passthrough)")
      self.assertNotIn(strict["id"], evidence["verification"])
      self.assertIn("SKIPPED", sections["Must Fix"])
      consensus = by_title["Notifications disabled by default"]
      self.assertEqual(consensus["bucket"], "Must Fix")
      self.assertEqual(set(consensus["axis_hits"]), {"primary", "neutral"})
      self.assertIs(evidence["baselines"][consensus["group_id"]]["repro_path_verified"], True)
      self.assertIn("Failure path Start with default settings and check notifications", sections["Must Fix"])
      failed = by_title["Retry setting is unsupported"]
      self.assertEqual(failed["verdict"], "INCONCLUSIVE")
      self.assertEqual(by_title["Label spelling differs"]["verdict"], "PARTIAL")
      detail = sections["Should Fix"].split(f"UID `{by_title['Label spelling differs']['uid']}`", 1)[1]
      comment = detail.split("```text", 1)[1].split("```", 1)[0]
      self.assertIn("The alternate settings view is the only view with the label mismatch.", comment)
      self.assertNotIn("The displayed label differs from its specification.", comment)
      batch, = [row for row in evidence["verification_batches"] if failed["id"] in row["ids"]]
      self.assertEqual((batch["state"], batch["error"]), ("FAILED", "Final message is malformed JSON"))
      self.assertIn(batch["error"], sections["Limits and self-check"])

      rows = [json.loads(line) for line in (out / "calls.jsonl").read_bytes().splitlines()]
      self.assertEqual(rows, evidence["calls"])
      self.assertEqual(Counter(row["receipt_id"] for row in rows), Counter(list(calls)))
      self.assertEqual({file.relative_to(out).as_posix() for file in (out / "bodies").iterdir()},
                       {row[key] for row in rows for key in ("req_path", "resp_path")})
      for row in rows:
        req, resp = calls[row["receipt_id"]]
        self.assertEqual((out / row["req_path"]).read_bytes(), req)
        self.assertEqual((out / row["resp_path"]).read_bytes(), resp)
        self.assertTrue({"request_bytes", "response_bytes"}.isdisjoint(row))
        self.assertEqual(row["model_observed"], json.loads(resp)["model"])
      requests = [json.loads(req) for req, _ in calls.values()]
      tool_results = {(req["model"], req["messages"][-1]["tool_call_id"]): req["messages"][-1]["content"]
                      for req in requests if req["messages"][-1]["role"] == "tool"}
      self.assertEqual(set(tool_results), {
        ("primary", "call-read_file"), ("primary-verifier", "call-grep"),
        ("diff-verifier", "call-read_file"), ("diff-verifier", "call-pr_commits"),
        ("diff-verifier", "call-show_commit_patch"),
      })
      self.assertEqual(tool_results["primary", "call-read_file"], "1: default = 'café'")
      self.assertEqual(tool_results["primary-verifier", "call-grep"], "src.py:1: default = 'café'")
      self.assertEqual(tool_results["diff-verifier", "call-read_file"], "3: retry_count = 1")
      middle = pr.commit_messages[0]["sha"]
      self.assertEqual(tool_results["diff-verifier", "call-pr_commits"], f"{middle}\nUpdate settings")
      commit_patch = tool_results["diff-verifier", "call-show_commit_patch"]
      self.assertEqual(commit_patch, next(file.patch for file in pr.files if file.path == "src.py") + "\n")
      failed_requests = [req for req in requests if req["model"] == "diff-verifier" and
                         [item["id"] for item in json.loads(req["messages"][1]["content"]).get("findings", [])]
                         == [failed["id"]]]
      self.assertEqual([req["messages"][-1]["role"] for req in failed_requests], ["user", "tool", "tool", "tool"])

      nonce, = attestations
      self.assertEqual(json.loads((out / "receipts/attestation-local.json").read_bytes())["nonce"], nonce)
      summary = evidence["receipts"]
      self.assertEqual(tuple(summary[key] for key in ("expected", "fetched", "verified", "missing")),
                       (len(rows), len(rows), len(rows), 0))
      self.assertIn(f"Expected {len(rows)} · Fetched {len(rows)} · Verified {len(rows)} · Missing 0",
                    sections["Receipts and application quote"])
      self.assertEqual(summary["checks"]["identity"]["pass"], len(rows))
      self.assertEqual(receipts.verify(out), summary)
      self.assertEqual(json.loads((out / "tee_quote.json").read_bytes()), {"in_tee": False})

  def test_review_cli_exits_nonzero_after_publishing_failed_report(self):
    def malformed_reply(_):
      return {"content": "{malformed initial JSON"}

    with (tempfile.TemporaryDirectory() as temporary,
          ThreadingHTTPServer(("127.0.0.1", 0), provider_handler({}, [], malformed_reply)) as server):
      work = Path(temporary)
      root = work / "checkout"
      pr = fixture_pr(root)
      config = work / "review.toml"
      config.write_text(f'''[endpoints.local]
base_url = "http://127.0.0.1:{server.server_port}/v1"
[[axes]]
id = "primary"
endpoint = "local"
model = "primary"
[verifiers]
for_primary = {{endpoint = "local", model = "primary-verifier"}}
''', encoding="utf-8")
      thread = threading.Thread(target=server.serve_forever)
      thread.start()
      try:
        with (patch.object(github, "fetch_pr", return_value=pr),
              patch.object(github, "checkout", return_value=root),
              patch.object(github, "fetch_versions", return_value=(pr.base_sha, pr.head_sha)),
              patch.object(tee_quote, "DSTACK_SOCKET", work / "absent.sock"),
              redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors):
          status = cli.main(["review", pr.url, "--config", str(config), "--out", str(work / "output")])
      finally:
        server.shutdown()
        thread.join()

      self.assertEqual(status, 1)
      report_path = work / "output" / "fixture--settings--pr-7" / "report.md"
      self.assertEqual(output.getvalue().splitlines(), [str(report_path)])
      evidence = json.loads(report_path.with_name("evidence.json").read_bytes())
      reason = "No initial axis produced a usable reply after repair."
      self.assertIs(evidence["review_failed"], True)
      self.assertEqual(evidence["failure_reason"], reason)
      self.assertEqual(Counter(call["phase"] for call in evidence["calls"]), {"initial": 2, "coverage_repair": 2})
      self.assertIn(f"**Review failed.** {reason.removesuffix('.')}", report_path.read_text(encoding="utf-8"))
      self.assertEqual(errors.getvalue().splitlines(), [f"fixture/settings#7: {reason}"])
