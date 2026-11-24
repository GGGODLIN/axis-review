import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from axis_review import github, report
from axis_review.cli import main
from axis_review.serve import OutputHandler
from axis_review.config import Axis, Config, Endpoint, Model, load_config
from axis_review.github import ChangedFile
from axis_review.llm import ChatError, Client, UNAVAILABLE
from axis_review.repo_tools import OUTPUT_LIMIT, TRUNCATED, execute
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class ConfigTests(unittest.TestCase):
  def config(self, *, endpoint="local", finder="finder", verifier="judge"):
    with tempfile.TemporaryDirectory() as work:
      path = Path(work) / "config.toml"
      path.write_text(f'''
[endpoints.local]
base_url = "http://127.0.0.1/v1/"
[[axes]]
id = "neutral"
endpoint = "{endpoint}"
model = "{finder}"
[verifiers]
for_diff_axes = {{endpoint = "local", model = "{verifier}"}}
''', encoding="utf-8")
      return load_config(path)

  def test_primary_optional(self):
    config = self.config()
    self.assertEqual(tuple(axis.id for axis in config.axes), ("neutral",))
    self.assertEqual(config.endpoints["local"].base_url, "http://127.0.0.1/v1")
    self.assertEqual(config.verifiers["for_diff_axes"].model, "judge")
    self.assertIsNone(config.endpoints["local"].api_key())

  def test_missing_endpoint(self):
    with self.assertRaisesRegex(ValueError, "undefined endpoint"):
      self.config(endpoint="unknown")

  def test_same_model_verifier_rejected(self):
    with self.assertRaisesRegex(ValueError, "different models"):
      self.config(verifier="finder")


class Server:
  def __init__(self, handler):
    self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    self.base = f"http://127.0.0.1:{self.server.server_port}"
    self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})

  def __enter__(self):
    self.thread.start()
    return self

  def __exit__(self, *error):
    self.server.shutdown()
    self.thread.join()
    self.server.server_close()


class TransportTests(unittest.TestCase):
  def test_exact_body_bytes_and_attempt_records_on_429_and_5xx(self):
    messages = [{"role": "user", "content": "試\n驗"}]
    bodies = [b'{"error":"retry"}\n', b'<temporarily unavailable>',
              b'\n {"usage":{"total_tokens":3},"model":"actual","id":"response"}\n']
    observed = []

    class Handler(BaseHTTPRequestHandler):
      def do_POST(self):
        index = len(observed)
        observed.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response((429, 503, 200)[index])
        if index == 0:
          self.send_header("Retry-After", "3")
        if index == 2:
          self.send_header("X-Receipt-ID", "receipt")
        self.end_headers()
        self.wfile.write(bodies[index])

      def log_message(self, *args):
        pass

    delays = []
    with Server(Handler) as server:
      config = Config({"local": Endpoint(server.base + "/v1")}, (), {})
      client = Client(config, sleep=delays.append)
      result, record = client.chat(phase="initial", axis="neutral", endpoint="local", model="requested",
                                   messages=messages, response_format={"type": "json_object"})
    sent = ('{"model":"requested","messages":[{"role":"user","content":"試\\n驗"}],'
            '"stream":false,"temperature":0,"response_format":{"type":"json_object"}}').encode()
    self.assertEqual(observed, [("/v1/chat/completions", sent)] * 3)
    self.assertEqual(delays, [3, 4])
    self.assertEqual([row.status for row in client.records], [429, 503, 200])
    self.assertEqual([row.response_bytes for row in client.records], bodies)
    self.assertEqual([row.model_observed for row in client.records], [UNAVAILABLE, UNAVAILABLE, "actual"])
    self.assertEqual((record.response_id, record.receipt_id, result["usage"]["total_tokens"]),
                     ("response", "receipt", 3))
    with tempfile.TemporaryDirectory() as work:
      root = Path(work)
      report.write_calls(root, client.records, config)
      rows = [json.loads(line) for line in (root / "calls.jsonl").read_bytes().splitlines()]
      self.assertEqual([row["seq"] for row in rows], [1, 2, 3])
      for row, body in zip(rows, bodies):
        self.assertEqual((root / row["req_path"]).read_bytes(), sent)
        self.assertEqual((root / row["resp_path"]).read_bytes(), body)
        self.assertNotIn("headers", row)

  def test_rejects_artifact_containing_environment_credential(self):
    with tempfile.TemporaryDirectory() as work, patch.dict(os.environ, {"TEST_AXIS_KEY": "synthetic-test-marker"}):
      root = Path(work)
      config = Config({"local": Endpoint("http://127.0.0.1", "TEST_AXIS_KEY")}, (), {})
      with self.assertRaisesRegex(ValueError, "environment credential"):
        report.write_evidence(root, {"echo": os.environ["TEST_AXIS_KEY"]}, config)
      self.assertEqual(list(root.iterdir()), [])
      client = Client(config)
      with self.assertRaisesRegex(ChatError, "environment credential"):
        client.chat(phase="initial", axis="neutral", endpoint="local", model="finder",
                    messages=[{"role": "user", "content": os.environ["TEST_AXIS_KEY"]}])
      self.assertEqual(client.records, [])


  def test_request_encoding_failure_is_a_chat_error(self):
    config = Config({"local": Endpoint("http://127.0.0.1")}, (), {})
    client = Client(config)
    with patch("axis_review.llm.build_opener") as opener, self.assertRaisesRegex(ChatError, "UTF-8 JSON"):
      client.chat(phase="verify", axis="neutral", endpoint="local", model="judge",
                  messages=[{"role": "assistant", "content": "\ud800"}])
    opener.assert_not_called()

  def test_escaped_response_credential_omits_body_and_keeps_diagnostic_index(self):
    synthetic = "synthetic-fixture-marker"
    escaped = ''.join(f"\\u{ord(char):04x}" for char in synthetic).encode()
    nested = json.dumps({"choices": [{"message": {"content": '{"echo":"' + escaped.decode() + '"}'}}]}).encode()
    responses = (b'{"error":"' + escaped + b'"}', nested, b"{malformed", b'{"model":"safe"}\n')
    with patch.dict(os.environ, {"TEST_AXIS_KEY": synthetic}):
      config = Config({"local": Endpoint("http://127.0.0.1", "TEST_AXIS_KEY")}, (), {})
      client = Client(config)
      for payload in responses:
        response = MagicMock(code=200, headers={})
        response.__enter__.return_value = response
        response.read.return_value = payload
        with patch("axis_review.llm.build_opener") as opener:
          opener.return_value.open.return_value = response
          params = dict(phase="initial", axis="neutral", endpoint="local", model="finder", messages=[])
          if payload == responses[-1]:
            client.chat(**params)
          else:
            with self.assertRaisesRegex(ChatError, "could not be safely checked"):
              client.chat(**params)
      with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        report.write_calls(root, client.records, config)
        rows = [json.loads(line) for line in (root / "calls.jsonl").read_bytes().splitlines()]
        for row in rows[:3]:
          self.assertIsNone(row["resp_path"])
          self.assertIn("response_body_hash_unavailable", row)
          self.assertFalse((root / "bodies" / f"{row['seq']}.resp.json").exists())
          self.assertTrue((root / row["req_path"]).is_file())
        self.assertEqual((root / rows[-1]["resp_path"]).read_bytes(), responses[-1])

  def test_usage_distinguishes_omitted_tokens_from_zero(self):
    usage = report._usage([{"usage": {"total_tokens": 5}}, {"usage": {"completion_tokens": 0}}, {"usage": None}])
    self.assertIn("total_tokens=5 (1/3 attempts)", usage)
    self.assertIn("completion_tokens=0 (1/3 attempts)", usage)
    self.assertNotIn("prompt_tokens", usage)


class RepoTests(unittest.TestCase):
  def test_path_confinement_and_truncation(self):
    with tempfile.TemporaryDirectory() as work:
      parent = Path(work)
      (parent / "outside").write_text("outside sentinel", encoding="utf-8")
      repo = parent / "repo"
      repo.mkdir()
      subprocess.run(["git", "init", "--quiet", "--template="], cwd=repo, check=True)
      (repo / "source.py").write_text("one\nneedle\n" + "y" * 13_000, encoding="utf-8")
      (repo / "escape").symlink_to(parent / "outside")
      (repo / "metadata").symlink_to(repo / ".git", target_is_directory=True)
      settings = {"user.name": "Fixture", "user.email": "fixture@example.invalid"}
      github._git(["add", "source.py", "escape", "metadata"], repo, settings)
      tree = github._git(["write-tree"], repo, settings).decode().strip()
      sha = github._git(["commit-tree", tree, "-m", "Fixture"], repo, settings).decode().strip()
      for file in ("../outside", str(parent / "outside"), "escape", ".git/HEAD", "metadata/HEAD"):
        with self.subTest(file=file):
          self.assertIn("Tool error", execute("read_file", {"path": file}, repo, head_sha=sha))
      self.assertEqual(execute("list_dir", {}, repo), "source.py")
      self.assertEqual(execute("grep", {"pattern": "needle"}, repo), "source.py:2: needle")
      self.assertEqual(execute("grep", {"pattern": "outside sentinel"}, repo), "")
      self.assertIn("Pinned head commit is unavailable", execute("read_file", {"path": "source.py"}, repo))
      self.assertEqual(execute("read_file", {"path": "source.py", "end_line": 2}, repo, head_sha=sha), "1: one\n2: needle")
      result = execute("read_file", {"path": "source.py"}, repo, head_sha=sha)
      self.assertEqual(len(result), OUTPUT_LIMIT)
      self.assertTrue(result.endswith(TRUNCATED))

  def test_checkout_fetches_pinned_base_and_exposes_path_filtered_pr_history(self):
    with tempfile.TemporaryDirectory() as work:
      sandbox = Path(work)
      remote = sandbox / "remote"
      remote.mkdir()
      config = {"user.name": "Fixture", "user.email": "fixture@example.invalid"}

      def git(*args):
        return github._git(list(args), remote, config).decode().strip()

      git("init", "--quiet", "--template=")
      (remote / "src.py").write_text("before\nremoved\n", encoding="utf-8")
      (remote / "deleted.py").write_text("base-only\n", encoding="utf-8")
      git("add", "src.py", "deleted.py")
      base = git("commit-tree", git("write-tree"), "-m", "Base commit")
      (remote / "src.py").write_text("after\n", encoding="utf-8")
      git("add", "src.py")
      middle = git("commit-tree", git("write-tree"), "-p", base, "-m", "Move source guard")
      (remote / "deleted.py").unlink()
      git("add", "-u", "--", "deleted.py")
      head = git("commit-tree", git("write-tree"), "-p", middle, "-m", "Remove other file")
      git("update-ref", "refs/heads/fixture", head)
      actual_git = github._git

      def local_git(args, cwd, options=None):
        return actual_git([str(remote) if arg == "https://github.com/fixture/repo.git" else arg for arg in args], cwd, options)

      pr = github.PR("fixture", "repo", 1, "Fixture", "fixture", base, head, [])
      with patch.object(github, "_git", side_effect=local_git) as calls:
        root = github.checkout(pr, sandbox)
      fetches = [call.args[0] for call in calls.call_args_list if call.args[0][0] == "fetch"]
      self.assertEqual([args[-1] for args in fetches], [head, base])
      (root / "src.py").write_text("not the blob\n", encoding="utf-8")
      kwargs = {"base_sha": base, "head_sha": head}
      self.assertEqual(execute("read_file", {"path": "src.py", "ref": "base"}, root, **kwargs), "1: before\n2: removed")
      self.assertEqual(execute("read_file", {"path": "src.py"}, root, **kwargs), "1: after")
      self.assertEqual(execute("read_file", {"path": "deleted.py", "ref": "base"}, root, **kwargs), "1: base-only")
      self.assertEqual(execute("pr_commits", {"path": "src.py"}, root, **kwargs), f"{middle}\nMove source guard")
      diff = execute("show_commit_patch", {"path": "src.py", "sha": middle}, root, **kwargs)
      self.assertIn("-removed", diff)
      self.assertIn("+after", diff)
      self.assertIn("outside the pinned PR range", execute("show_commit_patch", {"path": "src.py", "sha": base}, root, **kwargs))
      self.assertIn("Tool error", execute("read_file", {"path": "src.py", "ref": middle}, root, **kwargs))
      self.assertIn("Tool error", execute("pr_commits", {"path": "../src.py"}, root, **kwargs))

  def test_truncated_github_body_degrades_fallback_and_drift(self):
    from axis_review.review import _drift

    reply = MagicMock()
    reply.__enter__.return_value = reply
    reply.read.side_effect = IncompleteRead(b"partial", 10)
    pr = {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}, "title": "Change",
          "user": {"login": "reviewer"}, "changed_files": 1}
    files = [{"filename": "a.py", "status": "added", "additions": 1, "deletions": 0}]
    with patch.object(github, "build_opener") as opener:
      opener.return_value.open.return_value = reply
      with patch.object(github, "_json", side_effect=[pr, files, pr]):
        fetched = github.fetch_pr("https://github.com/owner/repo/pull/2")
      self.assertEqual(_drift(fetched)["state"], "UNAVAILABLE")
      with self.assertRaisesRegex(github.GitHubError, "IncompleteRead"):
        github.fetch_pr(fetched.url)
    self.assertIsNone(fetched.files[0].patch)
    self.assertIn("IncompleteRead", fetched.material_notes[0])

  def test_github_diff_fallback_keeps_quoted_and_deleted_sections(self):
    files = [ChangedFile("doculé space.md", "renamed", 1, 0, None, "old space.md"),
             ChangedFile("old.py", "removed", 0, 1, None),
             ChangedFile("missing.py", "modified", 1, 0, None)]
    diff = ('diff --git a/old space.md "b/docul\\303\\251 space.md"\nrename from old space.md\n'
            'rename to "docul\\303\\251 space.md"\n@@ -0,0 +1 @@\n+new\n'
            'diff --git a/old.py b/old.py\n--- a/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n')
    sections = github._diff_sections(diff, files)
    self.assertEqual(set(sections), {"doculé space.md", "old.py"})
    self.assertTrue(sections["doculé space.md"].endswith("+new"))
    self.assertTrue(sections["old.py"].endswith("-old"))

  def test_fetch_pr_requires_matching_file_count_and_fills_missing_patch(self):
    pr = {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}, "title": "Change",
          "user": {"login": "reviewer"}, "changed_files": 1, "body": "scope\n"}
    files = [{"filename": "a.py", "status": "added", "additions": 1, "deletions": 0}]
    diff = b"diff --git a/a.py b/a.py\n--- /dev/null\n+++ b/a.py\n@@ -0,0 +1 @@\n+new\n"
    with patch.object(github, "_json", side_effect=[pr, files, pr]), patch.object(github, "_api", return_value=diff) as api:
      fetched = github.fetch_pr("https://github.com/owner/repo/pull/2")
    api.assert_called_once_with("/repos/owner/repo/pulls/2", "application/vnd.github.v3.diff")
    self.assertEqual(fetched.description, pr["body"])
    self.assertTrue(fetched.files[0].patch.endswith("+new"))
    with patch.object(github, "_json", side_effect=[pr, []]):
      with self.assertRaisesRegex(github.GitHubError, "pagination count mismatch"):
        github.fetch_pr("https://github.com/owner/repo/pull/2")


class CLITests(unittest.TestCase):
  def test_verify_receipts_cli_prints_adapter_result(self):
    import io
    from contextlib import redirect_stdout

    summary = {"verified": 1, "expected": 1}
    with tempfile.TemporaryDirectory() as work, patch("axis_review.receipts.verify", return_value=summary) as verify:
      with redirect_stdout(io.StringIO()) as output:
        self.assertEqual(main(["verify-receipts", work]), 0)
      verify.assert_called_once_with(Path(work))
      self.assertEqual(json.loads(output.getvalue()), summary)

  def test_serve_output_is_static_and_does_not_follow_symlinks(self):
    from functools import partial

    with tempfile.TemporaryDirectory() as work:
      parent = Path(work)
      (parent / "outside").write_text("outside", encoding="utf-8")
      root = parent / "out"
      root.mkdir()
      (root / "link").symlink_to(parent / "outside")
      (root / "report.md").write_text("# Report\n", encoding="utf-8")
      with Server(partial(OutputHandler, directory=str(root), token="fixture")) as server:
        with urlopen(f"{server.base}/fixture/report.md", timeout=2) as reply:
          self.assertEqual(reply.read(), b"# Report\n")
          self.assertEqual(reply.headers.get("X-Content-Type-Options"), "nosniff")
        for path, method, status in (("/fixture/link", "GET", 404), ("/fixture/report.md", "POST", 501)):
          with self.assertRaises(HTTPError) as raised:
            urlopen(Request(server.base + path, method=method), timeout=2)
          with raised.exception as error:
            self.assertEqual(error.code, status)

  def test_review_cli_assigns_one_output_per_distinct_pr(self):
    import io
    from contextlib import redirect_stdout
    from types import SimpleNamespace

    config = Config({"local": Endpoint("http://127.0.0.1")},
                    (Axis("local", "finder", "neutral"),), {"for_diff_axes": Model("local", "judge")})
    with tempfile.TemporaryDirectory() as work, patch("axis_review.cli.load_config", return_value=config):
      with patch("axis_review.cli.run_review", side_effect=lambda url, cfg, dest: SimpleNamespace(out_dir=dest, review_failed=False)) as run:
        with redirect_stdout(io.StringIO()) as output:
          code = main(["review", "https://github.com/owner/first/pull/2", "https://github.com/owner/second/pull/2",
                       "https://github.com/Owner/First/pull/2/", "--config", "config.toml", "--out", work])
      self.assertEqual(code, 0)
      paths = [item.args[2] for item in run.call_args_list]
      self.assertEqual(len(paths), 2)
      self.assertEqual(len(set(paths)), 2)
      self.assertEqual(output.getvalue().splitlines(), [str(path / "report.md") for path in paths])
