import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from axis_review import github, report
from axis_review.cli import OutputHandler, main
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
      for file in ("../outside", str(parent / "outside"), "escape", ".git/HEAD", "metadata/HEAD"):
        with self.subTest(file=file):
          self.assertIn("Tool error", execute("read_file", {"path": file}, repo))
      self.assertEqual(execute("list_dir", {}, repo), "source.py")
      self.assertEqual(execute("grep", {"pattern": "needle"}, repo), "source.py:2: needle")
      self.assertEqual(execute("grep", {"pattern": "outside sentinel"}, repo), "")
      self.assertEqual(execute("read_file", {"path": "source.py", "end_line": 2}, repo), "1: one\n2: needle")
      result = execute("read_file", {"path": "source.py"}, repo)
      self.assertEqual(len(result), OUTPUT_LIMIT)
      self.assertTrue(result.endswith(TRUNCATED))

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

    with tempfile.TemporaryDirectory() as work, patch("axis_review.receipts.verify", return_value={"verified": 1}) as verify:
      with redirect_stdout(io.StringIO()) as output:
        self.assertEqual(main(["verify-receipts", work]), 0)
      verify.assert_called_once_with(Path(work))
      self.assertEqual(json.loads(output.getvalue()), {"verified": 1})

  def test_serve_output_is_static_and_does_not_follow_symlinks(self):
    from functools import partial

    with tempfile.TemporaryDirectory() as work:
      parent = Path(work)
      (parent / "outside").write_text("outside", encoding="utf-8")
      root = parent / "out"
      root.mkdir()
      (root / "link").symlink_to(parent / "outside")
      (root / "report.md").write_text("# Report\n", encoding="utf-8")
      with Server(partial(OutputHandler, directory=str(root))) as server:
        with urlopen(f"{server.base}/report.md", timeout=2) as reply:
          self.assertEqual(reply.read(), b"# Report\n")
          self.assertEqual(reply.headers.get("X-Content-Type-Options"), "nosniff")
        for path, method, status in (("/link", "GET", 404), ("/report.md", "POST", 501)):
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
      with patch("axis_review.cli.run_review", side_effect=lambda url, cfg, dest: SimpleNamespace(out_dir=dest)) as run:
        with redirect_stdout(io.StringIO()) as output:
          code = main(["review", "https://github.com/owner/first/pull/2", "https://github.com/owner/second/pull/2",
                       "https://github.com/Owner/First/pull/2/", "--config", "config.toml", "--out", work])
      self.assertEqual(code, 0)
      paths = [item.args[2] for item in run.call_args_list]
      self.assertEqual(len(paths), 2)
      self.assertEqual(len(set(paths)), 2)
      self.assertEqual(output.getvalue().splitlines(), [str(path / "report.md") for path in paths])
