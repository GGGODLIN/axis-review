import io
import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.client import HTTPResponse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from axis_review.cli import OutputHandler, main


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "fixture-access-token"


def request(root, path, method="GET"):
  connection = Mock()
  connection.makefile.return_value = io.BytesIO(f"{method} {path} HTTP/1.0\r\n\r\n".encode())
  OutputHandler(connection, ("127.0.0.1", 1), None, directory=str(root), token=TOKEN)
  reply = Mock()
  reply.makefile.return_value = io.BytesIO(b"".join(call.args[0] for call in connection.sendall.call_args_list))
  response = HTTPResponse(reply, method=method)
  response.begin()
  return response


class CLIContractTests(unittest.TestCase):
  def test_serve_requires_token_and_defaults_to_loopback(self):
    with (patch.dict(os.environ, {"AXIS_REVIEW_SERVE_TOKEN": TOKEN}),
          patch("axis_review.cli._serve", return_value=0) as serve):
      self.assertEqual(main(["serve", "out"]), 0)
      serve.assert_called_once_with(Path("out"), 8080, "127.0.0.1", TOKEN)
      self.assertEqual(main(["serve", "out", "--host", "0.0.0.0", "--token", "override"]), 0)
      serve.assert_called_with(Path("out"), 8080, "0.0.0.0", "override")
      with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
        main(["serve", "out", "--token", ""])
      self.assertEqual(error.exception.code, 1)
      self.assertEqual(serve.call_count, 2)
    with (patch.dict(os.environ, {"AXIS_REVIEW_SERVE_TOKEN": ""}),
          patch("axis_review.cli._serve") as serve, redirect_stderr(io.StringIO())):
      with self.assertRaises(SystemExit) as error:
        main(["serve", "out"])
      self.assertEqual(error.exception.code, 1)
      serve.assert_not_called()

  def test_serve_authenticates_first_segment(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      (root / "report.md").write_bytes(b"# Report\n")
      with request(root, f"/{TOKEN}/report.md") as response:
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"# Report\n")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
      with request(root, f"/{TOKEN}/report.md", "HEAD") as response:
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"")
      for method in ("GET", "HEAD", "POST"):
        for path in ("/report.md", "/incorrect/report.md"):
          with self.subTest(path=path, method=method), request(root, path, method) as response:
            self.assertEqual(response.status, 404)

  def test_serve_only_returns_files_and_does_not_select_indexes(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      (root / "nested").mkdir()
      (root / "nested" / "index.html").write_bytes(b"sample index")
      (root / "nested" / "alias.html").symlink_to("index.html")
      os.mkfifo(root / "event-pipe")
      for path in ("", "nested/", "event-pipe"):
        with self.subTest(path=path), request(root, f"/{TOKEN}/{path}") as response:
          self.assertEqual(response.status, 404)
      for name in ("index.html", "alias.html"):
        with request(root, f"/{TOKEN}/nested/{name}") as response:
          self.assertEqual(response.status, 200)
          self.assertEqual(response.read(), b"sample index")

  def test_verify_cli_exits_nonzero_for_present_but_unverified_receipt(self):
    for expected, fetched, verified, missing, exit_code in ((2, 2, 1, 0, 1), (2, 1, 1, 1, 1),
                                                            (2, 2, 2, 0, 0), (0, 0, 0, 0, 0)):
      summary = dict(expected=expected, fetched=fetched, verified=verified, missing=missing)
      with (patch("axis_review.receipts.verify", return_value=summary), redirect_stdout(io.StringIO()) as output):
        self.assertEqual(main(["verify-receipts", "out"]), exit_code)
        self.assertEqual(json.loads(output.getvalue()), summary)

  def test_review_cli_keeps_failed_report_and_reviews_remaining_prs(self):
    with tempfile.TemporaryDirectory() as directory:
      def run(url, config, out_dir):
        out_dir.mkdir()
        (out_dir / "report.md").write_text("review")
        failed = url.endswith("/1")
        return SimpleNamespace(out_dir=out_dir, review_failed=failed,
                               failure_reason="No usable initial axis replies" if failed else None)

      with (patch("axis_review.cli.load_config"), patch("axis_review.cli.run_review", side_effect=run),
            redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors):
        self.assertEqual(main(["review", "https://github.com/owner/repo/pull/1",
                               "https://github.com/owner/repo/pull/2", "--config", "config.toml", "--out", directory]), 1)
      paths = [Path(line) for line in output.getvalue().splitlines()]
      self.assertEqual([path.parent.name for path in paths], ["owner--repo--pr-1", "owner--repo--pr-2"])
      self.assertTrue(all(path.is_file() for path in paths))
      self.assertIn("owner/repo#1: No usable initial axis replies", errors.getvalue())

  def test_docs_clarify_english_templates_and_model_language(self):
    for name in ("README.md", "docs/design.md"):
      with self.subTest(name=name):
        text = (ROOT / name).read_text()
        self.assertRegex(text, r"`language` applies only to model-written text")
        self.assertRegex(text, r"report templates stay in English")


class ComposeContractTests(unittest.TestCase):
  def test_deploy_requires_and_checks_full_commit_before_running(self):
    compose = (ROOT / "docker-compose.yml").read_text()
    command = re.search(r"(?m)^      - \|\n((?:^        .+\n)+)", compose).group(1)
    command = textwrap.dedent(command).replace("$$", "$")
    stub = '''
git() {
  if [[ "$*" == *'rev-parse HEAD'* ]]; then
    printf '%s\\n' "$STUB_HEAD"
  else
    printf '%s\\n' git >> "$TRACE"
  fi
}
mktemp() { /usr/bin/mktemp -d "$PWD/checkout.XXXXXX"; }
python() {
  printf '%s\\n' install >> "$TRACE"
  STUB_HEAD="$STUB_INSTALLED_HEAD"
}
'''
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      executable = root / "axis-review"
      executable.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$TRACE"\n')
      executable.chmod(0o700)
      valid = "a" * 40
      mismatch = "b" * 40
      for ref, head, installed_head, expected_status, expected_trace in (
        ("main", valid, valid, 1, []),
        ("a" * 39, valid, valid, 1, []),
        ("g" * 40, valid, valid, 1, []),
        (valid, mismatch, valid, 1, []),
        (valid, valid, mismatch, 1, ["install"]),
        (valid.upper(), valid, valid, 0, ["install", "review", "serve"]),
      ):
        with self.subTest(ref=ref, head_matches=ref.lower() == head, stable=head == installed_head):
          trace = root / "trace"
          trace.write_text("")
          result = subprocess.run(["/bin/bash", "-ec", stub + command], cwd=root, env={
            "PATH": f"{root}:/usr/bin:/bin", "PR_URLS": "https://github.com/owner/repo/pull/1",
            "AXIS_REVIEW_REF": ref, "AXIS_REVIEW_SERVE_TOKEN": TOKEN, "STUB_HEAD": head,
            "STUB_INSTALLED_HEAD": installed_head, "TRACE": str(trace),
          }, capture_output=True, text=True, timeout=5)
          self.assertEqual(result.returncode, expected_status, result.stderr)
          lines = trace.read_text().splitlines()
          actions = [line.split()[0] for line in lines if line != "git"]
          self.assertEqual(actions, expected_trace)
          if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            self.assertEqual(lines, [])
          if expected_status == 0:
            self.assertEqual(lines[-1], "serve /data/out --host 0.0.0.0 --port 8080")
