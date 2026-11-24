import argparse
import json
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import load_config
from .github import GitHubError, parse_pr_url
from .review import run_review


class OutputHandler(SimpleHTTPRequestHandler):
  def send_head(self):
    directory = Path(self.directory)
    path = Path(self.translate_path(self.path))
    try:
      relative = path.relative_to(directory)
      root = directory.resolve()
      for part in relative.parts:
        if part.startswith("."):
          raise ValueError
        root = root / part
        if root.is_symlink():
          raise ValueError
    except (ValueError, OSError):
      self.send_error(404)
      return None
    return super().send_head()

  def guess_type(self, path):
    return "text/plain; charset=utf-8"

  def end_headers(self):
    self.send_header("X-Content-Type-Options", "nosniff")
    self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
    super().end_headers()

  def log_message(self, format, *args):
    # Request URLs can contain private paths or caller-supplied secrets.
    pass


def _serve(directory: Path, port: int, host: str) -> int:
  if not directory.is_dir():
    raise ValueError("Serve directory must exist")
  handler = partial(OutputHandler, directory=str(directory.resolve()))
  with ThreadingHTTPServer((host, port), handler) as server:
    print(f"Serving review output on {host}:{server.server_port}", flush=True)
    try:
      server.serve_forever()
    except KeyboardInterrupt:
      return 0
  return 0


def _parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(prog="axis-review", description="Run read-only multi-axis PR reviews.")
  sub = parser.add_subparsers(dest="command", required=True)
  review = sub.add_parser("review", help="Review one or more GitHub pull requests")
  review.add_argument("urls", nargs="+", metavar="PR_URL")
  review.add_argument("--config", type=Path, required=True, metavar="FILE")
  review.add_argument("--out", type=Path, required=True, metavar="DIR")
  receipts = sub.add_parser("verify-receipts", help="Verify saved receipts offline")
  receipts.add_argument("directory", type=Path, metavar="DIR")
  serve = sub.add_parser("serve", help="Serve the saved output as read-only files")
  serve.add_argument("directory", type=Path, metavar="DIR")
  serve.add_argument("--port", type=int, default=8080)
  serve.add_argument("--host", default="0.0.0.0")
  return parser


def main(argv: list[str] | None = None) -> int:
  parser = _parser()
  args = parser.parse_args(argv)
  try:
    if args.command == "serve":
      return _serve(args.directory, args.port, args.host)
    if args.command == "verify-receipts":
      from . import receipts

      print(json.dumps(receipts.verify(args.directory), indent=2))
      return 0
    config = load_config(args.config)
    prs = {}
    for url in args.urls:
      owner, repo, number = parse_pr_url(url)
      prs.setdefault((owner.lower(), repo.lower(), number), url)
    failed = False
    for (owner, repo, number), url in prs.items():
      identity = f"{owner}/{repo}#{number}"
      try:
        result = run_review(url, config, args.out / f"{owner}--{repo}--pr-{number}")
      except (ValueError, OSError, GitHubError) as error:
        message = str(error) if not isinstance(error, OSError) else (error.strerror or type(error).__name__)
        print(f"{identity}: {message}", file=sys.stderr)
        failed = True
        continue
      print(result.out_dir / "report.md")
    return int(failed)
  except (ValueError, OSError) as error:
    message = str(error) if not isinstance(error, OSError) else (error.strerror or type(error).__name__)
    parser.exit(1, f"axis-review: {message}\n")