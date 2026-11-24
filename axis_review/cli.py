import argparse
import json
import os
import sys
from pathlib import Path

from .config import load_config
from .github import GitHubError, parse_pr_url
from .review import run_review
from .serve import OutputHandler, require_serve_token, serve_output as _serve


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
  serve.add_argument("--host", default="127.0.0.1")
  serve.add_argument("--token", default=os.environ.get("AXIS_REVIEW_SERVE_TOKEN"),
                     help="Access token (defaults to AXIS_REVIEW_SERVE_TOKEN)")
  return parser


def main(argv: list[str] | None = None) -> int:
  parser = _parser()
  args = parser.parse_args(argv)
  try:
    if args.command == "serve":
      return _serve(args.directory, args.port, args.host, require_serve_token(args.token))
    if args.command == "verify-receipts":
      from . import receipts

      summary = receipts.verify(args.directory)
      print(json.dumps(summary, indent=2))
      return int(summary["verified"] != summary["expected"])
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
      if result.review_failed:
        print(f"{identity}: {result.failure_reason or 'Review failed'}", file=sys.stderr)
        failed = True
    return int(failed)
  except (ValueError, OSError) as error:
    message = str(error) if not isinstance(error, OSError) else (error.strerror or type(error).__name__)
    parser.exit(1, f"axis-review: {message}\n")