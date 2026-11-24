import json
import os
import re
import subprocess
from dataclasses import dataclass, replace
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, build_opener

from .llm import NoRedirect


_PR_URL = re.compile(r"https://github\.com/([\w-]+)/([\w.-]+)/pull/([1-9][0-9]*)/?", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{40}")


class GitHubError(RuntimeError):
  pass


@dataclass(frozen=True)
class ChangedFile:
  path: str
  status: str
  additions: int
  deletions: int
  patch: str | None
  previous_path: str | None = None


@dataclass(frozen=True)
class PR:
  owner: str
  repo: str
  number: int
  title: str
  author: str
  base_sha: str
  head_sha: str
  files: list[ChangedFile]
  description: str = ""
  commit_messages: tuple[dict, ...] = ()
  material_notes: tuple[str, ...] = ()

  @property
  def url(self) -> str:
    return f"https://github.com/{self.owner}/{self.repo}/pull/{self.number}"

  @property
  def api_path(self) -> str:
    return f"/repos/{self.owner}/{self.repo}/pulls/{self.number}"


def parse_pr_url(url: str) -> tuple[str, str, int]:
  match = _PR_URL.fullmatch(url)
  if not match or match[2] in {".", ".."}:
    raise ValueError("Expected https://github.com/OWNER/REPO/pull/NUMBER")
  return match[1], match[2], int(match[3])


def _api(path: str, accept: str = "application/vnd.github+json") -> bytes:
  headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
  token = os.environ.get("GITHUB_TOKEN")
  if token:
    headers["Authorization"] = f"Bearer {token}"
  try:
    req = Request(f"https://api.github.com{path}", headers=headers)
    with build_opener(NoRedirect()).open(req, timeout=60) as reply:
      return reply.read()
  except HTTPError as error:
    with error:
      raise GitHubError(f"GitHub returned HTTP {error.code}") from None
  except (OSError, HTTPException) as error:
    raise GitHubError(f"GitHub request failed ({type(error).__name__})") from None


def _json(path: str):
  try:
    return json.loads(_api(path))
  except ValueError:
    raise GitHubError("GitHub returned malformed JSON") from None


def _pages(path: str, expected: int) -> list[dict]:
  items = []
  for offset in range(0, expected, 100):
    page = _json(f"{path}?per_page=100&page={offset // 100 + 1}")
    if not isinstance(page, list):
      raise GitHubError("GitHub returned an invalid paginated response")
    items.extend(page)
    if len(page) < 100:
      break
  if len(items) != expected:
    raise GitHubError(f"GitHub pagination count mismatch: expected {expected}, got {len(items)}")
  return items


def _shas(info: dict) -> tuple[str, str]:
  base, head = info["base"]["sha"], info["head"]["sha"]
  if not _SHA.fullmatch(base) or not _SHA.fullmatch(head):
    raise GitHubError("GitHub returned an invalid base or head SHA")
  return base, head


def fetch_versions(pr: PR) -> tuple[str, str]:
  return _shas(_json(pr.api_path))


def _git_path(text: str) -> str:
  if not text.startswith('"'):
    return text
  # Git emits C-quoted UTF-8 bytes as octal sequences when core.quotePath is on.
  raw = bytearray()
  escapes = dict(zip('abtnvfr\\"', b'\a\b\t\n\v\f\r\\"'))
  for match in re.finditer(r"\\([0-7]{3}|.)|([^\\]+)", text[1:-1]):
    escape, literal = match.groups()
    if literal is not None:
      raw.extend(literal.encode())
    elif len(escape) == 3:
      raw.append(int(escape, 8))
    else:
      raw.append(escapes.get(escape, ord(escape)))
  return raw.decode("utf-8", errors="replace")


def _diff_sections(diff: str, files: list[ChangedFile]) -> dict[str, str]:
  by_path = {file.path: file for file in files}
  pairs = {f"a/{file.previous_path or file.path} b/{file.path}": file.path for file in files}
  result = {}
  for section in re.split(r"(?m)(?=^diff --git )", diff):
    if not section.startswith("diff --git "):
      continue
    first, _, rest = section.partition("\n")
    names = first.removeprefix("diff --git ")
    path = pairs.get(names)
    if path is None:
      match = re.fullmatch(r'("(?:\\.|[^"\\])*"|a/.+) ("(?:\\.|[^"\\])*"|b/.+)', names)
      if match:
        path = _git_path(match[2]).removeprefix("b/")
    if path not in by_path:
      # These headers precede all hunks. Hunk bodies may contain lookalike lines.
      metadata = re.split(r"(?m)^@@", rest, maxsplit=1)[0]
      for prefix in ("rename to ", "copy to ", "+++ b/", "+++ ", "--- a/", "--- "):
        match = re.search(rf"(?m)^{re.escape(prefix)}(.+)$", metadata)
        if match:
          candidate = _git_path(match[1].removesuffix("\t"))
          if prefix in {"+++ ", "--- "}:
            candidate = candidate.removeprefix("b/" if prefix == "+++ " else "a/")
          if candidate in by_path:
            path = candidate
            break
    if path in by_path:
      result[path] = section.rstrip("\n")
  return result


def fetch_pr(url: str) -> PR:
  owner, repo, number = parse_pr_url(url)
  api_path = f"/repos/{owner}/{repo}/pulls/{number}"
  info = _json(api_path)
  base, head = _shas(info)
  files = [ChangedFile(item["filename"], item["status"], item["additions"], item["deletions"],
                       item.get("patch"), item.get("previous_filename"))
           for item in _pages(f"{api_path}/files", info["changed_files"])]
  if len({file.path for file in files}) != len(files):
    raise GitHubError("GitHub returned duplicate changed file paths")

  notes = []
  if any(file.patch is None for file in files):
    try:
      diff = _api(api_path, "application/vnd.github.v3.diff").decode("utf-8", errors="replace")
      sections = _diff_sections(diff, files)
      files = [replace(file, patch=sections.get(file.path)) if file.patch is None else file
               for file in files]
    except GitHubError as error:
      notes.append(f"Full PR diff fallback failed: {error}")

  commits = ()
  count = info.get("commits", 0)
  if count:
    try:
      commits = tuple({"sha": item["sha"], "message": item["commit"]["message"]}
                      for item in _pages(f"{api_path}/commits", min(count, 250)))
      if count > 250:
        notes.append("PR commit messages limited to the first 250 GitHub results")
    except GitHubError as error:
      notes.append(f"PR commit messages unavailable: {error}")

  pr = PR(owner, repo, number, info["title"], info["user"]["login"], base, head, files,
          info.get("body") or "", commits, tuple(notes))
  if fetch_versions(pr) != (base, head):
    raise GitHubError("PR base or head changed while collecting input; rerun the review")
  return pr


def _git(args: list[str], cwd: Path, config: dict[str, str] | None = None) -> bytes:
  env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
  env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
  if config:
    env["GIT_CONFIG_COUNT"] = str(len(config))
    for index, (key, value) in enumerate(config.items()):
      env[f"GIT_CONFIG_KEY_{index}"] = key
      env[f"GIT_CONFIG_VALUE_{index}"] = value
  try:
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, timeout=180).stdout
  except (OSError, subprocess.SubprocessError) as error:
    raise GitHubError(f"git {args[0]} failed ({type(error).__name__})") from None


def checkout(pr: PR, workdir: Path) -> Path:
  root = workdir / "repo"
  root.mkdir()
  _git(["init", "--quiet", "--template="], root)
  remote = f"https://github.com/{pr.owner}/{pr.repo}.git"
  token = os.environ.get("GITHUB_TOKEN")
  config = {"http.followRedirects": "false"}
  if token:
    from base64 import b64encode

    credentials = b64encode(f"x-access-token:{token}".encode()).decode()
    config["http.https://github.com/.extraHeader"] = f"Authorization: Basic {credentials}"
  fetch = ["fetch", "--quiet", "--no-tags", "--", remote]
  # A shallow boundary can omit the commits that changed individual lines in the PR.
  try:
    _git([*fetch, pr.head_sha], root, config)
  except GitHubError:
    _git([*fetch, f"refs/pull/{pr.number}/head"], root, config)
  if _git(["rev-parse", "FETCH_HEAD"], root).decode().strip() != pr.head_sha:
    raise GitHubError("Fetched PR head does not match the captured head SHA")
  _git([*fetch, pr.base_sha], root, config)
  if _git(["rev-parse", "FETCH_HEAD"], root).decode().strip() != pr.base_sha:
    raise GitHubError("Fetched PR base does not match the captured base SHA")
  _git(["-c", "core.hooksPath=/dev/null", "checkout", "--quiet", "--detach", pr.head_sha], root)
  if _git(["rev-parse", "HEAD"], root).decode().strip() != pr.head_sha:
    raise GitHubError("Checkout HEAD does not match the captured head SHA")
  return root


def tracked_paths(root: Path, sha: str, path: str | None = None) -> list[str]:
  if not _SHA.fullmatch(sha):
    raise GitHubError("A pinned commit SHA is required")
  args = ["--literal-pathspecs", "ls-tree", "-rz", sha, "--"]
  if path is not None:
    args.append(path)
  entries = _git(args, root).split(b"\0")
  return sorted(os.fsdecode(entry.split(b"\t", 1)[1]) for entry in entries
                if entry.startswith((b"100644 blob ", b"100755 blob ")))


def read_blob(root: Path, sha: str, path: str) -> bytes:
  if path not in tracked_paths(root, sha, path):
    raise GitHubError("Path is not a regular file at the selected commit")
  return _git(["show", f"{sha}:{path}"], root)


def _pr_range(base: str, head: str) -> str:
  if not all(_SHA.fullmatch(sha) for sha in (base, head)):
    raise GitHubError("Pinned base and head commits are required")
  return f"{base}..{head}"


def pr_history(root: Path, base: str, head: str, path: str) -> list[tuple[str, str]]:
  args = ["--literal-pathspecs", "log", _pr_range(base, head), "-z", "--format=%H%x00%B",
          "--full-history", "--", path]
  fields = _git(args, root).decode("utf-8", errors="replace").split("\0")
  return list(zip(fields[:-1:2], fields[1::2]))


def pr_commit_patch(root: Path, base: str, head: str, sha: str, path: str) -> bytes:
  if not _SHA.fullmatch(sha) or sha.encode() not in _git(["rev-list", _pr_range(base, head), "--"], root).splitlines():
    raise GitHubError("Commit SHA is outside the pinned PR range")
  return _git(["--literal-pathspecs", "show", "--format=", "--no-ext-diff", "--no-textconv",
               "--diff-merges=first-parent", sha, "--", path], root)
