from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .github import GitHubError, read_blob
from .repo_tools import confined, git_lines


@dataclass(frozen=True)
class Anchor:
  status: str
  line_start: int | None = None
  line_end: int | None = None


def reanchor(source: str, anchor: str, reported_line: int | None) -> Anchor:
  if anchor == "<none>":
    return Anchor("<none>")
  snippet = git_lines(anchor)
  if not 1 <= len(snippet) <= 3 or not anchor.strip():
    return Anchor("FAILED")
  lines = git_lines(source)
  width = len(snippet)

  def hits(haystack, needle):
    return [index + 1 for index in range(len(haystack) - width + 1)
            if haystack[index:index + width] == needle]

  status = "exact"
  matches = hits(lines, snippet)
  if not matches:
    status = "normalized"
    matches = hits([" ".join(line.split()) for line in lines],
                   [" ".join(line.split()) for line in snippet])
  if not matches:
    return Anchor("FAILED")
  if len(matches) == 1:
    return Anchor(status, matches[0], matches[0] + width - 1)
  line = reported_line if reported_line is not None else matches[0]
  start = min(matches, key=lambda hit: (max(hit - line, line - (hit + width - 1), 0), hit))
  return Anchor("ambiguous", start, start + width - 1)


def anchor_file(root: Path, path: str, snippet: str, reported_line: int | None,
                *, head_sha: str | None = None) -> Anchor:
  if snippet == "<none>":
    return Anchor("<none>")
  try:
    if head_sha is not None:
      return reanchor(read_blob(root, head_sha, path).decode("utf-8"), snippet, reported_line)
    file = confined(root, path)
    if file.is_file():
      return reanchor(file.read_bytes().decode("utf-8"), snippet, reported_line)
  except (OSError, ValueError, GitHubError):
    pass
  return Anchor("FAILED")


def finding_uid(path: str, anchor: str, root_cause: str) -> str:
  identity = "\0".join((path, anchor, " ".join(root_cause.split()).lower()))
  return sha256(identity.encode("utf-8")).hexdigest()[:20]
