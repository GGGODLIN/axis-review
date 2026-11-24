import fnmatch
import os
from pathlib import Path


OUTPUT_LIMIT = 12_000
TRUNCATED = "\n[output truncated]"


def _tool(name: str, description: str, properties: dict, required: list[str]) -> dict:
  return {"type": "function", "function": {"name": name, "description": description,
          "parameters": {"type": "object", "properties": properties, "required": required,
                         "additionalProperties": False}}}


_TEXT = {"type": "string"}
_POSITIVE = {"type": "integer", "minimum": 1}
TOOLS = [
  _tool("read_file", "Read numbered lines from a checkout-relative text file (inclusive, 1-based).",
        {"path": _TEXT, "start_line": _POSITIVE, "end_line": _POSITIVE}, ["path"]),
  _tool("grep", "Search for a case-sensitive literal substring in checkout text files.",
        {"pattern": _TEXT, "glob": _TEXT, "max_results": _POSITIVE}, ["pattern"]),
  _tool("list_dir", "List a checkout-relative directory. Use . for the root.", {"path": _TEXT}, []),
]


def confined(root: Path, raw: str) -> Path:
  if not isinstance(raw, str) or not raw or "\x00" in raw:
    raise ValueError("Expected a non-empty checkout-relative path")
  path = Path(raw)
  if path.is_absolute() or ".." in path.parts or any(part.casefold() == ".git" for part in path.parts):
    raise ValueError("Path is outside the allowed checkout tree")
  root = root.resolve()
  try:
    resolved = (root / path).resolve(strict=True)
    relative = resolved.relative_to(root)
  except (ValueError, RuntimeError):
    raise ValueError("Path is outside the allowed checkout tree") from None
  if any(part.casefold() == ".git" for part in relative.parts):
    raise ValueError("Path is outside the allowed checkout tree")
  return resolved


def matches_glob(path: str, pattern: str) -> bool:
  return fnmatch.fnmatchcase(path, pattern) or (
    pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:])
  )


def _read(path: Path, start_line: int = 1, end_line: int | None = None):
  if type(start_line) is not int or start_line < 1:
    raise ValueError("start_line must be a positive integer")
  if end_line is not None and (type(end_line) is not int or end_line < start_line):
    raise ValueError("end_line must be an integer at or after start_line")
  if not path.is_file():
    raise ValueError("Path is not a regular file")
  with path.open(encoding="utf-8", errors="replace") as file:
    for index, line in enumerate(file, 1):
      if end_line is not None and index > end_line:
        break
      if index >= start_line:
        yield f"{index}: {line.rstrip(chr(10))}"


def _grep(root: Path, pattern: str, glob: str = "*", max_results: int = 100):
  if not isinstance(pattern, str) or not pattern:
    raise ValueError("pattern must be a non-empty string")
  if (not isinstance(glob, str) or not glob or Path(glob).is_absolute()
      or ".." in Path(glob).parts or ".git" in Path(glob).parts):
    raise ValueError("glob must remain within the checkout tree")
  if type(max_results) is not int or max_results < 1:
    raise ValueError("max_results must be a positive integer")
  found = 0
  for directory, subdirs, names in os.walk(root, followlinks=False):
    subdirs[:] = sorted(name for name in subdirs if name != ".git")
    for name in sorted(names):
      path = (Path(directory) / name).relative_to(root).as_posix()
      if not matches_glob(path, glob):
        continue
      try:
        candidate = confined(root, path)
        if not candidate.is_file():
          continue
        with candidate.open(encoding="utf-8", errors="replace") as file:
          if "\x00" in file.read(4096):
            continue
          file.seek(0)
          for index, line in enumerate(file, 1):
            if pattern in line:
              if found == max_results:
                yield TRUNCATED.strip()
                return
              found += 1
              yield f"{path}:{index}: {line.rstrip(chr(10))}"
      except (ValueError, OSError):
        continue


def _list(root: Path, path: str = "."):
  for entry in sorted(confined(root, path).iterdir()):
    try:
      target = confined(root, entry.relative_to(root).as_posix())
    except (ValueError, OSError):
      continue
    yield entry.name + ("/" if target.is_dir() else "")


def _limited(lines) -> str:
  output = ""
  for line in lines:
    addition = ("\n" if output else "") + line
    remaining = OUTPUT_LIMIT - len(output)
    if len(addition) > remaining:
      return (output + addition[:remaining])[:OUTPUT_LIMIT - len(TRUNCATED)] + TRUNCATED
    output += addition
  return output


def execute(name: str, args: dict, root: Path) -> str:
  root = root.resolve()
  try:
    if name == "read_file":
      params = dict(args)
      path = confined(root, params.pop("path"))
      return _limited(_read(path, **params))
    if name == "grep":
      return _limited(_grep(root, **args))
    if name == "list_dir":
      return _limited(_list(root, **args))
    return "Tool error: unknown tool"
  except (KeyError, TypeError):
    return "Tool error: arguments do not match the tool schema"
  except ValueError as error:
    return f"Tool error: {error}"
  except OSError as error:
    return f"Tool error: {error.strerror or type(error).__name__}"
