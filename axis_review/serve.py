import os
import re
import stat
from functools import partial
from hmac import compare_digest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


def require_serve_token(token: str | None) -> str:
  if token is None or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
    raise ValueError("Set AXIS_REVIEW_SERVE_TOKEN or --token to a nonempty token using letters, digits, '_' or '-'")
  return token


def _open_beneath(root: Path, parts: tuple[str, ...]):
  # Ensure a rename after resolution cannot redirect the subsequent open through a symlink.
  directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
  directory = os.open(root, directory_flags)
  try:
    for part in parts[:-1]:
      child = os.open(part, directory_flags, dir_fd=directory)
      os.close(directory)
      directory = child
    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
      info = os.fstat(fd)
      if not stat.S_ISREG(info.st_mode):
        raise ValueError("Not a regular file")
      return os.fdopen(fd, "rb"), info.st_size
    except BaseException:
      os.close(fd)
      raise
  finally:
    os.close(directory)


class OutputHandler(SimpleHTTPRequestHandler):
  def __init__(self, *args, token: str, directory: str):
    self.token = require_serve_token(token)
    super().__init__(*args, directory=str(Path(directory).resolve()))

  def _path_after_token(self) -> str | None:
    path = self.path.partition("?")[0]
    leading, _, tail = path.partition("/")
    token, separator, remaining = tail.partition("/")
    if not leading and separator and compare_digest(token.encode("utf-8"), self.token.encode("ascii")):
      return remaining
    return None

  def parse_request(self):
    if not super().parse_request():
      return False
    if self._path_after_token() is None:
      self.send_error(404)
      return False
    return True

  def send_head(self):
    remaining = self._path_after_token()
    if remaining is None:
      self.send_error(404)
      return None
    try:
      parts = unquote(remaining, errors="strict").split("/")
      if any(not part or part.startswith(".") for part in parts):
        raise ValueError("Invalid path")
      root = Path(self.directory)
      path = root.joinpath(*parts).resolve(strict=True)
      relative = path.relative_to(root)
      if any(part.startswith(".") for part in relative.parts) or not path.is_file():
        raise ValueError("Not a visible regular file")
      file, size = _open_beneath(root, relative.parts)
    except (ValueError, OSError, RuntimeError):
      self.send_error(404)
      return None
    try:
      self.send_response(200)
      self.send_header("Content-Type", "text/plain; charset=utf-8")
      self.send_header("Content-Length", str(size))
      self.end_headers()
      return file
    except BaseException:
      file.close()
      raise

  def end_headers(self):
    self.send_header("X-Content-Type-Options", "nosniff")
    self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
    self.send_header("Cache-Control", "no-store")
    self.send_header("Referrer-Policy", "no-referrer")
    super().end_headers()

  def log_message(self, format, *args):
    # Request URLs include the access token.
    pass


def serve_output(directory: Path, port: int, host: str, token: str) -> int:
  if not directory.is_dir():
    raise ValueError("Serve directory must exist")
  handler = partial(OutputHandler, directory=str(directory.resolve()), token=require_serve_token(token))
  with ThreadingHTTPServer((host, port), handler) as server:
    print(f"Serving review output on {host}:{server.server_port}", flush=True)
    try:
      server.serve_forever()
    except KeyboardInterrupt:
      return 0
  return 0
