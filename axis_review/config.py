import json
import os
import tomllib
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit


AXIS_IDS = ("primary", "neutral", "adversarial")


def require_credential_transport(base_url: str) -> None:
  url = urlsplit(base_url)
  if url.scheme == "https":
    return
  if url.scheme == "http" and url.hostname:
    if url.hostname == "localhost":
      return
    try:
      if ip_address(url.hostname).is_loopback:
        return
    except ValueError:
      pass
  raise ValueError("Endpoints with API credentials require HTTPS unless the host is loopback")


@dataclass(frozen=True)
class Endpoint:
  base_url: str
  api_key_env: str | None = None
  receipts: str = "none"
  # Some gateways default to a completion cap too small for a JSON review plus reasoning, and fail with HTTP 400.
  max_tokens: int | None = None

  def __post_init__(self) -> None:
    if self.api_key_env is not None:
      require_credential_transport(self.base_url)

  def api_key(self) -> str | None:
    if self.api_key_env is None:
      return None
    key = os.environ.get(self.api_key_env)
    if not key or any(not 33 <= ord(char) <= 126 for char in key):
      raise ValueError(f"Missing or invalid environment variable: {self.api_key_env}")
    return key


@dataclass(frozen=True)
class Model:
  endpoint: str
  model: str


@dataclass(frozen=True)
class Axis(Model):
  id: str


@dataclass(frozen=True)
class Config:
  endpoints: dict[str, Endpoint]
  axes: tuple[Axis, ...]
  verifiers: dict[str, Model]
  language: str = "en"
  max_tool_turns: int = 12
  verify_batch_size: int = 6
  spec_globs: tuple[str, ...] = ()
  spec_max_chars: int = 60_000


def _table(value, label: str) -> dict:
  if not isinstance(value, dict):
    raise ValueError(f"{label} must be a table")
  return value


def _text(value, label: str) -> str:
  if not isinstance(value, str) or not value.strip() or value != value.strip():
    raise ValueError(f"{label} must be a non-empty string without surrounding whitespace")
  return value


def _positive(value, label: str, minimum: int = 1) -> int:
  if type(value) is not int or value < minimum:
    raise ValueError(f"{label} must be an integer >= {minimum}")
  return value


def _endpoint(raw, name: str) -> Endpoint:
  table = _table(raw, f"endpoints.{name}")
  base_url = _text(table.get("base_url"), f"endpoints.{name}.base_url")
  try:
    url = urlsplit(base_url)
    port = url.port
    valid = (url.scheme in {"http", "https"} and url.hostname and (port is None or port > 0)
             and url.username is None and url.password is None and "@" not in url.netloc
             and not url.query and not url.fragment and not any(char.isspace() for char in base_url))
  except ValueError:
    valid = False
  if not valid:
    raise ValueError(f"endpoints.{name}.base_url must be an HTTP(S) URL without credentials, query, or fragment")
  key_env = table.get("api_key_env")
  if key_env is not None:
    _text(key_env, f"endpoints.{name}.api_key_env")
  receipts = table.get("receipts", "none")
  if receipts not in ("none", "phala-aci"):
    raise ValueError(f"Invalid receipt provider for endpoint {name}")
  max_tokens = table.get("max_tokens")
  if max_tokens is not None:
    _positive(max_tokens, f"endpoints.{name}.max_tokens")
  return Endpoint(base_url.rstrip("/"), key_env, receipts, max_tokens)


def load_config(path: str | Path) -> Config:
  with Path(path).open("rb") as file:
    data = tomllib.load(file)
  endpoints = {name: _endpoint(raw, name)
               for name, raw in _table(data.get("endpoints"), "endpoints").items()}

  def model(raw, label):
    table = _table(raw, label)
    endpoint = _text(table.get("endpoint"), f"{label}.endpoint")
    if endpoint not in endpoints:
      raise ValueError(f"{label} references an undefined endpoint")
    return Model(endpoint, _text(table.get("model"), f"{label}.model"))

  axes = []
  raw_axes = data.get("axes")
  if not isinstance(raw_axes, list) or not raw_axes:
    raise ValueError("At least one axis is required")
  for raw in raw_axes:
    axis_id = _table(raw, "axis").get("id")
    if axis_id not in AXIS_IDS or any(axis.id == axis_id for axis in axes):
      raise ValueError("Axis IDs must be unique and use primary, neutral, or adversarial")
    target = model(raw, f"axis {axis_id}")
    axes.append(Axis(target.endpoint, target.model, axis_id))
  verifiers = {name: model(raw, f"verifiers.{name}")
               for name, raw in _table(data.get("verifiers"), "verifiers").items()}
  if verifiers.keys() - {"for_primary", "for_diff_axes"}:
    raise ValueError("Unknown verifier role")
  for axis in axes:
    role = verifier_role(axis.id)
    if role not in verifiers:
      raise ValueError(f"Axis {axis.id} requires verifiers.{role}")
    if verifiers[role].model == axis.model:
      raise ValueError(f"Axis {axis.id} and verifiers.{role} must use different models")

  globs = data.get("spec_globs", [])
  if not isinstance(globs, list):
    raise ValueError("spec_globs must be an array of strings")
  return Config(
    endpoints, tuple(axes), verifiers,
    _text(data.get("language", "en"), "language"),
    _positive(data.get("max_tool_turns", 12), "max_tool_turns", 0),
    _positive(data.get("verify_batch_size", 6), "verify_batch_size"),
    tuple(_text(glob, "spec_globs entry") for glob in globs),
    _positive(data.get("spec_max_chars", 60_000), "spec_max_chars", 0),
  )


def verifier_role(axis: str) -> str:
  return "for_primary" if axis == "primary" else "for_diff_axes"


def ensure_no_credentials(data: bytes, config: Config | None = None, *, extra_keys=()) -> None:
  names = {"GITHUB_TOKEN"}
  if config is not None:
    names.update(endpoint.api_key_env for endpoint in config.endpoints.values() if endpoint.api_key_env)
  keys = {*extra_keys, *(os.environ.get(name) for name in names)}
  for key in keys:
    if key and (key.encode() in data or json.dumps(key)[1:-1].encode() in data):
      raise ValueError("Review data contains an environment credential")
