import json
import os
import time
from http.client import HTTPException, IncompleteRead
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Lock
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import Config, ensure_no_credentials


UNAVAILABLE = "UNAVAILABLE"
BACKOFF = (2, 4, 8, 16)


class NoRedirect(HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None


class ChatError(RuntimeError):
  pass


@dataclass(frozen=True)
class CallRecord:
  seq: int
  phase: str
  axis: str
  endpoint: str
  model: str
  model_observed: str
  request_bytes: bytes
  response_bytes: bytes
  status: int | None
  headers: dict[str, str]
  response_id: str | None
  receipt_id: str | None
  latency_s: float
  usage: dict | None
  error: str | None


def _retry_delay(value: str | None, fallback: int) -> float:
  if not value:
    return fallback
  try:
    return max(0, int(value))
  except ValueError:
    try:
      when = parsedate_to_datetime(value)
      if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
      return max(0, (when - datetime.now(timezone.utc)).total_seconds())
    except (ValueError, TypeError, OverflowError):
      return fallback


def _string(value) -> str | None:
  if not isinstance(value, str) or not value.strip():
    return None
  try:
    value.encode("utf-8")
  except UnicodeEncodeError:
    return None
  return value.strip()


def _decode(payload: bytes) -> dict | None:
  try:
    result = json.loads(payload)
    json.dumps(result, allow_nan=False)
  except (ValueError, RecursionError):
    return None
  return result if isinstance(result, dict) else None


def _check_json_strings(value, config: Config) -> None:
  if isinstance(value, str):
    ensure_no_credentials(value.encode("utf-8", errors="backslashreplace"), config)
    # Assistant content and tool arguments can themselves carry serialized JSON.
    text = value.strip()
    if text.startswith("```") and text.endswith("```"):
      text = text[3:-3].removeprefix("json").removeprefix("JSON").strip()
    if text.startswith(("{", "[", '"')):
      try:
        embedded = json.loads(text)
      except ValueError:
        return
      _check_json_strings(embedded, config)
  elif isinstance(value, dict):
    for key, child in value.items():
      _check_json_strings(key, config)
      _check_json_strings(child, config)
  elif isinstance(value, list):
    for child in value:
      _check_json_strings(child, config)


def unsafe_body_reason(payload: bytes, config: Config) -> str | None:
  names = {"GITHUB_TOKEN", *(endpoint.api_key_env for endpoint in config.endpoints.values() if endpoint.api_key_env)}
  if not any(os.environ.get(name) for name in names):
    return None
  try:
    ensure_no_credentials(payload, config)
  except ValueError:
    return "Body contains an environment credential"
  try:
    decoded = json.loads(payload)
    _check_json_strings(decoded, config)
  except (ValueError, RecursionError):
    return "Body may contain a credential or could not be safely checked"
  return None


class Client:
  def __init__(self, config: Config, *, timeout: float = 120, sleep=time.sleep):
    self.config = config
    self.timeout = timeout
    self.sleep = sleep
    self.records: list[CallRecord] = []
    self._lock = Lock()
    self._seq = 0

  def chat(self, *, phase, axis, endpoint, model, messages, tools=None,
           response_format=None, temperature=0) -> tuple[dict, CallRecord]:
    target = self.config.endpoints[endpoint]
    body = {"model": model, "messages": messages, "stream": False, "temperature": temperature}
    if tools is not None:
      body["tools"] = tools
    if response_format is not None:
      body["response_format"] = response_format
    if target.max_tokens is not None:
      body["max_tokens"] = target.max_tokens
    body.update(target.model_params.get(model, {}))
    try:
      payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
      raise ChatError("Chat request is not valid UTF-8 JSON") from None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
      if reason := unsafe_body_reason(payload, self.config):
        raise ValueError(reason)
      key = target.api_key()
    except ValueError as error:
      raise ChatError(str(error)) from None
    if key is not None:
      headers["Authorization"] = f"Bearer {key}"
    request = Request(f"{target.base_url}/chat/completions", data=payload, headers=headers)
    opener = build_opener(NoRedirect())
    timeout = self.timeout if target.timeout_s is None else target.timeout_s

    for attempt in range(len(BACKOFF) + 1):
      with self._lock:
        self._seq += 1
        seq = self._seq
      start = time.monotonic()
      status, received_headers, response, transport_error = None, {}, b"", None
      try:
        try:
          reply = opener.open(request, timeout=timeout)
        except HTTPError as error:
          reply = error
        with reply:
          status = reply.code
          received_headers = {name.lower(): value for name, value in reply.headers.items()}
          response = reply.read()
      except IncompleteRead as error:
        response = error.partial
        transport_error = "Incomplete HTTP response"
      except (OSError, HTTPException, EOFError) as error:
        transport_error = type(error).__name__

      decoded = _decode(response)
      unsafe = unsafe_body_reason(response, self.config)
      fields = decoded if decoded is not None and unsafe is None else {}
      http_ok = status is not None and 200 <= status < 300
      error_text = transport_error
      if error_text is None and not http_ok:
        error_text = f"HTTP {status}"
      if error_text is None and unsafe:
        error_text = unsafe
      if error_text is None and decoded is None:
        error_text = "Response is not a JSON object"
      usage = fields.get("usage")
      record = CallRecord(
        seq, phase, axis, endpoint, model, _string(fields.get("model")) or UNAVAILABLE,
        payload, response, status, received_headers, _string(fields.get("id")),
        _string(received_headers.get("x-receipt-id")), time.monotonic() - start,
        usage if isinstance(usage, dict) else None, error_text,
      )
      with self._lock:
        self.records.append(record)
      if error_text is None:
        return decoded, record
      retryable = transport_error is not None or status == 429 or (status is not None and 500 <= status < 600)
      if not retryable or attempt == len(BACKOFF):
        raise ChatError(error_text)
      self.sleep(_retry_delay(received_headers.get("retry-after"), BACKOFF[attempt]))
    raise AssertionError("HTTP attempt loop exhausted")
