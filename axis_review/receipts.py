"""Collect Phala ACI artifacts and check their offline consistency."""

import hashlib
import http.client
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from binascii import Error as HexError, unhexlify
from pathlib import Path

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import Config, ensure_no_credentials, require_credential_transport


NOT_VERIFIED = (
  "TDX quote vs Intel DCAP collateral",
  "RTMR3 event-log replay / compose hash",
  "attested upstream session",
)
CHECKS = (
  "receipt",
  "identity",
  "keyset_digest",
  "keyset_expiry",
  "signing_key",
  "signature",
  "request_body_hash",
  "response_body_hash",
  "upstream_verified",
)
STATUSES = ("pass", "fail", "missing", "unsupported", "unavailable")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
  # urllib's default redirect handler can forward Authorization to another origin.
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None


def _unique_object(pairs):
  obj = dict(pairs)
  if len(obj) != len(pairs):
    raise ValueError("Duplicate JSON member")
  return obj


def _decode_object(raw: bytes) -> dict:
  data = json.loads(raw, object_pairs_hook=_unique_object)
  if not isinstance(data, dict):
    raise ValueError("Expected a JSON object")
  return data


def _get_json(opener, url: str, api_key: str | None, validate_bytes) -> dict | None:
  headers = {"Accept": "application/json"}
  if api_key is not None:
    require_credential_transport(url)
    headers["Authorization"] = f"Bearer {api_key}"
  for attempt in range(3):
    try:
      request = urllib.request.Request(url, headers=headers)
      with opener.open(request, timeout=15) as response:
        data = _decode_object(response.read())
      validate_bytes(json.dumps(data, allow_nan=False).encode())
      return data
    except urllib.error.HTTPError as error:
      error.close()
      if error.code != 429 and not 500 <= error.code < 600:
        return None
    except (ValueError, RecursionError):
      return None
    except (OSError, http.client.HTTPException):
      pass
    if attempt < 2:
      time.sleep(0.25 * 2**attempt)
  return None


def _write_json(path: Path, value: dict) -> None:
  path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _attestation_path(receipts_dir: Path, endpoint: str) -> Path:
  return receipts_dir / f"attestation-{urllib.parse.quote(endpoint, safe='')}.json"


def _successful_calls(out_dir: Path):
  with (out_dir / "calls.jsonl").open(encoding="utf-8") as records:
    for line in records:
      if line.strip():
        call = _decode_object(line)
        status = call.get("status")
        if type(status) is int and 200 <= status < 300:
          if type(call.get("seq")) is not int or not isinstance(call.get("endpoint"), str):
            raise ValueError("Successful calls require an integer seq and a string endpoint")
          yield call


def _receipt_lookup(call: dict) -> tuple[str, str | None]:
  for call_field, signed_field in (("receipt_id", "receipt_id"), ("response_id", "chat_id")):
    value = call.get(call_field)
    if isinstance(value, str) and value:
      return signed_field, value
  return "receipt_id", None


def process(out_dir: Path, endpoints: dict[str, dict], *, config: Config | None = None) -> dict:
  """Fetch artifacts with the inference credential and then verify them offline."""
  receipts_dir = out_dir / "receipts"
  receipts_dir.mkdir(exist_ok=True)
  opener = urllib.request.build_opener(_NoRedirect())
  keys = tuple(target["api_key"] for target in endpoints.values())

  def validate_bytes(data):
    ensure_no_credentials(data, config, extra_keys=keys)

  for call in _successful_calls(out_dir):
    if call["endpoint"] not in endpoints:
      continue
    _, receipt_id = _receipt_lookup(call)
    if receipt_id is None:
      continue
    target = endpoints[call["endpoint"]]
    base_url = target["base_url"].rstrip("/")
    encoded_id = urllib.parse.quote(receipt_id, safe="")
    receipt = _get_json(opener, f"{base_url}/aci/receipts/{encoded_id}", target["api_key"], validate_bytes)
    if receipt is not None:
      _write_json(receipts_dir / f"{call['seq']}.json", receipt)

  for endpoint, target in endpoints.items():
    nonce = secrets.token_hex(32)
    base_url = target["base_url"].rstrip("/")
    report = _get_json(opener, f"{base_url}/aci/attestation?nonce={nonce}", target["api_key"], validate_bytes)
    if report is None:
      report = {"fetch_error": True}
    _write_json(_attestation_path(receipts_dir, endpoint), {**report, "nonce": nonce})
  summary = _verify(out_dir, endpoints=set(endpoints))
  _write_json(receipts_dir / "verification.json", summary)
  return summary


def _read_object(path: Path) -> tuple[dict | None, str]:
  try:
    return _decode_object(path.read_bytes()), "pass"
  except FileNotFoundError:
    return None, "missing"
  except (OSError, ValueError, RecursionError):
    return None, "fail"


def _digest(data: bytes) -> str:
  return "sha256:" + hashlib.sha256(data).hexdigest()


def _object(value) -> dict:
  return value if isinstance(value, dict) else {}


def _status(passed: bool) -> str:
  return "pass" if passed else "fail"


def _keyset_digest_status(report: dict, keyset: dict, receipt: dict) -> str:
  try:
    digest = _digest(rfc8785.dumps(keyset))
  except (ValueError, RecursionError):
    return "fail"
  return _status(digest == report.get("workload_keyset_digest") == receipt.get("workload_keyset_digest"))


def _signature_checks(keyset: dict, receipt: dict) -> tuple[str, str]:
  signing_keys = keyset.get("receipt_signing_keys")
  key_id = receipt.get("key_id")
  if not isinstance(signing_keys, list) or not isinstance(key_id, str) or not key_id:
    return "fail", "unavailable"
  matches = [key for key in signing_keys if _object(key).get("key_id") == key_id]
  if len(matches) != 1:
    return "fail", "unavailable"
  key = matches[0]
  if not isinstance(key.get("algo"), str):
    return "fail", "unavailable"
  if key["algo"] != "ed25519":
    return "unsupported", "unsupported"
  try:
    public_key = Ed25519PublicKey.from_public_bytes(unhexlify(key["public_key"]))
  except (HexError, KeyError, TypeError, ValueError):
    return "fail", "unavailable"
  try:
    unsigned = {field: value for field, value in receipt.items() if field != "signature"}
    public_key.verify(unhexlify(receipt["signature"]), rfc8785.dumps(unsigned))
  except (HexError, InvalidSignature, KeyError, TypeError, ValueError, RecursionError):
    return "pass", "fail"
  return "pass", "pass"


def _event(receipt: dict, event_type: str) -> dict:
  events = receipt.get("event_log")
  if not isinstance(events, list):
    return {}
  matches = [event for event in events if _object(event).get("type") == event_type]
  return matches[0] if len(matches) == 1 else {}


def _body_hash_status(root: Path, path, event: dict) -> str:
  if not isinstance(path, str) or not path or not isinstance(event.get("body_hash"), str):
    return "fail"
  try:
    body = (root / path).resolve()
    if not body.is_relative_to(root):
      return "fail"
    return _status(_digest(body.read_bytes()) == event["body_hash"])
  except (OSError, RuntimeError, ValueError):
    return "fail"


def _check_receipt(root: Path, call: dict, receipt: dict, report: dict | None, now: float) -> dict:
  checks = dict.fromkeys(CHECKS, "unavailable")
  checks["receipt"] = "pass"
  signed_field, expected_id = _receipt_lookup(call)
  checks["identity"] = _status(expected_id is not None and receipt.get(signed_field) == expected_id)
  keyset = _object(_object(_object(report).get("attestation")).get("workload_keyset"))
  if keyset:
    checks["keyset_digest"] = _keyset_digest_status(report, keyset, receipt)
    expiry = keyset.get("not_after")
    checks["keyset_expiry"] = _status(type(expiry) in (int, float) and now < expiry < float("inf"))
    checks["signing_key"], checks["signature"] = _signature_checks(keyset, receipt)
  elif report is not None and not report.get("fetch_error"):
    checks["keyset_digest"] = "fail"
  checks["request_body_hash"] = _body_hash_status(
    root, call.get("req_path"), _event(receipt, "request.received"),
  )
  checks["response_body_hash"] = _body_hash_status(
    root, call.get("resp_path"), _event(receipt, "response.returned"),
  )
  upstream = _event(receipt, "upstream.verified")
  checks["upstream_verified"] = _status(upstream.get("result") == "verified" and upstream.get("required") is True)
  return checks


def verify(out_dir: Path) -> dict:
  """Check saved artifacts without writing, networking, or trusting the gateway quote."""
  return _verify(out_dir)


def _verify(out_dir: Path, endpoints: set[str] | None = None) -> dict:
  root = out_dir.resolve()
  receipts_dir = root / "receipts"
  counts = {check: dict.fromkeys(STATUSES, 0) for check in CHECKS}
  rows = []
  verified = 0
  now = time.time()
  for call in _successful_calls(root):
    seq, endpoint = call["seq"], call["endpoint"]
    expected = call.get("receipt_expected")
    if "receipt_expected" in call and type(expected) is not bool:
      raise ValueError("receipt_expected must be a boolean")
    if expected is None and endpoints is not None:
      expected = endpoint in endpoints
    if expected is False:
      continue
    receipt, receipt_status = _read_object(receipts_dir / f"{seq}.json")
    attestation_path = _attestation_path(receipts_dir, endpoint)
    if expected is None and receipt_status == "missing" and not attestation_path.exists():
      # Older bundles did not record which endpoints expected receipts.
      continue
    if receipt is None:
      checks = {**dict.fromkeys(CHECKS, "unavailable"), "receipt": receipt_status}
    else:
      report, _ = _read_object(attestation_path)
      checks = _check_receipt(root, call, receipt, report, now)
    for check, status in checks.items():
      counts[check][status] += 1
    verified += all(status == "pass" for status in checks.values())
    rows.append({"seq": seq, "endpoint": endpoint, "checks": checks})
  return {
    "expected": len(rows),
    "fetched": counts["receipt"]["pass"],
    "verified": verified,
    "missing": counts["receipt"]["missing"],
    "checks": counts,
    "receipts": rows,
    "not_verified": list(NOT_VERIFIED),
  }
