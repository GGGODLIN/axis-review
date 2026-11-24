import hashlib
import json
import secrets
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from axis_review.config import Config, Endpoint
from axis_review.llm import CallRecord
from axis_review.receipts import process, verify
from axis_review.report import write_calls as write_call_artifacts


def digest(data):
  return "sha256:" + hashlib.sha256(data).hexdigest()


class ReceiptTests(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.saved = self.root / "receipts"
    self.saved.mkdir()
    (self.root / "bodies").mkdir()
    self.request = b'{"model":"test", "messages":[]}'
    self.response = b'{"id":"chat-123","choices":[]}\n'
    self.call = {
      "seq": 1, "endpoint": "phala", "status": 200,
      "receipt_id": "rcpt-123", "response_id": "chat-123", "receipt_expected": True,
      "req_path": "bodies/1.req.json", "resp_path": "bodies/1.resp.json",
    }
    (self.root / self.call["req_path"]).write_bytes(self.request)
    (self.root / self.call["resp_path"]).write_bytes(self.response)
    self.key = Ed25519PrivateKey.generate()
    self.keyset = {
      "subject": None,
      "not_after": int(time.time()) + 3600,
      "receipt_signing_keys": [{
        "key_id": "example", "algo": "ed25519",
        "public_key": self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
      }],
      "e2ee_public_keys": [], "tls_public_keys": [],
    }
    self.report = {"api_version": "aci/1", "attestation": {"workload_keyset": self.keyset}}
    self.receipt = {
      "api_version": "aci/1", "receipt_id": "rcpt-123", "chat_id": "chat-123",
      "model": "test", "endpoint": "/v1/chat/completions", "method": "POST",
      "served_at": int(time.time()), "key_id": "example",
      "event_log": [
        {"type": "request.received", "body_hash": digest(self.request)},
        {"type": "upstream.verified", "result": "verified", "required": True},
        {"type": "response.returned", "body_hash": digest(self.response)},
      ],
    }
    self.write_calls(self.call)
    self.bind_and_sign()

  def write_calls(self, *calls):
    (self.root / "calls.jsonl").write_text("".join(json.dumps(call) + "\n" for call in calls))

  def sign(self):
    self.receipt.pop("signature", None)
    self.receipt["signature"] = self.key.sign(rfc8785.dumps(self.receipt)).hex()

  def bind_and_sign(self):
    value = digest(rfc8785.dumps(self.keyset))
    self.report["workload_keyset_digest"] = value
    self.receipt["workload_keyset_digest"] = value
    self.sign()

  def save(self):
    (self.saved / "1.json").write_text(json.dumps(self.receipt))
    (self.saved / "attestation-phala.json").write_text(json.dumps(self.report))

  def assert_status(self, check, status):
    summary = verify(self.root)
    self.assertEqual(summary["receipts"][0]["checks"][check], status)
    self.assertEqual(summary["checks"][check][status], 1)
    self.assertEqual(summary["verified"], 0)
    return summary["receipts"][0]["checks"]

  def test_valid_receipt(self):
    self.save()
    summary = verify(self.root)
    self.assertEqual((summary["expected"], summary["fetched"], summary["verified"], summary["missing"]), (1, 1, 1, 0))
    self.assertEqual(set(summary["receipts"][0]["checks"].values()), {"pass"})
    self.assertEqual(summary["not_verified"], [
      "TDX quote vs Intel DCAP collateral",
      "RTMR3 event-log replay / compose hash",
      "attested upstream session",
    ])

  def test_verify_leaves_input_bundle_unchanged(self):
    self.save()
    before = {file: file.read_bytes() for file in self.root.rglob("*") if file.is_file()}
    self.assertEqual(verify(self.root)["verified"], 1)
    self.assertEqual({file: file.read_bytes() for file in self.root.rglob("*") if file.is_file()}, before)

  def test_signed_receipt_identity_matches_lookup_id(self):
    for id_field, alternate in (("receipt_id", "rcpt-other"), ("chat_id", "chat-other")):
      original = self.receipt[id_field]
      self.write_calls(self.call if id_field == "receipt_id" else {**self.call, "receipt_id": None})
      for value in (alternate, None):
        with self.subTest(id_field=id_field, value=value):
          if value is None:
            self.receipt.pop(id_field)
          else:
            self.receipt[id_field] = value
          self.sign()
          self.save()
          checks = self.assert_status("identity", "fail")
          self.assertEqual(checks["signature"], "pass")
      self.receipt[id_field] = original
      self.sign()
      self.save()
      self.assertEqual(verify(self.root)["verified"], 1)

  def test_expected_calls_survive_missing_artifacts_and_ids(self):
    self.saved.rmdir()
    self.write_calls(
      self.call,
      {**self.call, "seq": 2, "receipt_id": None, "response_id": None},
      {**self.call, "seq": 3, "receipt_expected": False},
    )
    summary = verify(self.root)
    self.assertEqual((summary["expected"], summary["verified"], summary["missing"]), (2, 0, 2))
    self.assertEqual([(row["seq"], row["checks"]["receipt"]) for row in summary["receipts"]],
                     [(1, "missing"), (2, "missing")])
    self.assertFalse(self.saved.exists())

  def test_saved_call_index_tracks_receipts_without_artifacts(self):
    config = Config({
      "phala": Endpoint("https://receipt.example/v1", receipts="phala-aci"),
      "local": Endpoint("http://127.0.0.1/v1"),
    }, (), {})
    calls = [CallRecord(seq, "initial", "neutral", endpoint, "finder", "finder", b"{}", b"{}",
                        status, {}, None, None, 0, None, None)
             for seq, endpoint, status in ((1, "phala", 200), (2, "phala", 429), (3, "local", 200))]
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      write_call_artifacts(root, calls, config)
      summary = verify(root)
    self.assertEqual((summary["expected"], summary["verified"], summary["missing"]), (1, 0, 1))
    self.assertEqual([row["seq"] for row in summary["receipts"]], [1])

  def test_tampered_signature(self):
    signature = bytearray.fromhex(self.receipt["signature"])
    signature[0] ^= 1
    self.receipt["signature"] = signature.hex()
    self.save()
    self.assert_status("signature", "fail")

  def test_exact_request_and_response_bytes(self):
    self.save()
    for kind, data in (("req", self.request), ("resp", self.response)):
      with self.subTest(kind=kind):
        path = self.root / self.call[f"{kind}_path"]
        path.write_bytes(data + b" ")
        check = {"req": "request_body_hash", "resp": "response_body_hash"}[kind]
        self.assert_status(check, "fail")
        path.write_bytes(data)

  def test_keyset_digest_must_match_report_and_receipt(self):
    for source in (self.report, self.receipt):
      original = source["workload_keyset_digest"]
      source["workload_keyset_digest"] = "sha256:" + "0" * 64
      self.sign()
      self.save()
      checks = self.assert_status("keyset_digest", "fail")
      self.assertEqual(checks["signature"], "pass")
      source["workload_keyset_digest"] = original

  def test_expired_keyset(self):
    self.keyset["not_after"] = int(time.time()) - 1
    self.bind_and_sign()
    self.save()
    self.assert_status("keyset_expiry", "fail")

  def test_unsupported_algorithm(self):
    self.keyset["receipt_signing_keys"][0]["algo"] = "ecdsa"
    self.bind_and_sign()
    self.save()
    self.assert_status("signing_key", "unsupported")
    self.assert_status("signature", "unsupported")

  def test_upstream_must_be_required_and_verified(self):
    for result, required in (("failed", True), ("verified", False), ("verified", 1)):
      with self.subTest(result=result, required=required):
        self.receipt["event_log"][1].update(result=result, required=required)
        self.sign()
        self.save()
        checks = self.assert_status("upstream_verified", "fail")
        self.assertEqual(checks["signature"], "pass")

  def test_missing_receipt(self):
    self.save()
    (self.saved / "1.json").unlink()
    checks = self.assert_status("receipt", "missing")
    self.assertEqual(checks["signature"], "unavailable")

  def test_process_discards_provider_data_with_synthetic_credential_marker(self):
    marker = secrets.token_hex(16)
    payload = json.dumps({"fixture_marker": marker}).encode()
    endpoint = {"base_url": "http://127.0.0.1/v1", "api_key": marker}
    with patch("axis_review.receipts.urllib.request.build_opener") as build_opener:
      opener = build_opener.return_value
      opener.open.side_effect = lambda *args, **kwargs: BytesIO(payload)
      summary = process(self.root, {"phala": endpoint})
    self.assertEqual(opener.open.call_count, 2)
    self.assertEqual(summary["checks"]["receipt"]["missing"], 1)
    self.assertFalse((self.saved / "1.json").exists())
    saved = json.loads((self.saved / "attestation-phala.json").read_bytes())
    self.assertEqual(set(saved), {"nonce", "fetch_error"})
    self.assertTrue(saved["fetch_error"])
    self.assertEqual(json.loads((self.saved / "verification.json").read_text()), summary)

  def test_process_uses_same_credential_and_one_nonce_per_endpoint(self):
    self.write_calls(
      self.call,
      {**self.call, "seq": 2, "receipt_id": None},
      {**self.call, "seq": 3, "status": 429, "receipt_expected": False},
      {**self.call, "seq": 4, "endpoint": "magpie", "receipt_expected": False},
      {**self.call, "seq": 5, "receipt_id": "rcpt-missing"},
      {**self.call, "seq": 6, "receipt_id": "rcpt-unavailable"},
      {**self.call, "seq": 7, "receipt_id": "rcpt-redirect"},
    )
    stub_key = secrets.token_hex(16)
    requests = []
    report, receipt = self.report, self.receipt

    class Handler(BaseHTTPRequestHandler):
      def log_message(self, format, *args):
        return

      def do_GET(self):
        request = urlsplit(self.path)
        authorized = self.headers.get("Authorization") == f"Bearer {stub_key}"
        requests.append((request.path, parse_qs(request.query), authorized))
        if not authorized:
          self.send_error(401)
          return
        if request.path.endswith("/attestation"):
          payload = report
        elif request.path.endswith(("/rcpt-123", "/chat-123")):
          payload = receipt
        elif request.path.endswith("/rcpt-unavailable"):
          self.send_error(503)
          return
        elif request.path.endswith("/rcpt-redirect"):
          self.send_response(302)
          self.send_header("Location", "/unexpected")
          self.end_headers()
          return
        else:
          self.send_error(404)
          return
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
      worker = threading.Thread(target=server.serve_forever)
      worker.start()
      try:
        endpoint = {"base_url": f"http://127.0.0.1:{server.server_port}/v1/", "api_key": stub_key}
        with patch("axis_review.receipts.time.sleep"):
          summary = process(self.root, {"phala": endpoint})
      finally:
        server.shutdown()
        worker.join()

    self.assertEqual((summary["fetched"], summary["verified"]), (2, 2))
    self.assertEqual(summary["checks"]["receipt"]["missing"], 3)
    self.assertEqual([entry["seq"] for entry in summary["receipts"]], [1, 2, 5, 6, 7])
    self.assertEqual(sorted(path for path, _, _ in requests), [
      "/v1/aci/attestation", "/v1/aci/receipts/chat-123",
      "/v1/aci/receipts/rcpt-123", "/v1/aci/receipts/rcpt-missing",
      "/v1/aci/receipts/rcpt-redirect",
      "/v1/aci/receipts/rcpt-unavailable", "/v1/aci/receipts/rcpt-unavailable",
      "/v1/aci/receipts/rcpt-unavailable",
    ])
    self.assertTrue(all(authorized for _, _, authorized in requests))
    nonce_query = next(query for path, query, _ in requests if path.endswith("/attestation"))
    self.assertRegex(nonce_query["nonce"][0], r"^[0-9a-f]{64}$")
    saved_report = json.loads((self.saved / "attestation-phala.json").read_text())
    self.assertEqual(saved_report, {**report, "nonce": nonce_query["nonce"][0]})
    self.assertEqual(json.loads((self.saved / "1.json").read_text()), receipt)
    self.assertEqual(json.loads((self.saved / "2.json").read_text()), receipt)
