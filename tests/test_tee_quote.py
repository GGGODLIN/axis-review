import hashlib
import json
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from axis_review.tee_quote import write_quote


class TeeQuoteTests(unittest.TestCase):
  def test_no_socket_does_not_need_sdk_or_evidence(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      with patch("axis_review.tee_quote.DSTACK_SOCKET", root / "missing.sock"):
        with patch.dict(sys.modules, {"dstack_sdk": None}):
          result = write_quote(root)
      self.assertEqual(result, {"in_tee": False})
      self.assertEqual(json.loads((root / "tee_quote.json").read_text()), result)

  def test_socket_requests_quote_over_exact_evidence_digest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      socket = root / "dstack.sock"
      socket.touch()
      evidence = b'{"findings": []}\n'
      (root / "evidence.json").write_bytes(evidence)
      try:
        import dstack_sdk
        import httpx
      except ImportError:
        self.skipTest("Install the tee extra to exercise the dstack SDK")

      requests = []

      def rpc(request):
        requests.append((request.url.path, json.loads(request.content)))
        if request.url.path == "/Info":
          return httpx.Response(200, json={
            "app_id": "test-app", "instance_id": "", "app_cert": "", "app_name": "",
            "device_id": "", "key_provider_info": "", "compose_hash": "",
            "tcb_info": {"app_compose": "", "event_log": []},
          })
        return httpx.Response(200, json={"quote": "quote-data", "event_log": "[]"})

      with (patch("axis_review.tee_quote.DSTACK_SOCKET", socket),
            patch.object(httpx, "HTTPTransport", return_value=httpx.MockTransport(rpc)) as transport):
        self.assertTrue(hasattr(dstack_sdk.DstackClientV0, "get_quote"))
        result = write_quote(root)
      transport.assert_called_once_with(uds=str(socket))
      self.assertEqual(requests, [
        ("/Info", {}), ("/GetQuote", {"report_data": hashlib.sha256(evidence).hexdigest()}),
      ])
      self.assertEqual(result, {
        "in_tee": True, "app_id": "test-app", "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        "quote": "quote-data",
      })
      self.assertEqual(json.loads((root / "tee_quote.json").read_text()), result)

  def test_quote_discards_data_with_synthetic_credential_marker(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      socket = root / "dstack.sock"
      socket.touch()
      (root / "evidence.json").write_bytes(b"{}\n")
      marker = secrets.token_hex(16)
      client = MagicMock()
      client.info.return_value = SimpleNamespace(app_id="test-app")
      client.get_quote.return_value = SimpleNamespace(quote=marker)
      sdk = SimpleNamespace(DstackClientV0=lambda endpoint: client)
      transport = SimpleNamespace(HTTPError=OSError)
      with (patch("axis_review.tee_quote.DSTACK_SOCKET", socket),
            patch.dict(sys.modules, {"dstack_sdk": sdk, "httpx": transport}),
            patch.dict("os.environ", {"GITHUB_TOKEN": marker})):
        with self.assertRaisesRegex(ValueError, "contains an environment credential"):
          write_quote(root)
      self.assertFalse((root / "tee_quote.json").exists())
