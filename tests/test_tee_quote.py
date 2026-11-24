import hashlib
import json
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

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
      client = Mock()
      client.info.return_value = SimpleNamespace(app_id="test-app")
      client.get_quote.return_value = SimpleNamespace(quote="quote-data")
      factory = Mock(return_value=client)
      sdk = SimpleNamespace(DstackClient=factory)
      with patch("axis_review.tee_quote.DSTACK_SOCKET", socket):
        with patch.dict(sys.modules, {"dstack_sdk": sdk}):
          result = write_quote(root)
      factory.assert_called_once_with()
      client.info.assert_called_once_with()
      client.get_quote.assert_called_once_with(hashlib.sha256(evidence).digest())
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
      client = Mock()
      client.info.return_value = SimpleNamespace(app_id="test-app")
      client.get_quote.return_value = SimpleNamespace(quote=marker)
      sdk = SimpleNamespace(DstackClient=Mock(return_value=client))
      with (patch("axis_review.tee_quote.DSTACK_SOCKET", socket),
            patch.dict(sys.modules, {"dstack_sdk": sdk}),
            patch.dict("os.environ", {"GITHUB_TOKEN": marker})):
        with self.assertRaisesRegex(ValueError, "contains an environment credential"):
          write_quote(root)
      self.assertFalse((root / "tee_quote.json").exists())
