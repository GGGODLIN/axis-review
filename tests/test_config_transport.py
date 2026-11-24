import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from axis_review.config import Endpoint, load_config
from axis_review.receipts import _get_json


class CredentialTransportTests(unittest.TestCase):
  def load_endpoint(self, url, *, keyed=True):
    with tempfile.TemporaryDirectory() as directory:
      config_path = Path(directory) / "config.toml"
      key_setting = 'api_key_env = "TEST_KEY"\n' if keyed else ""
      config_path.write_text(f'''[endpoints.api]
base_url = "{url}"
{key_setting}
[[axes]]
id = "neutral"
endpoint = "api"
model = "finder"
[verifiers]
for_diff_axes = {{ endpoint = "api", model = "judge" }}
''')
      return load_config(config_path).endpoints["api"]

  def test_remote_http_cannot_use_credentials(self):
    for url in ("http://review.example/v1", "http://localhost.example/v1"):
      with self.subTest(url=url):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
          self.load_endpoint(url)
        with self.assertRaisesRegex(ValueError, "HTTPS"):
          Endpoint(url, api_key_env="TEST_KEY")
    opener = Mock()
    with self.assertRaisesRegex(ValueError, "HTTPS"):
      _get_json(opener, "http://review.example/v1/aci/attestation", "fixture", Mock())
    opener.open.assert_not_called()

  def test_https_loopback_and_keyless_http_remain_supported(self):
    for url, keyed in (("https://review.example/v1", True), ("http://review.example/v1", False),
                       ("http://localhost:8090/v1", True), ("http://127.0.0.1/v1", True),
                       ("http://[::1]:8090/v1", True)):
      with self.subTest(url=url, keyed=keyed):
        self.assertEqual(self.load_endpoint(url, keyed=keyed).base_url, url)
