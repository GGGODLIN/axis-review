"""Generate an optional CVM quote for the saved evidence bytes."""

import hashlib
import json
from pathlib import Path

from .config import Config, ensure_no_credentials


DSTACK_SOCKET = Path("/var/run/dstack.sock")


def write_quote(out_dir: Path, *, config: Config | None = None) -> dict:
  result = {"in_tee": False}
  if DSTACK_SOCKET.exists():
    from dstack_sdk import DstackClientV0
    from httpx import HTTPError

    digest = hashlib.sha256((out_dir / "evidence.json").read_bytes()).digest()
    try:
      # The deployment targets Intel TDX and stores a raw quote, which the v1 API does not return.
      client = DstackClientV0(str(DSTACK_SOCKET))
      with client:
        app_id = client.info().app_id
        quote = client.get_quote(digest).quote
    except HTTPError:
      raise RuntimeError("dstack quote request failed") from None
    if not quote:
      raise ValueError("dstack returned an empty TDX quote")
    result = {"in_tee": True, "app_id": app_id, "evidence_sha256": digest.hex(), "quote": quote}
  payload = (json.dumps(result, indent=2) + "\n").encode()
  ensure_no_credentials(payload, config)
  (out_dir / "tee_quote.json").write_bytes(payload)
  return result
