"""
Stand-alone threat-feed verifier for the public feed repository (security-feed).

It checks threat_feed.json exactly the way Security (core/cloud_intel.py) accepts a feed, so the
publishing workflow can refuse a feed the app would reject, without access to the app's private
source code. Needs only the `cryptography` package.

    python verify_feed.py threat_feed.json

Keep FEED_KEYRING identical to FEED_KEYRING in core/cloud_intel.py (a test in the app repo
checks this). Only PUBLIC keys belong here.
"""

import hashlib
import json
import re
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FEED_KEYRING = {
    "k1": "e415786a2a27a188e91e4e2e1d30076ac015c40a12795c398603e8bd06bd74cf",
    "k2": "e7af1370f3e4b83500118e07cac433ff5ff8e7cb8cf20f7b89edd42d51d2fd11",
    "k3": "45baed5684d0ab3b598a7ffc171984c2f9e2340451b3e1d35a011a2959e74148",
}
LEGACY_FEED_KEY_ID = "k1"
MAX_AGE_DAYS = 30.0
MAX_FEED_BYTES = 20 * 1024 * 1024


def canonical_payload(signatures, domains=None, feed_version=None, metadata=None) -> bytes:
    canonical = {"signatures": signatures}
    if domains is not None:
        canonical["domains"] = domains
    if feed_version is not None:
        canonical["feed_version"] = feed_version
    if metadata is not None:
        canonical["metadata"] = metadata
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _timestamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                return time.mktime(time.strptime(value, fmt))
            except ValueError:
                pass
        try:
            return float(value)
        except ValueError:
            return None
    return None


def verify(feed, now=None):
    """(ok, reason) for a parsed feed manifest."""
    now = time.time() if now is None else now
    if not isinstance(feed, dict) or not isinstance(feed.get("signatures"), list):
        return False, "feed must be an object with a 'signatures' array"
    meta = feed.get("metadata") if isinstance(feed.get("metadata"), dict) else {}
    expires = _timestamp(meta.get("expires_at"))
    if expires is not None and now > expires:
        return False, "feed has expired (metadata.expires_at is in the past)"
    issued = _timestamp(meta.get("issued_at") or meta.get("timestamp"))
    if issued is not None and now - issued > MAX_AGE_DAYS * 86400:
        return False, f"feed is older than {MAX_AGE_DAYS:.0f} days"
    if "checksum" in feed:
        expected = hashlib.sha256(json.dumps(feed["signatures"], sort_keys=True,
                                             separators=(",", ":")).encode("utf-8")).hexdigest()
        if feed["checksum"] != expected:
            return False, "checksum does not match the signatures array"
    sig_hex = feed.get("signature") or feed.get("ed25519_signature")
    if not isinstance(sig_hex, str) or not sig_hex:
        return False, "Ed25519 signature missing"
    key_id = meta.get("key_id", LEGACY_FEED_KEY_ID) if feed.get("metadata") is not None else LEGACY_FEED_KEY_ID
    if not isinstance(key_id, str) or key_id not in FEED_KEYRING:
        return False, f"unknown signing key id {key_id!r}"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(FEED_KEYRING[key_id])).verify(
            bytes.fromhex(sig_hex.strip()),
            canonical_payload(feed["signatures"], feed.get("domains"), feed.get("feed_version"), feed.get("metadata")))
    except (InvalidSignature, ValueError):
        return False, f"signature does not verify with key {key_id}"
    for i, entry in enumerate(feed["signatures"]):
        if not isinstance(entry, dict):
            return False, f"entry {i} is not an object"
        digest = entry.get("sha256", "")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest.strip()):
            return False, f"entry {i} has an invalid sha256"
        if not entry.get("name"):
            return False, f"entry {i} has no threat name"
    return True, f"valid (key {key_id}, version {feed.get('feed_version')})"


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    path = args[0] if args else "threat_feed.json"
    with open(path, "rb") as f:
        raw = f.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        print(f"REJECTED: {path} is larger than {MAX_FEED_BYTES // (1024 * 1024)} MB")
        return 1
    ok, reason = verify(json.loads(raw.decode("utf-8")))
    print(f"{'OK' if ok else 'REJECTED'}: {path} - {reason}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
