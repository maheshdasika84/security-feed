"""
Stale-Publish & Health Monitor for Security Threat Feed (AVIR-145, AVIR-154).

Monitors published threat feeds (local or remote) to verify:
1. Cryptographic authenticity: verifies Ed25519 signature against trusted keyring and key scopes.
2. Freshness & Expiry: fails closed if missing, future (>1h), or expired (>30d or past expires_at).
3. Completeness & Integrity: ensures no duplicate CVEs, no placeholder 999.0 versions, >=5 CVEs.
4. Scope compliance: enforces scoped keys (e.g. kv1 for cves) cannot declare revocations or full feeds.

Usage:
    python check_stale_feed.py cve_feed.json
    python check_stale_feed.py threat_feed.json
    python check_stale_feed.py --url https://maheshdasika84.github.io/security-feed/cve_feed.json
"""

import argparse
import datetime
import json
import math
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

FEED_KEYRING = {
    "k1": "e415786a2a27a188e91e4e2e1d30076ac015c40a12795c398603e8bd06bd74cf",
    "k2": "e7af1370f3e4b83500118e07cac433ff5ff8e7cb8cf20f7b89edd42d51d2fd11",
    "k3": "45baed5684d0ab3b598a7ffc171984c2f9e2340451b3e1d35a011a2959e74148",
    "kv1": "eeff95869b631558bc77182dd0f5324a5dfaaac1c5c13ffe7e9302b74a7e1832",
}

KEY_SCOPE_FULL = "full"
KEY_SCOPE_CVES = "cves"

FEED_KEY_SCOPES = {
    "k1": KEY_SCOPE_FULL,
    "k2": KEY_SCOPE_FULL,
    "k3": KEY_SCOPE_FULL,
    "kv1": KEY_SCOPE_CVES,
}

LEGACY_FEED_KEY_ID = "k1"
MAX_FEED_BYTES = 20 * 1024 * 1024
FUTURE_TOLERANCE_SECONDS = 3600  # 1 hour


def _get_active_keyring() -> Tuple[Dict[str, str], Dict[str, str]]:
    keyring = dict(FEED_KEYRING)
    scopes = dict(FEED_KEY_SCOPES)
    test_keyring_json = os.environ.get("SECURITY_FEED_TEST_KEYRING")
    if test_keyring_json:
        try:
            extra = json.loads(test_keyring_json)
            for kid, entry in extra.items():
                if isinstance(entry, dict):
                    keyring[kid] = entry["pub"]
                    scopes[kid] = entry.get("scope", KEY_SCOPE_FULL)
                else:
                    keyring[kid] = str(entry)
                    scopes[kid] = KEY_SCOPE_FULL
        except Exception:
            pass
    return keyring, scopes


def canonical_payload(
    signatures=None,
    domains=None,
    feed_version=None,
    metadata=None,
    cves=None,
) -> bytes:
    canonical = {}
    if signatures is not None:
        canonical["signatures"] = signatures
    if domains is not None:
        canonical["domains"] = domains
    if feed_version is not None:
        canonical["feed_version"] = feed_version
    if metadata is not None:
        canonical["metadata"] = metadata
    if cves is not None:
        canonical["cves"] = cves
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_timestamp(val: Any) -> Optional[float]:
    if val is None or val is False or val is True or val == "":
        return None
    if isinstance(val, (int, float)):
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    s = str(val).strip()
    try:
        f = float(s)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(datetime.datetime.strptime(s, fmt).timetuple())
        except Exception:
            continue
    return None


def check_feed(
    data: Dict[str, Any],
    max_warn_days: float = 7.0,
    max_crit_days: float = 30.0,
    now: Optional[float] = None,
) -> int:
    if not isinstance(data, dict):
        print("CRITICAL: Feed must be a JSON object!")
        return 1

    current_time = time.time() if now is None else now
    keyring, scopes = _get_active_keyring()

    raw_meta = data.get("metadata")
    meta: Dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    if raw_meta is not None and not isinstance(raw_meta, dict):
        print("CRITICAL: metadata must be a JSON object!")
        return 1

    key_id = meta.get("key_id", LEGACY_FEED_KEY_ID) if raw_meta is not None else LEGACY_FEED_KEY_ID
    feed_ver = data.get("feed_version", "unknown")
    print(f"Feed Version : {feed_ver}")
    print(f"Key ID       : {key_id}")

    exit_code = 0

    # 1. Key authenticity & scope checks
    if key_id not in keyring:
        print(f"CRITICAL: Unknown or untrusted signing key id {key_id!r}!")
        exit_code = 1
        key_scope = KEY_SCOPE_FULL
    else:
        key_scope = scopes.get(key_id, KEY_SCOPE_FULL)

    if key_scope == KEY_SCOPE_FULL:
        if not isinstance(data.get("signatures"), list):
            print("CRITICAL: Full threat feed must contain a 'signatures' array!")
            exit_code = 1
    elif key_scope == KEY_SCOPE_CVES:
        if "cves" not in data or not isinstance(data.get("cves"), list) or not data.get("cves"):
            print(f"CRITICAL: Scoped key {key_id} requires a non-empty 'cves' array!")
            exit_code = 1
        if meta.get("scope") != KEY_SCOPE_CVES:
            print(f"CRITICAL: Feed signed with scoped key {key_id} must declare metadata.scope == 'cves'!")
            exit_code = 1
        if meta.get("revoked_key_ids"):
            print(f"CRITICAL: Scoped key {key_id} is not permitted to declare revoked_key_ids!")
            exit_code = 1

    # 2. Ed25519 signature verification
    sig_hex = data.get("signature") or data.get("ed25519_signature")
    if not isinstance(sig_hex, str) or not sig_hex.strip():
        print("CRITICAL: Ed25519 signature missing!")
        exit_code = 1
    elif key_id in keyring:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            payload = canonical_payload(
                signatures=data.get("signatures"),
                domains=data.get("domains"),
                feed_version=data.get("feed_version"),
                metadata=data.get("metadata"),
                cves=data.get("cves"),
            )
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(keyring[key_id]))
            pub.verify(bytes.fromhex(sig_hex.strip()), payload)
            print(f"Signature    : Verified with key {key_id} [{key_scope}]")
        except (InvalidSignature, ValueError) as e:
            print(f"CRITICAL: Ed25519 signature verification failed for key {key_id}: {e}")
            exit_code = 1
        except ImportError:
            print("CRITICAL: cryptography library is required for Ed25519 verification!")
            exit_code = 1

    # 3. Timestamps, future tolerance, and freshness/staleness
    gen_val = meta.get("generated_at") or meta.get("issued_at") or meta.get("timestamp")
    gen_ts = parse_timestamp(gen_val)
    print(f"Generated At : {gen_val} (epoch {f'{gen_ts:.0f}' if gen_ts is not None else 'invalid'})")

    if gen_ts is None or gen_ts <= 0:
        print("CRITICAL: Feed metadata contains no readable generated_at/issued_at timestamp!")
        exit_code = 1
    elif gen_ts > current_time + FUTURE_TOLERANCE_SECONDS:
        print(f"CRITICAL: Feed timestamp is in the future (>1h ahead: {gen_val}, epoch {gen_ts:.0f} vs now {current_time:.0f})!")
        exit_code = 1
    else:
        age_days = (current_time - gen_ts) / 86400.0
        print(f"Feed Age     : {age_days:.2f} days")
        if age_days > max_crit_days:
            print(f"CRITICAL: Threat feed is critically stale ({age_days:.1f} days > {max_crit_days} days)!")
            exit_code = 1
        elif age_days > max_warn_days:
            print(f"WARNING: Threat feed is out of date ({age_days:.1f} days > {max_warn_days} days).")

    # Explicit expiry check
    expires_val = meta.get("expires_at")
    if expires_val is not None:
        expires_ts = parse_timestamp(expires_val)
        if expires_ts is None or expires_ts <= 0:
            print(f"CRITICAL: Feed metadata contains malformed or unreadable expires_at timestamp: {expires_val!r}!")
            exit_code = 1
        elif current_time > expires_ts:
            print(f"CRITICAL: Feed has expired (metadata.expires_at {expires_val} is in the past)!")
            exit_code = 1

    # 4. CVE entries verification (completeness, duplicates, placeholders)
    if "cves" in data and data.get("cves") is not None:
        cves = data.get("cves")
        if not isinstance(cves, list):
            print("CRITICAL: 'cves' must be an array!")
            exit_code = 1
        else:
            print(f"Total CVEs   : {len(cves)}")
            if len(cves) < 5:
                print(f"CRITICAL: Feed contains fewer than 5 CVE entries ({len(cves)})!")
                exit_code = 1

            seen_cve_pkgs = set()
            duplicates = 0
            placeholders = 0
            malformed = 0

            CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
            PKG_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$")
            VERSION_PATTERN = re.compile(r"^\d+\.\d+(?:\.\d+)*$")

            for cve in cves:
                if not isinstance(cve, dict):
                    malformed += 1
                    continue
                cid = cve.get("cve_id")
                pkg = cve.get("package_name")
                fix = cve.get("fixed_version")

                if not isinstance(cid, str) or not isinstance(pkg, str) or not isinstance(fix, str):
                    malformed += 1
                    continue

                cid = cid.strip()
                pkg = pkg.strip()
                fix = fix.strip()

                if not cid or not pkg or not fix:
                    malformed += 1
                    continue

                if not CVE_ID_PATTERN.match(cid):
                    malformed += 1
                    continue
                if not PKG_NAME_PATTERN.match(pkg):
                    malformed += 1
                    continue
                if not VERSION_PATTERN.match(fix):
                    malformed += 1
                    continue

                if fix == "999.0" or "999" in fix:
                    placeholders += 1

                pair = (cid.upper(), pkg)
                if pair in seen_cve_pkgs:
                    duplicates += 1
                seen_cve_pkgs.add(pair)

            if malformed > 0:
                print(f"CRITICAL: Feed contains {malformed} malformed CVE entries!")
                exit_code = 1
            if placeholders > 0:
                print(f"CRITICAL: Feed contains {placeholders} entries with placeholder version 999.0!")
                exit_code = 1
            if duplicates > 0:
                print(f"CRITICAL: Feed contains {duplicates} duplicate CVE entries!")
                exit_code = 1

    # 5. Signatures integrity (for full feeds or feeds with signatures)
    if "signatures" in data and data.get("signatures") is not None:
        sigs = data.get("signatures")
        if not isinstance(sigs, list):
            print("CRITICAL: 'signatures' must be an array!")
            exit_code = 1
        elif key_scope == KEY_SCOPE_FULL and len(sigs) == 0:
            print("CRITICAL: Full threat feed contains 0 signatures!")
            exit_code = 1
        else:
            seen_hashes = set()
            dup_sigs = 0
            invalid_sigs = 0
            for s in sigs:
                if not isinstance(s, dict):
                    invalid_sigs += 1
                    continue
                h = str(s.get("sha256", "")).strip().lower()
                if not h or not re.fullmatch(r"[0-9a-f]{64}", h) or not s.get("name"):
                    invalid_sigs += 1
                    continue
                if h in seen_hashes:
                    dup_sigs += 1
                seen_hashes.add(h)

            if invalid_sigs > 0:
                print(f"CRITICAL: Feed contains {invalid_sigs} invalid signature entries!")
                exit_code = 1
            if dup_sigs > 0:
                print(f"CRITICAL: Feed contains {dup_sigs} duplicate signature hashes!")
                exit_code = 1

    if exit_code == 0:
        print("PASS: Threat feed is authentic, valid, fresh, and complete.")
    return exit_code


def main() -> None:
    parser = argparse.ArgumentParser(description="Check threat feed freshness and integrity")
    parser.add_argument("feed_file", nargs="?", default=None, help="Path to local feed JSON file")
    parser.add_argument("--url", help="URL of remote feed to fetch and monitor")
    parser.add_argument("--warn-days", type=float, default=7.0, help="Warning threshold in days")
    parser.add_argument("--crit-days", type=float, default=30.0, help="Critical threshold in days")
    args = parser.parse_args()

    if args.url:
        parsed_url = urllib.parse.urlparse(args.url)
        if parsed_url.scheme != "https":
            print(f"CRITICAL: Remote feed URL must use HTTPS, got {args.url!r}")
            sys.exit(1)
        print(f"Fetching threat feed from {args.url}...")
        req = urllib.request.Request(args.url, headers={"User-Agent": "AegisGuard-Monitor/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read(MAX_FEED_BYTES + 1)
            if len(raw) > MAX_FEED_BYTES:
                print(f"CRITICAL: Remote feed exceeds maximum size of {MAX_FEED_BYTES // (1024 * 1024)} MB!")
                sys.exit(1)
            data = json.loads(raw.decode("utf-8"))
    else:
        feed_path = args.feed_file
        if not feed_path:
            feed_path = "cve_feed.json" if os.path.exists("cve_feed.json") else "threat_feed.json"
        if not os.path.exists(feed_path):
            print(f"CRITICAL: Feed file not found: {feed_path}")
            sys.exit(1)
        file_size = os.path.getsize(feed_path)
        if file_size > MAX_FEED_BYTES:
            print(f"CRITICAL: Feed file {feed_path} exceeds maximum size of {MAX_FEED_BYTES // (1024 * 1024)} MB!")
            sys.exit(1)
        with open(feed_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    sys.exit(check_feed(data, args.warn_days, args.crit_days))


if __name__ == "__main__":
    main()
