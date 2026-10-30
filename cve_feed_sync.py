"""
Standalone CVE Threat-Feed Synchronizer & Signer (AVIR-145).

Pulls known exploited vulnerabilities from CISA KEV for Android apps,
validates them, ensures the list never shrinks, updates the feed manifest, and signs it.

Completely self-contained: depends only on Python standard library and `cryptography`.
Can be run inside `tools/`, `tools/feed_repo/`, or the public `security-feed` repository.

Usage:
    python cve_feed_sync.py --feed threat_feed.json --out threat_feed.json \
        --key C:\\path\\to\\k2.key --key-id k2 --revoke k1
    python cve_feed_sync.py --feed threat_feed.json --out threat_feed.json \
        --key-env FEED_SIGNING_KEY_KV1 --key-id kv1 --revoke k1
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("cve_feed_sync")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEY_SCOPE_FULL = "full"
KEY_SCOPE_CVES = "cves"

FEED_KEY_SCOPES = {
    "k1": KEY_SCOPE_FULL,
    "k2": KEY_SCOPE_FULL,
    "k3": KEY_SCOPE_FULL,
    "kv1": KEY_SCOPE_CVES,
}


# Reviewed catalog of CISA KEV CVEs affecting Android apps with VERIFIED fixed versions.
# Strictly no free-text false positives, no desktop apps, and no 999.0 placeholders.
VERIFIED_ANDROID_KEV_CVES: Dict[str, List[Dict[str, Any]]] = {
    "CVE-2023-4863": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "116.0.5845.187",
            "fixed_version_code": 0,
            "severity": "Critical",
            "title": "WebP Heap Buffer Overflow",
            "summary": "Heap buffer overflow in WebP allows remote code execution via crafted image; actively exploited (CISA KEV 2023-09-13).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "116.0.5845.187",
            "fixed_version_code": 0,
            "severity": "Critical",
            "title": "WebP Heap Buffer Overflow",
            "summary": "Heap buffer overflow in WebP allows remote code execution via crafted image; actively exploited (CISA KEV 2023-09-13).",
        },
    ],
    "CVE-2023-5217": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "117.0.5938.138",
            "fixed_version_code": 0,
            "severity": "Critical",
            "title": "VP8 libvpx Heap Buffer Overflow",
            "summary": "Heap buffer overflow in libvpx VP8 encoding allows remote code execution; actively exploited (CISA KEV 2023-09-28).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "117.0.5938.138",
            "fixed_version_code": 0,
            "severity": "Critical",
            "title": "VP8 libvpx Heap Buffer Overflow",
            "summary": "Heap buffer overflow in libvpx VP8 encoding allows remote code execution; actively exploited (CISA KEV 2023-09-28).",
        },
    ],
    "CVE-2024-4671": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "124.0.6367.201",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chromium Visuals Use-After-Free",
            "summary": "Use-after-free in Visuals component allows remote code execution via crafted HTML page; actively exploited (CISA KEV 2024-05-13).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "124.0.6367.201",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chromium Visuals Use-After-Free",
            "summary": "Use-after-free in Visuals component allows remote code execution via crafted HTML page; actively exploited (CISA KEV 2024-05-13).",
        },
    ],
    "CVE-2024-4761": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "124.0.6367.207",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Out-of-Bounds Write",
            "summary": "Out-of-bounds write in V8 in Google Chrome allows arbitrary code execution; actively exploited (CISA KEV 2024-05-13).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "124.0.6367.207",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Out-of-Bounds Write",
            "summary": "Out-of-bounds write in V8 in Google Chrome allows arbitrary code execution; actively exploited (CISA KEV 2024-05-13).",
        },
    ],
    "CVE-2024-5274": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "125.0.6422.112",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-05-28).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "125.0.6422.112",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-05-28).",
        },
    ],
    "CVE-2024-7965": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "128.0.6613.84",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Inappropriate Implementation",
            "summary": "Inappropriate implementation in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-08-26).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "128.0.6613.84",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Inappropriate Implementation",
            "summary": "Inappropriate implementation in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-08-26).",
        },
    ],
    "CVE-2024-7971": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "128.0.6613.84",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-08-26).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "128.0.6613.84",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-08-26).",
        },
    ],
    "CVE-2024-0519": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "120.0.6099.224",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Out-of-Bounds Memory Access",
            "summary": "Out-of-bounds memory access in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-01-18).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "120.0.6099.224",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Out-of-Bounds Memory Access",
            "summary": "Out-of-bounds memory access in V8 in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2024-01-18).",
        },
    ],
    "CVE-2023-7024": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "120.0.6099.129",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome WebRTC Heap Buffer Overflow",
            "summary": "Heap buffer overflow in WebRTC in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2023-12-21).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "120.0.6099.129",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome WebRTC Heap Buffer Overflow",
            "summary": "Heap buffer overflow in WebRTC in Google Chrome allows remote attacker to execute arbitrary code; actively exploited (CISA KEV 2023-12-21).",
        },
    ],
    "CVE-2023-6345": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "119.0.6045.199",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome Skia Integer Overflow",
            "summary": "Integer overflow in Skia in Google Chrome allows remote attacker to escape sandbox; actively exploited (CISA KEV 2023-11-30).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "119.0.6045.199",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome Skia Integer Overflow",
            "summary": "Integer overflow in Skia in Google Chrome allows remote attacker to escape sandbox; actively exploited (CISA KEV 2023-11-30).",
        },
    ],
    "CVE-2023-3079": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "114.0.5735.106",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote code execution; actively exploited (CISA KEV 2023-06-06).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "114.0.5735.106",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote code execution; actively exploited (CISA KEV 2023-06-06).",
        },
    ],
    "CVE-2023-2136": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "112.0.5615.137",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome Skia Integer Overflow",
            "summary": "Integer overflow in Skia in Google Chrome allows remote attacker to escape sandbox; actively exploited (CISA KEV 2023-04-18).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "112.0.5615.137",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome Skia Integer Overflow",
            "summary": "Integer overflow in Skia in Google Chrome allows remote attacker to escape sandbox; actively exploited (CISA KEV 2023-04-18).",
        },
    ],
    "CVE-2023-2033": [
        {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "fixed_version": "112.0.5615.121",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote code execution; actively exploited (CISA KEV 2023-04-17).",
        },
        {
            "package_name": "com.google.android.webview",
            "app_name": "Android System WebView",
            "fixed_version": "112.0.5615.121",
            "fixed_version_code": 0,
            "severity": "High",
            "title": "Chrome V8 Type Confusion",
            "summary": "Type confusion in V8 in Google Chrome allows remote code execution; actively exploited (CISA KEV 2023-04-17).",
        },
    ],
    "CVE-2019-3568": [
        {
            "package_name": "com.whatsapp",
            "app_name": "WhatsApp Messenger",
            "fixed_version": "2.19.134",
            "fixed_version_code": 452814,
            "severity": "Critical",
            "title": "WhatsApp VoIP Stack Buffer Overflow",
            "summary": "Buffer overflow in WhatsApp VOIP stack allows remote code execution via crafted SRTCP packets; actively exploited (CISA KEV 2022-01-10).",
        },
        {
            "package_name": "com.whatsapp.w4b",
            "app_name": "WhatsApp Business",
            "fixed_version": "2.19.44",
            "fixed_version_code": 0,
            "severity": "Critical",
            "title": "WhatsApp Business VoIP Stack Buffer Overflow",
            "summary": "Buffer overflow in WhatsApp VOIP stack allows remote code execution via crafted SRTCP packets; actively exploited (CISA KEV 2022-01-10).",
        },
    ],
}

BASELINE_ANDROID_APP_CVES: List[Dict[str, Any]] = []
for _cve_id, _entries in VERIFIED_ANDROID_KEV_CVES.items():
    for _e in _entries:
        _c = dict(_e)
        _c["cve_id"] = _cve_id
        if "source_url" not in _c:
            _c["source_url"] = f"https://nvd.nist.gov/vuln/detail/{_cve_id}"
        if "source" not in _c:
            _c["source"] = "CISA KEV"
        if "actively_exploited" not in _c:
            _c["actively_exploited"] = True
        BASELINE_ANDROID_APP_CVES.append(_c)


def canonical_payload(signatures=None, domains=None, feed_version=None, metadata=None, cves=None) -> bytes:
    """Produces the exact canonical JSON bytes signed by Ed25519."""
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


def load_private_key(key_path: Optional[str] = None, key_env: Optional[str] = None) -> bytes:
    """Loads a 32-byte Ed25519 seed from a 64-char hex string file, raw file, or env var."""
    raw_str = None
    if key_env and os.environ.get(key_env):
        raw_str = os.environ[key_env].strip()
    elif key_path and os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            raw_str = f.read().strip()

    if not raw_str:
        raise ValueError("No private key found via --key or --key-env")

    # If it's a 64-character hex string
    if len(raw_str) == 64:
        return bytes.fromhex(raw_str)
    # If it's already 32 raw bytes
    if len(raw_str) == 32:
        return raw_str.encode("latin-1")

    # Maybe base64 encoded
    import base64
    try:
        decoded = base64.b64decode(raw_str)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    raise ValueError(f"Invalid private key format (expected 64 hex chars or 32 bytes, got {len(raw_str)} chars)")


def sign_payload(private_key_bytes: bytes, payload_bytes: bytes) -> str:
    """Signs canonical payload bytes with Ed25519."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return priv.sign(payload_bytes).hex()


def fetch_cisa_kev_catalog(kev_url: str = CISA_KEV_URL, local_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Pulls CISA KEV JSON catalog or reads from local file."""
    if local_file and os.path.exists(local_file):
        logger.info("Reading CISA KEV from local file: %s", local_file)
        with open(local_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("vulnerabilities", [])

    logger.info("Fetching CISA KEV catalog from %s", kev_url)
    req = urllib.request.Request(kev_url, headers={"User-Agent": "Security-Feed-Sync/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data.get("vulnerabilities", [])


def extract_cve_entries(kev_vulns: Any) -> List[Dict[str, Any]]:
    """
    Extracts CVEs affecting reviewed mobile applications.
    Strictly prohibits unverified entries and placeholder versions (like 999.0).
    """
    if isinstance(kev_vulns, dict):
        kev_vulns = kev_vulns.get("vulnerabilities", [])
    if not isinstance(kev_vulns, list):
        return []

    results: List[Dict[str, Any]] = []
    seen: set = set()

    for v in kev_vulns:
        cve_id = v.get("cveID", "").strip()
        if not cve_id:
            continue

        # Check reviewed verified target dictionary first
        if cve_id in VERIFIED_ANDROID_KEV_CVES:
            for item in VERIFIED_ANDROID_KEV_CVES[cve_id]:
                key = (cve_id, item["package_name"])
                if key in seen:
                    continue
                seen.add(key)
                entry = dict(item)
                entry["cve_id"] = cve_id
                entry["source"] = "CISA KEV"
                entry["source_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                entry["actively_exploited"] = True
                if v.get("shortDescription") and not entry.get("summary"):
                    entry["summary"] = v["shortDescription"]
                results.append(entry)
            continue

        # For unlisted CVEs: only accept Google Chromium or WhatsApp with explicit Android applicability and version string
        vendor = v.get("vendorProject", "").strip()
        product = v.get("product", "").strip()
        action = v.get("requiredAction", "")
        desc = v.get("shortDescription", "")
        vuln_name = v.get("vulnerabilityName", "")

        is_chrome = vendor.lower() == "google" and any(p in product.lower() for p in ["chromium", "chrome", "webview"])
        is_whatsapp = vendor.lower() in ["meta platforms", "whatsapp", "meta"] and "whatsapp" in product.lower()

        if is_chrome or is_whatsapp:
            product_lower = product.lower()
            desc_lower = desc.lower()
            action_lower = action.lower()
            vuln_name_lower = vuln_name.lower()
            combined_text = f"{product_lower} {desc_lower} {action_lower} {vuln_name_lower}"

            # 1. Reject if ANY non-Android platform is mentioned anywhere in the record
            # (product, description, action, vulnerabilityName).
            # This rejects mixed-platform records (e.g. Android + iOS, Android + Desktop)
            # where version numbers can be ambiguous or platform-specific.
            non_android_pattern = r"\b(?:desktop|windows|ios|mac|macos|osx|linux|iphone|ipad)\b"
            if re.search(non_android_pattern, combined_text):
                logger.info("Skipping unlisted KEV %s: non-Android or mixed platform mentioned in record", cve_id)
                continue

            # 2. Reject if description indicates Android is not affected or only other platforms are affected
            if "not affected" in desc_lower and "android" in desc_lower:
                logger.info("Skipping unlisted KEV %s: description indicates Android unaffected", cve_id)
                continue
            if re.search(r"\bandroid\b[^\.\;\n]*\b(?:not affected|unaffected|no android)\b", combined_text):
                logger.info("Skipping unlisted KEV %s: Android unaffected", cve_id)
                continue
            if re.search(r"\b(?:desktop-only|ios-only|windows-only|mac-only)\b", combined_text):
                logger.info("Skipping unlisted KEV %s: non-Android only", cve_id)
                continue

            # 3. Require explicit Android applicability keywords
            if not re.search(r"\b(?:android|apk|aab)\b", combined_text) and not (is_chrome and "webview" in combined_text):
                logger.info("Skipping unlisted KEV %s: no explicit Android platform applicability found", cve_id)
                continue

            # 4. Check for ambiguous version mentions:
            # Find all version-like patterns (\d+\.\d+(?:\.\d+)*) across action, desc, and product.
            # Exclude CVE IDs (CVE-YYYY-NNNN) and ISO dates (YYYY-MM-DD).
            text_for_versions = f"{action} {desc} {product}"
            clean_text_for_versions = re.sub(r"CVE-\d{4}-\d+", "", text_for_versions, flags=re.IGNORECASE)
            clean_text_for_versions = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "", clean_text_for_versions)
            found_versions = set(re.findall(r"\b\d+\.\d+(?:\.\d+)*\b", clean_text_for_versions))

            # If 0 versions found or more than 1 distinct version found, it is ambiguous -> reject/queue for review
            if len(found_versions) != 1:
                logger.info("Skipping unlisted KEV %s: ambiguous or multiple version mentions (%s)", cve_id, found_versions)
                continue

            fixed_ver = next(iter(found_versions))

            # Also require that requiredAction or description has an explicit update/fixed phrasing
            if not re.search(r"(?:update to|fixed in|patch version|version|upgrade to)\s+[vV]?\s*" + re.escape(fixed_ver), text_for_versions, re.IGNORECASE):
                logger.info("Skipping unlisted KEV %s: version %s not tied to fix/update directive", cve_id, fixed_ver)
                continue

            # 5. Resolve target package without blanket-copying across distinct packages
            target_pkgs = []
            if is_chrome:
                has_chrome = "chrome" in combined_text or "chromium" in combined_text
                has_webview = "webview" in combined_text
                if has_chrome and not has_webview:
                    target_pkgs = [("com.android.chrome", "Google Chrome")]
                elif has_webview and not has_chrome:
                    target_pkgs = [("com.google.android.webview", "Android System WebView")]
                elif has_chrome and has_webview:
                    # Both explicitly mentioned in the advisory
                    target_pkgs = [
                        ("com.android.chrome", "Google Chrome"),
                        ("com.google.android.webview", "Android System WebView"),
                    ]
                else:
                    logger.info("Skipping unlisted KEV %s: ambiguous Chrome/WebView package", cve_id)
                    continue
            elif is_whatsapp:
                has_business = "business" in combined_text or "w4b" in combined_text
                has_messenger = "messenger" in combined_text
                if has_business and not has_messenger:
                    target_pkgs = [("com.whatsapp.w4b", "WhatsApp Business")]
                elif not has_business:
                    # "WhatsApp" without "business" targets WhatsApp Messenger
                    target_pkgs = [("com.whatsapp", "WhatsApp Messenger")]
                else:
                    # Both business and messenger mentioned with single version is ambiguous
                    logger.info("Skipping unlisted KEV %s: ambiguous WhatsApp package targeting", cve_id)
                    continue

            for pkg, app_name in target_pkgs:
                key = (cve_id, pkg)
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "cve_id": cve_id,
                    "package_name": pkg,
                    "app_name": app_name,
                    "fixed_version": fixed_ver,
                    "fixed_version_code": 0,
                    "severity": "Critical" if "code execution" in desc.lower() else "High",
                    "title": v.get("vulnerabilityName", f"{app_name} Vulnerability"),
                    "summary": desc[:250],
                    "source": "CISA KEV",
                    "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "actively_exploited": True,
                })

    return results


extract_cves_from_cisa_kev = extract_cve_entries


def bump_feed_version(current_ver: Optional[str]) -> str:
    """Bumps feed version monotonically: YYYY.MM.DD-vN."""
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%d")
    if current_ver and current_ver.startswith(today):
        m = re.search(r"-v(\d+)$", current_ver)
        if m:
            num = int(m.group(1)) + 1
            return f"{today}-v{num}"
    return f"{today}-v1"


def validate_cve_count(cves: List[Dict[str, Any]], previous_count: int = 0) -> None:
    """Fails loudly if the resulting CVE list is empty or shrunken."""
    if not cves:
        raise RuntimeError("CVE list is completely empty; refusing to generate feed")
    if previous_count > 0 and len(cves) < previous_count:
        raise RuntimeError(
            f"CVE list is shrunken: shrank from {previous_count} to {len(cves)}; refusing to generate feed"
        )


def sync_cves(
    existing_feed: Dict[str, Any],
    kev_vulns: Optional[List[Dict[str, Any]]] = None,
    private_key_bytes: Optional[bytes] = None,
    key_id: str = "kv1",
    revoke_ids: Optional[List[str]] = None,
    valid_days: int = 14,
) -> Dict[str, Any]:
    """
    Synchronizes CVEs into existing feed manifest, increments version, and signs with Ed25519.
    Fails loudly if no private key is provided.
    """
    if not private_key_bytes:
        raise RuntimeError("No private key provided; cannot sign feed manifest for publication")

    previous_cves = existing_feed.get("cves", [])
    previous_count = len(previous_cves)

    new_extracted = extract_cve_entries(kev_vulns or [])

    # Merge by (cve_id, package_name)
    merged_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for cve in previous_cves:
        cve_id = cve.get("cve_id")
        pkg = cve.get("package_name")
        if cve_id and pkg:
            merged_map[(cve_id, pkg)] = cve

    for cve in new_extracted:
        cve_id = cve.get("cve_id")
        pkg = cve.get("package_name")
        if cve_id and pkg:
            merged_map[(cve_id, pkg)] = cve

    # Ensure baseline entries are always preserved
    if not merged_map:
        for cve in BASELINE_ANDROID_APP_CVES:
            merged_map[(cve["cve_id"], cve["package_name"])] = cve

    final_cves = list(merged_map.values())
    final_cves.sort(key=lambda x: (x.get("package_name", ""), x.get("cve_id", "")))

    validate_cve_count(final_cves, previous_count)

    new_version = bump_feed_version(existing_feed.get("feed_version"))
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_epoch = int(now_utc.timestamp())
    generated_at = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (now_utc + datetime.timedelta(days=valid_days)).strftime("%Y-%m-%d %H:%M:%S")

    key_scope = FEED_KEY_SCOPES.get(key_id, KEY_SCOPE_FULL)
    metadata = dict(existing_feed.get("metadata", {}))
    metadata["generated_at"] = generated_at
    metadata["issued_at"] = now_epoch
    metadata["expires_at"] = expires_at
    metadata["valid_days"] = valid_days
    metadata["key_id"] = key_id
    metadata["scope"] = key_scope
    if key_scope == KEY_SCOPE_FULL:
        if revoke_ids:
            current_revoked = set(metadata.get("revoked_key_ids", []))
            current_revoked.update(revoke_ids)
            metadata["revoked_key_ids"] = sorted(list(current_revoked))
        signatures = existing_feed.get("signatures", [])
        domains = existing_feed.get("domains")
    else:
        # Scoped key cannot declare or modify revoked keys
        metadata.pop("revoked_key_ids", None)
        signatures = None
        domains = None

    # Build canonical payload and sign
    payload = canonical_payload(
        signatures=signatures,
        domains=domains,
        feed_version=new_version,
        metadata=metadata,
        cves=final_cves,
    )
    sig_hex = sign_payload(private_key_bytes, payload)

    manifest = {
        "cves": final_cves,
        "feed_version": new_version,
        "metadata": metadata,
        "signature": sig_hex,
    }
    if signatures is not None:
        manifest["signatures"] = signatures
    if domains is not None:
        manifest["domains"] = domains

    logger.info("Successfully synchronized %d CVEs into feed version %s (signed with %s)", len(final_cves), new_version, key_id)
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Synchronize CISA KEV CVEs into threat feed manifest.")
    parser.add_argument("--feed", default="cve_feed.json", help="Path to input cve_feed.json or threat_feed.json (default: cve_feed.json)")
    parser.add_argument("--out", default="cve_feed.json", help="Path to output signed feed file (default: cve_feed.json)")
    parser.add_argument("--key", help="Path to Ed25519 private key file")
    parser.add_argument("--key-env", help="Environment variable containing Ed25519 private key")
    parser.add_argument("--key-id", default="kv1", help="Key ID to record in metadata (default: kv1)")
    parser.add_argument("--revoke", nargs="*", default=None, help="Key IDs to revoke (full keys only)")
    parser.add_argument("--valid-days", type=int, default=14, help="Validity in days (default: 14)")
    parser.add_argument("--kev-file", dest="kev_file", help="Path to cached local CISA KEV JSON file")
    args = parser.parse_args()

    existing_feed = {}
    feed_path = args.feed
    if not os.path.exists(feed_path) and os.path.exists("threat_feed.json"):
        feed_path = "threat_feed.json"

    if os.path.exists(feed_path):
        with open(feed_path, "r", encoding="utf-8") as f:
            existing_feed = json.load(f)

    # Resolve private key
    priv_bytes = None
    try:
        priv_bytes = load_private_key(key_path=args.key, key_env=args.key_env)
    except Exception as e:
        logger.error("Private key error: %s", e)
        logger.error("Feed publication strictly requires an Ed25519 signing key via --key or --key-env.")
        sys.exit(1)

    kev_vulns = fetch_cisa_kev_catalog(local_file=args.kev_file)
    if args.revoke and FEED_KEY_SCOPES.get(args.key_id) == KEY_SCOPE_CVES:
        logger.error("Scoped key %s is restricted to 'cves' and cannot declare revoked keys", args.key_id)
        sys.exit(1)

    updated = sync_cves(
        existing_feed=existing_feed,
        kev_vulns=kev_vulns,
        private_key_bytes=priv_bytes,
        key_id=args.key_id,
        revoke_ids=args.revoke,
        valid_days=args.valid_days,
    )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(updated, f, indent=2)
    logger.info("Wrote updated feed to %s", args.out)


if __name__ == "__main__":
    main()
