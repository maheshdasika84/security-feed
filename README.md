# Security threat feed

The signed threat-intelligence feed for the Security app (Windows and Android), published with
GitHub Pages at:

    https://maheshdasika84.github.io/security-feed/threat_feed.json

The feed is public on purpose: it contains only fingerprints of known malware and known
malicious domains. It is **Ed25519-signed**; the app rejects any feed whose signature, signing
key, age or version does not check out, so hosting it here does not let anyone (including
GitHub) change what the app trusts.

This repository holds no source code and **never** a private key. It is generated from
`tools/feed_repo/` in the (private) Security repository.

Keys: `k2` signs (current), `k3` is the offline spare, `k1` is revoked (keep `--revoke k1`
in every feed so clients that missed an earlier feed still learn it).

## Publish an update

1. Prepare the unsigned manifest (`signatures`, `domains`, `feed_version`) outside this repository.
   Raise `feed_version` every time: clients refuse older versions.
2. On the machine that holds the key, sign it with the **current** key `k2` (tool in the Security
   repository):

   ```
   python tools/feed_signing.py sign --key <path>\k2.key --key-id k2 --revoke k1 --in manifest.json --out threat_feed.json --valid-days 14
   ```

3. Check it the way the app will, commit `threat_feed.json` here and push to `main`:

   ```
   python verify_feed.py threat_feed.json
   ```

The workflow (`.github/workflows/pages.yml`) runs the same check and only publishes a feed that
passes. Feeds expire, so re-sign at least every `--valid-days` days (at most 30).

## If a signing key leaks

Sign with the next key (`k3`, already built into every client) and revoke the leaked one:

```
python tools/feed_signing.py sign --key <path>\k3.key --key-id k3 --revoke k1 k2 --in manifest.json --out threat_feed.json
```

Then generate a new spare key offline, add its **public** key to `FEED_KEYRING` in the app
(`core/cloud_intel.py`, `ThreatFeedManager.java`) and in `verify_feed.py`, and ship an app release.

## One-time setup

Settings → Pages → Build and deployment → Source: **GitHub Actions**.
