#!/usr/bin/env python3
"""Verify a signed lyta-shield backup.

Usage:
    python3 scripts/verify-backup.py <manifest.json>

Returns 0 if the tarball signature and SHA-256 match, otherwise 1.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/verify-backup.py <manifest.json|backup_dir>", file=sys.stderr)
        sys.exit(1)

    arg = Path(sys.argv[1])
    if arg.is_dir():
        candidates = sorted(arg.glob("lyta-shield-*.manifest"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            print(f"[FAIL] no backup manifest found in {arg}", file=sys.stderr)
            sys.exit(1)
        manifest_path = candidates[0]
        print(f"[INFO] verifying latest backup: {manifest_path.name}")
    else:
        manifest_path = arg
    manifest = json.loads(manifest_path.read_text())
    backup_dir = manifest_path.parent
    tar_path = backup_dir / manifest["tarball"]
    sig_path = backup_dir / manifest["signature"]
    pub_key_b64 = manifest["public_key"]
    sign_message = manifest["sign_message"].encode()

    if not tar_path.exists():
        print(f"[FAIL] tarball missing: {tar_path}", file=sys.stderr)
        sys.exit(1)
    if not sig_path.exists():
        print(f"[FAIL] signature missing: {sig_path}", file=sys.stderr)
        sys.exit(1)

    # Verify SHA-256
    digest = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    if digest != manifest["sha256"]:
        print(f"[FAIL] SHA-256 mismatch: expected {manifest['sha256']} got {digest}", file=sys.stderr)
        sys.exit(1)
    print(f"[OK] SHA-256 matches: {digest}")

    # Verify signature
    verify_key = VerifyKey(base64.b64decode(pub_key_b64))
    try:
        verify_key.verify(sign_message, sig_path.read_bytes())
        print("[OK] signature verified")
    except BadSignatureError:
        print("[FAIL] signature verification failed", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] backup {manifest['tarball']} is authentic and intact")


if __name__ == "__main__":
    main()
