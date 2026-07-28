#!/usr/bin/env python3
"""Sign a backup tarball of the lyta-shield tree with Ed25519 (NaCl).

Usage:
    python3 scripts/backup-sign.py [backup_dir]

Creates:
    backup_dir/lyta-shield-YYYYmmddHHMMSS.tar.gz
    backup_dir/lyta-shield-YYYYmmddHHMMSS.tar.gz.sig
    backup_dir/lyta-shield-YYYYmmddHHMMSS.tar.gz.manifest

Keys:
    Private key: var/keys/backup-sign.nacl
    Public key:  var/keys/backup-sign.nacl.pub
"""

import base64
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey

LYTA_DIR = Path(__file__).resolve().parent.parent
KEY = LYTA_DIR / "var" / "keys" / "backup-sign.nacl"
PUB = LYTA_DIR / "var" / "keys" / "backup-sign.nacl.pub"


def main():
    backup_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else LYTA_DIR / "var" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    if not KEY.exists():
        print(f"[WARN] signing key not found: {KEY}", file=sys.stderr)
        print("[INFO] generating new Ed25519 keypair automatically", file=sys.stderr)
        subprocess.run([sys.executable, str(LYTA_DIR / "scripts" / "generate-backup-key.py")], check=True)

    signing_key = SigningKey(KEY.read_bytes())
    verify_key = signing_key.verify_key

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    base = backup_dir / f"lyta-shield-{timestamp}"
    tar_path = Path(f"{base}.tar.gz")
    sig_path = Path(f"{base}.tar.gz.sig")
    manifest_path = Path(f"{base}.manifest")

    # Build tarball of everything except var/backups, var/keys, .git, and event logs
    skip = {"var/backups", "var/keys", ".git", "var/hermes-guard-events.jsonl"}
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
        tmp_path = Path(tmp.name)
    try:
        with tarfile.open(tmp_path, "w:gz") as tar:
            for f in sorted(LYTA_DIR.rglob("*")):
                if f.is_dir():
                    continue
                rel = f.relative_to(LYTA_DIR)
                rel_str = str(rel)
                if any(rel_str.startswith(s) or s in rel_str for s in skip):
                    continue
                tar.add(f, arcname=rel_str)

        # Compute SHA-256 of tarball
        digest = hashlib.sha256(tmp_path.read_bytes()).hexdigest()

        # Sign the digest (include algorithm and filename in the signed message)
        sign_message = f"lyta-shield-backup|sha256|{digest}|{tar_path.name}".encode()
        signature = signing_key.sign(sign_message).signature

        # Move into place
        tmp_path.rename(tar_path)
        sig_path.write_bytes(signature)

        # Write manifest
        manifest = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "source": str(LYTA_DIR),
            "tarball": tar_path.name,
            "sha256": digest,
            "signature": sig_path.name,
            "public_key": base64.b64encode(verify_key.encode()).decode(),
            "sign_message": sign_message.decode(),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

        print(f"[OK] backup: {tar_path}")
        print(f"[OK] signature: {sig_path}")
        print(f"[OK] manifest: {manifest_path}")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


if __name__ == "__main__":
    main()
