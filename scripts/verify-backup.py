#!/usr/bin/env python3
"""Verify a signed LYTA Shield backup against an external trust anchor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from backup_common import trusted_public_key_path, verify_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="trusted Ed25519 public key (default: LYTA_BACKUP_PUBLIC_KEY or user config)",
    )
    args = parser.parse_args()

    try:
        archive, manifest = verify_manifest(args.manifest, args.public_key)
    except (OSError, ValueError) as error:
        print(f"[FAIL] backup verification: {error}", file=sys.stderr)
        return 1

    print("[OK] backup verified")
    print(f"  archive: {archive}")
    print(f"  sha256:  {manifest['sha256']}")
    print(f"  trust:   {(args.public_key or trusted_public_key_path()).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
