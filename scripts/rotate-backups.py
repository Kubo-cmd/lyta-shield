#!/usr/bin/env python3
"""Rotate signed backups: keep N recent backups and remove older ones.

Usage:
    python3 scripts/rotate-backups.py [keep_count] [backup_dir]

Default: keep 7 most recent backups in var/backups.
"""
import sys
from pathlib import Path

LYTA_DIR = Path(__file__).resolve().parent.parent
BACKUP_DIR = Path(sys.argv[2]) if len(sys.argv) > 2 else LYTA_DIR / "var" / "backups"
KEEP = int(sys.argv[1]) if len(sys.argv) > 1 else 7


def main() -> int:
    if not BACKUP_DIR.exists():
        print(f"[INFO] backup directory does not exist: {BACKUP_DIR}")
        return 0

    # Find manifest files (each backup has .tar.gz, .sig, .manifest)
    manifests = sorted(BACKUP_DIR.glob("lyta-shield-*.manifest"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0

    for old in manifests[KEEP:]:
        base = old.stem
        for ext in [".tar.gz", ".tar.gz.sig", ".manifest"]:
            f = BACKUP_DIR / f"{base}{ext}"
            if f.exists():
                f.unlink()
                removed += 1
        print(f"[INFO] rotated out old backup: {base}")

    print(f"[OK] kept {len(manifests[:KEEP])} backups, removed {removed} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
