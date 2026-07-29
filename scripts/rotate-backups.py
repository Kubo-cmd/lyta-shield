#!/usr/bin/env python3
"""Rotate signed backups while refusing unsafe manifest paths."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from .backup_common import read_manifest
except ImportError:  # Direct script execution.
    from backup_common import read_manifest

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keep", nargs="?", type=int, default=7)
    parser.add_argument("backup_dir", nargs="?", type=Path, default=ROOT / "var" / "backups")
    parser.add_argument("--prune-legacy", action="store_true", help="remove obsolete pre-v2 backup triplets")
    args = parser.parse_args()
    if args.keep < 1:
        raise SystemExit("keep must be at least 1")
    if not args.backup_dir.exists():
        print(f"[INFO] backup directory does not exist: {args.backup_dir}")
        return 0

    manifests = sorted(
        args.backup_dir.glob("lyta-shield-*.tar.gz.manifest.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    skipped = 0
    for manifest_path in manifests[args.keep:]:
        try:
            manifest = read_manifest(manifest_path)
            archive_path = manifest_path.parent / manifest["archive"]
        except (OSError, ValueError) as error:
            print(f"[WARN] skipped invalid manifest {manifest_path.name}: {error}")
            skipped += 1
            continue
        archive_path.unlink(missing_ok=True)
        manifest_path.unlink()
        removed += 2
        print(f"[INFO] rotated out backup: {manifest['archive']}")
    legacy_removed = 0
    if args.prune_legacy:
        if not manifests:
            raise SystemExit("refusing to prune legacy backups without a v2 backup")
        for legacy_manifest in args.backup_dir.glob("lyta-shield-*.manifest"):
            base = legacy_manifest.name[: -len(".manifest")]
            for name in (f"{base}.manifest", f"{base}.tar.gz", f"{base}.tar.gz.sig"):
                path = args.backup_dir / name
                if path.is_file() and not path.is_symlink():
                    path.unlink()
                    legacy_removed += 1
    print(
        f"[OK] kept {min(len(manifests), args.keep)} backups, "
        f"removed {removed} current files and {legacy_removed} legacy files, skipped {skipped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
