#!/usr/bin/env python3
"""Generate a deterministic CycloneDX release SBOM from project metadata."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import uuid
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = str(project["version"])
    if args.tag != f"v{version}":
        raise SystemExit(f"tag/version mismatch: {args.tag} != v{version}")

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    namespace = uuid.UUID("ec68eeea-53c8-4c85-8798-f1d3efc3508d")
    serial = uuid.uuid5(namespace, f"{args.commit}:{args.tag}")

    components = []
    dependencies = []
    for requirement in project.get("dependencies", []):
        name = requirement.split(";", 1)[0].split("[", 1)[0]
        for separator in (">=", "==", "~=", "<=", ">", "<"):
            name = name.split(separator, 1)[0]
        name = name.strip()
        if name:
            reference = f"pkg:pypi/{name.lower()}"
            components.append({"type": "library", "name": name, "bom-ref": reference, "purl": reference})
            dependencies.append(reference)

    root_ref = f"pkg:pypi/{project['name']}@{version}"
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "lyta-shield-sbom", "version": "1"}]},
            "component": {
                "type": "application",
                "name": project["name"],
                "version": version,
                "bom-ref": root_ref,
                "purl": root_ref,
                "properties": [
                    {"name": "vcs:commit", "value": args.commit},
                    {"name": "vcs:tag", "value": args.tag},
                ],
            },
        },
        "components": sorted(components, key=lambda component: component["name"].lower()),
        "dependencies": [{"ref": root_ref, "dependsOn": sorted(dependencies)}],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
