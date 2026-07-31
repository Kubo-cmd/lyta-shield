#!/usr/bin/env python3
"""Generate a deterministic CycloneDX release SBOM from project metadata."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.metadata as metadata
import json
import os
import re
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

    lock_text = Path("requirements-build.lock").read_text(encoding="utf-8")
    locked = {
        re.sub(r"[-_.]+", "-", name).lower(): (name, resolved)
        for name, resolved in re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\\\s]+)", lock_text)
    }
    if not locked:
        raise SystemExit("requirements-build.lock has no exact package versions")

    components = []
    graph: dict[str, list[str]] = {}
    for canonical, (name, resolved) in sorted(locked.items()):
        reference = f"pkg:pypi/{canonical}@{resolved}"
        components.append({
            "type": "library",
            "name": name,
            "version": resolved,
            "bom-ref": reference,
            "purl": reference,
            "properties": [{"name": "source:lockfile", "value": "requirements-build.lock"}],
        })
        children = []
        try:
            declared = metadata.requires(name) or []
        except metadata.PackageNotFoundError:
            declared = []
        for requirement in declared:
            match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
            dependency = re.sub(r"[-_.]+", "-", match.group(1)).lower() if match else ""
            if dependency in locked:
                _, dep_version = locked[dependency]
                children.append(f"pkg:pypi/{dependency}@{dep_version}")
        graph[reference] = sorted(set(children))

    root_dependencies = []
    for requirement in project.get("dependencies", []):
        match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
        canonical = re.sub(r"[-_.]+", "-", match.group(1)).lower() if match else ""
        if canonical not in locked:
            raise SystemExit(f"runtime dependency is not exactly resolved in requirements-build.lock: {requirement}")
        _, resolved = locked[canonical]
        root_dependencies.append(f"pkg:pypi/{canonical}@{resolved}")

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
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(root_dependencies)},
            *({"ref": reference, "dependsOn": children} for reference, children in sorted(graph.items())),
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
