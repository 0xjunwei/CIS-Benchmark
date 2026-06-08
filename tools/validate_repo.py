#!/usr/bin/env python3
"""Repository validation for benchmark metadata and wrappers."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is invalid JSON: {exc}")


def validate_manifest() -> None:
    manifest = load_json(ROOT / "benchmarks" / "manifest.json")
    ids = set()
    for entry in manifest.get("benchmarks", []):
        benchmark_id = entry.get("id")
        if not benchmark_id:
            fail("Manifest entry missing id")
        if benchmark_id in ids:
            fail(f"Duplicate benchmark id: {benchmark_id}")
        ids.add(benchmark_id)
        for key in ("source_url", "status"):
            if key not in entry:
                fail(f"Manifest entry {benchmark_id} missing {key}")
        for path_key in ("remediation_entrypoint", "validation_entrypoint", "controls_file"):
            value = entry.get(path_key)
            if value:
                candidate = value.split()[0]
                if not (ROOT / candidate).exists():
                    fail(f"Manifest entry {benchmark_id} references missing {path_key}: {value}")


def validate_controls() -> None:
    for path in ROOT.glob("benchmarks/windows/**/controls.*.json"):
        data = load_json(path)
        seen = set()
        for control in data.get("controls", []):
            control_id = control.get("id")
            if not control_id:
                fail(f"{path.relative_to(ROOT)} contains a control without id")
            if control_id in seen:
                fail(f"{path.relative_to(ROOT)} duplicates control id {control_id}")
            seen.add(control_id)
            status = control.get("implementation_status")
            if status not in {"automated", "manual", "organization_defined", "not_applicable", "unsupported"}:
                fail(f"{path.relative_to(ROOT)} control {control_id} has invalid implementation_status {status!r}")
            if control.get("type") == "registry":
                registry = control.get("registry", {})
                for key in ("name", "type", "expected_value"):
                    if key not in registry:
                        fail(f"{path.relative_to(ROOT)} control {control_id} registry missing {key}")
                if control.get("scope") == "user" and "sub_path" not in registry:
                    fail(f"{path.relative_to(ROOT)} user control {control_id} missing registry.sub_path")
                if control.get("scope") != "user" and "path" not in registry:
                    fail(f"{path.relative_to(ROOT)} machine control {control_id} missing registry.path")


def validate_shell() -> None:
    for path in ROOT.glob("benchmarks/linux/**/*.sh"):
        subprocess.run(["bash", "-n", str(path)], check=True)


def main() -> int:
    validate_manifest()
    validate_controls()
    validate_shell()
    print("Repository metadata and shell syntax validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
