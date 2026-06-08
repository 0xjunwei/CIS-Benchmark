#!/usr/bin/env python3
"""Repository validation for benchmark metadata and wrappers."""
from __future__ import annotations

import json
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
    profile_matrix_file = manifest.get("profile_matrix_file")
    if profile_matrix_file and not (ROOT / profile_matrix_file).exists():
        fail(f"Manifest references missing profile_matrix_file: {profile_matrix_file}")
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
        source_metadata = entry.get("source_metadata", {})
        if entry.get("active") and source_metadata.get("comparison_status") not in {
            "needs_authorized_source_review",
            "reviewed_against_authorized_source",
            "mismatch",
            "not_implemented",
        }:
            fail(f"Manifest entry {benchmark_id} has invalid or missing source_metadata.comparison_status")
        if (
            entry.get("controls_file")
            and source_metadata.get("comparison_status") != "reviewed_against_authorized_source"
            and entry.get("remediation_entrypoint")
        ):
            fail(f"Manifest entry {benchmark_id} must not advertise remediation before authorized source review")
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
            source_review_status = control.get("source_review_status")
            if source_review_status not in {
                "needs_authorized_source_review",
                "reviewed_against_authorized_source",
                "mismatch",
                "organization_defined",
                "not_implemented",
            }:
                fail(f"{path.relative_to(ROOT)} control {control_id} has invalid source_review_status {source_review_status!r}")
            if control.get("type") == "registry":
                registry = control.get("registry", {})
                for key in ("name", "type", "expected_value"):
                    if key not in registry:
                        fail(f"{path.relative_to(ROOT)} control {control_id} registry missing {key}")
                if control.get("scope") == "user" and "sub_path" not in registry:
                    fail(f"{path.relative_to(ROOT)} user control {control_id} missing registry.sub_path")
                if control.get("scope") != "user" and "path" not in registry:
                    fail(f"{path.relative_to(ROOT)} machine control {control_id} missing registry.path")


def validate_profile_matrix() -> None:
    path = ROOT / "benchmarks" / "profile-matrix.json"
    matrix = load_json(path)
    manifest = load_json(ROOT / "benchmarks" / "manifest.json")
    manifest_controls = {
        entry.get("controls_file")
        for entry in manifest.get("benchmarks", [])
        if entry.get("controls_file")
    }
    allowed_profile_statuses = {
        "starter_subset_12_controls_not_full_profile",
        "scaffold_no_controls_imported",
        "delegates_to_canonical_usg_profile",
        "archived_unsafe_reference_only",
    }
    allowed_source_statuses = {
        "needs_authorized_source_review",
        "reviewed_against_authorized_source",
        "mismatch",
        "organization_defined",
        "not_implemented",
    }
    for system in matrix.get("systems", []):
        system_id = system.get("system_id")
        for profile in system.get("profiles", []):
            profile_id = profile.get("profile_id")
            profile_status = profile.get("profile_status")
            source_status = profile.get("source_review_status")
            if profile_status not in allowed_profile_statuses:
                fail(f"Profile matrix {system_id}/{profile_id} has invalid profile_status {profile_status!r}")
            if source_status not in allowed_source_statuses:
                fail(f"Profile matrix {system_id}/{profile_id} has invalid source_review_status {source_status!r}")
            controls_file = profile.get("controls_file")
            if controls_file:
                controls_path = ROOT / controls_file
                if not controls_path.exists():
                    fail(f"Profile matrix {system_id}/{profile_id} references missing controls_file: {controls_file}")
                if controls_file not in manifest_controls:
                    fail(f"Profile matrix {system_id}/{profile_id} controls_file is missing from manifest: {controls_file}")
                controls_data = load_json(controls_path)
                if profile_status == "scaffold_no_controls_imported":
                    if controls_data.get("coverage_status") != "scaffold_no_controls_imported":
                        fail(f"Profile matrix {system_id}/{profile_id} scaffold controls file has unexpected coverage_status")
                    if controls_data.get("controls"):
                        fail(f"Profile matrix {system_id}/{profile_id} scaffold controls file should have an empty controls list")
                    if profile.get("remediation_entrypoint"):
                        fail(f"Profile matrix {system_id}/{profile_id} scaffold should not advertise remediation_entrypoint")
                if source_status == "needs_authorized_source_review":
                    comparison = controls_data.get("source_comparison", {})
                    if comparison.get("status") != "needs_authorized_source_review":
                        fail(f"Profile matrix {system_id}/{profile_id} controls file missing source_comparison needs_authorized_source_review")
                    if profile.get("remediation_entrypoint"):
                        fail(f"Profile matrix {system_id}/{profile_id} must not advertise remediation before authorized source review")
            for entrypoint_key in ("validation_entrypoint", "remediation_entrypoint"):
                entrypoint = profile.get(entrypoint_key)
                if entrypoint:
                    candidate = entrypoint.split()[0]
                    if not (ROOT / candidate).exists():
                        fail(f"Profile matrix {system_id}/{profile_id} references missing {entrypoint_key}: {entrypoint}")


def validate_shell_wrappers_static() -> None:
    for path in ROOT.glob("benchmarks/linux/**/*.sh"):
        text = path.read_text(encoding="utf-8")
        required_fragments = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            'MODE="audit"',
            "--yes",
            "SUPPORTED_PROFILES",
            "usg-profiles",
            'REPORT_DIR="$REPO_ROOT/reports/linux/ubuntu/',
            "command -v usg",
            "usg list",
            'profile=$PROFILE',
            'grep -Fx -- "$PROFILE"',
            "2>&1 | tee -a",
            'if [[ "$YES" -ne 1 ]]',
            "run_usg()",
            "usg_exit_code=",
            "final_status=completed",
            "final_status=failed",
            'usg "$action" "$PROFILE" 2>&1 | tee -a "$REPORT"',
        ]
        for fragment in required_fragments:
            if fragment not in text:
                fail(f"{path.relative_to(ROOT)} missing static safety fragment: {fragment}")
        remediate_pos = text.find("remediate)")
        yes_pos = text.find('if [[ "$YES" -ne 1 ]]', remediate_pos)
        remediation_dry_run_pos = text.find('if [[ "$DRY_RUN" -eq 1 ]]', remediate_pos)
        if remediate_pos == -1 or yes_pos == -1 or remediation_dry_run_pos == -1 or yes_pos > remediation_dry_run_pos:
            fail(f"{path.relative_to(ROOT)} checks dry-run before the remediation --yes gate")


def validate_windows_module_static() -> None:
    path = ROOT / "benchmarks" / "windows" / "common" / "CisWindowsHardening.psm1"
    text = path.read_text(encoding="utf-8")
    required_fragments = [
        "New-CisReportStatusLegend",
        "validation_boundary",
        "source_review_status",
        "status_legend",
        "not compliance evidence",
        "ConvertTo-Json -Depth 8",
        "ReportPath must stay under repository reports directory",
        "Assert-CisControlsReadyForRemediation",
        "reviewed_against_authorized_source",
        "Remediation is disabled until the control set is reviewed against authorized CIS source material",
        "Export-ModuleMember -Function Test-IsAdministrator,Get-WindowsEditionAndBuild,Assert-CisSupportedWindowsTarget,Invoke-CisControls",
    ]
    for fragment in required_fragments:
        if fragment not in text:
            fail(f"{path.relative_to(ROOT)} missing static report-safety fragment: {fragment}")


def validate_windows_entrypoints_static() -> None:
    for path in ROOT.glob("benchmarks/windows/**/Invoke-Cis*.ps1"):
        if "windows-10-enterprise" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        required_fragments = [
            "SupportsShouldProcess",
            "[switch] $Remediate",
            "[switch] $IncludeOfflineUserHives",
            "Assert-CisSupportedWindowsTarget",
            "ShouldProcess",
            "scaffold-only or empty",
            "reviewed against authorized CIS source material",
            "Invoke-CisControls",
            "Join-Path $repoRoot $ReportPath",
            "-Confirm:$false",
        ]
        for fragment in required_fragments:
            if fragment not in text:
                fail(f"{path.relative_to(ROOT)} missing static entrypoint-safety fragment: {fragment}")

    for path in ROOT.glob("benchmarks/windows/**/Test-Cis*.ps1"):
        if "windows-10-enterprise" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "-Remediate" in text:
            fail(f"{path.relative_to(ROOT)} audit wrapper must not pass -Remediate")
        for fragment in ("[switch] $IncludeOfflineUserHives", "-IncludeOfflineUserHives:$IncludeOfflineUserHives"):
            if fragment not in text:
                fail(f"{path.relative_to(ROOT)} missing audit wrapper safety fragment: {fragment}")


def validate_open_source_readiness() -> None:
    required_files = [
        "README.md",
        "LICENSE",
        "NOTICE",
        ".gitignore",
        ".gitattributes",
        ".github/ISSUE_TEMPLATE/benchmark-review.yml",
        ".github/ISSUE_TEMPLATE/safety-bug.yml",
        ".github/workflows/static-review.yml",
    ]
    for relative_path in required_files:
        if not (ROOT / relative_path).exists():
            fail(f"Missing open-source readiness file: {relative_path}")

    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        fail("LICENSE must contain Apache License 2.0 text")

    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    required_notice_fragments = [
        "not affiliated",
        "not included in this repository",
        "respective owners",
        "Apache License 2.0",
    ]
    for fragment in required_notice_fragments:
        if fragment not in notice:
            fail(f"NOTICE missing boundary fragment: {fragment}")

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    required_gitignore_fragments = [
        "*.docx",
        "legacy/windows-10-enterprise/original/",
        "*.scanner-output.*",
        "*.cis-cat.*",
        "*.xccdf*.xml",
        "*.usg-results.*",
    ]
    for fragment in required_gitignore_fragments:
        if fragment not in gitignore:
            fail(f".gitignore missing source/scanner protection: {fragment}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required_readme_fragments = [
        "not an official CIS product",
        "not compliance evidence",
        "benchmarks/profile-matrix.json",
        "source-review worksheet",
        "Do not commit CIS PDFs, Build Kits, scanner exports",
        "do not describe it as full Level 1 coverage",
        "One static reviewer pass was assigned per benchmark area",
    ]
    for fragment in required_readme_fragments:
        if fragment not in readme:
            fail(f"README missing safety/readiness fragment: {fragment}")


def validate_markdown_cleanup() -> None:
    markdown_files = sorted(
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*.md")
        if ".git" not in path.relative_to(ROOT).parts
    )
    if markdown_files != ["README.md"]:
        fail(f"Only README.md should remain as Markdown documentation; found: {', '.join(markdown_files)}")


def validate_no_committed_source_material() -> None:
    forbidden_suffixes = {
        ".docx",
        ".pdf",
        ".zip",
        ".7z",
        ".tar",
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tgz",
        ".scanner-output",
        ".arf.xml",
        ".oval-results.xml",
    }
    forbidden_name_fragments = {
        ".scanner-output.",
        ".cis-cat.",
        ".usg-results.",
    }
    forbidden_prefix_fragments = {
        "xccdf",
    }
    forbidden_source_dirs = {
        "authorized-sources",
        "cis-authorized-sources",
        "cis-sources",
        "legacy/windows-10-enterprise/original",
    }
    forbidden_legacy_paths = {
        "CIS LEVEL 1.bat",
        "Manual Steps Required to Comply with Windows 10 CIS Level 1.docx",
        "password policy.inf",
        "benchmarks/windows/desktop/windows-10-enterprise/README.md",
    }
    ignored_dirs = {".git"}
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        relative_posix = relative.as_posix()
        if any(part in ignored_dirs for part in relative.parts):
            continue
        if path.is_file():
            if relative_posix in forbidden_legacy_paths:
                fail(f"Unsafe legacy artifact must not be committed: {relative}")
            if any(relative_posix == directory or relative_posix.startswith(f"{directory}/") for directory in forbidden_source_dirs):
                fail(f"Authorized source or unsafe legacy material must stay outside the repository: {relative}")
            name = path.name.lower()
            if any(name.endswith(suffix) for suffix in forbidden_suffixes):
                fail(f"Authorized source/scanner/binary manual artifact must not be committed: {relative}")
            if any(fragment in name for fragment in forbidden_name_fragments):
                fail(f"Authorized source/scanner/binary manual artifact must not be committed: {relative}")
            if any(name.startswith(fragment) and name.endswith(".xml") for fragment in forbidden_prefix_fragments):
                fail(f"Authorized source/scanner/binary manual artifact must not be committed: {relative}")


def main() -> int:
    validate_manifest()
    validate_controls()
    validate_profile_matrix()
    validate_shell_wrappers_static()
    validate_windows_module_static()
    validate_windows_entrypoints_static()
    validate_open_source_readiness()
    validate_markdown_cleanup()
    validate_no_committed_source_material()
    print("Repository metadata and static wrapper validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
