# CIS Benchmark-Aligned Hardening Framework

This repository is a community hardening framework for building auditable, reviewable remediation helpers inspired by CIS Benchmarks. It is not an official CIS product, not a Canonical product, and not compliance evidence by itself.

> Warning: Do not run these scripts on a workstation, server, or production asset until you have reviewed every control against the official CIS source material you are licensed to use, tested in an isolated lab, captured backups, and created a rollback plan.

## Compliance Boundary

Running a script is not the same as passing a CIS audit. Treat every run as a change-control event:

1. Download the official CIS Benchmark PDF or Build Kit under your own CIS terms.
2. Compare local metadata against that authorized source.
3. Run a scanner or vendor-supported tool in a lab first.
4. Back up local policy and system state.
5. Apply remediation only after explicit approval.
6. Validate again with CIS-CAT Pro, vendor-supported tooling, or another authorized scanner.

This project stores implementation metadata, wrapper logic, and links. Do not commit CIS PDFs, Build Kits, scanner exports, or other licensed source material.

## Benchmark Matrix

The manifest in `benchmarks/manifest.json` is the source of truth for tracked targets. The full Level 1/Level 2 profile inventory is tracked in `benchmarks/profile-matrix.json`.

| Target | Version status | Entry point | Coverage status |
| --- | --- | --- | --- |
| Microsoft Windows 11 Enterprise | 5.0.1 claim pending authorized-source comparison | `benchmarks/windows/desktop/windows-11-enterprise/Invoke-CisWindows11Profile.ps1 -Profile <level1|level2>` | Level 1 starter subset; Level 2 scaffold |
| Microsoft Windows Server 2025 | 2.0.0 claim pending authorized-source comparison | `benchmarks/windows/server/windows-server-2025/Invoke-CisWindowsServer2025Profile.ps1 -Profile <profile>` | Level 1/2 Member Server and Domain Controller scaffolds |
| Ubuntu Linux 24.04 LTS | 2.0.0 claim pending authorized-source comparison | `benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh` | Delegates to Canonical USG profile selected at runtime |
| Ubuntu Linux 22.04 LTS | 3.0.0 claim pending authorized-source comparison | `benchmarks/linux/ubuntu/22.04/cis-ubuntu-22.04.sh` | Delegates to Canonical USG profile selected at runtime |

Legacy Windows 10 support is inactive. Unsafe historical root artifacts are deleted from the publishable repository; any local legacy source/manual copies must stay ignored and are not safe-to-run remediation.

## Profile Levels

All active systems now have safe profile scaffolding for their CIS Level 1 and Level 2 variants:

- Windows 11 Enterprise: Level 1 and Level 2.
- Windows Server 2025: Level 1 Member Server, Level 2 Member Server, Level 1 Domain Controller, and Level 2 Domain Controller.
- Ubuntu 24.04 and Ubuntu 22.04: `cis_level1_server`, `cis_level2_server`, `cis_level1_workstation`, and `cis_level2_workstation`.

Missing Windows profiles are scaffolds with empty control lists until authorized CIS source material is reviewed. Ubuntu profiles delegate to Canonical USG and must still be validated against the installed USG profile and official CIS source material before they are treated as accurate.

Windows profile entrypoints are:

```powershell
.\benchmarks\windows\desktop\windows-11-enterprise\Test-CisWindows11Profile.ps1 -Profile level2
.\benchmarks\windows\server\windows-server-2025\Test-CisWindowsServer2025Profile.ps1 -Profile level2-member-server
.\benchmarks\windows\server\windows-server-2025\Test-CisWindowsServer2025Profile.ps1 -Profile level2-domain-controller
```

These commands are examples for future lab use; they were not run during repository preparation.

## Repository Layout

```text
benchmarks/
  manifest.json
  windows/
    common/
    desktop/windows-11-enterprise/
    server/windows-server-2025/
  linux/ubuntu/24.04/
  linux/ubuntu/22.04/
legacy/windows-10-enterprise/
reports/
tools/
```

## Status Legend

- `pass`: A local automated check matched the expected metadata value.
- `fail`: A local automated check did not match the expected metadata value.
- `organization_defined`: Local policy decision required; not a pass result.
- `manual-validation-required`: Automation did not validate the control.
- `remediated-needs-validation`: A remediation path was invoked, but separate authorized validation is required.
- `whatif`: Preview only; no remediation should have been applied.
- `needs_authorized_source_review`: Must be checked against official CIS source material before it is treated as accurate.
- `reviewed_against_authorized_source`: A maintainer recorded an authorized-source comparison.
- `mismatch`: Local metadata differs from the authorized source.
- `not_implemented`: Tracked but not implemented.
- `scaffold_no_controls_imported`: The profile exists, but no controls have been imported or validated.

## Windows Usage

Open an elevated PowerShell session on the target OS. The `Invoke-*` entrypoints now default to audit mode. Signed-out user hives and the default profile are not loaded unless `-IncludeOfflineUserHives` is supplied.

Audit Windows 11 starter controls:

```powershell
.\benchmarks\windows\desktop\windows-11-enterprise\Invoke-CisWindows11Profile.ps1 -Profile level1
```

Windows remediation is disabled while a profile or automated control is still marked `needs_authorized_source_review`, `organization_defined`, `mismatch`, or `not_implemented`. Only profiles whose control mappings are recorded as `reviewed_against_authorized_source` should advertise remediation, and those paths still require explicit `-Remediate` plus PowerShell `ShouldProcess` approval.

Windows Server 2025 role/profile scaffolds use the matching server folder. These scaffold profiles have no imported controls yet and should be used for source-review preparation only:

```powershell
.\benchmarks\windows\server\windows-server-2025\Invoke-CisWindowsServer2025Profile.ps1 -Profile level1-member-server
.\benchmarks\windows\server\windows-server-2025\Invoke-CisWindowsServer2025Profile.ps1 -Profile level2-domain-controller
```

The Windows scripts perform OS caption checks and refuse unsupported targets unless `-Force` is supplied. Use `-Force` only after confirming the benchmark applies to the host.

## Windows Control Model

Windows controls are represented as JSON metadata rather than raw one-way registry commands. Each control records implementation status and source review status. Current Windows metadata is a starter subset only; do not describe it as full Level 1 coverage.

Windows report files include benchmark ID, coverage status, source comparison metadata, a status legend, and per-control `source_review_status`. Treat `pass` as a local metadata check only, not as proof that the CIS source mapping is accurate or that the system is compliant.

The shared Windows module rejects remediation for scaffold-only profiles, empty control sets, and any control set whose source comparison status is not `reviewed_against_authorized_source`.

Windows report paths must stay under this repository's `reports/` directory. External report paths are rejected to avoid scattering helper evidence or accidentally publishing sensitive system details.

User-scope controls apply to loaded interactive user hives by default. Add `-IncludeOfflineUserHives` only when the change window explicitly allows temporary loading of signed-out profile hives and the default profile.

The password policy template is an aggregate starter control. It requires separate validation with `secedit` export, `net accounts`, CIS-CAT Pro, or another authorized scanner.

## Ubuntu Usage

The Ubuntu wrappers delegate to Canonical Ubuntu Security Guide (`usg`) profiles. They do not embed CIS benchmark controls. The default profile is `cis_level1_server`, and the selected profile is written into the wrapper report.

Supported profile names are:

- `cis_level1_server`
- `cis_level2_server`
- `cis_level1_workstation`
- `cis_level2_workstation`

Audit Ubuntu 24.04:

```bash
sudo ./benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh --audit
```

Preview Ubuntu 24.04 remediation:

```bash
sudo ./benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh --remediate --dry-run --yes
```

The `--yes` flag acknowledges remediation mode even for dry-run previews; dry-run prints the intended `usg fix` command without applying it.

Apply Ubuntu 24.04 remediation only after lab testing and approval:

```bash
sudo ./benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh --remediate --yes
```

Ubuntu 22.04 uses the matching folder:

```bash
sudo ./benchmarks/linux/ubuntu/22.04/cis-ubuntu-22.04.sh --audit
sudo ./benchmarks/linux/ubuntu/22.04/cis-ubuntu-22.04.sh --remediate --dry-run --yes
```

Canonical USG may generate authoritative HTML/XML artifacts under `/var/lib/usg/`; the text report in this repository is a helper capture, not formal compliance evidence.

## Accuracy Workflow

Authorized source files should stay outside this repository working tree. `.gitignore` also blocks defensive local folder names such as `authorized-sources/` and `cis-authorized-sources/`, but those folders are not publishable content and static validation treats source material in the repository as a failure.

For each benchmark review:

1. Record the official source filename and SHA-256 in `benchmarks/manifest.json`.
2. Confirm the profile exists in `benchmarks/profile-matrix.json`.
3. Compare product, version, profile, control IDs, expected values, and validation notes.
4. Mark each control as `reviewed_against_authorized_source`, `needs_authorized_source_review`, `mismatch`, `organization_defined`, or `not_implemented`.
5. Keep full CIS text, PDFs, Build Kits, and scanner outputs out of commits.

Use this safe source-review worksheet structure in issues, pull requests, or private notes. Do not copy CIS prose, tables, screenshots, scanner output, or licensed text.

| Field | Value |
| --- | --- |
| Reviewer |  |
| Review date |  |
| Benchmark product/version/profile |  |
| Authorized source filename |  |
| Authorized source SHA-256 |  |
| Repository control file |  |
| Manifest entry ID |  |
| Comparison status | `needs_authorized_source_review` |

For every imported control, compare ID, title/provenance, expected value, profile applicability, validation behavior, remediation behavior, and whether the value is organization-defined. Safe notes should describe repository-side decisions, such as "expected value differs from source", "manual validation only", "organization-defined value", or "not implemented in this profile".

## Static Review Status

The current review was static-only. Benchmark scripts, repository validators, `usg`, `reg.exe`, `secedit.exe`, and shell syntax checks were not run on this computer.

One static reviewer pass was assigned per benchmark area:

- Windows 11 Enterprise.
- Windows Server 2025.
- Ubuntu 24.04 LTS.
- Ubuntu 22.04 LTS.
- Legacy Windows 10 Enterprise.

The static review improved audit-first behavior, explicit remediation gates, offline-hive opt-in, profile scaffolding, report boundary metadata, and source-material protections. It does not prove exact CIS control accuracy. Exact accuracy remains pending until authorized CIS PDFs or Build Kits are reviewed outside the repository.

Before publishing:

- Confirm only `README.md` remains as Markdown documentation.
- Confirm official CIS PDFs, Build Kits, scanner exports, report archives, legacy raw scripts, and binary manual documents such as `.docx` files are not committed.
- Confirm scaffold-only profiles have empty `controls` lists and do not advertise remediation.
- Confirm Windows profiles with unreviewed embedded controls do not advertise remediation.
- Confirm Windows entrypoints remain audit-first with `ShouldProcess`, OS target checks, explicit `-Remediate`, and explicit `-IncludeOfflineUserHives`.
- Confirm Ubuntu wrappers keep profile-neutral benchmark IDs, exact profile checks, and `--yes` for every remediation-mode path, including dry-run previews.
- Confirm `tools/validate_repo.py` remains static-only and does not execute benchmark scripts or host hardening tools.

Official public entry points:

- CIS Benchmarks: <https://www.cisecurity.org/cis-benchmarks>
- Microsoft Windows Desktop Benchmarks: <https://www.cisecurity.org/benchmark/microsoft_windows_desktop>
- Microsoft Windows Server Benchmarks: <https://www.cisecurity.org/benchmark/microsoft_windows_server/>
- Ubuntu Linux Benchmarks: <https://www.cisecurity.org/benchmark/ubuntu_linux>
- Canonical USG audit docs: <https://documentation.ubuntu.com/security/compliance/usg/cis-audit/>
- Canonical USG profile docs: <https://documentation.ubuntu.com/security/compliance/usg/cis-benchmarks/>

## Contributing

Security hardening changes can lock people out, break applications, or create false confidence. Contributions should include the benchmark target, profile, authorized-source comparison status, expected rollback considerations, and whether the change is audit-only or remediation-capable.

Contribution ground rules:

- Be respectful and evidence-first.
- Do not commit official CIS PDFs, Build Kits, scanner exports, report archives, binary manual documents, or licensed benchmark text.
- Do not claim a control is accurate until it has been compared against authorized source material and safe source metadata is recorded.
- Do not add remediation that runs by default.
- Do not run benchmark remediation on someone else's machine to support a contribution.
- Report security-sensitive issues privately when possible; if no private channel exists, open a minimal public issue asking for a private contact path without sensitive details.

## License

Code and documentation in this repository are released under the Apache License 2.0. See `NOTICE` for non-affiliation and trademark/source-material boundaries. CIS Benchmarks and related source material remain subject to CIS terms and are not licensed by this repository.
