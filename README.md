# CIS Benchmark Hardening Framework

This repository began as a Windows 10 CIS Level 1 batch file. It now provides a safer framework for building auditable CIS Benchmark remediation variants across Windows and Linux without redistributing CIS benchmark content.

> **Warning**
> These scripts and framework changes were generated with Codex and have not yet been tested on production Windows or Linux systems. Treat them as unvalidated starter automation: review every control, test in an isolated lab, create backups/rollback plans, and confirm results with authorized CIS audit tooling before using them to harden real assets.

## Important compliance note

Running a hardening script is not the same as passing a CIS audit. Treat every run as a change-control event:

1. Run an audit first and save evidence.
2. Back up local policy and relevant system state.
3. Apply remediation in a lab or pilot group.
4. Reboot when a control requires it.
5. Run the matching audit profile again.
6. Use CIS-CAT Pro, vendor-supported tooling, or another authorized scanner for formal audit evidence.

The scripts in this repository store implementation metadata, checks, and links. Download official CIS Benchmarks from CIS under the applicable license/terms and import only controls you are authorized to use.

## Supported benchmark matrix

The current manifest is in `benchmarks/manifest.json` and was verified on 2026-06-08 against official CIS benchmark pages.

| Target | CIS benchmark version | Entry point | Status |
| --- | --- | --- | --- |
| Microsoft Windows 11 Enterprise | 5.0.1 | `benchmarks/windows/desktop/windows-11-enterprise/Invoke-CisWindows11Level1.ps1` | Framework-ready; needs full authorized control import before claiming full compliance |
| Microsoft Windows Server 2025 | 2.0.0 | `benchmarks/windows/server/windows-server-2025/Invoke-CisWindowsServer2025Level1.ps1` | Framework-ready; needs full authorized control import before claiming full compliance |
| Ubuntu Linux 24.04 LTS | 2.0.0 | `benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh` | Wrapper-ready; prefers Ubuntu Security Guide / authorized scanner |
| Ubuntu Linux 22.04 LTS | 3.0.0 | `benchmarks/linux/ubuntu/22.04/cis-ubuntu-22.04.sh` | Wrapper-ready; prefers Ubuntu Security Guide / authorized scanner |
| Windows 10 Enterprise legacy | historical | `CIS LEVEL 1.bat` | Historical reference only |

## Repository layout

```text
benchmarks/
  manifest.json
  windows/
    common/
      CisWindowsHardening.psm1
      password-policy-level1.inf
    desktop/windows-11-enterprise/
    server/windows-server-2025/
  linux/ubuntu/24.04/
  linux/ubuntu/22.04/
reports/
```

## Windows usage

Open an elevated PowerShell session on the target OS.

Audit only:

```powershell
.\benchmarks\windows\desktop\windows-11-enterprise\Test-CisWindows11Level1.ps1
```

Remediate Windows 11 Enterprise Level 1 starter controls:

```powershell
.\benchmarks\windows\desktop\windows-11-enterprise\Invoke-CisWindows11Level1.ps1
```

Preview changes without applying them:

```powershell
.\benchmarks\windows\desktop\windows-11-enterprise\Invoke-CisWindows11Level1.ps1 -WhatIf
```

Windows Server 2025 uses the matching server folder:

```powershell
.\benchmarks\windows\server\windows-server-2025\Test-CisWindowsServer2025Level1.ps1
.\benchmarks\windows\server\windows-server-2025\Invoke-CisWindowsServer2025Level1.ps1
```

The scripts perform OS caption checks and refuse unsupported targets unless `-Force` is supplied. Use `-Force` only after confirming the benchmark applies to the host.

## Windows control model

Windows controls are represented as JSON metadata instead of raw, one-way `reg add` commands. Each automated registry control includes:

- CIS control identifier.
- Title.
- Machine or user scope.
- Registry path, value name, type, and expected value.
- Attack-surface reduction rationale.
- Validation note.
- Implementation status: `automated`, `manual`, `organization_defined`, `not_applicable`, or `unsupported`.

The PowerShell module applies machine-scope settings through the registry provider and handles user-scope settings by enumerating existing local profiles with `Win32_UserProfile`, applying settings to loaded user hives, temporarily loading signed-out users' `NTUSER.DAT` hives under `HKEY_USERS`, and updating the default profile for future users. This replaces the previous invalid pattern of writing to `HKU\Software\...` and prevents signed-out existing users from being missed.

## Password policy

The legacy `password policy.inf` is now represented as `benchmarks/windows/common/password-policy-level1.inf` and can be imported by the PowerShell framework with `secedit`. In a domain-joined environment, domain Group Policy may override local security policy; validate effective policy after Group Policy refresh.

## Linux / Ubuntu usage

The Ubuntu wrappers intentionally prefer Canonical Ubuntu Security Guide (`usg`) or an authorized scanner instead of embedding CIS benchmark text.

Audit Ubuntu 24.04:

```bash
./benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh --audit
```

Remediate Ubuntu 24.04:

```bash
sudo ./benchmarks/linux/ubuntu/24.04/cis-ubuntu-24.04.sh --remediate
```

Audit Ubuntu 22.04:

```bash
./benchmarks/linux/ubuntu/22.04/cis-ubuntu-22.04.sh --audit
```

Remediate Ubuntu 22.04:

```bash
sudo ./benchmarks/linux/ubuntu/22.04/cis-ubuntu-22.04.sh --remediate
```

If `usg` is not installed, the wrapper writes a report explaining that vendor-supported CIS tooling or an authorized scanner is required.

## Rollout guidance

- Test every profile in a lab before production.
- Confirm application compatibility, especially for authentication, SMB, firewall, UAC, and exploit-mitigation settings.
- Export current local security policy and critical registry paths before remediation.
- Expect some controls to require reboot or sign-out/sign-in.
- Document all `organization_defined` controls before enforcing them.
- Prefer centralized Group Policy / MDM for domain or enterprise fleets.
- Keep benchmark versions in `benchmarks/manifest.json` current as CIS publishes updates.

## Official CIS sources

- Microsoft Windows Desktop Benchmarks: <https://www.cisecurity.org/benchmark/microsoft_windows_desktop>
- Microsoft Windows Server Benchmarks: <https://www.cisecurity.org/benchmark/microsoft_windows_server/>
- Ubuntu Linux Benchmarks: <https://www.cisecurity.org/benchmark/ubuntu_linux>
- All CIS Benchmarks: <https://www.cisecurity.org/cis-benchmarks>

## Legacy files

The root-level `CIS LEVEL 1.bat`, `password policy.inf`, and manual DOCX are retained for comparison only. New development should use the structured benchmark folders and validation-first workflow.
