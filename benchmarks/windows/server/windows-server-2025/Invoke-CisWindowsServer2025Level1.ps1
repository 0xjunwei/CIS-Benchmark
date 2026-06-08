[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $Force,
    [switch] $AuditOnly,
    [string] $ReportPath = "reports/windows/windows-server-2025/level1-results.json"
)

$modulePath = Join-Path $PSScriptRoot '..\..\common\CisWindowsHardening.psm1'
$controlsPath = Join-Path $PSScriptRoot 'controls.windows-server2025.level1.json'
Import-Module $modulePath -Force

if (-not (Test-IsAdministrator)) {
    throw 'Run this script in an elevated PowerShell session so loaded and signed-out user hives can be audited or remediated.'
}

Assert-CisSupportedWindowsTarget -SupportedCaptionPatterns @('*Windows Server 2025*') -Force:$Force | Out-Null
$mode = if ($AuditOnly) { 'Audit' } else { 'Remediate' }
Invoke-CisControls -ControlsPath $controlsPath -Mode $mode -WhatIf:$WhatIfPreference -ReportPath $ReportPath
