[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $Force,
    [switch] $AuditOnly,
    [string] $ReportPath = "reports/windows/windows-11-enterprise/level1-results.json"
)

$modulePath = Join-Path $PSScriptRoot '..\..\common\CisWindowsHardening.psm1'
$controlsPath = Join-Path $PSScriptRoot 'controls.windows11.enterprise.level1.json'
Import-Module $modulePath -Force

if (-not $AuditOnly -and -not (Test-IsAdministrator)) {
    throw 'Run this script in an elevated PowerShell session.'
}

Assert-CisSupportedWindowsTarget -SupportedCaptionPatterns @('*Windows 11 Enterprise*') -Force:$Force | Out-Null
$mode = if ($AuditOnly) { 'Audit' } else { 'Remediate' }
Invoke-CisControls -ControlsPath $controlsPath -Mode $mode -WhatIf:$WhatIfPreference -ReportPath $ReportPath
