[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('level1','level2')] [string] $Profile = 'level1',
    [switch] $Force,
    [switch] $Remediate,
    [switch] $IncludeOfflineUserHives,
    [string] $ReportPath
)

$modulePath = Join-Path $PSScriptRoot '..\..\common\CisWindowsHardening.psm1'
$profileControls = @{
    'level1' = 'controls.windows11.enterprise.level1.json'
    'level2' = 'controls.windows11.enterprise.level2.json'
}
$controlsPath = Join-Path $PSScriptRoot $profileControls[$Profile]
Import-Module $modulePath -Force

if (-not (Test-IsAdministrator)) {
    throw 'Run this script in an elevated PowerShell session. Add -IncludeOfflineUserHives only when signed-out and default profile hive access is approved.'
}

Assert-CisSupportedWindowsTarget -SupportedCaptionPatterns @('*Windows 11 Enterprise*') -Force:$Force | Out-Null
$mode = if ($Remediate) { 'Remediate' } else { 'Audit' }
$controlMetadata = Get-Content -LiteralPath $controlsPath -Raw | ConvertFrom-Json
if ($Remediate -and ($controlMetadata.coverage_status -eq 'scaffold_no_controls_imported' -or @($controlMetadata.controls).Count -eq 0)) {
    throw "Remediation is disabled for scaffold-only or empty profile '$Profile'."
}
if ($Remediate -and $controlMetadata.source_comparison.status -ne 'reviewed_against_authorized_source') {
    throw "Remediation is disabled until profile '$Profile' is reviewed against authorized CIS source material."
}
if (-not $ReportPath) {
    $reportName = if ($Remediate) { 'remediation' } else { 'audit' }
    $ReportPath = "reports/windows/windows-11-enterprise/$Profile-$reportName.json"
}
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..\..')).Path
if (-not [System.IO.Path]::IsPathRooted($ReportPath)) {
    $ReportPath = Join-Path $repoRoot $ReportPath
}

$previewOnly = $false
if ($Remediate) {
    $approved = $PSCmdlet.ShouldProcess("Windows 11 Enterprise $Profile controls", 'Apply remediation')
    if (-not $approved -and -not $WhatIfPreference) {
        return
    }
    $previewOnly = -not $approved
}

Invoke-CisControls -ControlsPath $controlsPath -Mode $mode -WhatIf:($WhatIfPreference -or $previewOnly) -Confirm:$false -IncludeOfflineUserHives:$IncludeOfflineUserHives -ReportPath $ReportPath
