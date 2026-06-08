[CmdletBinding()]
param(
    [switch] $Force,
    [switch] $IncludeOfflineUserHives,
    [string] $ReportPath = "reports/windows/windows-11-enterprise/level1-audit.json"
)

& (Join-Path $PSScriptRoot 'Invoke-CisWindows11Level1.ps1') -Force:$Force -IncludeOfflineUserHives:$IncludeOfflineUserHives -ReportPath $ReportPath
