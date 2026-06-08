[CmdletBinding()]
param(
    [switch] $Force,
    [switch] $IncludeOfflineUserHives,
    [string] $ReportPath = "reports/windows/windows-server-2025/level1-audit.json"
)

& (Join-Path $PSScriptRoot 'Invoke-CisWindowsServer2025Level1.ps1') -Force:$Force -IncludeOfflineUserHives:$IncludeOfflineUserHives -ReportPath $ReportPath
