[CmdletBinding()]
param(
    [switch] $Force,
    [string] $ReportPath = "reports/windows/windows-11-enterprise/level1-audit.json"
)

& (Join-Path $PSScriptRoot 'Invoke-CisWindows11Level1.ps1') -AuditOnly -Force:$Force -ReportPath $ReportPath
