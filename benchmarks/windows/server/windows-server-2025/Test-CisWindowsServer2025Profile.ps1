[CmdletBinding()]
param(
    [ValidateSet('level1-member-server','level2-member-server','level1-domain-controller','level2-domain-controller')] [string] $Profile = 'level1-member-server',
    [switch] $Force,
    [switch] $IncludeOfflineUserHives,
    [string] $ReportPath
)

$invokePath = Join-Path $PSScriptRoot 'Invoke-CisWindowsServer2025Profile.ps1'
& $invokePath -Profile $Profile -Force:$Force -IncludeOfflineUserHives:$IncludeOfflineUserHives -ReportPath $ReportPath
