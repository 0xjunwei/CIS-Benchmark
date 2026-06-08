[CmdletBinding()]
param(
    [ValidateSet('level1','level2')] [string] $Profile = 'level1',
    [switch] $Force,
    [switch] $IncludeOfflineUserHives,
    [string] $ReportPath
)

$invokePath = Join-Path $PSScriptRoot 'Invoke-CisWindows11Profile.ps1'
& $invokePath -Profile $Profile -Force:$Force -IncludeOfflineUserHives:$IncludeOfflineUserHives -ReportPath $ReportPath
