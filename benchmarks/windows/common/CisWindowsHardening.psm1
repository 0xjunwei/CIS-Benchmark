Set-StrictMode -Version Latest

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsEditionAndBuild {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [pscustomobject]@{
        Caption      = $os.Caption
        Version      = $os.Version
        BuildNumber  = [int]$os.BuildNumber
        ProductType  = $os.ProductType
        Architecture = $os.OSArchitecture
    }
}

function Assert-CisSupportedWindowsTarget {
    param(
        [Parameter(Mandatory)] [string[]] $SupportedCaptionPatterns,
        [switch] $Force
    )

    $target = Get-WindowsEditionAndBuild
    $matched = $false
    foreach ($pattern in $SupportedCaptionPatterns) {
        if ($target.Caption -like $pattern) {
            $matched = $true
            break
        }
    }

    if (-not $matched -and -not $Force) {
        throw "Unsupported OS '$($target.Caption)' build $($target.BuildNumber). Re-run with -Force only after confirming the CIS benchmark applies."
    }

    return $target
}

function ConvertTo-RegistryHivePath {
    param([Parameter(Mandatory)] [string] $RegistryPath)

    if ($RegistryPath -match '^(HKLM|HKEY_LOCAL_MACHINE)\\(.+)$') {
        return "Registry::HKEY_LOCAL_MACHINE\$($Matches[2])"
    }
    if ($RegistryPath -match '^(HKCU|HKEY_CURRENT_USER)\\(.+)$') {
        return "Registry::HKEY_CURRENT_USER\$($Matches[2])"
    }
    if ($RegistryPath -match '^(HKU|HKEY_USERS)\\(.+)$') {
        return "Registry::HKEY_USERS\$($Matches[2])"
    }
    throw "Unsupported registry hive in '$RegistryPath'."
}

function Set-CisRegistryPolicy {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Control,
        [switch] $WhatIf
    )

    $path = ConvertTo-RegistryHivePath -RegistryPath $Control.registry.path
    if ($WhatIf) {
        Write-Information "Would set $path::$($Control.registry.name) to $($Control.registry.expected_value)" -InformationAction Continue
        return
    }

    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    $propertyType = switch ($Control.registry.type) {
        'REG_DWORD' { 'DWord' }
        'REG_SZ'    { 'String' }
        'REG_EXPAND_SZ' { 'ExpandString' }
        default { throw "Unsupported registry type '$($Control.registry.type)' for $($Control.id)." }
    }

    New-ItemProperty -LiteralPath $path -Name $Control.registry.name -PropertyType $propertyType -Value $Control.registry.expected_value -Force | Out-Null
}

function Test-CisRegistryPolicy {
    param([Parameter(Mandatory)] [pscustomobject] $Control)

    $path = ConvertTo-RegistryHivePath -RegistryPath $Control.registry.path
    $actual = $null
    $passed = $false
    if (Test-Path -LiteralPath $path) {
        $item = Get-ItemProperty -LiteralPath $path -Name $Control.registry.name -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $actual = $item.($Control.registry.name)
            $passed = ([string]$actual -eq [string]$Control.registry.expected_value)
        }
    }

    [pscustomobject]@{
        id = $Control.id
        title = $Control.title
        status = if ($passed) { 'pass' } else { 'fail' }
        expected = $Control.registry.expected_value
        actual = $actual
        evidence = "$($Control.registry.path)::$($Control.registry.name)"
        implementation_status = $Control.implementation_status
        source_review_status = $Control.source_review_status
    }
}

function Get-CisInteractiveUserSids {
    $sidPattern = '^S-1-5-21-.+-\d+$'
    Get-ChildItem -Path Registry::HKEY_USERS |
        Where-Object { $_.PSChildName -match $sidPattern -and $_.PSChildName -notmatch '_Classes$' } |
        Select-Object -ExpandProperty PSChildName
}

function ConvertTo-CisOfflineHiveName {
    param([Parameter(Mandatory)] [string] $Identity)

    $safeName = $Identity -replace '[^A-Za-z0-9_]', '_'
    return "CIS_OFFLINE_$safeName"
}

function Get-CisUserProfileTargets {
    param([switch] $IncludeOfflineUserHives)

    $sidPattern = '^S-1-5-21-.+-\d+$'
    $loadedSids = @(Get-CisInteractiveUserSids)
    $seen = @{}
    $targets = New-Object System.Collections.Generic.List[object]

    if ($IncludeOfflineUserHives) {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile |
            Where-Object {
                $_.SID -match $sidPattern -and
                -not $_.Special -and
                $_.LocalPath -and
                (Test-Path -LiteralPath (Join-Path $_.LocalPath 'NTUSER.DAT'))
            })

        foreach ($profile in $profiles) {
            $isLoaded = $loadedSids -contains $profile.SID
            $targets.Add([pscustomobject]@{
                Sid = $profile.SID
                LocalPath = $profile.LocalPath
                HiveFile = Join-Path $profile.LocalPath 'NTUSER.DAT'
                RegistryKeyName = if ($isLoaded) { $profile.SID } else { ConvertTo-CisOfflineHiveName -Identity $profile.SID }
                IsLoaded = $isLoaded
                IsDefaultProfile = $false
            })
            $seen[$profile.SID] = $true
        }
    }

    foreach ($sid in $loadedSids) {
        if (-not $seen.ContainsKey($sid)) {
            $targets.Add([pscustomobject]@{
                Sid = $sid
                LocalPath = $null
                HiveFile = $null
                RegistryKeyName = $sid
                IsLoaded = $true
                IsDefaultProfile = $false
            })
        }
    }

    if ($IncludeOfflineUserHives) {
        $defaultHive = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
        if (Test-Path -LiteralPath $defaultHive) {
            $targets.Add([pscustomobject]@{
                Sid = 'DEFAULT_PROFILE'
                LocalPath = Join-Path $env:SystemDrive 'Users\Default'
                HiveFile = $defaultHive
                RegistryKeyName = 'CIS_DEFAULT_USER'
                IsLoaded = Test-Path -LiteralPath 'Registry::HKEY_USERS\CIS_DEFAULT_USER'
                IsDefaultProfile = $true
            })
        }
    }

    return $targets
}

function Mount-CisUserProfileHive {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Target,
        [switch] $WhatIf
    )

    $registryPath = "HKU\$($Target.RegistryKeyName)"
    $providerPath = "Registry::HKEY_USERS\$($Target.RegistryKeyName)"
    if ($Target.IsLoaded -or (Test-Path -LiteralPath $providerPath)) {
        return [pscustomobject]@{
            RegistryPath = $registryPath
            ProviderPath = $providerPath
            ShouldUnload = $false
            Status = 'loaded'
        }
    }

    if (-not $Target.HiveFile) {
        return [pscustomobject]@{
            RegistryPath = $registryPath
            ProviderPath = $providerPath
            ShouldUnload = $false
            Status = 'missing-hive-file'
        }
    }

    if ($WhatIf) {
        Write-Information "Would load offline user hive $($Target.HiveFile) into $registryPath." -InformationAction Continue
        return [pscustomobject]@{
            RegistryPath = $registryPath
            ProviderPath = $providerPath
            ShouldUnload = $false
            Status = 'whatif-offline-hive-not-loaded'
        }
    }

    & reg.exe load $registryPath $Target.HiveFile | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{
            RegistryPath = $registryPath
            ProviderPath = $providerPath
            ShouldUnload = $false
            Status = "load-failed-$LASTEXITCODE"
        }
    }

    return [pscustomobject]@{
        RegistryPath = $registryPath
        ProviderPath = $providerPath
        ShouldUnload = $true
        Status = 'loaded-offline'
    }
}

function Dismount-CisUserProfileHive {
    param([Parameter(Mandatory)] [pscustomobject] $Mount)

    if (-not $Mount.ShouldUnload) {
        return
    }

    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    & reg.exe unload $Mount.RegistryPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to unload offline user hive $($Mount.RegistryPath); reg.exe exited with $LASTEXITCODE."
    }
}

function Invoke-CisUserRegistryPolicy {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Control,
        [switch] $Apply,
        [switch] $WhatIf,
        [switch] $IncludeOfflineUserHives
    )

    $results = New-Object System.Collections.Generic.List[object]
    $targets = @(Get-CisUserProfileTargets -IncludeOfflineUserHives:$IncludeOfflineUserHives)

    foreach ($target in $targets) {
        $mount = Mount-CisUserProfileHive -Target $target -WhatIf:$WhatIf
        if ($mount.Status -like 'load-failed-*' -or $mount.Status -eq 'missing-hive-file') {
            $results.Add([pscustomobject]@{
                id = $Control.id
                title = $Control.title
                status = 'fail'
                target = $target.Sid
                hive_status = $mount.Status
                evidence = $target.HiveFile
                implementation_status = $Control.implementation_status
                source_review_status = $Control.source_review_status
            })
            continue
        }

        try {
            $copy = $Control.PSObject.Copy()
            $copy.registry = $Control.registry.PSObject.Copy()
            $copy.registry.path = "$($mount.RegistryPath)\$($Control.registry.sub_path)"

            if ($Apply) {
                Set-CisRegistryPolicy -Control $copy -WhatIf:$WhatIf
            }

            $result = if ($Apply -and $WhatIf) {
                [pscustomobject]@{
                    id = $Control.id
                    title = $Control.title
                    status = 'whatif'
                    target = $target.Sid
                    hive_status = $mount.Status
                    evidence = "$($copy.registry.path)::$($copy.registry.name)"
                    implementation_status = $Control.implementation_status
                    source_review_status = $Control.source_review_status
                }
            } else {
                Test-CisRegistryPolicy -Control $copy
            }
            $result | Add-Member -NotePropertyName target -NotePropertyValue $target.Sid -Force
            $result | Add-Member -NotePropertyName hive_status -NotePropertyValue $mount.Status -Force
            $results.Add($result)
        } finally {
            Dismount-CisUserProfileHive -Mount $mount
        }
    }

    return $results
}

function New-CisReportStatusLegend {
    [ordered]@{
        pass = 'A local automated check matched the expected metadata value; this is not proof of CIS compliance or authorized-source accuracy.'
        fail = 'A local automated check did not match the expected metadata value.'
        organization_defined = 'The setting depends on local policy and is not a pass result.'
        'manual-validation-required' = 'Automation did not validate the control; authorized manual or scanner evidence is required.'
        'remediated-needs-validation' = 'A remediation path was invoked; a separate authorized validation pass is required.'
        whatif = 'Preview only; no remediation should have been applied.'
    }
}

function Get-CisRepositoryRoot {
    param([Parameter(Mandatory)] [string] $StartPath)

    $current = (Resolve-Path -LiteralPath $StartPath).Path
    if (-not (Get-Item -LiteralPath $current).PSIsContainer) {
        $current = Split-Path -Parent $current
    }

    while ($current) {
        if (Test-Path -LiteralPath (Join-Path $current 'benchmarks\manifest.json')) {
            return $current
        }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) {
            break
        }
        $current = $parent
    }

    throw "Could not locate repository root from '$StartPath'."
}

function Resolve-CisReportPath {
    param(
        [Parameter(Mandatory)] [string] $ControlsPath,
        [Parameter(Mandatory)] [string] $ReportPath
    )

    $repoRoot = Get-CisRepositoryRoot -StartPath $ControlsPath
    if ([System.IO.Path]::IsPathRooted($ReportPath)) {
        $resolvedReportPath = [System.IO.Path]::GetFullPath($ReportPath)
    } else {
        $resolvedReportPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ReportPath))
    }

    $reportsRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'reports'))
    $reportsRootPrefix = $reportsRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedReportPath.StartsWith($reportsRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "ReportPath must stay under repository reports directory: $reportsRoot"
    }

    return $resolvedReportPath
}

function Assert-CisControlsReadyForRemediation {
    param([Parameter(Mandatory)] [pscustomobject] $Controls)

    $comparisonStatus = $Controls.source_comparison.status
    if ($comparisonStatus -ne 'reviewed_against_authorized_source') {
        throw "Remediation is disabled until the control set is reviewed against authorized CIS source material. Current source comparison status: $comparisonStatus."
    }

    $blockingControls = @($Controls.controls | Where-Object {
        $_.implementation_status -eq 'automated' -and
        $_.source_review_status -ne 'reviewed_against_authorized_source'
    })
    if ($blockingControls.Count -gt 0) {
        $first = $blockingControls[0]
        throw "Remediation is disabled because $($blockingControls.Count) automated control(s) have not been reviewed against authorized CIS source material. First blocking control: $($first.id) status '$($first.source_review_status)'."
    }
}

function Import-CisSecurityTemplate {
    param(
        [Parameter(Mandatory)] [string] $TemplatePath,
        [switch] $WhatIf
    )

    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        throw "Security template not found: $TemplatePath"
    }

    $database = Join-Path $env:TEMP "cis-hardening-$(Get-Date -Format yyyyMMddHHmmss).sdb"
    if ($WhatIf) {
        Write-Information "Would import security template $TemplatePath using secedit." -InformationAction Continue
        return
    }

    & secedit.exe /configure /db $database /cfg $TemplatePath /areas SECURITYPOLICY | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "secedit failed with exit code $LASTEXITCODE."
    }
}

function Invoke-CisControls {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string] $ControlsPath,
        [ValidateSet('Remediate','Audit')] [string] $Mode = 'Audit',
        [switch] $IncludeOfflineUserHives,
        [string] $ReportPath
    )

    $resolvedControlsPath = (Resolve-Path -LiteralPath $ControlsPath).Path
    $controls = Get-Content -LiteralPath $resolvedControlsPath -Raw | ConvertFrom-Json
    $controlCount = @($controls.controls).Count
    if ($Mode -eq 'Remediate' -and ($controls.coverage_status -eq 'scaffold_no_controls_imported' -or $controlCount -eq 0)) {
        throw "Remediation is disabled for scaffold-only or empty control set '$($controls.benchmark_id)'."
    }
    if ($Mode -eq 'Remediate') {
        Assert-CisControlsReadyForRemediation -Controls $controls
    }

    if ($Mode -eq 'Remediate') {
        $approved = $PSCmdlet.ShouldProcess($controls.benchmark_id, 'Apply CIS remediation controls')
        if (-not $approved -and -not $WhatIfPreference) {
            return @()
        }
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($control in $controls.controls) {
        if ($control.implementation_status -ne 'automated') {
            $results.Add([pscustomobject]@{
                id = $control.id
                title = $control.title
                status = $control.implementation_status
                evidence = $control.validation_note
                implementation_status = $control.implementation_status
                source_review_status = $control.source_review_status
            })
            continue
        }

        if ($control.scope -eq 'user') {
            $userResults = Invoke-CisUserRegistryPolicy -Control $control -Apply:($Mode -eq 'Remediate') -WhatIf:$WhatIfPreference -IncludeOfflineUserHives:$IncludeOfflineUserHives
            foreach ($userResult in $userResults) {
                $results.Add($userResult)
            }
            continue
        }

        if ($Mode -eq 'Remediate') {
            if ($control.type -eq 'security_template') {
                $templatePath = $control.template_path
                if (-not [System.IO.Path]::IsPathRooted($templatePath)) {
                    $templatePath = Join-Path (Split-Path -Parent $resolvedControlsPath) $templatePath
                }
                Import-CisSecurityTemplate -TemplatePath $templatePath -WhatIf:$WhatIfPreference
            } else {
                Set-CisRegistryPolicy -Control $control -WhatIf:$WhatIfPreference
            }
        }

        if ($control.type -eq 'registry' -and $control.scope -ne 'user') {
            $results.Add((Test-CisRegistryPolicy -Control $control))
        } else {
            $results.Add([pscustomobject]@{
                id = $control.id
                title = $control.title
                status = if ($Mode -eq 'Remediate' -and $WhatIfPreference) { 'whatif' } elseif ($Mode -eq 'Remediate') { 'remediated-needs-validation' } else { 'manual-validation-required' }
                evidence = $control.validation_note
                implementation_status = $control.implementation_status
                source_review_status = $control.source_review_status
            })
        }
    }

    if ($ReportPath) {
        $ReportPath = Resolve-CisReportPath -ControlsPath $resolvedControlsPath -ReportPath $ReportPath
        $reportDirectory = Split-Path -Parent $ReportPath
        if ($reportDirectory -and -not (Test-Path -LiteralPath $reportDirectory)) {
            New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
        }
        $reportDocument = [pscustomobject]@{
            benchmark_id = $controls.benchmark_id
            coverage_status = $controls.coverage_status
            source_comparison = $controls.source_comparison
            generated_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            mode = $Mode
            whatif = [bool]$WhatIfPreference
            include_offline_user_hives = [bool]$IncludeOfflineUserHives
            validation_boundary = 'Helper report only; not compliance evidence. Review source_review_status and validate with CIS-CAT Pro, vendor-supported tooling, or another authorized scanner.'
            status_legend = New-CisReportStatusLegend
            results = $results
        }
        $reportDocument | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    }

    return $results
}

Export-ModuleMember -Function Test-IsAdministrator,Get-WindowsEditionAndBuild,Assert-CisSupportedWindowsTarget,Invoke-CisControls
