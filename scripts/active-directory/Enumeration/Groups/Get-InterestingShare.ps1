# Get-InterestingShare.ps1
# File Share Access Enumeration for Active Directory
# Finds interesting share permissions, especially through group memberships

#region Helper Functions

function Test-IsDefaultShare {
    <#
    .SYNOPSIS
    Checks if a share is a default/boring share.
    #>
    param(
        [string]$ShareName
    )

    $defaultShares = @(
        'ADMIN$',
        'C$', 'D$', 'E$', 'F$',  # Drive shares
        'IPC$',
        'print$',
        'NETLOGON',
        'SYSVOL'
    )

    return $defaultShares -contains $ShareName
}

function Get-ShareSensitivity {
    <#
    .SYNOPSIS
    Determines the sensitivity level of a share based on name/path.
    #>
    param(
        [string]$ShareName,
        [string]$SharePath
    )

    # High sensitivity keywords
    $highKeywords = @('backup', 'admin', 'confidential', 'secret', 'password', 'private', 'executive', 'finance', 'hr', 'legal')

    # Medium sensitivity keywords
    $mediumKeywords = @('share', 'common', 'public', 'users', 'department', 'project', 'data')

    $lowerName = $ShareName.ToLower()
    $lowerPath = $SharePath.ToLower()

    foreach($keyword in $highKeywords) {
        if($lowerName -match $keyword -or $lowerPath -match $keyword) {
            return 'HIGH'
        }
    }

    foreach($keyword in $mediumKeywords) {
        if($lowerName -match $keyword -or $lowerPath -match $keyword) {
            return 'MEDIUM'
        }
    }

    return 'LOW'
}

function Get-SharePermission {
    <#
    .SYNOPSIS
    Gets permissions for a specific share.

    .DESCRIPTION
    Retrieves ACL information for a network share, showing which principals have access.

    .PARAMETER ComputerName
    Computer hosting the share

    .PARAMETER ShareName
    Name of the share

    .EXAMPLE
    Get-SharePermission -ComputerName "DC01" -ShareName "Finance"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [string]$ShareName,

        [PSCredential]$Credential
    )

    try {
        # Get the share object
        $params = @{
            CimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
        }

        $share = Get-SmbShare @params | Where-Object { $_.Name -eq $ShareName }

        if(-not $share) {
            Write-Verbose "Share $ShareName not found on $ComputerName"
            return $null
        }

        # Get share ACL
        $shareAccess = Get-SmbShareAccess @params -Name $ShareName

        $results = @()

        foreach($ace in $shareAccess) {
            $results += [PSCustomObject]@{
                ComputerName = $ComputerName
                ShareName = $ShareName
                SharePath = $share.Path
                Principal = $ace.AccountName
                AccessRight = $ace.AccessRight
                AccessControlType = $ace.AccessControlType
            }
        }

        return $results
    }
    catch {
        Write-Verbose "Error getting share permissions for \\$ComputerName\$ShareName : $_"
        return $null
    }
}

#endregion

#region Main Functions

function Find-InterestingShare {
    <#
    .SYNOPSIS
    Finds interesting file shares in the domain.

    .DESCRIPTION
    Scans domain computers for file shares and identifies interesting access patterns,
    especially shares accessible through group memberships.

    .PARAMETER ComputerName
    Specific computer(s) to scan. If not specified, scans all domain computers.

    .PARAMETER GroupName
    Specific group to check - shows all shares this group has access to

    .PARAMETER ExcludeDefault
    Exclude default shares (C$, ADMIN$, IPC$, etc.)

    .PARAMETER Sensitivity
    Only show shares of specific sensitivity (HIGH, MEDIUM, LOW)

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use

    .PARAMETER ShowProgress
    Display progress bar

    .EXAMPLE
    Find-InterestingShare -ExcludeDefault

    .EXAMPLE
    Find-InterestingShare -GroupName "IT Support" -Verbose

    .EXAMPLE
    Find-InterestingShare -ComputerName "FILE01" -Sensitivity HIGH
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$ComputerName,

        [string]$GroupName,

        [switch]$ExcludeDefault,

        [ValidateSet('HIGH','MEDIUM','LOW','All')]
        [string]$Sensitivity = 'All',

        [string]$Server,

        [PSCredential]$Credential,

        [switch]$ShowProgress
    )

    begin {
        Write-Host "`nScanning for interesting file shares...`n" -ForegroundColor Cyan

        $allResults = @()
        $computers = @()

        # Get list of computers to scan
        if($ComputerName) {
            $computers = $ComputerName
            Write-Verbose "Scanning specified computers: $($computers -join ', ')"
        }
        else {
            Write-Verbose "Retrieving all domain computers..."
            $params = @{
                Filter = "OperatingSystem -like '*Server*'"
                Properties = 'Name', 'DNSHostName', 'OperatingSystem'
            }
            if($Server) { $params['Server'] = $Server }
            if($Credential) { $params['Credential'] = $Credential }

            try {
                $computers = Get-ADComputer @params -ErrorAction Stop |
                             Select-Object -ExpandProperty DNSHostName
                Write-Verbose "Found $($computers.Count) servers to scan"
            }
            catch {
                Write-Error "Failed to retrieve domain computers: $_"
                return
            }
        }

        $totalComputers = $computers.Count
        $currentComputer = 0
    }

    process {
        foreach($computer in $computers) {
            $currentComputer++

            if($ShowProgress) {
                Write-Progress -Activity "Scanning file shares" `
                               -Status "Scanning $computer ($currentComputer of $totalComputers)" `
                               -PercentComplete (($currentComputer / $totalComputers) * 100)
            }

            Write-Verbose "Scanning shares on $computer"

            try {
                # Get all shares on this computer
                $cimSession = New-CimSession -ComputerName $computer -ErrorAction Stop
                $shares = Get-SmbShare -CimSession $cimSession -ErrorAction Stop

                foreach($share in $shares) {
                    # Skip default shares if requested
                    if($ExcludeDefault -and (Test-IsDefaultShare -ShareName $share.Name)) {
                        Write-Verbose "  Skipping default share: $($share.Name)"
                        continue
                    }

                    Write-Verbose "  Checking share: $($share.Name)"

                    # Get share permissions
                    $shareAccess = Get-SmbShareAccess -CimSession $cimSession -Name $share.Name -ErrorAction Stop

                    foreach($ace in $shareAccess) {
                        # Filter by group if specified
                        if($GroupName) {
                            if($ace.AccountName -notmatch $GroupName) {
                                continue
                            }
                        }

                        # Determine if this is group-based access
                        $isGroupAccess = $ace.AccountName -match '\\'  # Domain\Group format

                        # Try to determine if it's a group
                        $principalType = 'Unknown'
                        try {
                            $accountName = $ace.AccountName -replace '^.*\\'

                            # Try as group
                            $grpParams = @{
                                Identity = $accountName
                                ErrorAction = 'SilentlyContinue'
                            }
                            if($Server) { $grpParams['Server'] = $Server }
                            if($Credential) { $grpParams['Credential'] = $Credential }

                            $group = Get-ADGroup @grpParams
                            if($group) {
                                $principalType = 'Group'
                            }
                            else {
                                # Try as user
                                $user = Get-ADUser @grpParams
                                if($user) {
                                    $principalType = 'User'
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not determine type for: $($ace.AccountName)"
                        }

                        # Get sensitivity
                        $sensitivity = Get-ShareSensitivity -ShareName $share.Name -SharePath $share.Path

                        # Filter by sensitivity if requested
                        if($Sensitivity -ne 'All' -and $sensitivity -ne $Sensitivity) {
                            continue
                        }

                        $result = [PSCustomObject]@{
                            ComputerName = $computer
                            ShareName = $share.Name
                            SharePath = $share.Path
                            ShareDescription = $share.Description
                            Principal = $ace.AccountName
                            PrincipalType = $principalType
                            AccessRight = $ace.AccessRight
                            AccessControlType = $ace.AccessControlType
                            Sensitivity = $sensitivity
                            UNCPath = "\\$computer\$($share.Name)"
                        }

                        $allResults += $result
                    }
                }

                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Failed to scan $computer : $_"
            }
        }
    }

    end {
        if($ShowProgress) {
            Write-Progress -Activity "Scanning file shares" -Completed
        }

        if($allResults.Count -eq 0) {
            Write-Host "No interesting shares found." -ForegroundColor Yellow
            return
        }

        # Display results with color coding
        Write-Host "Found $($allResults.Count) share permission entries:`n" -ForegroundColor Green

        # Group by share for cleaner display
        $groupedByShare = $allResults | Group-Object UNCPath

        foreach($shareGroup in $groupedByShare) {
            $firstResult = $shareGroup.Group[0]

            # Color code by sensitivity
            $color = switch($firstResult.Sensitivity) {
                'HIGH' { 'Red' }
                'MEDIUM' { 'Yellow' }
                default { 'White' }
            }

            Write-Host "  [$($firstResult.Sensitivity)] " -ForegroundColor $color -NoNewline
            Write-Host "$($shareGroup.Name)" -ForegroundColor Cyan

            if($firstResult.ShareDescription) {
                Write-Host "    Description: $($firstResult.ShareDescription)" -ForegroundColor Gray
            }

            # Show permissions
            foreach($perm in $shareGroup.Group | Where-Object { $_.AccessControlType -eq 'Allow' }) {
                $permColor = if($perm.PrincipalType -eq 'Group') { 'Green' } else { 'White' }

                Write-Host "    - " -NoNewline
                Write-Host "$($perm.Principal) " -ForegroundColor $permColor -NoNewline
                Write-Host "[$($perm.PrincipalType)] " -ForegroundColor Gray -NoNewline
                Write-Host "has $($perm.AccessRight)" -ForegroundColor $permColor
            }

            Write-Host ""
        }

        return $allResults
    }
}

function Test-GroupShareAccess {
    <#
    .SYNOPSIS
    Tests what file shares a specific group can access.

    .DESCRIPTION
    Scans domain file shares to determine which ones are accessible by members of a specific group.
    Useful for privilege escalation when you can add yourself to a group.

    .PARAMETER GroupName
    Name of the group to test

    .PARAMETER ComputerName
    Specific computer(s) to scan. If not specified, scans all domain servers.

    .PARAMETER ExcludeDefault
    Exclude default shares (C$, ADMIN$, IPC$, etc.)

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use

    .PARAMETER ShowProgress
    Display progress bar

    .EXAMPLE
    Test-GroupShareAccess -GroupName "Backup Operators"

    .EXAMPLE
    Test-GroupShareAccess -GroupName "IT Support" -ComputerName "FILE01","FILE02" -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,

        [string[]]$ComputerName,

        [switch]$ExcludeDefault,

        [string]$Server,

        [PSCredential]$Credential,

        [switch]$ShowProgress
    )

    Write-Host "`nTesting share access for group: " -ForegroundColor Cyan -NoNewline
    Write-Host "$GroupName`n" -ForegroundColor Green

    # Verify group exists
    try {
        $params = @{
            Identity = $GroupName
            ErrorAction = 'Stop'
        }
        if($Server) { $params['Server'] = $Server }
        if($Credential) { $params['Credential'] = $Credential }

        $group = Get-ADGroup @params
        Write-Verbose "Found group: $($group.DistinguishedName)"
    }
    catch {
        Write-Error "Group '$GroupName' not found: $_"
        return
    }

    # Find all shares accessible by this group
    $findParams = @{
        GroupName = $GroupName
        ExcludeDefault = $ExcludeDefault
        ShowProgress = $ShowProgress
    }
    if($ComputerName) { $findParams['ComputerName'] = $ComputerName }
    if($Server) { $findParams['Server'] = $Server }
    if($Credential) { $findParams['Credential'] = $Credential }

    $results = Find-InterestingShare @findParams

    if($results) {
        Write-Host "`nSummary:" -ForegroundColor Cyan

        $highSensitivity = ($results | Where-Object { $_.Sensitivity -eq 'HIGH' }).Count
        $readAccess = ($results | Where-Object { $_.AccessRight -match 'Read' }).Count
        $changeAccess = ($results | Where-Object { $_.AccessRight -match 'Change|Full' }).Count
        $fullAccess = ($results | Where-Object { $_.AccessRight -match 'Full' }).Count

        Write-Host "  Total shares accessible: $($results.Count)" -ForegroundColor Green
        Write-Host "  High sensitivity shares: $highSensitivity" -ForegroundColor $(if($highSensitivity -gt 0){'Red'}else{'Green'})
        Write-Host "  Read access: $readAccess" -ForegroundColor Yellow
        Write-Host "  Change access: $changeAccess" -ForegroundColor Yellow
        Write-Host "  Full access: $fullAccess" -ForegroundColor $(if($fullAccess -gt 0){'Red'}else{'Yellow'})
    }

    return $results
}

function Get-NestedGroupShares {
    <#
    .SYNOPSIS
    Finds shares accessible through nested group memberships.

    .DESCRIPTION
    Identifies file shares that are accessible through nested group memberships,
    which might not be immediately obvious.

    .PARAMETER UserName
    User to check (defaults to current user)

    .PARAMETER MaxDepth
    Maximum depth for nested group resolution

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use

    .EXAMPLE
    Get-NestedGroupShares

    .EXAMPLE
    Get-NestedGroupShares -UserName "jdoe" -Verbose
    #>
    [CmdletBinding()]
    param(
        [string]$UserName = $env:USERNAME,

        [ValidateRange(1,10)]
        [int]$MaxDepth = 5,

        [string]$Server,

        [PSCredential]$Credential
    )

    Write-Host "`nFinding shares accessible through nested groups for: " -ForegroundColor Cyan -NoNewline
    Write-Host "$UserName`n" -ForegroundColor Green

    # Get all groups (including nested) for the user
    try {
        $params = @{
            Identity = $UserName
            Properties = 'MemberOf'
            ErrorAction = 'Stop'
        }
        if($Server) { $params['Server'] = $Server }
        if($Credential) { $params['Credential'] = $Credential }

        $user = Get-ADUser @params
        Write-Verbose "Found user: $($user.DistinguishedName)"

        # Get nested groups
        $allGroups = @()
        $processedGroups = @{}

        function Get-NestedGroups {
            param([string]$GroupDN, [int]$Depth)

            if($Depth -ge $MaxDepth) { return }
            if($processedGroups.ContainsKey($GroupDN)) { return }

            $processedGroups[$GroupDN] = $true

            try {
                $grpParams = @{
                    Identity = $GroupDN
                    Properties = 'MemberOf'
                    ErrorAction = 'Stop'
                }
                if($Server) { $grpParams['Server'] = $Server }
                if($Credential) { $grpParams['Credential'] = $Credential }

                $group = Get-ADGroup @grpParams
                $allGroups += $group

                foreach($parentDN in $group.MemberOf) {
                    Get-NestedGroups -GroupDN $parentDN -Depth ($Depth + 1)
                }
            }
            catch {
                Write-Verbose "Could not process group: $GroupDN"
            }
        }

        foreach($groupDN in $user.MemberOf) {
            Get-NestedGroups -GroupDN $groupDN -Depth 0
        }

        Write-Verbose "Found $($allGroups.Count) groups (including nested)"

        # Find shares for all these groups
        $allShares = @()

        foreach($group in $allGroups) {
            Write-Verbose "Checking shares for group: $($group.Name)"
            $shares = Find-InterestingShare -GroupName $group.Name -ExcludeDefault -Credential $Credential -Server $Server

            foreach($share in $shares) {
                $share | Add-Member -NotePropertyName 'ViaGroup' -NotePropertyValue $group.Name -Force
                $allShares += $share
            }
        }

        if($allShares.Count -eq 0) {
            Write-Host "No shares found accessible through group memberships." -ForegroundColor Yellow
        }
        else {
            Write-Host "Found $($allShares.Count) shares accessible through group memberships`n" -ForegroundColor Green
            $allShares | Format-Table UNCPath, ViaGroup, AccessRight, Sensitivity -AutoSize
        }

        return $allShares
    }
    catch {
        Write-Error "Failed to process user '$UserName': $_"
    }
}

#endregion

# Example usage:
# Find-InterestingShare -ExcludeDefault -ShowProgress
# Test-GroupShareAccess -GroupName "IT Support" -Verbose
# Get-NestedGroupShares -UserName "jdoe"
