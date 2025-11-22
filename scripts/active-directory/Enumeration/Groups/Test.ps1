function Get-GroupMembershipPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('SamAccountName')]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetGroup,

        [Parameter(DontShow)]
        [string[]]$CurrentPath = @(),

        [Parameter(DontShow)]
        [hashtable]$VisitedGroups = @{},

        [Parameter(DontShow)]
        [hashtable]$MembershipCache = @{},

        [switch]$FindAllPaths,

        [ValidateRange(1, 100)]
        [int]$MaxDepth = 50,

        [Parameter(DontShow)]
        [int]$CurrentDepth = 0
    )

    # Check depth limit to prevent excessive recursion
    if($CurrentDepth -ge $MaxDepth) {
        Write-Verbose "Maximum depth ($MaxDepth) reached for '$UserName'"
        return $false
    }

    Write-Verbose "Processing '$UserName' at depth $CurrentDepth"

    # Check cache first to avoid redundant AD queries
    if(-not $MembershipCache.ContainsKey($UserName)) {
        try {
            Write-Verbose "Querying AD for group membership of '$UserName'"
            # Get all groups the user is a direct member of and cache the result
            $MembershipCache[$UserName] = Get-ADPrincipalGroupMembership $UserName -ErrorAction Stop |
                                          Select-Object -ExpandProperty Name
            Write-Verbose "Found $($MembershipCache[$UserName].Count) groups for '$UserName'"
        }
        catch {
            Write-Warning "Failed to get group membership for '$UserName': $_"
            $MembershipCache[$UserName] = @()
            return $false
        }
    }
    else {
        Write-Verbose "Using cached membership for '$UserName' ($($MembershipCache[$UserName].Count) groups)"
    }

    $userGroups = $MembershipCache[$UserName]
    $foundPath = $false

    foreach($group in $userGroups) {
        # Avoid circular references
        if($VisitedGroups.ContainsKey($group)) {
            Write-Verbose "Circular reference detected: $group (skipping)"
            continue
        }
        $VisitedGroups[$group] = $true

        $newPath = $CurrentPath + $group
        Write-Verbose "Checking group: $group (path length: $($newPath.Length))"

        # If we found the target group, record the path
        if($group -eq $TargetGroup) {
            $pathString = "$UserName -> " + ($newPath -join " -> ")
            Write-Verbose "Found path to target group!"

            # Just print the path (AllPaths collection removed for simplicity)
            Write-Host $pathString -ForegroundColor Green

            $foundPath = $true

            # If not finding all paths, return immediately
            if(-not $FindAllPaths) {
                $VisitedGroups.Remove($group)
                return $true
            }
        }
        else {
            # Recursively check if this group is a member of other groups
            $found = Get-GroupMembershipPath -UserName $group -TargetGroup $TargetGroup `
                                             -CurrentPath $newPath -VisitedGroups $VisitedGroups `
                                             -MembershipCache $MembershipCache `
                                             -FindAllPaths:$FindAllPaths -MaxDepth $MaxDepth `
                                             -CurrentDepth ($CurrentDepth + 1) `
                                             -Verbose:$VerbosePreference
            if($found) {
                $foundPath = $true
                if(-not $FindAllPaths) {
                    $VisitedGroups.Remove($group)
                    return $true
                }
            }
        }

        # Remove from visited to allow other paths through this group
        if($FindAllPaths) {
            $VisitedGroups.Remove($group)
        }
    }

    Write-Verbose "Completed processing '$UserName' (found path: $foundPath)"
    return $foundPath
}

function Find-PathToGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'GroupName')]
        [string]$TargetGroup,

        [switch]$FindAllPaths,

        [ValidateRange(1, 100)]
        [int]$MaxDepth = 50,

        [switch]$ShowProgress
    )

    Write-Host "`nFinding paths to $TargetGroup...`n" -ForegroundColor Cyan
    Write-Verbose "Parameters: FindAllPaths=$FindAllPaths, MaxDepth=$MaxDepth, ShowProgress=$ShowProgress"

    try {
        Write-Verbose "Retrieving all members of group '$TargetGroup'"
        # Get all members (direct and nested) of the target group
        $members = Get-ADGroupMember -Identity $TargetGroup -Recursive -ErrorAction Stop |
                    Where-Object { $_.objectClass -eq 'user' }

        if($members.Count -eq 0) {
            Write-Host "No user members found in group '$TargetGroup'" -ForegroundColor Yellow
            Write-Verbose "Group '$TargetGroup' has no user members"
            return
        }

        Write-Host "Found $($members.Count) user member(s). Analyzing paths...`n" -ForegroundColor Cyan
        Write-Verbose "Processing $($members.Count) users to find paths"

        # Create a shared cache to improve performance across all path searches
        $sharedCache = @{}
        $memberCount = $members.Count
        $currentMember = 0

        foreach($member in $members) {
            $currentMember++
            $userName = $member.SamAccountName
            Write-Verbose "Processing user $currentMember/$memberCount : $userName"

            if($ShowProgress) {
                Write-Progress -Activity "Finding paths to $TargetGroup" `
                               -Status "Processing user $currentMember of $memberCount" `
                               -PercentComplete (($currentMember / $memberCount) * 100) `
                               -CurrentOperation $userName
            }

            Get-GroupMembershipPath -UserName $userName -TargetGroup $TargetGroup `
                                    -MembershipCache $sharedCache -FindAllPaths:$FindAllPaths `
                                    -MaxDepth $MaxDepth -Verbose:$VerbosePreference
        }

        if($ShowProgress) {
            Write-Progress -Activity "Finding paths to $TargetGroup" -Completed
        }

        Write-Verbose "Completed path analysis for all $memberCount members"
    }
    catch {
        Write-Error "Failed to retrieve members of group '$TargetGroup': $_"
    }
}

# Example usage:
# Find-PathToGroup -TargetGroup "Domain Admins"
# Find-PathToGroup -TargetGroup "Domain Admins" -FindAllPaths -ShowProgress
# Find-PathToGroup -TargetGroup "Enterprise Admins" -MaxDepth 20 -ShowProgress