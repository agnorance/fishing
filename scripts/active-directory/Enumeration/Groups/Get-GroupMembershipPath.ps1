function Get-GroupMembershipPath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$true)]
        [string]$TargetGroup,
        [string[]]$CurrentPath = @(),
        [hashtable]$VisitedGroups = @{}
    )
    
    # Get all groups the user is a direct member of
    $userGroups = Get-ADPrincipalGroupMembership $UserName | Select-Object -ExpandProperty Name
    
    foreach($group in $userGroups) {
        # Avoid circular references
        if($VisitedGroups.ContainsKey($group)) {
            continue
        }
        $VisitedGroups[$group] = $true
        
        $newPath = $CurrentPath + $group
        
        # If we found the target group, print the path
        if($group -eq $TargetGroup) {
            $pathString = "$UserName -> " + ($newPath -join " -> ")
            Write-Host $pathString -ForegroundColor Green
            return $true
        }
        
        # Recursively check if this group is a member of other groups
        $found = Get-GroupMembershipPath -UserName $group -TargetGroup $TargetGroup -CurrentPath $newPath -VisitedGroups $VisitedGroups
        if($found) {
            return $true
        }
    }
    
    return $false
}

function Find-PathToGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetGroup
    )
    
    Write-Host "`nFinding paths to $TargetGroup...`n" -ForegroundColor Cyan
    
    # Get all members (direct and nested) of the target group
    $members = Get-NestedGroupMember -GroupName $TargetGroup
    
    foreach($member in $members) {
        $userName = $member.SamAccountName
        Get-GroupMembershipPath -UserName $userName -TargetGroup $TargetGroup
    }
}

# Example usage:
# Find-PathToGroup -TargetGroup "Domain Admins"