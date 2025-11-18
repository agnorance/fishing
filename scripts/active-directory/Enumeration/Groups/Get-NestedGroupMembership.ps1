function Get-DirectGroupMember {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    Get-ADGroupMember -Identity $GroupName | 
    Select-Object SamAccountName, objectClass, distinguishedName
}

function Get-NestedGroupMember {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    $members = @()
    $group = Get-ADGroup -Identity $GroupName -Properties Members
    
    foreach($member in $group.Members) {
        $obj = Get-ADObject -Identity $member -Properties ObjectClass, SamAccountName
        
        if($obj.ObjectClass -eq "user") {
            $members += Get-ADUser -Identity $obj.SamAccountName
        }
        elseif($obj.ObjectClass -eq "group") {
            $members += Get-NestedGroupMember -GroupName $obj.SamAccountName
        }
    }
    
    return $members | Sort-Object -Property SamAccountName -Unique
}

function Get-GroupMembershipOverview {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )

    Write-Host "`nGroup Membership Overview for: $GroupName`n" -ForegroundColor Cyan
    
    Write-Host "Direct Members:" -ForegroundColor Yellow
    $directMembers = Get-DirectGroupMember -GroupName $GroupName
    $directMembers | Format-Table -AutoSize
    
    Write-Host "`nAll Nested Members:" -ForegroundColor Yellow
    $nestedMembers = Get-NestedGroupMember -GroupName $GroupName
    $nestedMembers | Select-Object SamAccountName, DistinguishedName | Format-Table -AutoSize
    
    Write-Host "Summary:" -ForegroundColor Green
    Write-Host "Direct Members Count: $($directMembers.Count)"
    Write-Host "Total Nested Members Count: $($nestedMembers.Count)"
}

# Example usage:
# Get-GroupMembershipOverview -GroupName "Domain Admins"