function Get-DirectGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$GroupName
    )

    try {
        Write-Verbose "Retrieving direct members of group '$GroupName'"
        $members = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop |
                   Select-Object SamAccountName, objectClass, distinguishedName
        Write-Verbose "Found $($members.Count) direct members in '$GroupName'"
        return $members
    }
    catch {
        Write-Error "Failed to retrieve direct members of group '$GroupName': $_"
        return @()
    }
}

function Get-NestedGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$GroupName,

        [Parameter(DontShow)]
        [hashtable]$VisitedGroups = @{},

        [ValidateRange(1, 100)]
        [int]$MaxDepth = 50,

        [Parameter(DontShow)]
        [int]$CurrentDepth = 0
    )

    $members = @()

    # Check depth limit to prevent excessive recursion
    if($CurrentDepth -ge $MaxDepth) {
        Write-Verbose "Maximum depth ($MaxDepth) reached for group '$GroupName'"
        return @()
    }

    Write-Verbose "Processing group '$GroupName' at depth $CurrentDepth"

    try {
        # Prevent circular references
        if($VisitedGroups.ContainsKey($GroupName)) {
            Write-Verbose "Circular reference detected: $GroupName (skipping)"
            return @()
        }
        $VisitedGroups[$GroupName] = $true

        # Use Get-ADGroupMember which is more efficient than Get-ADGroup + Get-ADObject
        Write-Verbose "Querying AD for members of group '$GroupName'"
        $groupMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
        Write-Verbose "Found $($groupMembers.Count) direct members in '$GroupName'"

        $userCount = 0
        $nestedGroupCount = 0

        foreach($member in $groupMembers) {
            try {
                if($member.objectClass -eq "user") {
                    # Get full user object with all properties
                    Write-Verbose "  Adding user: $($member.SamAccountName)"
                    $members += Get-ADUser -Identity $member.SamAccountName -ErrorAction Stop
                    $userCount++
                }
                elseif($member.objectClass -eq "group") {
                    # Recursively get nested group members
                    Write-Verbose "  Recursing into nested group: $($member.SamAccountName)"
                    $members += Get-NestedGroupMember -GroupName $member.SamAccountName `
                                                      -VisitedGroups $VisitedGroups `
                                                      -MaxDepth $MaxDepth `
                                                      -CurrentDepth ($CurrentDepth + 1) `
                                                      -Verbose:$VerbosePreference
                    $nestedGroupCount++
                }
            }
            catch {
                Write-Warning "Failed to process member '$($member.SamAccountName)': $_"
            }
        }

        Write-Verbose "Completed '$GroupName': $userCount users, $nestedGroupCount nested groups"
    }
    catch {
        Write-Error "Failed to retrieve group '$GroupName': $_"
        return @()
    }

    $uniqueMembers = $members | Sort-Object -Property SamAccountName -Unique
    Write-Verbose "Returning $($uniqueMembers.Count) unique members from '$GroupName'"
    return $uniqueMembers
}

function Get-GroupMembershipOverview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$GroupName,

        [ValidateRange(1, 100)]
        [int]$MaxDepth = 50,

        [ValidateSet('Screen', 'CSV', 'JSON')]
        [string]$OutputFormat = 'Screen',

        [ValidateScript({
            if($_ -and -not (Test-Path (Split-Path $_ -Parent))) {
                throw "Parent directory does not exist: $(Split-Path $_ -Parent)"
            }
            $true
        })]
        [string]$OutputPath
    )

    Write-Host "`nGroup Membership Overview for: $GroupName`n" -ForegroundColor Cyan
    Write-Verbose "Parameters: MaxDepth=$MaxDepth, OutputFormat=$OutputFormat"

    Write-Host "Retrieving direct members..." -ForegroundColor Yellow
    $directMembers = Get-DirectGroupMember -GroupName $GroupName -Verbose:$VerbosePreference

    Write-Host "Retrieving nested members..." -ForegroundColor Yellow
    $nestedMembers = Get-NestedGroupMember -GroupName $GroupName -MaxDepth $MaxDepth -Verbose:$VerbosePreference

    Write-Verbose "Direct members: $($directMembers.Count), Nested members: $($nestedMembers.Count)"

    # Output based on format
    switch($OutputFormat) {
        'CSV' {
            if(-not $OutputPath) {
                $OutputPath = ".\GroupMembership_${GroupName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
            Write-Verbose "Exporting to CSV: $OutputPath"
            $nestedMembers | Select-Object SamAccountName, DistinguishedName, Name, UserPrincipalName |
                            Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
        }
        'JSON' {
            if(-not $OutputPath) {
                $OutputPath = ".\GroupMembership_${GroupName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            }
            Write-Verbose "Exporting to JSON: $OutputPath"
            $output = @{
                GroupName = $GroupName
                DirectMemberCount = $directMembers.Count
                TotalNestedMemberCount = $nestedMembers.Count
                DirectMembers = $directMembers
                NestedMembers = $nestedMembers
                Timestamp = Get-Date -Format 'o'
            }
            $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath
            Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
        }
        default {
            Write-Verbose "Displaying results on screen"
            Write-Host "Direct Members:" -ForegroundColor Yellow
            $directMembers | Format-Table -AutoSize

            Write-Host "`nAll Nested Members:" -ForegroundColor Yellow
            $nestedMembers | Select-Object SamAccountName, DistinguishedName | Format-Table -AutoSize

            Write-Host "`nSummary:" -ForegroundColor Green
            Write-Host "Direct Members Count: $($directMembers.Count)"
            Write-Host "Total Nested Members Count: $($nestedMembers.Count)"
        }
    }
}

# Example usage:
# Get-GroupMembershipOverview -GroupName "Domain Admins"
# Get-GroupMembershipOverview -GroupName "Domain Admins" -OutputFormat CSV
# Get-GroupMembershipOverview -GroupName "Enterprise Admins" -OutputFormat JSON -OutputPath "C:\Reports\EA_members.json"
# Get-GroupMembershipOverview -GroupName "Nested Group" -MaxDepth 20