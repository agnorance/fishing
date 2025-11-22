# Get-DangerousAcl.ps1
# ACL Enumeration Script for Active Directory
# Replaces PowerView's ACL enumeration with improved performance and features

#region Helper Functions

function Get-DangerousRight {
    <#
    .SYNOPSIS
    Checks if an ActiveDirectoryRights value represents a dangerous permission.

    .DESCRIPTION
    Returns true if the rights include dangerous permissions like GenericAll, WriteDacl, WriteOwner, etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights
    )

    $dangerousRights = @(
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.DirectoryServices.ActiveDirectoryRights]::Self
    )

    foreach($dangerous in $dangerousRights) {
        if($Rights -band $dangerous) {
            return $true
        }
    }

    return $false
}

function ConvertFrom-SID {
    <#
    .SYNOPSIS
    Converts a SID to a readable name.

    .DESCRIPTION
    Attempts to resolve a SID to a domain\username or group name. Returns SID if resolution fails.
    If already a name, returns it as-is.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID,

        [string]$Server,

        [PSCredential]$Credential
    )

    # Check if it's already a name (not a SID)
    # SIDs start with S-1- or are in format like "S-1-5-..."
    # Names contain backslashes or are well-known names
    if($SID -match '^S-1-\d') {
        # It's a SID, try to resolve it
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
            return $objUser.Value
        }
        catch {
            # Could not resolve, return SID
            return $SID
        }
    }
    else {
        # It's already a name, return as-is
        return $SID
    }
}

function Test-IsPrivilegedAccount {
    <#
    .SYNOPSIS
    Checks if an account is already in a privileged group.

    .DESCRIPTION
    Returns true if the account is a member of Domain Admins, Enterprise Admins, etc.
    Used to filter out "expected" permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,

        [string]$Server,

        [PSCredential]$Credential,

        [hashtable]$PrivilegedAccountCache = @{}
    )

    # Check cache first
    if($PrivilegedAccountCache.ContainsKey($Identity)) {
        return $PrivilegedAccountCache[$Identity]
    }

    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators"
    )

    try {
        $params = @{
            Identity = $Identity
            ErrorAction = 'Stop'
        }
        if($Server) { $params['Server'] = $Server }
        if($Credential) { $params['Credential'] = $Credential }

        $user = Get-ADUser @params -Properties MemberOf -ErrorAction Stop

        foreach($group in $privilegedGroups) {
            if($user.MemberOf -match "CN=$group,") {
                Write-Verbose "$Identity is member of privileged group: $group"
                $PrivilegedAccountCache[$Identity] = $true
                return $true
            }
        }

        $PrivilegedAccountCache[$Identity] = $false
        return $false
    }
    catch {
        # If we can't resolve, assume not privileged
        Write-Verbose "Could not check privileges for $Identity : $_"
        $PrivilegedAccountCache[$Identity] = $false
        return $false
    }
}

function Get-RightsDescription {
    <#
    .SYNOPSIS
    Converts ActiveDirectoryRights flags to human-readable description.
    #>
    param(
        [System.DirectoryServices.ActiveDirectoryRights]$Rights
    )

    $descriptions = @()

    # Check for the most important/dangerous rights
    $checks = @(
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll; Name = "GenericAll (Full Control)"}
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl; Name = "WriteDacl (Modify Permissions)"}
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner; Name = "WriteOwner (Take Ownership)"}
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite; Name = "GenericWrite"}
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty; Name = "WriteProperty"}
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight; Name = "ExtendedRight"}
        @{Flag = [System.DirectoryServices.ActiveDirectoryRights]::Self; Name = "Self"}
    )

    foreach($check in $checks) {
        if(($Rights -band $check.Flag) -eq $check.Flag) {
            $descriptions += $check.Name
        }
    }

    if($descriptions.Count -eq 0) {
        # Return the raw rights if no dangerous ones found
        return $Rights.ToString()
    }

    return ($descriptions -join ", ")
}

#endregion

#region Core ACL Functions

function Get-ObjectAcl {
    <#
    .SYNOPSIS
    Gets the ACL for an Active Directory object.

    .DESCRIPTION
    Retrieves and parses the ACL (Access Control List) for specified AD objects.
    Improved version of PowerView's Get-ObjectAcl with better performance and filtering.

    .PARAMETER Identity
    The identity of the AD object (DN, GUID, SID, or SamAccountName)

    .PARAMETER ObjectType
    The type of object to search for (User, Group, Computer, OrganizationalUnit, Domain, GPO)

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use for the query

    .PARAMETER DangerousOnly
    Only return ACEs with dangerous rights

    .PARAMETER ExcludeInherited
    Exclude inherited ACEs

    .PARAMETER ExcludeDefaultPrincipals
    Exclude well-known principals (SYSTEM, Domain Admins, etc.)

    .EXAMPLE
    Get-ObjectAcl -Identity "Domain Admins" -DangerousOnly

    .EXAMPLE
    Get-ObjectAcl -ObjectType Group -DangerousOnly -ExcludeInherited
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('DistinguishedName','SamAccountName','Name')]
        [string]$Identity,

        [ValidateSet('User','Group','Computer','OrganizationalUnit','Domain','GPO','All')]
        [string]$ObjectType = 'All',

        [string]$Server,

        [PSCredential]$Credential,

        [switch]$DangerousOnly,

        [switch]$ExcludeInherited,

        [switch]$ExcludeDefaultPrincipals
    )

    begin {
        Write-Verbose "Starting Get-ObjectAcl"
        $results = @()

        # Well-known SIDs to exclude if requested
        $defaultPrincipals = @(
            'S-1-5-18', # SYSTEM
            'S-1-5-32-544', # Administrators
            'S-1-5-32-548', # Account Operators
            'S-1-5-32-549', # Server Operators
            'S-1-5-32-550', # Print Operators
            'S-1-5-32-551'  # Backup Operators
        )
    }

    process {
        try {
            $objects = @()

            # Build parameters for AD query
            $params = @{
                ErrorAction = 'Stop'
            }
            if($Server) { $params['Server'] = $Server }
            if($Credential) { $params['Credential'] = $Credential }

            # Get objects based on type and identity
            if($Identity) {
                Write-Verbose "Searching for specific object: $Identity"
                $found = $false

                # Try as a group name first (most common for ACL checks)
                try {
                    Write-Verbose "Trying Get-ADGroup..."
                    $groupParams = @{
                        Identity = $Identity
                        Properties = 'nTSecurityDescriptor'
                        ErrorAction = 'Stop'
                    }
                    if($Server) { $groupParams['Server'] = $Server }
                    if($Credential) { $groupParams['Credential'] = $Credential }

                    $obj = Get-ADGroup @groupParams
                    if($obj) {
                        Write-Verbose "Found as group: $($obj.DistinguishedName)"
                        $objects += $obj
                        $found = $true
                    }
                }
                catch {
                    Write-Verbose "Not found as group: $_"
                }

                # Try as a user name
                if(-not $found) {
                    try {
                        Write-Verbose "Trying Get-ADUser..."
                        $userParams = @{
                            Identity = $Identity
                            Properties = 'nTSecurityDescriptor'
                            ErrorAction = 'Stop'
                        }
                        if($Server) { $userParams['Server'] = $Server }
                        if($Credential) { $userParams['Credential'] = $Credential }

                        $obj = Get-ADUser @userParams
                        if($obj) {
                            Write-Verbose "Found as user: $($obj.DistinguishedName)"
                            $objects += $obj
                            $found = $true
                        }
                    }
                    catch {
                        Write-Verbose "Not found as user: $_"
                    }
                }

                # Try as a computer name
                if(-not $found) {
                    try {
                        Write-Verbose "Trying Get-ADComputer..."
                        $compParams = @{
                            Identity = $Identity
                            Properties = 'nTSecurityDescriptor'
                            ErrorAction = 'Stop'
                        }
                        if($Server) { $compParams['Server'] = $Server }
                        if($Credential) { $compParams['Credential'] = $Credential }

                        $obj = Get-ADComputer @compParams
                        if($obj) {
                            Write-Verbose "Found as computer: $($obj.DistinguishedName)"
                            $objects += $obj
                            $found = $true
                        }
                    }
                    catch {
                        Write-Verbose "Not found as computer: $_"
                    }
                }

                # Try as DN/GUID/SID directly
                if(-not $found) {
                    try {
                        Write-Verbose "Trying Get-ADObject (DN/GUID/SID)..."
                        $objParams = @{
                            Identity = $Identity
                            Properties = 'nTSecurityDescriptor'
                            ErrorAction = 'Stop'
                        }
                        if($Server) { $objParams['Server'] = $Server }
                        if($Credential) { $objParams['Credential'] = $Credential }

                        $obj = Get-ADObject @objParams
                        if($obj) {
                            Write-Verbose "Found as AD object: $($obj.DistinguishedName)"
                            $objects += $obj
                            $found = $true
                        }
                    }
                    catch {
                        Write-Verbose "Not found as AD object: $_"
                    }
                }

                if(-not $found) {
                    Write-Warning "Could not find object: $Identity"
                }
            }
            else {
                Write-Verbose "Searching for all objects of type: $ObjectType"

                $filter = switch($ObjectType) {
                    'User' { { ObjectClass -eq 'user' -and ObjectCategory -eq 'person' } }
                    'Group' { { ObjectClass -eq 'group' } }
                    'Computer' { { ObjectClass -eq 'computer' } }
                    'OrganizationalUnit' { { ObjectClass -eq 'organizationalUnit' } }
                    'Domain' { { ObjectClass -eq 'domainDNS' } }
                    'GPO' { { ObjectClass -eq 'groupPolicyContainer' } }
                    'All' { { ObjectClass -like '*' } }
                }

                $objects = Get-ADObject -Filter $filter @params -Properties nTSecurityDescriptor
            }

            Write-Verbose "Found $($objects.Count) objects to process"

            # Process each object's ACL
            foreach($obj in $objects) {
                Write-Verbose "Processing ACL for: $($obj.DistinguishedName)"

                $acl = $obj.nTSecurityDescriptor.Access

                foreach($ace in $acl) {
                    # Apply filters
                    if($ExcludeInherited -and $ace.IsInherited) {
                        continue
                    }

                    if($ExcludeDefaultPrincipals -and $defaultPrincipals -contains $ace.IdentityReference.Value) {
                        continue
                    }

                    if($DangerousOnly -and -not (Get-DangerousRight -Rights $ace.ActiveDirectoryRights)) {
                        continue
                    }

                    # Build result object
                    $result = [PSCustomObject]@{
                        ObjectDN = $obj.DistinguishedName
                        ObjectName = $obj.Name
                        ObjectClass = $obj.ObjectClass
                        PrincipalSID = $ace.IdentityReference.Value
                        PrincipalName = ConvertFrom-SID -SID $ace.IdentityReference.Value -Server $Server -Credential $Credential
                        Rights = $ace.ActiveDirectoryRights
                        RightsDescription = Get-RightsDescription -Rights $ace.ActiveDirectoryRights
                        AccessControlType = $ace.AccessControlType
                        IsInherited = $ace.IsInherited
                        InheritanceFlags = $ace.InheritanceFlags
                        ObjectType = $ace.ObjectType
                        InheritedObjectType = $ace.InheritedObjectType
                    }

                    $results += $result
                }
            }
        }
        catch {
            Write-Error "Error processing ACL: $_"
        }
    }

    end {
        Write-Verbose "Returning $($results.Count) ACL entries"
        return $results
    }
}

#endregion

#region Shadow Admin Detection

function Find-ShadowAdmin {
    <#
    .SYNOPSIS
    Finds non-privileged accounts with dangerous ACL permissions (Shadow Admins).

    .DESCRIPTION
    Identifies accounts that have dangerous permissions on privileged objects but are not themselves
    members of privileged groups. These are often overlooked privilege escalation paths.

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use for the query

    .PARAMETER TargetGroup
    Specific privileged group to check (default: Domain Admins)

    .PARAMETER ShowProgress
    Display progress bar

    .EXAMPLE
    Find-ShadowAdmin -Verbose

    .EXAMPLE
    Find-ShadowAdmin -TargetGroup "Enterprise Admins" -ShowProgress
    #>
    [CmdletBinding()]
    param(
        [string]$Server,

        [PSCredential]$Credential,

        [string]$TargetGroup = "Domain Admins",

        [switch]$ShowProgress
    )

    Write-Host "`nSearching for Shadow Admins...`n" -ForegroundColor Cyan
    Write-Verbose "Target group: $TargetGroup"

    $privilegedCache = @{}
    $shadowAdmins = @()

    try {
        # Define privileged objects to check
        $privilegedTargets = @(
            $TargetGroup,
            "Enterprise Admins",
            "Schema Admins",
            "Administrators"
        )

        $totalTargets = $privilegedTargets.Count
        $currentTarget = 0

        foreach($target in $privilegedTargets) {
            $currentTarget++

            if($ShowProgress) {
                Write-Progress -Activity "Finding Shadow Admins" `
                               -Status "Checking $target ($currentTarget of $totalTargets)" `
                               -PercentComplete (($currentTarget / $totalTargets) * 100)
            }

            Write-Verbose "Checking ACLs on: $target"

            $params = @{
                Identity = $target
                DangerousOnly = $true
                ExcludeInherited = $true
                ErrorAction = 'SilentlyContinue'
            }
            if($Server) { $params['Server'] = $Server }
            if($Credential) { $params['Credential'] = $Credential }

            $acls = Get-ObjectAcl @params

            foreach($acl in $acls) {
                # Skip if principal is already privileged
                $principalName = $acl.PrincipalName

                # Skip well-known SIDs and system accounts
                if($principalName -match '^S-1-5-' -or
                   $principalName -match 'SYSTEM|BUILTIN|NT AUTHORITY') {
                    continue
                }

                # Extract just the username if domain\user format
                $username = if($principalName -match '\\') {
                    $principalName.Split('\')[1]
                } else {
                    $principalName
                }

                # Check if already privileged
                $isPrivileged = Test-IsPrivilegedAccount -Identity $username `
                                                          -Server $Server `
                                                          -Credential $Credential `
                                                          -PrivilegedAccountCache $privilegedCache

                if(-not $isPrivileged) {
                    Write-Verbose "Found shadow admin: $principalName has $($acl.RightsDescription) on $target"

                    $shadowAdmins += [PSCustomObject]@{
                        ShadowAdmin = $principalName
                        ShadowAdminSID = $acl.PrincipalSID
                        TargetObject = $acl.ObjectName
                        TargetDN = $acl.ObjectDN
                        Rights = $acl.RightsDescription
                        AccessType = $acl.AccessControlType
                        EscalationPotential = "High"
                    }
                }
            }
        }

        if($ShowProgress) {
            Write-Progress -Activity "Finding Shadow Admins" -Completed
        }

        # Display results
        if($shadowAdmins.Count -eq 0) {
            Write-Host "No shadow admins found." -ForegroundColor Yellow
        }
        else {
            Write-Host "Found $($shadowAdmins.Count) shadow admin(s):`n" -ForegroundColor Green
            $shadowAdmins | Format-Table -AutoSize
        }

        return $shadowAdmins
    }
    catch {
        Write-Error "Error finding shadow admins: $_"
    }
}

#endregion

#region Main Functions

function Get-DangerousAcl {
    <#
    .SYNOPSIS
    Comprehensive ACL enumeration to find dangerous permissions in Active Directory.

    .DESCRIPTION
    Scans Active Directory for dangerous ACL permissions that could lead to privilege escalation.
    More efficient and feature-rich than PowerView's ACL enumeration.

    .PARAMETER TargetIdentity
    Specific object to check ACLs on

    .PARAMETER TargetType
    Type of objects to scan (User, Group, Computer, GPO, All)

    .PARAMETER Rights
    Specific rights to search for (GenericAll, WriteDacl, WriteOwner, etc.)

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use

    .PARAMETER OutputFormat
    Output format (Screen, CSV, JSON)

    .PARAMETER OutputPath
    Path for output file

    .PARAMETER ExcludePrivileged
    Exclude results where the principal is already privileged

    .PARAMETER ExcludeExpected
    Exclude expected/default ACLs (Domain Admins on itself, etc.)

    .PARAMETER ShowExpected
    Include expected/default ACLs in results

    .PARAMETER ShowProgress
    Display progress bar

    .PARAMETER Detailed
    Show full detailed output instead of summary table

    .EXAMPLE
    Get-DangerousAcl -TargetIdentity "Domain Admins"

    .EXAMPLE
    Get-DangerousAcl -TargetType Group -OutputFormat CSV

    .EXAMPLE
    Get-DangerousAcl -TargetIdentity "Domain Admins" -Rights GenericAll,WriteDacl -ExcludePrivileged -ExcludeExpected
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$TargetIdentity,

        [ValidateSet('User','Group','Computer','OrganizationalUnit','Domain','GPO','All')]
        [string]$TargetType = 'Group',

        [ValidateSet('GenericAll','WriteDacl','WriteOwner','GenericWrite','WriteProperty','ExtendedRight','Self','All')]
        [string[]]$Rights = @('All'),

        [string]$Server,

        [PSCredential]$Credential,

        [ValidateSet('Screen','CSV','JSON')]
        [string]$OutputFormat = 'Screen',

        [string]$OutputPath,

        [switch]$ExcludePrivileged,

        [switch]$ExcludeExpected,

        [switch]$ShowExpected,

        [switch]$ShowProgress,

        [switch]$Detailed
    )

    Write-Host "`nEnumerating Dangerous ACLs...`n" -ForegroundColor Cyan
    Write-Verbose "Target Type: $TargetType, Rights: $($Rights -join ', ')"

    # Define expected/default ACL combinations to filter out
    $expectedACLs = @(
        # Object -> Principal combinations that are expected
        @{Object = 'Domain Admins'; Principal = 'Domain Admins'},
        @{Object = 'Domain Admins'; Principal = 'Enterprise Admins'},
        @{Object = 'Domain Admins'; Principal = 'Administrators'},
        @{Object = 'Domain Admins'; Principal = 'Everyone'; Rights = 'ExtendedRight'},  # Send-As
        @{Object = 'Domain Admins'; Principal = 'Cert Publishers'; Rights = 'WriteProperty'},  # Certificate publishing
        @{Object = 'Enterprise Admins'; Principal = 'Enterprise Admins'},
        @{Object = 'Enterprise Admins'; Principal = 'Domain Admins'},
        @{Object = 'Administrators'; Principal = 'Administrators'},
        @{Object = 'Schema Admins'; Principal = 'Schema Admins'},
        @{Object = 'Schema Admins'; Principal = 'Enterprise Admins'}
    )

    try {
        $params = @{
            DangerousOnly = $true
            ExcludeInherited = $true
            ErrorAction = 'Stop'
        }

        if($TargetIdentity) {
            $params['Identity'] = $TargetIdentity
        }
        else {
            $params['ObjectType'] = $TargetType
        }

        if($Server) { $params['Server'] = $Server }
        if($Credential) { $params['Credential'] = $Credential }

        Write-Verbose "Retrieving ACLs..."
        $acls = Get-ObjectAcl @params

        # Filter by specific rights if requested
        if($Rights -notcontains 'All') {
            Write-Verbose "Filtering by rights: $($Rights -join ', ')"
            $acls = $acls | Where-Object {
                $aceRights = $_.Rights
                $match = $false
                foreach($right in $Rights) {
                    $rightEnum = [System.DirectoryServices.ActiveDirectoryRights]::$right
                    if($aceRights -band $rightEnum) {
                        $match = $true
                        break
                    }
                }
                $match
            }
        }

        # Exclude privileged principals if requested
        if($ExcludePrivileged) {
            Write-Verbose "Excluding privileged principals..."
            $privilegedCache = @{}
            $filtered = @()

            foreach($acl in $acls) {
                $principalName = $acl.PrincipalName

                # Skip system accounts
                if($principalName -match '^S-1-5-|SYSTEM|BUILTIN|NT AUTHORITY') {
                    continue
                }

                $username = if($principalName -match '\\') {
                    $principalName.Split('\')[1]
                } else {
                    $principalName
                }

                $isPrivileged = Test-IsPrivilegedAccount -Identity $username `
                                                          -Server $Server `
                                                          -Credential $Credential `
                                                          -PrivilegedAccountCache $privilegedCache

                if(-not $isPrivileged) {
                    $filtered += $acl
                }
            }

            $acls = $filtered
        }

        # Exclude expected ACLs if requested (or if not explicitly showing them)
        if($ExcludeExpected -or (-not $ShowExpected)) {
            Write-Verbose "Excluding expected/default ACLs..."
            $filtered = @()

            foreach($acl in $acls) {
                $isExpected = $false
                $objectName = $acl.ObjectName
                $principalName = $acl.PrincipalName -replace '^.*\\'  # Remove domain prefix

                foreach($expected in $expectedACLs) {
                    # Check if object and principal match
                    if($objectName -eq $expected.Object -and $principalName -eq $expected.Principal) {
                        # If specific rights are defined for this combo, check them
                        if($expected.Rights) {
                            if($acl.RightsDescription -match $expected.Rights) {
                                $isExpected = $true
                                break
                            }
                        }
                        else {
                            # No specific rights defined, so any rights are expected
                            $isExpected = $true
                            break
                        }
                    }
                }

                if(-not $isExpected) {
                    $filtered += $acl
                }
                else {
                    Write-Verbose "Filtered out expected ACL: $objectName <- $principalName"
                }
            }

            $acls = $filtered
        }

        Write-Verbose "Found $($acls.Count) dangerous ACL entries"

        # Output results
        switch($OutputFormat) {
            'CSV' {
                if(-not $OutputPath) {
                    $OutputPath = ".\DangerousAcls_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                }
                $acls | Export-Csv -Path $OutputPath -NoTypeInformation
                Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
            }
            'JSON' {
                if(-not $OutputPath) {
                    $OutputPath = ".\DangerousAcls_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                }
                $output = @{
                    Timestamp = Get-Date -Format 'o'
                    TargetIdentity = $TargetIdentity
                    TargetType = $TargetType
                    TotalEntries = $acls.Count
                    Entries = $acls
                }
                $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath
                Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
            }
            default {
                if($acls.Count -eq 0) {
                    Write-Host "No unexpected dangerous ACLs found. All ACLs appear to be default/expected." -ForegroundColor Green
                    Write-Host "Use -ShowExpected to include default ACLs, or -Verbose to see what was filtered." -ForegroundColor Gray
                }
                else {
                    Write-Host "Found $($acls.Count) interesting ACL entries:`n" -ForegroundColor Yellow

                    # Display with color coding
                    foreach($acl in $acls) {
                        # Determine severity and color
                        $color = 'White'
                        $severity = 'Medium'

                        if($acl.RightsDescription -match 'GenericAll') {
                            $color = 'Red'
                            $severity = 'CRITICAL'
                        }
                        elseif($acl.RightsDescription -match 'WriteDacl|WriteOwner') {
                            $color = 'Magenta'
                            $severity = 'HIGH'
                        }
                        elseif($acl.RightsDescription -match 'GenericWrite|WriteProperty') {
                            $color = 'Yellow'
                            $severity = 'MEDIUM'
                        }

                        # Format principal name (remove domain prefix for brevity)
                        $shortPrincipal = $acl.PrincipalName -replace '^.*\\'

                        Write-Host "  [$severity] " -ForegroundColor $color -NoNewline
                        Write-Host "$shortPrincipal " -ForegroundColor Cyan -NoNewline
                        Write-Host "has " -NoNewline
                        Write-Host "$($acl.RightsDescription) " -ForegroundColor $color -NoNewline
                        Write-Host "on " -NoNewline
                        Write-Host "$($acl.ObjectName)" -ForegroundColor Green
                    }

                    # Show detailed view if requested
                    if($Detailed) {
                        Write-Host "`nDetailed View:" -ForegroundColor Cyan
                        $acls | Format-List ObjectDN, ObjectName, PrincipalName, Rights, RightsDescription, AccessControlType, IsInherited
                    }
                }
            }
        }

        return $acls
    }
    catch {
        Write-Error "Error enumerating ACLs: $_"
    }
}

function Get-AclPrivEscPath {
    <#
    .SYNOPSIS
    Finds privilege escalation paths through ACL permissions.

    .DESCRIPTION
    Traces paths from a source user to a target group (like Domain Admins) through ACL permissions.
    Shows chains like: User A -> has WriteDacl on -> User B -> member of -> Domain Admins

    .PARAMETER SourceUser
    Starting user (defaults to current user)

    .PARAMETER TargetGroup
    Target privileged group (default: Domain Admins)

    .PARAMETER Server
    Domain controller to query

    .PARAMETER Credential
    Credentials to use

    .PARAMETER MaxDepth
    Maximum path depth to search (default: 5)

    .PARAMETER ShowProgress
    Display progress bar

    .EXAMPLE
    Get-AclPrivEscPath

    .EXAMPLE
    Get-AclPrivEscPath -SourceUser "joffrey.baratheon" -TargetGroup "Domain Admins" -Verbose
    #>
    [CmdletBinding()]
    param(
        [string]$SourceUser = $env:USERNAME,

        [string]$TargetGroup = "Domain Admins",

        [string]$Server,

        [PSCredential]$Credential,

        [ValidateRange(1,10)]
        [int]$MaxDepth = 5,

        [switch]$ShowProgress
    )

    Write-Host "`nSearching for ACL-based privilege escalation paths...`n" -ForegroundColor Cyan
    Write-Verbose "Source: $SourceUser -> Target: $TargetGroup (Max Depth: $MaxDepth)"

    $paths = @()
    $visited = @{}

    function Search-AclPath {
        param(
            [string]$CurrentObject,
            [string[]]$CurrentPath,
            [int]$Depth
        )

        if($Depth -ge $MaxDepth) {
            Write-Verbose "Max depth reached at $CurrentObject"
            return
        }

        if($visited.ContainsKey($CurrentObject)) {
            Write-Verbose "Already visited: $CurrentObject"
            return
        }

        $visited[$CurrentObject] = $true
        Write-Verbose "Checking ACLs from: $CurrentObject (Depth: $Depth)"

        # Get ACLs where current object has dangerous permissions
        try {
            $params = @{
                DangerousOnly = $true
                ExcludeInherited = $true
                ErrorAction = 'SilentlyContinue'
            }
            if($Server) { $params['Server'] = $Server }
            if($Credential) { $params['Credential'] = $Credential }

            # Get all objects in AD
            $allObjects = Get-ADObject -Filter * @params -Properties nTSecurityDescriptor

            foreach($obj in $allObjects) {
                $acl = $obj.nTSecurityDescriptor.Access

                foreach($ace in $acl) {
                    # Check if current object is the principal
                    $principal = ConvertFrom-SID -SID $ace.IdentityReference.Value -Server $Server -Credential $Credential

                    if($principal -match $CurrentObject) {
                        # Check if this is dangerous
                        if(Get-DangerousRight -Rights $ace.ActiveDirectoryRights) {
                            $targetName = $obj.Name
                            $newPath = $CurrentPath + "has $($ace.ActiveDirectoryRights) on $targetName"

                            Write-Verbose "Found: $CurrentObject has $($ace.ActiveDirectoryRights) on $targetName"

                            # Check if target is the target group or member of it
                            if($targetName -eq $TargetGroup) {
                                # Found a path!
                                $pathString = $newPath -join " -> "
                                Write-Host "FOUND PATH: $pathString" -ForegroundColor Green
                                $paths += $pathString
                            }
                            else {
                                # Recurse
                                Search-AclPath -CurrentObject $targetName -CurrentPath $newPath -Depth ($Depth + 1)
                            }
                        }
                    }
                }
            }

            # Also check group memberships
            try {
                $userObj = Get-ADUser -Identity $CurrentObject @params -Properties MemberOf -ErrorAction SilentlyContinue

                if($userObj) {
                    foreach($groupDN in $userObj.MemberOf) {
                        $group = Get-ADGroup -Identity $groupDN @params
                        $groupName = $group.Name

                        $newPath = $CurrentPath + "member of $groupName"

                        if($groupName -eq $TargetGroup) {
                            $pathString = $newPath -join " -> "
                            Write-Host "FOUND PATH: $pathString" -ForegroundColor Green
                            $paths += $pathString
                        }
                        else {
                            Search-AclPath -CurrentObject $groupName -CurrentPath $newPath -Depth ($Depth + 1)
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not check group membership for $CurrentObject"
            }
        }
        catch {
            Write-Verbose "Error searching from $CurrentObject : $_"
        }
    }

    # Start the search
    Search-AclPath -CurrentObject $SourceUser -CurrentPath @($SourceUser) -Depth 0

    if($paths.Count -eq 0) {
        Write-Host "No ACL-based privilege escalation paths found from $SourceUser to $TargetGroup" -ForegroundColor Yellow
    }
    else {
        Write-Host "`nFound $($paths.Count) path(s):`n" -ForegroundColor Green
        $paths | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
    }

    return $paths
}

#endregion

# Example usage:

# Basic ACL enumeration
# Get-ObjectAcl -Identity "Domain Admins" -DangerousOnly -Verbose
# Get-ObjectAcl -ObjectType Group -DangerousOnly -ExcludeInherited

# Find shadow admins (non-privileged accounts with dangerous permissions)
# Find-ShadowAdmin -Verbose
# Find-ShadowAdmin -TargetGroup "Enterprise Admins" -ShowProgress

# Comprehensive dangerous ACL scanning
# Get-DangerousAcl -TargetIdentity "Domain Admins"  # Auto-filters expected ACLs
# Get-DangerousAcl -TargetIdentity "Domain Admins" -ExcludePrivileged  # Only show non-privileged principals
# Get-DangerousAcl -TargetIdentity "Domain Admins" -ShowExpected  # Include default ACLs
# Get-DangerousAcl -TargetIdentity "Domain Admins" -Detailed  # Show full details
# Get-DangerousAcl -TargetType Group -OutputFormat CSV
# Get-DangerousAcl -TargetIdentity "Domain Admins" -Rights GenericAll,WriteDacl -OutputFormat JSON

# Find privilege escalation paths through ACLs
# Get-AclPrivEscPath
# Get-AclPrivEscPath -SourceUser "joffrey.baratheon" -TargetGroup "Domain Admins" -Verbose

# Advanced: Scan all groups and export to JSON
# Get-DangerousAcl -TargetType Group -ExcludePrivileged -OutputFormat JSON -OutputPath "C:\temp\acls.json"

# Pipeline usage
# Get-ADGroup "Domain Admins" | Get-ObjectAcl -DangerousOnly
