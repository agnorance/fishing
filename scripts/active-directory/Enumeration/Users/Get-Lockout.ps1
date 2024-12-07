function Get-UserLockoutStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Username = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Domain = "",

        [Parameter(Mandatory=$false)]
        [switch]$AllUsers,

        [Parameter(Mandatory=$false)]
        [string]$Filter = "",

        [Parameter(Mandatory=$false)]
        [switch]$LockedOnly,

        [Parameter(Mandatory=$false)]
        [switch]$HasBadPwdOnly,

        [Parameter(Mandatory=$false)]
        [switch]$DisabledOnly
    )
    
    try {
        # Get domain context if not provided
        if ([string]::IsNullOrEmpty($Domain)) {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }

        # Create DirectorySearcher object
        $domainDN = "LDAP://" + ([ADSI]"").distinguishedName
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$domainDN)
        
        # Build search filter
        if ($Username) {
            $baseFilter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$Username))"
        } else {
            $baseFilter = "(&(objectCategory=person)(objectClass=user)"
            
            if ($Filter) {
                $baseFilter += $Filter
            }
            
            $baseFilter += ")"
        }

        $searcher.Filter = $baseFilter
        $searcher.PropertiesToLoad.AddRange(@(
            "sAMAccountName",
            "lockoutTime",
            "badPwdCount",
            "badPasswordTime",
            "lastLogon",
            "userAccountControl"
        ))
        
        $results = $searcher.FindAll()
        
        if ($results.Count -eq 0) {
            Write-Host "[-] No users found matching criteria" -ForegroundColor Red
            return
        }

        # Print header
        Write-Host "`nLocked Account Status Report" -ForegroundColor Cyan
        Write-Host "==========================" -ForegroundColor Cyan
        $format = "{0,-20} {1,-8} {2,-8} {3,6} {4,-25} {5,-25}"
        Write-Host ($format -f "Username", "Locked", "Disabled", "BadPwd", "Last Bad Attempt", "Last Logon")
        Write-Host ("-" * 95)

        $userStatuses = @()
        
        foreach ($result in $results) {
            $user = $result.Properties
            $username = $user.samaccountname[0]
            
            # Get account status details
            $lockoutTime = if ($user.lockouttime.Count -gt 0 -and $user.lockouttime[0] -gt 0) {
                [datetime]::FromFileTime($user.lockouttime[0])
            } else { $null }
            
            $badPwdCount = if ($user.badpwdcount.Count -gt 0) {
                $user.badpwdcount[0]
            } else { 0 }
            
            $lastBadPassword = if ($user.badpasswordtime.Count -gt 0) {
                [datetime]::FromFileTime($user.badpasswordtime[0])
            } else { $null }
            
            $lastLogon = if ($user.lastlogon.Count -gt 0 -and $user.lastlogon[0] -gt 0) {
                [datetime]::FromFileTime($user.lastlogon[0])
            } else { "Never" }
            
            $userAccountControl = $user.useraccountcontrol[0]
            $isDisabled = ($userAccountControl -band 0x2) -eq 0x2
            $isLocked = ($lockoutTime -ne $null)

            # Apply filters
            if ($LockedOnly -and -not $isLocked) { continue }
            if ($HasBadPwdOnly -and $badPwdCount -eq 0) { continue }
            if ($DisabledOnly -and -not $isDisabled) { continue }

            # Format timestamps
            $lastBadPasswordStr = if ($lastBadPassword) { 
                $lastBadPassword.ToString("MM/dd/yyyy HH:mm:ss") 
            } else { "Never" }
            
            $lastLogonStr = if ($lastLogon -ne "Never") {
                $lastLogon.ToString("MM/dd/yyyy HH:mm:ss")
            } else { "Never" }

            # Print formatted output
            $color = if ($isLocked) { "Red" } else { "White" }
            Write-Host ($format -f $username, 
                                 $(if ($isLocked) { "YES" } else { "NO" }), 
                                 $(if ($isDisabled) { "YES" } else { "NO" }), 
                                 $badPwdCount, 
                                 $lastBadPasswordStr,
                                 $lastLogonStr) -ForegroundColor $color

            # Create status object for return
            $userStatuses += [PSCustomObject]@{
                Username = $username
                IsLocked = $isLocked
                IsDisabled = $isDisabled
                BadPasswordCount = $badPwdCount
                LastBadPasswordAttempt = $lastBadPassword
                LastLogon = if ($lastLogon -eq "Never") { $null } else { $lastLogon }
                LockoutTime = $lockoutTime
            }
        }

        # Only return objects, don't format them
        return $userStatuses
    }
    catch {
        Write-Host "[-] Error checking lockout status: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-DomainLockoutPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = ""
    )
    
    try {
        # Connect to domain
        $domainDN = ([ADSI]"").distinguishedName
        if (-not $domainDN) {
            throw "Failed to get domain DN"
        }

        $DomainObj = [ADSI]"LDAP://$domainDN"
        if (-not $DomainObj) {
            throw "Failed to connect to domain"
        }

        # Get lockout threshold
        $lockoutThreshold = $DomainObj.Properties['lockoutthreshold'].Value
        if ($null -eq $lockoutThreshold) {
            $lockoutThreshold = 0
        }

        # Get lockout duration and observation window using large integer conversion
        $lockoutDuration = 0
        $observationWindow = 0

        if ($DomainObj.Properties['lockoutduration'].Value) {
            $rawDuration = $DomainObj.ConvertLargeIntegerToInt64($DomainObj.Properties['lockoutduration'].Value)
            $lockoutDuration = [math]::Abs($rawDuration/600000000)
        }

        if ($DomainObj.Properties['lockoutObservationWindow'].Value) {
            $rawWindow = $DomainObj.ConvertLargeIntegerToInt64($DomainObj.Properties['lockoutObservationWindow'].Value)
            $observationWindow = [math]::Abs($rawWindow/600000000)
        }

        # Display results
        Write-Host "`nDomain Lockout Policy" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host "Domain: $domainDN"

        Write-Host "Lockout Threshold: " -NoNewline
        if ($lockoutThreshold -eq 0) {
            Write-Host "No lockout policy configured" -ForegroundColor Yellow
        } else {
            Write-Host "$lockoutThreshold attempts" -ForegroundColor Green
        }

        Write-Host "Lockout Duration: " -NoNewline
        if ($lockoutDuration -gt 0) {
            Write-Host "$lockoutDuration minutes" -ForegroundColor Green
        } else {
            Write-Host "Not configured" -ForegroundColor Yellow
        }

        Write-Host "Observation Window: " -NoNewline
        if ($observationWindow -gt 0) {
            Write-Host "$observationWindow minutes" -ForegroundColor Green
        } else {
            Write-Host "Not configured" -ForegroundColor Yellow
        }

        # Return as custom object
        return [PSCustomObject]@{
            DomainName = $domainDN.ToString()  # Convert to string to avoid array format
            LockoutThreshold = $lockoutThreshold
            LockoutDuration = if ($lockoutDuration -gt 0) { $lockoutDuration } else { "Not Configured" }
            ObservationWindow = if ($observationWindow -gt 0) { $observationWindow } else { "Not Configured" }
        }
    }
    catch {
        Write-Host "[-] Error retrieving domain lockout policy: $($_.Exception.Message)" -ForegroundColor Red
        Write-Verbose $_.Exception.StackTrace
        return $null
    }
}