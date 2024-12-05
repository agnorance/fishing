# Active Directory

## Commands

### Install ActiveDirectory module

```powershell
# Administrator shell
Install-WindowsFeature RSAT-AD-Powershell
```

### Enumerate Users

```powershell
# List All Users in the Domain
Get-ADUser -Filter * -Properties DisplayName, SamAccountName | Select-Object DisplayName, SamAccountName

# Find Disabled Users
Get-ADUser -Filter {Enabled -eq $false} -Properties SamAccountName | Select-Object SamAccountName

# Find Users with Passwords That Never Expire
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties SamAccountName, PasswordNeverExpires | Select-Object SamAccountName, PasswordNeverExpires

# Find Recently Created Users
Get-ADUser -Filter * -Properties WhenCreated | Where-Object { $_.WhenCreated -gt (Get-Date).AddDays(-30) } | Select-Object SamAccountName, WhenCreated
```

---

### Enumerate Groups

```powershell
#### List All Groups in the Domain
Get-ADGroup -Filter * | Select-Object Name

#### Find Members of a Specific Group
# Replace `Domain Admins` with the group you want to investigate:
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, ObjectClass

#### Find Groups Without Members
Get-ADGroup -Filter * | ForEach-Object {     $group = $_     $members = Get-ADGroupMember -Identity $group.Name     if ($members.Count -eq 0) {         $group.Name     } }

#### Find Groups Without Members
Get-ADGroup -Filter * | ForEach-Object {     $group = $_     $members = Get-ADGroupMember -Identity $group.Name     if ($members.Count -eq 0) {         $group.Name     } }

#### Find members of all groups and write to .csv
# Good for a first look
Get-ADGroup -Filter * | ForEach-Object { $group = $_.Name "Group: $group" | Out-File -FilePath "group_members.txt" -Append "Members:" | Out-File -FilePath "group_members.txt" -Append Get-ADGroupMember -Identity $group -Recursive | Select-Object Name, SamAccountName | Format-Table | Out-File -FilePath "group_members.txt" -Append "-" * 50 | Out-File -FilePath "samaccounts-groups-all.txt" -Append }

#### Find members of all groups and write to list
# Without schnick schnack
$outputFile = "samaccounts-groups-all.txt"
Get-ADGroup -Filter * | ForEach-Object {
    Get-ADGroupMember -Identity $_.Name -Recursive | Select-Object -ExpandProperty SamAccountName
} | Out-File -FilePath $outputFile

#### Find all members and write samAccountName to .csv
Get-ADGroup -Filter * | ForEach-Object { Get-ADGroupMember -Identity $_ -Recursive | Select-Object -ExpandProperty SamAccountName } | Sort-Object -Unique | Out-File -FilePath "samaccounts.txt"

#### Find members of specific group and write samAccountName to .csv
Get-ADGroupMember -Identity "local Admins" -Recursive | Select-Object -ExpandProperty SamAccountName | Out-File -FilePath "samaccounts-local-Admins.txt"

#### Find members of specific groups and write samAccountName to .csv
# Replace `"Group Name 1", "Group Name 2"` with the groups you’re looking for:
$groupNames = @("Group Name 1", "Group Name 2")
$outputFile = "samaccounts-groups.txt" 
$allSamAccounts = foreach ($groupName in $groupNames) { Get-ADGroupMember -Identity $groupName -Recursive | Select-Object -ExpandProperty SamAccountName } $allSamAccounts | Out-File -FilePath $outputFile
```

---
### Enumerate Computers

```powershell
# List All Computers in the Domain
Get-ADComputer -Filter * | Select-Object Name, OperatingSystem

# Find Disabled Computers
Get-ADComputer -Filter {Enabled -eq $false} | Select-Object Name

# Find Computers Running a Specific OS
# Replace `Windows Server 2019` with the OS you’re looking for:
Get-ADComputer -Filter {OperatingSystem -like "*Windows Server 2019*"} | Select-Object Name, OperatingSystem
```

---
### Domain Information

```powershell
# Get Domain Controllers
Get-ADDomainController -Filter *

# Get Domain Details
Get-ADDomain

# Find Sites in the Domain
Get-ADReplicationSite -Filter *
```

---

### Search for Misconfigurations

```powershell
# Find Accounts Without Pre-Authentication Required
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName, DoesNotRequirePreAuth

# Find Users with Weak Password Settings
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | Select-Object SamAccountName, PasswordNotRequired
```

---
### Export Results

```powershell
# Find all users and export results to .csv with display and samAccountName
Get-ADUser -Filter * -Properties DisplayName, SamAccountName | Select-Object DisplayName, SamAccountName | Export-Csv -Path "users.csv" -NoTypeInformation
```

---
### Search by LDAP Filters

```powershell
# Find users by ldap filter
Get-ADUser -LDAPFilter "(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=com)" | Select-Object SamAccountName
```

## Useful Links


### Documentation


### Lists


### Sidehustle
