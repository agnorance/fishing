# Active Directory Group & ACL Enumeration Scripts

Comprehensive PowerShell scripts for Active Directory reconnaissance and privilege escalation path finding.

## Scripts Overview

### 1. Get-GroupMembershipPath.ps1
Finds paths from users to privileged groups through nested group memberships.

**Features:**
- Find first or all paths to target groups
- Circular reference detection
- Caching for performance
- Progress indicators
- Verbose logging
- Pipeline support

**Usage:**
```powershell
. .\Get-GroupMembershipPath.ps1

# Basic usage
Find-PathToGroup -TargetGroup "Domain Admins"

# Find all paths with progress
Find-PathToGroup -TargetGroup "Domain Admins" -FindAllPaths -ShowProgress

# With verbose logging
Find-PathToGroup -TargetGroup "Enterprise Admins" -Verbose -MaxDepth 20
```

### 2. Get-NestedGroupMembership.ps1
Enumerates direct and nested group members with export capabilities.

**Features:**
- Recursive nested group enumeration
- Circular reference detection
- Multiple output formats (Screen, CSV, JSON)
- Depth limiting
- Verbose logging
- Pipeline support

**Usage:**
```powershell
. .\Get-NestedGroupMembership.ps1

# Basic overview
Get-GroupMembershipOverview -GroupName "Domain Admins"

# Export to CSV
Get-GroupMembershipOverview -GroupName "Domain Admins" -OutputFormat CSV

# Export to JSON with custom path
Get-GroupMembershipOverview -GroupName "Enterprise Admins" -OutputFormat JSON -OutputPath "C:\Reports\EA.json"

# Get nested members only
Get-NestedGroupMember -GroupName "Administrators" -MaxDepth 20 -Verbose
```

### 3. Get-DangerousAcl.ps1 (NEW!)
Advanced ACL enumeration to find privilege escalation paths through permissions.

**Features:**
- Comprehensive ACL scanning
- Shadow admin detection (non-privileged accounts with dangerous permissions)
- ACL-based privilege escalation path finding
- Multiple output formats (Screen, CSV, JSON)
- Performance optimizations and caching
- Extensive filtering options
- Better than PowerView's ACL enumeration

**Main Functions:**

#### Get-ObjectAcl
Core ACL enumeration function.

```powershell
# Get dangerous ACLs on Domain Admins group
Get-ObjectAcl -Identity "Domain Admins" -DangerousOnly -Verbose

# Scan all groups for dangerous permissions
Get-ObjectAcl -ObjectType Group -DangerousOnly -ExcludeInherited

# Pipeline usage
Get-ADGroup "Domain Admins" | Get-ObjectAcl -DangerousOnly
```

#### Find-ShadowAdmin
Discovers non-privileged accounts with dangerous permissions on privileged objects.

```powershell
# Find shadow admins
Find-ShadowAdmin -Verbose

# Check specific target group
Find-ShadowAdmin -TargetGroup "Enterprise Admins" -ShowProgress
```

#### Get-DangerousAcl
Comprehensive dangerous ACL scanning with flexible output.

```powershell
# Basic scan
Get-DangerousAcl -TargetIdentity "Domain Admins"

# Scan all groups, exclude already-privileged principals
Get-DangerousAcl -TargetType Group -ExcludePrivileged -Verbose

# Export to CSV
Get-DangerousAcl -TargetType Group -OutputFormat CSV

# Filter by specific rights
Get-DangerousAcl -TargetIdentity "Domain Admins" -Rights GenericAll,WriteDacl -OutputFormat JSON
```

#### Get-AclPrivEscPath
Finds privilege escalation paths through ACL permissions.

```powershell
# Find paths from current user
Get-AclPrivEscPath

# Find paths from specific user
Get-AclPrivEscPath -SourceUser "joffrey.baratheon" -TargetGroup "Domain Admins" -Verbose

# Limit search depth
Get-AclPrivEscPath -SourceUser "tyrion.lannister" -MaxDepth 3
```

## Dangerous ACL Rights Detected

The scripts identify these dangerous permissions:
- **GenericAll** - Full control over the object
- **WriteDacl** - Modify permissions (can grant yourself any right)
- **WriteOwner** - Take ownership (can then grant yourself any right)
- **GenericWrite** - Write to any property
- **WriteProperty** - Write to specific properties
- **ExtendedRight** - Special rights (force password change, etc.)
- **Self** - Add/remove self from groups

## Common Privilege Escalation Scenarios

### Scenario 1: Shadow Admin Detection
```powershell
# Find non-privileged accounts with dangerous ACL permissions
. .\Get-DangerousAcl.ps1
Find-ShadowAdmin -Verbose -ShowProgress

# Example output:
# ShadowAdmin: tyrion.lannister
# TargetObject: Domain Admins
# Rights: WriteDacl (Modify Permissions)
# EscalationPotential: High
```

### Scenario 2: Complete Group Enumeration
```powershell
# Export all privileged group memberships
. .\Get-NestedGroupMembership.ps1

$groups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach($group in $groups) {
    Get-GroupMembershipOverview -GroupName $group -OutputFormat JSON
}
```

### Scenario 3: Find All Paths to Domain Admin
```powershell
# Combine group paths and ACL paths
. .\Get-GroupMembershipPath.ps1
. .\Get-DangerousAcl.ps1

# Group membership paths
Find-PathToGroup -TargetGroup "Domain Admins" -FindAllPaths -Verbose

# ACL-based paths
Get-AclPrivEscPath -TargetGroup "Domain Admins" -Verbose
```

### Scenario 4: Complete Domain Privilege Analysis
```powershell
# Full enumeration and export
. .\Get-DangerousAcl.ps1

# 1. Find shadow admins
$shadowAdmins = Find-ShadowAdmin -ShowProgress

# 2. Get all dangerous ACLs on groups
$groupAcls = Get-DangerousAcl -TargetType Group -ExcludePrivileged -OutputFormat JSON -OutputPath "group_acls.json"

# 3. Check specific high-value targets
$targets = @("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
foreach($target in $targets) {
    Get-DangerousAcl -TargetIdentity $target -OutputFormat CSV
}
```

## Performance Tips

1. **Use caching**: The scripts automatically cache AD queries - run multiple commands in the same session
2. **Use -Verbose**: See what's being cached and queried
3. **Limit depth**: Use `-MaxDepth` to speed up recursive operations
4. **Filter early**: Use `-ExcludePrivileged` to reduce noise
5. **Export large results**: Use JSON/CSV output for large datasets

## Comparison with PowerView

| Feature | PowerView | These Scripts |
|---------|-----------|---------------|
| Group enumeration | ✓ | ✓ Better (caching, progress) |
| ACL enumeration | ✓ | ✓ Better (filtering, performance) |
| Shadow admin detection | Manual | ✓ Automated |
| Path finding | Limited | ✓ Comprehensive (groups + ACLs) |
| Output formats | Screen only | Screen, CSV, JSON |
| Caching | None | ✓ Built-in |
| Error handling | Basic | ✓ Comprehensive |
| Progress indicators | None | ✓ Optional |
| Pipeline support | Limited | ✓ Full support |
| Verbose logging | Limited | ✓ Extensive |

## Testing with GOAD

These scripts are perfect for testing with the Game of Active Directory (GOAD) lab:

```powershell
# Connect as cersei.lannister (member of Domain Admins, Lannister, Baratheon, Small Council)
runas /user:sevenkingdoms.local\cersei.lannister powershell.exe
# Password: il0vejaime

# Load scripts
cd C:\path\to\scripts
. .\Get-GroupMembershipPath.ps1
. .\Get-NestedGroupMembership.ps1
. .\Get-DangerousAcl.ps1

# Test group paths
Find-PathToGroup -TargetGroup "Domain Admins" -FindAllPaths -Verbose

# Test ACL enumeration
Get-DangerousAcl -TargetType Group -ExcludePrivileged

# Find shadow admins
Find-ShadowAdmin -ShowProgress
```

## Author & Credits

Created to replace and improve upon PowerView's ACL enumeration capabilities with modern PowerShell best practices.

## License

Use responsibly for authorized penetration testing and security assessments only.
