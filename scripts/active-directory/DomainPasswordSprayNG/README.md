# DomainPasswordSprayNG

A PowerShell-based Active Directory password spraying tool that performs controlled password spraying attacks while respecting domain lockout policies and providing detailed logging capabilities.

## Features

- 🔒 Automatic lockout policy detection and observation window handling
- 📋 Support for both single passwords and password lists
- 👥 Domain user enumeration with filtering options
- ⏱️ Configurable delays and jitter between attempts
- 📊 Detailed progress tracking and statistics
- 📝 Comprehensive logging options
- 🛡️ Built-in safety features to prevent account lockouts
- 🎯 Targeted testing capabilities for specific users or groups

## Requirements

- PowerShell 5.1 or later
- Domain user credentials
- Appropriate permissions to query Active Directory

## Usage

### Basic Usage

```powershell
# Test all domain users with a single password
Invoke-DomainPasswordSprayNG -Password "Winter2023!"

# Test specific users from a file
Invoke-DomainPasswordSprayNG -UserList ".\users.txt" -Password "Winter2023!" -OutFile "valid.txt"

# Test multiple passwords against a single user
Invoke-DomainPasswordSprayNG -Username "testuser" -PasswordList ".\passes.txt" -Domain "test.local"
```

### Advanced Usage

```powershell
# Test with delay and jitter to avoid detection
Invoke-DomainPasswordSprayNG -UserList ".\users.txt" -Password "Winter2023!" -Delay 1 -Jitter 0.3

# Test username as password for all users
Invoke-DomainPasswordSprayNG -UsernameAsPassword -Force -LogLevel Verbose

# Test with custom LDAP filter
Invoke-DomainPasswordSprayNG -Password "Winter2023!" -Filter "(description=*admin*)"
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| Username | Single username to test |
| UserList | Path to file containing usernames |
| Password | Single password to test |
| PasswordList | Path to file containing passwords |
| OutFile | Path to save successful credentials |
| Domain | Target domain (default: current domain) |
| Filter | Custom LDAP filter for user enumeration |
| Force | Bypasses the confirmation prompt |
| Fudge | Additional delay between password rounds |
| Delay | Delay between authentication attempts |
| Jitter | Random delay variation (0-1) |
| LogLevel | Detail level (Quiet/Normal/Verbose) |
| LogToFile | Enable logging to file |
| LogFilePath | Path for log file |
| UsernameAsPassword | Test username as password |
| ContinueOnSuccess | Continue testing after finding valid credentials |
| ContinueOnSuccess | Stop testing after finding valid credentials |

## Safety Features

- Automatic detection of domain lockout policies
- Enforced observation window between password attempts
- Configurable delays to prevent overwhelming domain controllers
- Warning prompts before execution
- Progress tracking with estimated completion times

## Logging

The tool provides multiple logging options:
- Console output with configurable verbosity
- File logging with detailed attempt information
- Progress bars with real-time statistics
- Summary reports with success rates and compromised accounts

## Best Practices

1. **Always** test in a controlled environment first
2. Start with a small user set to validate configuration
3. Use appropriate delays to avoid detection
4. Monitor for account lockouts
5. Keep logs for audit purposes
6. Use during normal business hours to blend with regular traffic

## License

MIT License

## Disclaimer

This tool is for legitimate security testing only. Always ensure you have proper authorization before testing any systems or networks. Unauthorized password spraying attacks may be illegal and can cause system disruption or account lockouts.

## Author

Created by agnorance

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.