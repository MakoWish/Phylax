# Phýlax

**Greek** φύλαξ (phýlax)  
[800-500 BCE] Ancient Greece - Watcher, guard, sentinel, guardian, keeper, protector

![Phylax Password Policy](logo.png)

## About

Phylax was designed to improve password hygiene in Windows environments by allowing organizations to:

- Enforce minimum complexity and length requirements
- Reject passwords that match common patterns, strings, or common dictionary words
- Block known compromised or disallowed passwords via a blacklist
- Target enforcement to specific Active Directory groups with three levels of length requirements (ie. default, admin, service account)
- Log all password change activity and reasons for rejection
- Support near-real-time updates to policies via registry and file changes — no reboot or DLL reload required

Phylax provides a flexible foundation for organizations looking to enforce modern password security best practices while maintaining full control and auditability.

Technical reference: [Password Filters](https://learn.microsoft.com/en-us/windows/win32/secmgmt/password-filters?redirectedfrom=MSDN)

## Quick Links

* [Installation](#installation)
* [Configuration](#configuration)
* [Bug Reporting](#bug-reporting)
* [Disclaimer](#diclaimer)
* [Removal](#removal)

## Installation

Grab the latest release from [releases](https://github.com/MakoWish/Phylax/releases/latest/download/phylax.dll). 

The downloaded `phylax.dll` must be placed on each domain controller in `C:\Windows\System32\`. Once the DLL is saved into `System32`, you must modify the registry to load the DLL on boot. Under:

```reg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\lsa
```

Find and edit the `REG_MULTI_SZ` key `Notification Packages` and append the name of the DLL `phylax` (without the DLL extension) onto a new line. 

![Enable Phylax](registry_enable.png)

On first start, Phylax will create the default registry settings automatically (see [Registry Settings](#registry-settings) below). If you would prefer to change any of these settings before first start (helpful for pilot group testing), you may use the provided [default_registry_settings.reg](../main/default_registry_settings.reg) to create the defaults, then adjust to your liking. Here is an example configuration with sample enforced groups defined (these may be different in your environment):

![Sample Registry Settings](example_registry_settings.png)

Once you have placed `phylax.dll` into `C:\Windows\System32\` and are satisfied with your settings, or would like to accept the defaults, reboot the domain controller(s) for the password policy to take effect.

_**Note**: Reboots are not required for changes. Modifications to the blacklist, bad patterns file, and registry settings changes are loaded automatically._

_**Important**: If `RunAsPPL` is enabled on your domain controllers, you will need to have the DLL signed by Microsoft as outlined [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-manage)._

## Removal

To uninstall Phylax, you must remove the `phylax` string from the `REG_MULTI_SZ` key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\lsa\Notification Packages`. Save the changes, and reboot the domain controller. Once back online, the password policy will no longer be in effect.

## Configuration

### Registry Settings

Phylax is configured via the Windows Registry under:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Phylax
```

The following table outlines the default settings that are generated on first start.

| Key Name                | Type        | Default                          | Description |
|-------------------------|-------------|----------------------------------|-------------|
| `LogPath`               | `REG_SZ`    | `C:\Windows\System32`            | Path to the folder where logs will be written |
| `LogName`               | `REG_SZ`    | `phylax.log`                     | Name of the log file |
| `LogSize`               | `REG_DWORD` | `10240`                          | Maximum log file size in kB before rotation |
| `LogRetention`          | `REG_DWORD` | `10`                             | Number of rotated logs to retain |
| `LogLevel`              | `REG_SZ`    | `INFO`                           | One of: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `EnforcedGroups`        | `REG_SZ`    | *(empty)*                        | Comma-delimited list of AD group names to enforce policy on (if empty, policy is applied to all users) |
| `MinimumLength`         | `REG_DWORD` | `12`                             | Default minimum allowed password length |
| `AdmingGroups`          | `REG_SZ`    | *(empty)*                        | Comma-delimited list of admin groups to enforce different password length |
| `AdminMinLength`        | `REG_DWORD` | `15`                             | Minimum allowed password length for admin groups |
| `ServiceAccountGroups`  | `REG_SZ`    | *(empty)*                        | Comma-delimited list of admin groups to enforce different password length |
| `ServiceMinLength`      | `REG_DWORD` | `20`                             | Minimum allowed password length for service account groups |
| `Complexity`            | `REG_DWORD` | `3`                              | Minimum number of character classes (uppercase, lowercase, digit, symbol) required |
| `RejectSequences`       | `REG_DWORD` | `1`                              | Reject character sequences (e.g. `abcd`, `1234`) |
| `RejectSequencesLength` | `REG_DWORD` | `3`                              | Minimum sequence length to reject |
| `RejectRepeats`         | `REG_DWORD` | `1`                              | Reject repeated characters (e.g. `aaaa`, `1111`) |
| `RejectRepeatsLength`   | `REG_DWORD` | `3`                              | Minimum repeat length to reject |
| `BlacklistFile`         | `REG_SZ`    | `C:\Windows\System32\phylax_blacklist.txt` | Path to blacklist file (one password per line) |
| `BadPatternsFile`       | `REG_SZ`    | `C:\Windows\System32\phylax_bad_patterns.txt` | Path to file with known bad substrings |

### Real-Time Updates

Phylax watches for changes to both the registry and external files (`BlacklistFile`, `BadPatternsFile`). You do **not** need to restart services or reboot to apply changes:
- Registry keys are reloaded automatically every 10 seconds if changes are detected.
- Blacklist and pattern files are reloaded automatically every 10 seconds if changes are detected.

### Enforcing for Specific Groups

To apply the policy only to select AD groups (useful during pilot testing):

```reg
"EnforcedGroups"="Password Policy Users"
```

To apply a different password length requirement for administrators:

```reg
"AdminGroups"="System Administrators, Domain Admins"
```

To apply a different password length requirement for service accounts:

```reg
"ServiceAccountGroups"="Service Accounts"
```

If the current user changing their password is not a member of any of the listed groups, the policy checks will be skipped for that attempt. If `EnforcedGroups` is empty, the password policy applies to all users not found in `AdminGroups` or `ServiceAccountGroups`.

**_NOTE: Group memberships are top-level only. Nested groups are not checked!_**

### Blocklist & Pattern Files

#### Blacklist File

Path: `C:\Windows\System32\phylax_blacklist.txt`, or as defined in `BlacklistFile`  
Format: one complete password per line (e.g. breached or disallowed passwords)  
Case-insensitive matches of the full blacklisted password will be rejected.  
**Example**:  
```
p@ssw0rd1!
breached@cct1
qwerty731
letmein
changeme
```

#### Bad Patterns File

Path: `C:\Windows\System32\phylax_bad_patterns.txt`, or as defined in `BadPatternsFile`  
Format: one string per line.  
Case-insensitive matches of a string. If a password **_contains_** this string (anywhere), it will be rejected.  
**Example**:  
```
admin
@dmin
p@ss
qwerty
companyname
```

This allows rejecting passwords like `MyAdminPass123` even though `admin` is only part of the full string.

### Sequence Rejection

```reg
"RejectSequences"="1"
```

Setting this to `1` (default) enables blocking of character sequences (`1234`, `4321`, `abcd`, `dcba`).  
Setting this to `0` disables this enforcement.

```reg
"RejectSequencesLength"="3"
```

Setting this to `3` (default) will block three-character sequences like `123` or `bca`, but will allow shorter sequences like `12`, or `ba`
If `RejectSequences` is set to `0`, this setting is ignored.

### Repeated Character Rejection

```reg
"RejectRepeats"="1"
```

Setting this to `1` (default) enables blocking of repeated characters (`1111`, `aaaa`).  
Setting this to `0` disables this enforcement.

```reg
"RejectRepeatsLength"="3"
```

Setting this to `3` (default) will block three-character repetitions like `111` or `aaa`, but will allow shorter repetitions like `11`, or `aa`
If `RejectRepeats` is set to `0`, this setting is ignored. 

## Bug Reporting

Please report bugs or unexpected behavior by opening an issue in the [GitHub Issues](../../issues) section.

When reporting a bug, include the following where applicable:
- Description of the issue
- Version of Windows / Active Directory
- Relevant log entries from `phylax.log`
- Reproduction steps, if known
- Registry settings (with any sensitive values redacted)

---

## Contributing

Contributions are welcome!

### To contribute:
1. Fork the repository
2. Create a new feature or fix branch
3. Make your changes with clear commit messages
4. Submit a pull request with a description of what you changed and why

**Please test your changes thoroughly before submitting.**

If you're not sure where to start, feel free to open a discussion or an issue — suggestions, testing, documentation improvements, and code are all welcome.

---

## License

Phylax is released under the MIT License. See [LICENSE](../main/LICENSE) for details.

## Disclaimer

Although all efforts have been made to ensure this software functions without issue, I take no responsibility for the use (or misuse) of the code provided in this repository. Domain controllers are critical to the function of a Microsoft Active Directory domain, so please thoroughly test this software before deploying into production.
