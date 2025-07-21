# Phýlax

**Greek** φύλαξ (phýlax)  
[800-500 BCE] Ancient Greece - Watcher, guard, sentinel, guardian, keeper, protector

![Phylax Password Policy](logo.png)

## About

Phylax is a password policy add-in for Microsoft Active Directory. Any time a password is set or changed, Phylax is called to check for blacklisted passwords or blacklisted patterns.

Technical reference: [Password Filters](https://learn.microsoft.com/en-us/windows/win32/secmgmt/password-filters?redirectedfrom=MSDN)

### Blacklisted Passwords

The blacklisted passwords file (default: `C:\Windows\System32\phylax_blacklist.txt`) should contain a list of blacklisted passwords that are to be blocked. This list enforces an exact, case-sensitive match of passwords to be blocked. This is helpful for blocking known-breached passwords.

**Example**:  
`phylax_blacklist.txt` contains `S3cr3tP@ss`  
* A user attempts to change their password to `s2cr3tP@ss`
  * Blocked since the password matches without case sensitivity. 
* A user attempts to change their password to `S3cr3tP@ssw0rd!`
  * Not blocked since appending `w0rd!` renders this not an exact match.

### Bad Patterns

The bad patterns file (default: `C:\Windows\System32\phylax_bad_patterns.txt`) should contain a list of patterns or strings that may not exist in a password at all. This is a case-insensitive match.

**Example**:  
`phylax_bad_patterns.txt` contains `S3cr3tP@ss`
* A user attempts to change their password to `s3cr3tp@ss`
  * Blocked since the password matches without case sensitivity.
* A user attempts to change their password to `S3cr3tP@ssw0rd!`
  * Blocked since the password still contains the bad pattern `S3cr3tP@ss`
## Configuration

Phylax is highly configurable via self-reloading registry settings. The first time Phylax is run, the following default registry settings are created. 

![Registry Settings](registry.png)

These settings may be adjusted at any time, and the changes will be reloaded automatically. A check is performed every one minute for any changes.

### Default Registry Settings

The first time Phylax is loaded, all default registry settings are created. If you would like to make these settings beforehand, to ensure your preferences are loaded at the start, you may do so. Registry settings are located in:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Phylax
```

|**Setting**|**Description**|**Default**|
|-|--------------------------------|-|
|**LogLevel**|Setting the logging level (DEBUG, INFO, WARN, ERROR)|`INFO`|
|**LogPath**|Path to the log file|`C:\Windows\System32\`|
|**LogName**|Change the log file name|`phylax.log`|
|**LogRetention**|Number of log files to be retained|`10`|
|**LogSize**|Size (in kB) of log file before rotating|`10240`|
|**Complexity**|How many categories (lower, upper, number, special) must be included|`3`|
|**MinimumLength**|Minimum password length to be enforced|`12`|
|**RejectRepeats**|Reject repeated characters (`111`, `!!!`, `aaa`, `AAA`)|`1`|
|**RejectRepeatsLength**|Length of pattern to be rejected|`3`|
|**RejectSequences**|Reject sequence of characters (`123`, `321`, `abc`, `bca`)|`1`|
|**RejectSequencesLength**|Length of sequence to be rejected|`3`|
|**EnforcedGroups**|Comma-delimited list of Active Directory security groups to apply policy to.|None|
|**BadPatternsFile**|Location of "bad patterns" file.|`C:\Windows\System32\phylax_bad_patterns.txt`|
|**BlacklistFile**|Location of password blacklist file.|`C:\Windows\System32\phylax_blacklist.txt`|

## Contributing

If you would like to contribute to this project, please first open an issue with details on what you would like to contribute, and why. From there, we can discuss the proposed changes before opening a PR.
