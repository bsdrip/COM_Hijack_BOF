# COM Hijack BOF

A Beacon Object File (BOF) for Cobalt Strike and Mythic C2 that implements COM hijacking for persistence on Windows systems.

## Overview

This BOF exploits Windows Component Object Model (COM) registry search order by creating entries in `HKEY_CURRENT_USER` that take precedence over `HKEY_LOCAL_MACHINE`. When a legitimate application or scheduled task attempts to instantiate the hijacked COM object, your malicious DLL is loaded instead.

## Features

- **Hijack Mode**: Creates HKCU registry keys to redirect COM object instantiation to a malicious DLL
- **Delete Mode**: Removes COM hijack registry entries (cleanup)
- **Automatic ThreadingModel matching**: Reads and mirrors the ThreadingModel from HKLM for compatibility
- **Comprehensive validation**: Validates CLSID format, DLL existence, and registry state
- **Verbose output**: Detailed logging for operational awareness
- **No admin required**: Operates entirely in HKCU without elevated privileges

## MITRE ATT&CK

- **Technique**: T1546.015 - Event Triggered Execution: Component Object Model Hijacking
- **Tactic**: Persistence, Privilege Escalation

## Usage

### Hijack Mode

Creates a COM hijack by adding registry entries in HKCU:
```
bof_com_hijack hijack <dll_path> <clsid>
```

**Example:**
```
bof_com_hijack hijack C:\Users\Public\evil.dll {0358B920-0AC7-461F-98F4-58E32CD89148}
```

**Requirements:**
- DLL must exist at the specified path
- CLSID must exist in HKLM (the BOF will verify this)
- CLSID must NOT already exist in HKCU

### Delete Mode

Removes a COM hijack from HKCU:
```
bof_com_hijack delete <clsid>
```

**Example:**
```
bof_com_hijack delete {0358B920-0AC7-461F-98F4-58E32CD89148}
```

**Note:** The DLL file is NOT deleted from disk - only the registry entries are removed.

## Finding Hijackable CLSIDs

Use the following PowerShell commands to find suitable COM objects with scheduled task triggers:
```powershell
# Find all scheduled tasks that use COM objects
$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
    foreach ($action in $task.Actions) {
        if ($action.ClassId -ne $null) {
            Write-Host "Task: $($task.TaskName)"
            Write-Host "  CLSID: $($action.ClassId)"
            Write-Host "  Triggers: $($task.Triggers.CimClass.CimClassName -join ', ')"
        }
    }
}

# Check if a CLSID is hijackable
$clsid = "{0358B920-0AC7-461F-98F4-58E32CD89148}"
$hklm = Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32"
$hkcu = Test-Path "HKCU:\Software\Classes\CLSID\$clsid\InProcServer32"

if ($hklm -and -not $hkcu) {
    Write-Host "[HIJACKABLE] $clsid"
}
```

## Common Hijackable CLSIDs (Windows 10/11)

| CLSID | Name | Trigger | Notes |
|-------|------|---------|-------|
| `{0358B920-0AC7-461F-98F4-58E32CD89148}` | CacheTask | Logon | WinINet cache cleanup |
| `{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}` | MsCtfMonitor | Logon | Text services framework |
| `{6F58F65F-EC0E-4ACA-99FE-FC5A1A25E4BE}` | Installation (LangComp) | Logon | Language components |

**Note:** Always enumerate CLSIDs on your specific target as availability varies by Windows version and installed software.

## Compilation

### For Cobalt Strike
```bash
# Compile BOF
x86_64-w64-mingw32-gcc -c bof_com_hijack.c -o bof_com_hijack.o

# Load in Cobalt Strike
beacon> inline-execute /path/to/bof_com_hijack.o hijack C:\evil.dll {CLSID}
```

### For Mythic C2

Integrate with agents that support BOF execution (e.g., Apollo, Athena).

## Detection & Mitigation

### Detection

- Monitor registry changes in `HKCU\Software\Classes\CLSID\`
- Alert on mismatches between HKLM and HKCU COM registrations
- Track unusual DLL loads from user-writable directories
- Sysmon Event ID 13 (Registry value set) for `InProcServer32`

### Mitigation

- Use application whitelisting (AppLocker, WDAC)
- Enable LSA protection
- Restrict write access to user profile directories
- Monitor scheduled tasks for COM handler changes
- Implement registry auditing on `HKCU\Software\Classes\CLSID\`

## OpSec Considerations

- **DLL Location**: Place DLL in legitimate-looking paths (e.g., `%LOCALAPPDATA%\Microsoft\`)
- **DLL Name**: Use names that blend with the legitimate DLL (e.g., `wininet.dll`)
- **Cleanup**: Always use delete mode to remove hijacks when done
- **Thread Safety**: Ensure your DLL doesn't crash the host process
- **Logging**: Be aware this generates registry modification events

## License

For authorized security testing and red team operations only.

## References

- [MITRE ATT&CK T1546.015](https://attack.mitre.org/techniques/T1546/015/)
- [MDSec COM Hijacking Article](https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-2-com-hijacking/)
- [Microsoft COM Documentation](https://docs.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal)

## Author

Written for educational and authorized security testing purposes.