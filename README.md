# ISTA VM Toolkit

`ISTA-VM-Toolkit.ps1` is a Windows PowerShell script that applies or reverts
common optimizations for BMW ISTA virtual machines. It focuses on service
tuning, UI tweaks, Defender hardening, Microsoft Store removal, and optional
auto-login configuration. The script is self-contained and uses manual argument
parsing so it runs on legacy PowerShell builds that do not support advanced
parameter syntax.

## Requirements

- Windows 10 / 11 virtual machine with PowerShell 5.1 or later.
- Run PowerShell as Administrator (the script validates elevation).
- Execution policy that permits unsigned local scripts. If the file was
  downloaded, clear the Zone.Identifier with:
  ```powershell
  Unblock-File C:\Path\To\ISTA-VM-Toolkit.ps1
  ```
- Optional: snapshot the VM before making changes.

## Quick Start

```powershell
cd C:\ista
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\ISTA-VM-Toolkit.ps1 -help       # show built-in help text
.\ISTA-VM-Toolkit.ps1 -all        # apply all optimizations
.\ISTA-VM-Toolkit.ps1 -all -revert  # revert everything (uses latest backup)
```

## Command-Line Switches

| Switch | Description |
| ------ | ----------- |
| `-all` | Apply all optimization blocks (`-services`, `-ui`, `-defenderhard`, `-removestore`). |
| `-services` | Disable or set Manual startup for known non-essential services (with special handling for DoSvc and PIM indexers). |
| `-ui` | Apply UI and policy tweaks for performance, disable indexing on `C:`, and attempt to switch to a high-performance power profile. |
| `-defenderhard` | Disable Windows Defender/ATP features, scheduled tasks, and related services. |
| `-removestore` | Remove the Microsoft Store, ClipSVC/WSService, and selected bundled UWP apps. |
| `-autologin user password` | Configure automatic logon credentials. |
| `-noautologin` | Remove the automatic logon configuration. |
| `-revert` | Revert the requested blocks instead of applying them. When used with `-all`, all revert routines run. |
| `-frombackup <csv>` | Specify a service-backup CSV created earlier (used during `-services -revert`). |
| `-backupdir <path>` | Override the directory used for backups and logs (`C:\_VMOptimize` by default). Positional path arguments are also accepted. |
| `-reportonly` | Dry run. Commands are not executed; actions are logged to the console. |
| `-norestart` | Suppress restart prompts in the output (informational flag only). |
| `-help` | Print the usage summary and exit. |

## Backups, Logging, and Reverts

- When applying changes, the script exports the current service startup modes to
  `<backupdir>\service-backup-<timestamp>.csv`. Reverting services uses the CSV
  (latest by default) or falls back to safe Manual startup defaults.
- All runs create a transcript log at `<backupdir>\ista-vm-toolkit-<timestamp>.txt`
  unless `-reportonly` is specified.
- Reverting Defender settings and Store removal re-enables the related services
  and attempts to re-register the Microsoft Store AppX package if present.
- Auto-login settings are reverted whenever `-revert` is paired with either
  `-autologin` or `-noautologin`.

## Dry Run Mode

Use `-reportonly` to preview every action without modifying the system. This is
useful for change reviews or documentation purposes. The script still validates
administrative privileges and prints the same step breakdown.

## Recommendations

- Reboot the VM after applying or reverting changes (the script reminds you at
  the end of each run).
- Keep at least one clean backup CSV in a safe location before further
  experimentation.
- When distributing the script, maintain ASCII encoding to avoid PowerShell
  parser issues caused by smart quotes or non-ASCII punctuation.
