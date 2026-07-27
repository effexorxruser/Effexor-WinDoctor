# WinPE desktop-shell spike metrics

Physical boot metrics cannot be measured from this workspace. This file captures
the required comparison table, placeholders, and the exact procedure to run on
physical Ventoy media before merge.

## Measurement procedure

Use the same target machine and Ventoy stick for both profiles:

1. Build `minimal-shell` and `desktop-shell` from the same commit.
2. Copy both ISOs to the same Ventoy device.
3. Reboot and cold-boot each ISO separately.
4. Start timing at Ventoy launch selection.
5. Stop timing when the desktop becomes interactive:
   - `minimal-shell`: Effexor Diagnostics main window is responsive.
   - `desktop-shell`: taskbar/desktop is visible and Effexor Diagnostics window
     is responsive in the taskbar.
6. Capture screenshots after boot:
   - full desktop or Diagnostics window
   - taskbar visibility
   - any startup error dialogs
7. Record process list and working set from Task Manager equivalent, WMIC,
   PowerShell `Get-Process`, or the shell's process viewer.
8. Record free RAM immediately after boot and before starting any extra tools.
9. Record shell working set:
   - `minimal-shell`: `effexorwinpe-shell.exe`
   - `desktop-shell`: `WinXShell.exe` plus `effexorwinpe-shell.exe`
10. Record reboot/shutdown behavior and fallback to `cmd.exe`.

## Build-time artifacts measurable here

| Artifact | Status |
|----------|--------|
| `minimal-shell` boot.wim size | _TBD: requires ADK build on Windows_ |
| `desktop-shell` boot.wim size | _TBD: requires staged WinXShell.exe + ADK build_ |
| `EffexorWinPE-amd64.iso` size | _TBD: requires ADK build on Windows_ |
| `EffexorWinPE-Desktop-Spike-amd64.iso` size | _TBD: requires staged WinXShell.exe + ADK build_ |

## Runtime comparison

| Metric | minimal-shell | desktop-shell | Notes |
|--------|---------------|---------------|-------|
| Ventoy launch to interactive desktop | _TBD_ | _TBD_ | same hardware, cold boot |
| Free RAM after boot | _TBD_ | _TBD_ | measure before extra tooling |
| Shell working set | _TBD_ | _TBD_ | WinXShell.exe only for desktop profile |
| Effexor Diagnostics working set | _TBD_ | _TBD_ | `effexorwinpe-shell.exe` |
| Process list | _TBD_ | _TBD_ | attach or summarize |
| Startup errors | _TBD_ | _TBD_ | dialogs, missing DLLs, shell faults |
| Reboot/shutdown flow | _TBD_ | _TBD_ | verify shell/menu action and fallback |

## Expected process baselines

`minimal-shell`:

- `effexorwinpe-shell.exe`
- `cmd.exe` after Diagnostics exits

`desktop-shell`:

- `WinXShell.exe`
- `effexorwinpe-shell.exe --windowed`
- `cmd.exe` after Diagnostics exits

## Merge gate reminder

Do not merge until physical Ventoy smoke has been completed against
`EffexorWinPE-Desktop-Spike-amd64.iso` and the table above is filled with real
measurements.
