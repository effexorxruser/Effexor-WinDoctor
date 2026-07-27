# ADR 0002: Experimental WinPE desktop-shell profile (spike)

- Status: proposed (spike only)
- Date: 2026-07-24

## Context

The release WinPE image launches `effexorwinpe-shell.exe` from `startnet.cmd`
and falls back to `cmd.exe`. That keeps the rescue UI self-contained and free of
third-party shell binaries.

Technicians still ask for a more familiar desktop (taskbar, wallpaper, tray) on
some repair jobs. WinPE does not ship Explorer. Community shells such as
WinXShell / PExplorer (ROS Explorer lineage) exist for WinPE, but redistribution,
reproducibility, and license obligations are non-trivial.

## Decision

Add an **experimental, opt-in build profile** `desktop-shell` that never replaces
the default `minimal-shell` release path:

1. Default profile remains `minimal-shell` (current `startnet.cmd` + Effexor GUI).
2. `desktop-shell` may stage a **checksum-pinned, LGPL-2.1-compatible** shell
   binary only after provenance is recorded under `third_party/`.
3. Experimental ISO output uses the distinct filename
   `EffexorWinPE-Desktop-Spike-amd64.iso` so it cannot overwrite the release ISO.
4. Desktop-shell startup keeps Effexor Diagnostics as the technician app by
   auto-launching it in windowed mode after WinXShell starts.
5. Rollback is switching the profile back to `minimal-shell` (or rebuilding the
   release ISO). No runtime dual-shell switch is required for the spike.

### Candidate source (research)

| Item | Finding |
|------|---------|
| Open shellpart source | [slorelee/PExplorer](https://github.com/slorelee/PExplorer) branch `WinXShell_shellpart` |
| License | LGPL-2.1 |
| Scope | Portable desktop / taskbar / tray replacement for WinPE |
| x64 | Documented as supported |
| Full WinXShell.exe (DuiLib + Lua UI packs) | Separate product; author states many UI libs are **not** open source — **out of scope** for redistribution in this repo |

Spike rule: only pursue reproducible builds from the LGPL shellpart sources (or a
clearly licensed fork such as sandboxie-plus/SbieShell lineage). Do not vendor
opaque WinXShell release zips without source, license text, and checksum.

## Consequences

- Release images stay unchanged unless an operator explicitly passes
  `-ShellProfile desktop-shell`.
- LGPL obligations (license notice, offer of corresponding source, linking rules)
  must be completed before any redistributed experimental ISO leaves the lab.
- Memory and boot timing must be measured on disposable media; desktop shells
  increase RAM use versus `minimal-shell`.
- Physical Ventoy / Hyper-V validation of the experimental ISO is separate from
  RC1 release sign-off.
