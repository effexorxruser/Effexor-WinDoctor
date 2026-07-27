# WinXShell / PExplorer provenance (spike)

Status: **not staged** — no redistributable binary is checked into this tree.

## Intended open source line

| Field | Value |
|-------|-------|
| Project | PExplorer / WinXShell shellpart |
| Upstream | https://github.com/slorelee/PExplorer |
| Source URL | https://github.com/slorelee/PExplorer/tree/WinXShell_shellpart |
| Source branch | `WinXShell_shellpart` |
| Exact revision | `5f8b886f326e706e6e4bba0e0b15da7da344857e` |
| License | LGPL-2.1 |
| License file | `third_party/winxshell/LICENSE.upstream-LGPL-2.1.txt` |
| Architecture target | windows/amd64 |
| Redistribution decision | Hold — spike research only until a reproducible local build is recorded below |

## Closed / out-of-scope artifacts

Full WinXShell.exe releases that bundle DuiLib + Lua UI packs are treated as a
**different product**. Upstream has stated that many of those UI libraries are
not open source. Do not drop those zips into this directory.

## When a binary is staged

Fill every row, place `WinXShell.exe` beside this file (gitignored), and keep
`third_party/winxshell/MANIFEST.json` as the machine-readable source of truth
for the license path and SHA-256. `Build-WinPE.ps1` copies the manifest license
file into the WIM as `LICENSE.LGPL-2.1.txt`.

| Field | Value |
|-------|-------|
| Built from commit | _TBD_ |
| Build date (UTC) | _TBD_ |
| Build host / toolchain | _TBD_ |
| SHA-256 of `WinXShell.exe` | _TBD_ |
| License file present | _TBD_ |
| Smoke notes | _TBD_ |
