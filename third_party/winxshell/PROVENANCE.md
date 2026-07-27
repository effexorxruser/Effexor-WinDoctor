# WinXShell / PExplorer provenance (spike)

Status: **local_test_only** — binary staged locally for experimental ISO builds.
Not approved for redistribution outside the lab.

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
| Redistribution decision | local_test_only — experimental lab artifact only |

## Closed / out-of-scope artifacts

Full WinXShell.exe releases that bundle DuiLib + Lua UI packs are treated as a
**different product**. Upstream has stated that many of those UI libraries are
not open source. Do not drop those zips into this directory.

## Staged binary (local test)

`third_party/winxshell/MANIFEST.json` is the machine-readable source of truth
for the license path and SHA-256. `Build-WinPE.ps1` copies the manifest license
file into the WIM as `LICENSE.LGPL-2.1.txt`.

| Field | Value |
|-------|-------|
| Built from commit | `5f8b886f326e706e6e4bba0e0b15da7da344857e` |
| Build date (UTC) | 2026-07-27T17:50:23Z |
| Build host / toolchain | DESKTOP-E60MF1G / VS Build Tools 2022 17.14.37, MSVC 14.44.35207 (v143), Windows SDK 10.0.26100.0 |
| SHA-256 of `WinXShell.exe` | `5C88AB009A4F0B43590F0E1A7EDFB397BD2D80F49E0F82F5D2655344F9615EF3` |
| Required sibling DLL | `notifyhook.dll` (SHA-256 `1A570CA09F3C3571B55F176C0D76ED55965BF87CD6E03ABAB95B57BCBBBC9F3E`) |
| License file present | `LICENSE.upstream-LGPL-2.1.txt` (copied into WIM as `LICENSE.LGPL-2.1.txt`) |
| Native config | `WinXShell.jcfg` |
| Smoke notes | Source-built locally; physical Ventoy smoke still required |
