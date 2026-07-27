# EffexorWinPE UI architecture

The technician GUI is a single native Win32 executable:

`payload/EffexorWinPE/bin/effexorwinpe-shell.exe`

It is a presentation and orchestration layer only. Diagnostic inventory and
triage logic remain in `effexorwinpe-collector` and `effexorwinpe-agent`.

## Goals

- Run in constrained WinPE without .NET, Electron, WebView2, OpenGL, or Fyne
- One `windows/amd64` EXE built with `CGO_ENABLED=0`
- Read-only MVP: inspect, collect, analyze, export, open `cmd.exe`, power actions
- Russian UI by default with English fallback
- Survive schema evolution through an adapter / view-model boundary

## Package map

| Package | Responsibility |
|---------|----------------|
| `cmd/effexorwinpe-shell` | Process entry, flags, wiring |
| `internal/shell/winui` | Native Win32 windowing (`//go:build windows`) |
| `internal/shell/present` | Screen text composition from view-models + i18n |
| `internal/shell/viewmodel` | UI DTOs decoupled from diagnostic structs |
| `internal/shell/adapter` | `diagnostics.Report` / `diagnosis.Assessment` / `session.Session` → view-model |
| `internal/shell/orchestrator` | Subprocess lifecycle, timeouts, exit mapping |
| `internal/shell/export` | Copy report/diagnosis/session/journal to technician media |
| `internal/shell/journal` | Local stdout/stderr and shell event log |
| `internal/shell/mock` | Embedded schema 1.3.0 fixtures for desktop development |
| `internal/shell/i18n` + `locales/` | Embedded string catalogs |

## Runtime flow

1. WinPE `startnet.cmd` initializes networking and starts either the default
   `minimal-shell` flow or the experimental `desktop-shell` flow.
2. `minimal-shell` launches `effexorwinpe-shell.exe` directly.
3. `desktop-shell` calls `Start-DesktopShell.cmd`, which starts WinXShell,
   waits for the shell process with a bounded timeout, writes a startup log,
   then launches `effexorwinpe-shell.exe --windowed` via
   `Launch-EffexorDiagnostics.cmd`.
4. After Diagnostics exits, or if desktop bootstrap fails, `cmd.exe` starts so
   emergency console access remains.
5. From the GUI, the technician starts diagnostics.
6. Shell runs `effexorwinpe-collector.exe` then `effexorwinpe-agent.exe`.
7. Shell decodes JSON through `diagnostics.DecodeReportJSON` (supports 1.3.0 and legacy 1.2.0 migration on the base branch).
8. Adapter builds view-models; Win32 UI renders localized screens.
9. Export copies artifacts to a chosen folder (USB or other writable media).

Default artifact paths (WinPE):

- `X:\EffexorWinPE\reports\initial.json`
- `X:\EffexorWinPE\reports\initial-diagnosis.json`
- `X:\EffexorWinPE\reports\initial-diagnosis-session.json`
- `X:\EffexorWinPE\reports\shell-journal.log`

## Desktop mock mode

On a normal Windows workstation:

```powershell
go build -trimpath -o effexorwinpe-shell.exe ./cmd/effexorwinpe-shell
.\effexorwinpe-shell.exe --mock --windowed
```

Mock mode loads embedded fixtures and does not require collector/agent binaries.
Default startup is fullscreen/kiosk (`--kiosk`); use `--windowed` or Esc to restore
a normal window. Layout targets 1024×768 and scales for 100%/125% DPI via
`WM_DPICHANGED`.

Worker threads never touch HWND controls directly. Progress and completion are
posted to the UI thread with `PostMessageW(WM_APP+…)` and applied in `wndProc`.

## Win32 surface

Primary DLLs:

- `user32.dll` — windowing, message loop, controls, message boxes, shutdown
- `gdi32.dll` — fonts, brushes, text/background colors
- `comctl32.dll` — common control initialization
- `shell32.dll` — folder browse dialog
- `kernel32.dll` — module handle

External Go dependency: `golang.org/x/sys/windows` (UTF-16 helpers and HWND types).

## Autostart

`build/Build-WinPE.ps1` writes `Windows\System32\startnet.cmd` to launch the shell,
then `cmd.exe`. Default profile is `minimal-shell`. An experimental
`desktop-shell` profile (separate ISO name, LGPL provenance gate) is documented
in [desktop-shell-spike.md](desktop-shell-spike.md). An optional template is
shipped at `payload/EffexorWinPE/config/winpeshl.ini.example` for operators who
prefer `winpeshl.ini` instead of `startnet.cmd`. The default image does not
install `winpeshl.ini`, avoiding a double launch.

## Safety

The MVP does not expose destructive repair actions (format, BCD edits, BitLocker
unlock/disable, registry mutation, driver removal). Power actions ask for
confirmation. Full technical subprocess output stays in the journal; the UI shows
short localized errors.
