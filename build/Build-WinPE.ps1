[CmdletBinding()]
param(
    [ValidateSet("amd64")]
    [string]$Architecture = "amd64",
    [string]$Language = "en-us",
    [string]$UILanguage = "ru-RU",
    [ValidateSet("minimal-shell", "desktop-shell")]
    [string]$ShellProfile = "minimal-shell",
    [string]$OutputDirectory = "",
    [switch]$IncludeLocalDrivers,
    [switch]$SkipOSLanguagePack,
    [switch]$BootEx
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepoRoot "out"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$WorkingDirectory = Join-Path $OutputDirectory "winpe-$Architecture"
$MountDirectory = Join-Path $WorkingDirectory "mount"
$IsoName = if ($ShellProfile -eq "desktop-shell") {
    "EffexorWinPE-Desktop-Spike-$Architecture.iso"
} else {
    "EffexorWinPE-$Architecture.iso"
}
$IsoPath = Join-Path $OutputDirectory $IsoName
$DesktopShellVendorDir = Join-Path $RepoRoot "third_party/winxshell"
$DesktopShellBinary = Join-Path $DesktopShellVendorDir "WinXShell.exe"
$DesktopShellProvenance = Join-Path $DesktopShellVendorDir "PROVENANCE.md"
$DesktopShellManifest = Join-Path $DesktopShellVendorDir "MANIFEST.json"
$DesktopShellNotifyHook = Join-Path $DesktopShellVendorDir "notifyhook.dll"
$DesktopShellJcfg = Join-Path $DesktopShellVendorDir "WinXShell.jcfg"

function Resolve-RepoPath {
    param(
        [string]$Root,
        [string]$PathValue
    )

    if ([IO.Path]::IsPathRooted($PathValue)) {
        return [IO.Path]::GetFullPath($PathValue)
    }

    return [IO.Path]::GetFullPath((Join-Path $Root $PathValue))
}

function Read-DesktopShellManifest {
    param(
        [string]$ManifestPath,
        [string]$Root
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "ShellProfile desktop-shell requires third-party manifest at $ManifestPath."
    }

    $ManifestData = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    foreach ($Field in @(
            "project",
            "revision",
            "source_url",
            "license",
            "license_file",
            "applied_patches",
            "build_instructions",
            "sha256",
            "redistribution_status"
        )) {
        if (-not ($ManifestData.PSObject.Properties.Name -contains $Field)) {
            throw "Desktop-shell manifest is missing field: $Field"
        }
    }

    $LicensePath = Resolve-RepoPath -Root $Root -PathValue $ManifestData.license_file
    $ManifestData | Add-Member -NotePropertyName ResolvedLicensePath -NotePropertyValue $LicensePath -Force
    return $ManifestData
}

function Assert-DesktopShellProvenanceAligned {
    param(
        [object]$ManifestData,
        [string]$ProvenancePath
    )

    if (-not (Test-Path -LiteralPath $ProvenancePath)) {
        throw "ShellProfile desktop-shell requires provenance at $ProvenancePath."
    }

    $ProvenanceText = Get-Content -LiteralPath $ProvenancePath -Raw
    foreach ($ExpectedValue in @(
            $ManifestData.revision,
            $ManifestData.source_url,
            $ManifestData.license,
            $ManifestData.license_file
        )) {
        if ($ProvenanceText -notlike "*$ExpectedValue*") {
            throw "Desktop-shell provenance must include manifest value: $ExpectedValue"
        }
    }

    if ($ManifestData.redistribution_status -eq "hold" -and $ProvenanceText -notmatch '(?i)\bhold\b') {
        throw "Desktop-shell provenance must document redistribution hold status."
    }

    if ($ManifestData.sha256 -eq "TBD") {
        if ($ProvenanceText -notmatch '(?i)SHA-256 of `WinXShell\.exe`\s*\|\s*_?TBD_?\s*\|') {
            throw "Desktop-shell provenance must keep SHA-256 as TBD while the manifest does."
        }
        return
    }

    if ($ProvenanceText -notlike "*$($ManifestData.sha256)*") {
        throw "Desktop-shell provenance must include the manifest SHA-256 value."
    }
}

$AdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits/10/Assessment and Deployment Kit"
$WinPERoot = Join-Path $AdkRoot "Windows Preinstallation Environment"
$CopyPE = Join-Path $WinPERoot "copype.cmd"
$MakeWinPEMedia = Join-Path $WinPERoot "MakeWinPEMedia.cmd"
$OptionalComponents = Join-Path $WinPERoot "$Architecture/WinPE_OCs"

if (-not (Test-Path $CopyPE)) {
    throw "Windows ADK Deployment Tools were not found at $CopyPE."
}
if (-not (Test-Path $MakeWinPEMedia)) {
    throw "Windows PE add-on was not found at $MakeWinPEMedia."
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Build-WinPE.ps1 must run from an elevated PowerShell session."
}

& (Join-Path $PSScriptRoot "Build-Payload.ps1")

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
if (Test-Path $WorkingDirectory) {
    Remove-Item -Recurse -Force $WorkingDirectory
}

& $CopyPE $Architecture $WorkingDirectory
if ($LASTEXITCODE -ne 0) {
    throw "copype failed with exit code $LASTEXITCODE."
}

$BootWim = Join-Path $WorkingDirectory "media/sources/boot.wim"
$Mounted = $false
try {
    & dism.exe /Mount-Image "/ImageFile:$BootWim" /Index:1 "/MountDir:$MountDirectory"
    if ($LASTEXITCODE -ne 0) {
        throw "DISM failed to mount boot.wim."
    }
    $Mounted = $true

    $Packages = @(
        "WinPE-WMI.cab",
        "WinPE-NetFX.cab",
        "WinPE-Scripting.cab",
        "WinPE-PowerShell.cab",
        "WinPE-StorageWMI.cab",
        "WinPE-DismCmdlets.cab",
        "WinPE-SecureStartup.cab",
        "WinPE-EnhancedStorage.cab"
    )
    foreach ($Package in $Packages) {
        $PackagePath = Join-Path $OptionalComponents $Package
        if (-not (Test-Path $PackagePath)) {
            throw "Required WinPE optional component is missing: $PackagePath"
        }
        & dism.exe "/Image:$MountDirectory" /Add-Package "/PackagePath:$PackagePath"
        if ($LASTEXITCODE -ne 0) {
            throw "DISM failed while adding $Package."
        }

        $LocalizedName = $Package -replace "\.cab$", "_$Language.cab"
        $LocalizedPath = Join-Path $OptionalComponents "$Language/$LocalizedName"
        if (Test-Path $LocalizedPath) {
            & dism.exe "/Image:$MountDirectory" /Add-Package "/PackagePath:$LocalizedPath"
            if ($LASTEXITCODE -ne 0) {
                throw "DISM failed while adding $LocalizedName."
            }
        }
    }

    $PayloadTarget = Join-Path $MountDirectory "EffexorWinPE"
    & (Join-Path $PSScriptRoot "Copy-ImagePayload.ps1") `
        -SourceRoot $RepoRoot `
        -DestinationRoot $PayloadTarget `
        -ManifestPath (Join-Path $RepoRoot "manifests/image-payload.json")

    $DiagnosticsLauncher = Join-Path $PayloadTarget "Launch-EffexorDiagnostics.cmd"
    $DiagnosticsLauncherBody = @"
@echo off
setlocal
set "EFFEXOR_DIAGNOSTICS=X:\EffexorWinPE\bin\effexorwinpe-shell.exe"
if /I "%~1"=="--wait" (
  "%EFFEXOR_DIAGNOSTICS%" --windowed
  exit /b %ERRORLEVEL%
)
start "Effexor Diagnostics" "%EFFEXOR_DIAGNOSTICS%" --windowed
exit /b 0
"@
    Set-Content -LiteralPath $DiagnosticsLauncher -Value $DiagnosticsLauncherBody -Encoding ASCII

    $StartnetShellLines = @(
        "X:\EffexorWinPE\bin\effexorwinpe-shell.exe"
    )
    if ($ShellProfile -eq "desktop-shell") {
        $DesktopShellMetadata = Read-DesktopShellManifest -ManifestPath $DesktopShellManifest -Root $RepoRoot
        if (-not (Test-Path $DesktopShellBinary)) {
            throw "ShellProfile desktop-shell requires $DesktopShellBinary (see docs/desktop-shell-spike.md)."
        }
        if (-not (Test-Path -LiteralPath $DesktopShellNotifyHook)) {
            throw "ShellProfile desktop-shell requires $DesktopShellNotifyHook beside WinXShell.exe."
        }
        if (-not (Test-Path -LiteralPath $DesktopShellJcfg)) {
            throw "ShellProfile desktop-shell requires native config $DesktopShellJcfg."
        }
        Assert-DesktopShellProvenanceAligned -ManifestData $DesktopShellMetadata -ProvenancePath $DesktopShellProvenance
        if ($DesktopShellMetadata.sha256 -eq "TBD") {
            throw "ShellProfile desktop-shell requires a real sha256 in $DesktopShellManifest before desktop-shell builds."
        }
        if ($DesktopShellMetadata.redistribution_status -eq "hold") {
            throw "ShellProfile desktop-shell is blocked while redistribution_status=hold in $DesktopShellManifest."
        }
        if (-not (Test-Path -LiteralPath $DesktopShellMetadata.ResolvedLicensePath)) {
            throw "ShellProfile desktop-shell requires license_file from manifest: $($DesktopShellMetadata.license_file)"
        }
        $ExpectedHash = $DesktopShellMetadata.sha256.ToUpperInvariant()
        $ActualHash = (Get-FileHash -LiteralPath $DesktopShellBinary -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($ActualHash -ne $ExpectedHash) {
            throw "WinXShell.exe SHA-256 mismatch. expected=$ExpectedHash actual=$ActualHash"
        }
        $VendorTarget = Join-Path $PayloadTarget "third_party/winxshell"
        $DesktopBootstrap = Join-Path $PayloadTarget "Start-DesktopShell.cmd"
        $DesktopBootstrapBody = @"
@echo off
setlocal EnableExtensions
set "SHELL_EXE=X:\EffexorWinPE\third_party\winxshell\WinXShell.exe"
set "DIAGNOSTICS_LAUNCHER=X:\EffexorWinPE\Launch-EffexorDiagnostics.cmd"
set "STARTUP_LOG=X:\EffexorWinPE\reports\desktop-shell-startup.log"
set "READY_SETTLE_SECONDS=5"
>>"%STARTUP_LOG%" echo [%date% %time%] Desktop bootstrap started.
if not exist "%SHELL_EXE%" (
  >>"%STARTUP_LOG%" echo [%date% %time%] ERROR missing WinXShell binary.
  exit /b 1
)
start "Effexor Desktop" "%SHELL_EXE%" -winpe
REM Base WinPE lacks process-list and delay utilities. Use ping settle delay instead.
>>"%STARTUP_LOG%" echo [%date% %time%] Waiting %READY_SETTLE_SECONDS%s for WinXShell settle (ping-based).
ping -n %READY_SETTLE_SECONDS% 127.0.0.1 >nul
>>"%STARTUP_LOG%" echo [%date% %time%] Launching Diagnostics after settle delay.
call "%DIAGNOSTICS_LAUNCHER%" --wait
set "DIAGNOSTICS_EXIT=%ERRORLEVEL%"
>>"%STARTUP_LOG%" echo [%date% %time%] Diagnostics exited with code %DIAGNOSTICS_EXIT%.
exit /b %DIAGNOSTICS_EXIT%
"@
        $DiagnosticsDesktopEntryBody = @"
@echo off
call X:\EffexorWinPE\Launch-EffexorDiagnostics.cmd
"@
        foreach ($EntryPath in @(
                (Join-Path $MountDirectory "Users/Default/Desktop/Effexor Diagnostics.cmd"),
                (Join-Path $MountDirectory "ProgramData/Microsoft/Windows/Start Menu/Programs/Effexor Diagnostics.cmd")
            )) {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $EntryPath) | Out-Null
            Set-Content -LiteralPath $EntryPath -Value $DiagnosticsDesktopEntryBody -Encoding ASCII
        }
        New-Item -ItemType Directory -Force -Path $VendorTarget | Out-Null
        Set-Content -LiteralPath $DesktopBootstrap -Value $DesktopBootstrapBody -Encoding ASCII
        Copy-Item -LiteralPath $DesktopShellBinary -Destination (Join-Path $VendorTarget "WinXShell.exe") -Force
        Copy-Item -LiteralPath $DesktopShellNotifyHook -Destination (Join-Path $VendorTarget "notifyhook.dll") -Force
        Copy-Item -LiteralPath $DesktopShellJcfg -Destination (Join-Path $VendorTarget "WinXShell.jcfg") -Force
        Copy-Item -LiteralPath $DesktopShellMetadata.ResolvedLicensePath -Destination (Join-Path $VendorTarget "LICENSE.LGPL-2.1.txt") -Force
        Copy-Item -LiteralPath $DesktopShellProvenance -Destination (Join-Path $VendorTarget "PROVENANCE.md") -Force
        Copy-Item -LiteralPath $DesktopShellManifest -Destination (Join-Path $VendorTarget "MANIFEST.json") -Force
        # Launch desktop shell first, then start Diagnostics windowed so it stays
        # visible in the taskbar. If Diagnostics exits, cmd.exe remains available.
        $StartnetShellLines = @(
            'call X:\EffexorWinPE\Start-DesktopShell.cmd'
        )
    }

    if ($IncludeLocalDrivers) {
        $Drivers = Join-Path $RepoRoot "drivers/local"
        if (-not (Test-Path $Drivers)) {
            throw "-IncludeLocalDrivers was requested, but drivers/local does not exist."
        }
        & dism.exe "/Image:$MountDirectory" /Add-Driver "/Driver:$Drivers" /Recurse
        if ($LASTEXITCODE -ne 0) {
            throw "DISM failed while adding local drivers."
        }
    }

    if (-not $SkipOSLanguagePack) {
        & (Join-Path $PSScriptRoot "Add-WinPELanguage.ps1") `
            -MountDirectory $MountDirectory `
            -Locale $UILanguage `
            -Architecture $Architecture `
            -AdkRoot $AdkRoot
    }

    # Launch the technician GUI (and optional experimental desktop shell).
    # cmd.exe remains available after the shell exits so emergency console
    # access is preserved if the UI cannot start.
    $StartnetBody = ($StartnetShellLines -join "`r`n")
    $Startnet = @"
wpeinit
wpeutil InitializeNetwork
if not exist X:\EffexorWinPE\reports mkdir X:\EffexorWinPE\reports
$StartnetBody
cmd.exe
"@
    Set-Content -Path (Join-Path $MountDirectory "Windows/System32/startnet.cmd") -Value $Startnet -Encoding ASCII
    Write-Host "ShellProfile=$ShellProfile ISO=$IsoPath"

    & dism.exe /Unmount-Image "/MountDir:$MountDirectory" /Commit
    if ($LASTEXITCODE -ne 0) {
        throw "DISM failed to commit boot.wim."
    }
    $Mounted = $false
}
finally {
    if ($Mounted) {
        & dism.exe /Unmount-Image "/MountDir:$MountDirectory" /Discard | Out-Null
    }
}

if (Test-Path $IsoPath) {
    Remove-Item -Force $IsoPath
}
$MediaArguments = @("/ISO", $WorkingDirectory, $IsoPath)
if ($BootEx) {
    $MediaArguments += "/bootex"
}
& $MakeWinPEMedia @MediaArguments
if ($LASTEXITCODE -ne 0) {
    throw "MakeWinPEMedia failed with exit code $LASTEXITCODE."
}

Write-Host "WinPE image ready: $IsoPath"
