# Verifies desktop-shell spike scaffolding without building an ISO.
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BuildWinPE = Join-Path $PSScriptRoot "Build-WinPE.ps1"
$Provenance = Join-Path $RepoRoot "third_party/winxshell/PROVENANCE.md"
$Manifest = Join-Path $RepoRoot "third_party/winxshell/MANIFEST.json"
$Docs = @(
    (Join-Path $RepoRoot "docs/desktop-shell-spike.md"),
    (Join-Path $RepoRoot "docs/decisions/0002-winpe-desktop-shell-spike.md"),
    (Join-Path $RepoRoot "docs/desktop-shell-metrics.md"),
    $Provenance,
    $Manifest
)

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

function Assert-ManifestFields {
    param([object]$ManifestData)

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
}

function Assert-ProvenanceAligned {
    param(
        [object]$ManifestData,
        [string]$ProvenanceText
    )

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

function Assert-DesktopShellGate {
    param(
        [object]$ManifestData,
        [string]$Root,
        [string]$BinaryPath
    )

    Assert-ManifestFields -ManifestData $ManifestData

    $LicensePath = Resolve-RepoPath -Root $Root -PathValue $ManifestData.license_file
    if (-not (Test-Path -LiteralPath $LicensePath)) {
        throw "ShellProfile desktop-shell requires license_file from manifest: $($ManifestData.license_file)"
    }
    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        throw "ShellProfile desktop-shell requires $BinaryPath (see docs/desktop-shell-spike.md)."
    }
    if ($ManifestData.sha256 -eq "TBD") {
        throw "ShellProfile desktop-shell requires a real sha256 in MANIFEST.json before desktop-shell builds."
    }
    if ($ManifestData.redistribution_status -eq "hold") {
        throw "ShellProfile desktop-shell is blocked while redistribution_status=hold in MANIFEST.json."
    }

    $ActualHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($ActualHash -ne $ManifestData.sha256.ToUpperInvariant()) {
        throw "WinXShell.exe SHA-256 mismatch. expected=$($ManifestData.sha256.ToUpperInvariant()) actual=$ActualHash"
    }
}

function New-ProvenanceText {
    param([object]$ManifestData)

    $ShaDisplay = if ($ManifestData.sha256 -eq "TBD") { "_TBD_" } else { $ManifestData.sha256 }
    $RedistributionText = if ($ManifestData.redistribution_status -eq "hold") {
        "Hold - validation pending"
    } else {
        "Allowed - validated"
    }

    return @"
# WinXShell / PExplorer provenance (test)

| Field | Value |
|-------|-------|
| Upstream | $($ManifestData.source_url) |
| Exact revision | $($ManifestData.revision) |
| License | $($ManifestData.license) |
| License file | $($ManifestData.license_file) |
| Redistribution decision | $RedistributionText |
| SHA-256 of `WinXShell.exe` | $ShaDisplay |
"@
}

foreach ($Path in $Docs) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing desktop-shell spike file: $Path"
    }
}

$BuildText = Get-Content -LiteralPath $BuildWinPE -Raw
foreach ($Needle in @(
        'ValidateSet("minimal-shell", "desktop-shell")',
        'EffexorWinPE-Desktop-Spike-$Architecture.iso',
        'EffexorWinPE-$Architecture.iso',
        'Read-DesktopShellManifest',
        'license_file',
        'LICENSE.LGPL-2.1.txt',
        'Start-DesktopShell.cmd',
        'desktop-shell-startup.log',
        'Launch-EffexorDiagnostics.cmd',
        'notifyhook.dll',
        'WinXShell.jcfg',
        'ping -n %READY_SETTLE_SECONDS% 127.0.0.1 >nul'
    )) {
    if ($BuildText -notlike "*$Needle*") {
        throw "Build-WinPE.ps1 is missing expected desktop-shell spike content: $Needle"
    }
}
if ($BuildText -like '*/min*') {
    throw "Build-WinPE.ps1 must not launch WinXShell with /min."
}
if ($BuildText -match '(?i)\btasklist(\.exe)?(\s|/)' -or $BuildText -match '(?i)\btimeout(\.exe)?\s+/t\b') {
    throw "Build-WinPE.ps1 must not depend on tasklist.exe or timeout.exe in WinPE bootstrap."
}
if ($BuildText -notlike '*if ($ShellProfile -eq "desktop-shell")*') {
    throw "Build-WinPE.ps1 must keep desktop-shell gating separate from minimal-shell startup."
}

$JcfgPath = Join-Path $RepoRoot "third_party/winxshell/WinXShell.jcfg"
if (-not (Test-Path -LiteralPath $JcfgPath)) {
    throw "Missing native WinXShell config: $JcfgPath"
}
$JcfgText = Get-Content -LiteralPath $JcfgPath -Raw
foreach ($Needle in @('JS_STARTMENU', 'Wpeutil.exe', 'Reboot', 'Shutdown')) {
    if ($JcfgText -notlike "*$Needle*") {
        throw "WinXShell.jcfg is missing expected content: $Needle"
    }
}

$ManifestData = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
Assert-ManifestFields -ManifestData $ManifestData

$ResolvedLicensePath = Resolve-RepoPath -Root $RepoRoot -PathValue $ManifestData.license_file
if (-not (Test-Path -LiteralPath $ResolvedLicensePath)) {
    throw "Manifest license_file does not exist: $($ManifestData.license_file)"
}
if ($ResolvedLicensePath -like "*LICENSE.LGPL-2.1.txt") {
    throw "Manifest must point at the tracked source license file, not the copied WIM filename."
}

$ProvenanceText = Get-Content -LiteralPath $Provenance -Raw
Assert-ProvenanceAligned -ManifestData $ManifestData -ProvenanceText $ProvenanceText

$VendorExe = Join-Path $RepoRoot "third_party/winxshell/WinXShell.exe"
if (Test-Path -LiteralPath $VendorExe) {
    Write-Host "Note: WinXShell.exe is present locally; ISO builds may use desktop-shell after manifest gates pass."
} else {
    Write-Host "desktop-shell fail-closed ok: no WinXShell.exe staged (expected for default checkout)."
}

$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ("desktop-shell-spike-tests-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
try {
    $TempRepoRoot = Join-Path $TempRoot "repo"
    $TempVendorRoot = Join-Path $TempRepoRoot "third_party/winxshell"
    New-Item -ItemType Directory -Force -Path $TempVendorRoot | Out-Null

    $TempLicenseRelative = "third_party/winxshell/LICENSE.fixture.txt"
    $TempLicensePath = Join-Path $TempRepoRoot $TempLicenseRelative
    Set-Content -LiteralPath $TempLicensePath -Value "fixture license" -Encoding ASCII

    $TempBinaryPath = Join-Path $TempVendorRoot "WinXShell.exe"
    Set-Content -LiteralPath $TempBinaryPath -Value "fixture-binary" -Encoding ASCII
    $TempBinaryHash = (Get-FileHash -LiteralPath $TempBinaryPath -Algorithm SHA256).Hash.ToUpperInvariant()

    $PositiveManifest = [pscustomobject]@{
        project = "PExplorer / WinXShell shellpart"
        revision = "rev-123"
        source_url = "https://example.test/source"
        license = "LGPL-2.1"
        license_file = $TempLicenseRelative
        applied_patches = @()
        build_instructions = @("fixture")
        sha256 = $TempBinaryHash
        redistribution_status = "allowed"
    }
    Assert-ProvenanceAligned -ManifestData $PositiveManifest -ProvenanceText (New-ProvenanceText -ManifestData $PositiveManifest)
    Assert-DesktopShellGate -ManifestData $PositiveManifest -Root $TempRepoRoot -BinaryPath $TempBinaryPath

    $NegativeCases = @(
        @{
            Name = "sha256 TBD"
            Manifest = ($PositiveManifest | Select-Object *)
            Expected = "real sha256"
            Mutate = { param($M) $M.sha256 = "TBD" }
        },
        @{
            Name = "redistribution hold"
            Manifest = ($PositiveManifest | Select-Object *)
            Expected = "redistribution_status=hold"
            Mutate = { param($M) $M.redistribution_status = "hold" }
        },
        @{
            Name = "missing binary"
            Manifest = ($PositiveManifest | Select-Object *)
            Expected = "requires"
            BinaryPath = (Join-Path $TempVendorRoot "missing.exe")
            Mutate = { param($M) }
        },
        @{
            Name = "hash mismatch"
            Manifest = ($PositiveManifest | Select-Object *)
            Expected = "SHA-256 mismatch"
            Mutate = { param($M) $M.sha256 = ("0" * 64) }
        },
        @{
            Name = "missing license"
            Manifest = ($PositiveManifest | Select-Object *)
            Expected = "license_file"
            Mutate = { param($M) $M.license_file = "third_party/winxshell/MISSING.txt" }
        }
    )

    foreach ($Case in $NegativeCases) {
        & $Case.Mutate $Case.Manifest
        $CaseBinaryPath = if ($Case.ContainsKey("BinaryPath")) { $Case.BinaryPath } else { $TempBinaryPath }
        try {
            Assert-DesktopShellGate -ManifestData $Case.Manifest -Root $TempRepoRoot -BinaryPath $CaseBinaryPath
            throw "Negative gate case unexpectedly passed: $($Case.Name)"
        }
        catch {
            if ($_.Exception.Message -notlike "*$($Case.Expected)*") {
                throw "Negative gate case '$($Case.Name)' failed with unexpected message: $($_.Exception.Message)"
            }
        }
    }

    try {
        Assert-ProvenanceAligned -ManifestData $PositiveManifest -ProvenanceText (New-ProvenanceText -ManifestData @{
                revision = $PositiveManifest.revision
                source_url = $PositiveManifest.source_url
                license = $PositiveManifest.license
                license_file = $PositiveManifest.license_file
                sha256 = "TBD"
                redistribution_status = "hold"
            })
        throw "Provenance mismatch test unexpectedly passed."
    }
    catch {
        if ($_.Exception.Message -notlike "*SHA-256*") {
            throw
        }
    }
}
finally {
    if (Test-Path -LiteralPath $TempRoot) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force
    }
}

Write-Host "Desktop-shell spike checks passed."
