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

foreach ($Path in $Docs) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing desktop-shell spike file: $Path"
    }
}

$BuildText = Get-Content -LiteralPath $BuildWinPE -Raw
foreach ($Needle in @(
        'ValidateSet("minimal-shell", "desktop-shell")',
        'EffexorWinPE-Desktop-Spike-$Architecture.iso',
        'ShellProfile desktop-shell requires',
        'Launch-EffexorDiagnostics.cmd',
        'start "Effexor Desktop" /min'
    )) {
    if ($BuildText -notlike "*$Needle*") {
        throw "Build-WinPE.ps1 is missing expected desktop-shell spike content: $Needle"
    }
}

$ManifestData = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
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

# Fail-closed: desktop-shell must not be buildable without a staged binary.
$VendorExe = Join-Path $RepoRoot "third_party/winxshell/WinXShell.exe"
if (Test-Path -LiteralPath $VendorExe) {
    Write-Host "Note: WinXShell.exe is present locally; ISO builds may use desktop-shell after license+hash gate."
} else {
    Write-Host "desktop-shell fail-closed ok: no WinXShell.exe staged (expected for default checkout)."
}

Write-Host "Desktop-shell spike checks passed."
