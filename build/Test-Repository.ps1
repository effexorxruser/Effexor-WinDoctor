[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    Get-Content "contracts/diagnostic-report.schema.json" -Raw | ConvertFrom-Json | Out-Null
    Get-Content "contracts/diagnosis.schema.json" -Raw | ConvertFrom-Json | Out-Null
    Get-Content "contracts/diagnostic-session.schema.json" -Raw | ConvertFrom-Json | Out-Null
    Get-Content "manifests/tools.json" -Raw | ConvertFrom-Json | Out-Null
    Get-Content "manifests/drivers.json" -Raw | ConvertFrom-Json | Out-Null
    Get-Content "manifests/image-payload.json" -Raw | ConvertFrom-Json | Out-Null

    & (Join-Path $PSScriptRoot "Test-PayloadAllowlist.ps1")

    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go was not found. Install Go 1.24 or newer."
    }
    & go test ./...
    if ($LASTEXITCODE -ne 0) {
        throw "Go tests failed with exit code $LASTEXITCODE."
    }

    & (Join-Path $PSScriptRoot "Test-Add-WinPELanguage.ps1")
    & (Join-Path $PSScriptRoot "Test-DesktopShellSpike.ps1")

    $PreviousGoOS = $env:GOOS
    $PreviousGoArch = $env:GOARCH
    $PreviousCgo = $env:CGO_ENABLED
    try {
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        $ShellOut = Join-Path ([IO.Path]::GetTempPath()) "effexorwinpe-shell-test.exe"
        & go build -trimpath -o $ShellOut ./cmd/effexorwinpe-shell
        if ($LASTEXITCODE -ne 0) {
            throw "effexorwinpe-shell windows/amd64 build failed with exit code $LASTEXITCODE."
        }
        if (-not (Test-Path $ShellOut)) {
            throw "effexorwinpe-shell windows/amd64 build did not produce $ShellOut."
        }
        Write-Host "Shell executable build ok: $ShellOut"
    }
    finally {
        $env:GOOS = $PreviousGoOS
        $env:GOARCH = $PreviousGoArch
        $env:CGO_ENABLED = $PreviousCgo
    }

    Write-Host "Repository checks passed."
}
finally {
    Pop-Location
}
