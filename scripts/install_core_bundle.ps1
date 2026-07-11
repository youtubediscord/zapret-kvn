[CmdletBinding()]
param(
    [string]$Archive = "",
    [string]$CoreDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Archive) {
    $Archive = Join-Path $repoRoot ".cache/core-bundle/core-windows-x64.7z"
}
if (-not $CoreDirectory) {
    $CoreDirectory = Join-Path $repoRoot "core"
}
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "Core bundle not found: $Archive"
}

$sevenZipCommand = Get-Command 7z -ErrorAction SilentlyContinue
$sevenZipPath = if ($sevenZipCommand) { $sevenZipCommand.Source } else { "" }
if (-not $sevenZipPath -and $env:ProgramFiles) {
    $candidate = Join-Path $env:ProgramFiles "7-Zip\7z.exe"
    if (Test-Path -LiteralPath $candidate) {
        $sevenZipPath = $candidate
    }
}
if (-not $sevenZipPath) {
    throw "7z is required to install the core bundle"
}

try {
    if (Test-Path -LiteralPath $CoreDirectory) {
        Remove-Item -LiteralPath $CoreDirectory -Recurse -Force -ErrorAction Stop
    }
    New-Item -ItemType Directory -Force -Path $CoreDirectory | Out-Null
}
catch {
    throw "Cannot replace '$CoreDirectory'. Stop ZapretKVN.exe and its cores, then retry. $($_.Exception.Message)"
}

$arguments = @(
    "x", "-y",
    "-o$CoreDirectory",
    $Archive
)
$process = Start-Process -FilePath $sevenZipPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "7z extraction failed with exit code $($process.ExitCode)"
}

& (Join-Path $PSScriptRoot "verify_core_bundle.ps1") -CoreDirectory $CoreDirectory
Write-Host "[core] installed: $CoreDirectory"
