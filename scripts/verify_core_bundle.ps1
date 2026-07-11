[CmdletBinding()]
param(
    [string]$CoreDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (-not $CoreDirectory) {
    $CoreDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) "core"
}

$manifestPath = Join-Path $CoreDirectory "core-manifest.windows-x64.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Core manifest not found: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schema -ne 1 -or [string]$manifest.platform -ne "windows-x64") {
    throw "Unsupported core manifest: $manifestPath"
}

foreach ($file in $manifest.files) {
    $path = Join-Path $CoreDirectory ([string]$file.name)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing core file: $($file.name)"
    }
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedHash = ([string]$file.sha256).ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Core file hash mismatch for $($file.name): expected $expectedHash, got $actualHash"
    }
}

$singBoxSource = $manifest.sources | Where-Object { [string]$_.id -eq "sing-box-extended" } | Select-Object -First 1
if (-not $singBoxSource -or [string]$singBoxSource.version -notmatch "extended") {
    throw "Core manifest does not identify an extended sing-box build"
}
$singBoxPath = Join-Path $CoreDirectory "sing-box.exe"
$singBoxProcess = Start-Process -FilePath $singBoxPath -ArgumentList @("version") -NoNewWindow -Wait -PassThru
if ($singBoxProcess.ExitCode -ne 0) {
    throw "Bundled sing-box failed its version command with exit code $($singBoxProcess.ExitCode)"
}
$xrayPath = Join-Path $CoreDirectory "xray.exe"
$xrayProcess = Start-Process -FilePath $xrayPath -ArgumentList @("version") -NoNewWindow -Wait -PassThru
if ($xrayProcess.ExitCode -ne 0) {
    throw "Bundled Xray failed its version command with exit code $($xrayProcess.ExitCode)"
}

Write-Host "[core] verified $($manifest.files.Count) files"
Write-Host "[core] sing-box: $($singBoxSource.version)"
