[CmdletBinding()]
param(
    [string]$LockFile = "",
    [string]$OutputArchive = "",
    [string]$DownloadCache = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $LockFile) {
    $LockFile = Join-Path $PSScriptRoot "core-lock.windows-x64.json"
}
if (-not $OutputArchive) {
    $OutputArchive = Join-Path $repoRoot ".cache/core-bundle/core-windows-x64.7z"
}
if (-not $DownloadCache) {
    $DownloadCache = Join-Path $repoRoot ".cache/core-downloads"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VerifiedArchive($Source, [string]$CacheDirectory) {
    $archivePath = Join-Path $CacheDirectory ([string]$Source.archive)
    $expectedHash = ([string]$Source.sha256).ToLowerInvariant()
    if (Test-Path -LiteralPath $archivePath) {
        if ((Get-Sha256 $archivePath) -eq $expectedHash) {
            Write-Host "[core] cache hit: $($Source.id) $($Source.version)"
            return $archivePath
        }
        Remove-Item -LiteralPath $archivePath -Force
    }

    Write-Host "[core] downloading $($Source.id) $($Source.version)"
    $partialPath = "$archivePath.partial"
    Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
    try {
        $curlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue
        $sourceUrls = @()
        if ($Source.PSObject.Properties.Name -contains "urls") {
            $sourceUrls = @($Source.urls | ForEach-Object { [string]$_ })
        }
        if ($sourceUrls.Count -eq 0) {
            $sourceUrls = @([string]$Source.url)
        }
        $downloaded = $false
        $lastDownloadError = $null
        foreach ($sourceUrl in $sourceUrls) {
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                try {
                    if ($curlCommand) {
                        $curlArguments = @(
                            "--fail", "--location",
                            "--connect-timeout", "30",
                            "--max-time", "120",
                            "--output", $partialPath,
                            $sourceUrl
                        )
                        $curlProcess = Start-Process -FilePath $curlCommand.Source -ArgumentList $curlArguments `
                            -NoNewWindow -Wait -PassThru
                        if ($curlProcess.ExitCode -ne 0) {
                            throw "curl.exe failed with exit code $($curlProcess.ExitCode)"
                        }
                    }
                    else {
                        Invoke-WebRequest -UseBasicParsing -TimeoutSec 120 -Uri $sourceUrl -OutFile $partialPath
                    }
                    $downloaded = $true
                    break
                }
                catch {
                    $lastDownloadError = $_
                    Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
                    Write-Host "[core] download retry $attempt/2 for $($Source.id) from $sourceUrl"
                    Start-Sleep -Seconds 2
                }
            }
            if ($downloaded) {
                break
            }
        }
        if (-not $downloaded) {
            throw $lastDownloadError
        }
        $actualHash = Get-Sha256 $partialPath
        if ($actualHash -ne $expectedHash) {
            throw "SHA-256 mismatch for $($Source.archive): expected $expectedHash, got $actualHash"
        }
        Move-Item -LiteralPath $partialPath -Destination $archivePath -Force
    }
    finally {
        Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
    }
    return $archivePath
}

$lock = Get-Content -LiteralPath $LockFile -Raw | ConvertFrom-Json
if ([int]$lock.schema -ne 1 -or [string]$lock.platform -ne "windows-x64") {
    throw "Unsupported core lock format: $LockFile"
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
    throw "7z is required to create the core bundle"
}

New-Item -ItemType Directory -Force -Path $DownloadCache | Out-Null
$outputDirectory = Split-Path -Parent $OutputArchive
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ZapretKVN-core-" + [guid]::NewGuid().ToString("N"))
$stagingDirectory = Join-Path $temporaryRoot "core"
New-Item -ItemType Directory -Force -Path $stagingDirectory | Out-Null
$manifestFiles = @()

try {
    foreach ($source in $lock.sources) {
        $archivePath = Get-VerifiedArchive $source $DownloadCache
        $extractDirectory = Join-Path $temporaryRoot ([string]$source.id)
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force

        foreach ($mapping in $source.files) {
            $pattern = [string]$mapping.match
            $extractPrefix = $extractDirectory.TrimEnd("\") + "\"
            $matches = @(
                Get-ChildItem -LiteralPath $extractDirectory -Recurse -File | Where-Object {
                    $relative = $_.FullName.Substring($extractPrefix.Length).Replace("\", "/")
                    $relative -match $pattern
                }
            )
            if ($matches.Count -ne 1) {
                throw "Expected exactly one '$pattern' in $($source.archive), found $($matches.Count)"
            }

            $targetName = [string]$mapping.target
            $targetPath = Join-Path $stagingDirectory $targetName
            Copy-Item -LiteralPath $matches[0].FullName -Destination $targetPath -Force
            $manifestFiles += [ordered]@{
                name = $targetName
                source = [string]$source.id
                version = [string]$source.version
                sha256 = Get-Sha256 $targetPath
            }
        }
    }

    $manifest = [ordered]@{
        schema = 1
        platform = "windows-x64"
        generated_at_utc = [DateTime]::UtcNow.ToString("o")
        lock_sha256 = Get-Sha256 $LockFile
        sources = $lock.sources | ForEach-Object {
            [ordered]@{
                id = [string]$_.id
                version = [string]$_.version
                archive_sha256 = [string]$_.sha256
                url = [string]$_.url
            }
        }
        files = $manifestFiles
    }
    $manifestPath = Join-Path $stagingDirectory "core-manifest.windows-x64.json"
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    Remove-Item -LiteralPath $OutputArchive -Force -ErrorAction SilentlyContinue
    $sevenZipArguments = @(
        "a", "-t7z", "-mx=7", "-y",
        $OutputArchive,
        (Join-Path $stagingDirectory "*")
    )
    $sevenZipProcess = Start-Process -FilePath $sevenZipPath -ArgumentList $sevenZipArguments `
        -NoNewWindow -Wait -PassThru
    if ($sevenZipProcess.ExitCode -ne 0) {
        throw "7z failed with exit code $($sevenZipProcess.ExitCode)"
    }
    Write-Host "[core] bundle ready: $OutputArchive"
    Write-Host "[core] SHA-256: $(Get-Sha256 $OutputArchive)"
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
