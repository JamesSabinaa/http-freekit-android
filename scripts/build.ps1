param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Transport peer dependency installation failed' }
    & ./gradlew.bat :core-protocol:test :app:testDebugUnitTest :core-security:testDebugUnitTest :core-security:assembleDebugAndroidTest :core-security:lintDebug :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug --console=plain
    if ($LASTEXITCODE -ne 0) { throw 'Android validation failed' }
    $outputDir = Join-Path $repoRoot 'dist'
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    $apkName = 'http-freekit-android-debug.apk'
    $apkPath = Join-Path $outputDir $apkName
    Copy-Item -LiteralPath (Join-Path $repoRoot 'app/build/outputs/apk/debug/app-debug.apk') -Destination $apkPath -Force
    $digest = (Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $outputDir "$apkName.sha256"), "$digest  $apkName`n")
    $sourceCommit = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot determine source commit' }
    $sourceStatus = git status --porcelain
    if ($LASTEXITCODE -ne 0) { throw 'Cannot determine source state' }
    $metadata = [ordered]@{
        artifact = $apkName
        sha256 = $digest
        version = '0.1.0-dev-debug'
        sourceCommit = $sourceCommit
        sourceDirty = [bool]$sourceStatus
        protocol = 'v1-draft-not-integrated'
        compatibleDesktopCommit = $null
        captureImplemented = $false
        signing = 'local Android debug key; not a release identity'
    } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $outputDir 'http-freekit-android-debug-metadata.json'), $metadata + "`n")
    Write-Output "Validated and exported $apkPath"
} finally {
    Pop-Location
}
