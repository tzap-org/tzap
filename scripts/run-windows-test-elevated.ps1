param(
    [Parameter(Mandatory = $true)]
    [string]$TestFilter,
    [string]$TestRoot = '',
    [string]$LogPath = ''
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repository

if ($TestRoot) {
    $env:TZAP_WINDOWS_TEST_ROOT = $TestRoot
} else {
    Remove-Item Env:TZAP_WINDOWS_TEST_ROOT -ErrorAction SilentlyContinue
}
if (-not $LogPath) {
    $LogPath = Join-Path $repository 'target\windows-elevated-test.log'
}

$ErrorActionPreference = 'Continue'
& cargo test -p tzap --bin tzap $TestFilter -- --exact --nocapture 2>&1 |
    Tee-Object -FilePath $LogPath
$testExitCode = $LASTEXITCODE
exit $testExitCode
