# Headless smoke-test for Brother_DJF.bt via 010 Editor CLI.
# Requires 010 Editor on PATH or at the default install location.
# Docs: https://www.sweetscape.com/010editor/manual/CommandLine.htm
#
# Usage:
#   .\test_bt.ps1
#   .\test_bt.ps1 -Djf ..\..\downloads\firmware\blobs\LZ4266_ZC_1.djf

param(
    [string]$Djf = (Join-Path $PSScriptRoot "..\..\downloads\firmware\blobs\LZ4279_R.djf"),
    [string]$Template = (Join-Path $PSScriptRoot "Brother_DJF.bt")
)

$ErrorActionPreference = "Stop"

$exe = $null
foreach ($c in @(
    (Get-Command 010editor -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "C:\Program Files\010 Editor\010Editor.exe",
    "C:\Program Files (x86)\010 Editor\010Editor.exe"
)) {
    if ($c -and (Test-Path -LiteralPath $c)) { $exe = $c; break }
}
if (-not $exe) { throw "010 Editor not found (010editor / default install path)" }

$Djf = (Resolve-Path -LiteralPath $Djf).Path
$Template = (Resolve-Path -LiteralPath $Template).Path
$btDir = Split-Path -Parent $Template
$btName = Split-Path -Leaf $Template

Write-Host "010:      $exe"
Write-Host "template: $Template"
Write-Host "file:     $Djf"

# -template: resolves relative to cwd or the configured Templates directory.
# -noui / -nowarnings: no UI, no blocking dialogs
# -exitnoerrors: exit only if template compiled and ran cleanly
$p = Start-Process -FilePath $exe `
    -ArgumentList @("`"$Djf`"", "-template:$btName", "-noui", "-nowarnings", "-exitnoerrors") `
    -WorkingDirectory $btDir `
    -PassThru -Wait -NoNewWindow

Write-Host "exit code: $($p.ExitCode)"
if ($p.ExitCode -ne 0) {
    Write-Error "Template failed (non-zero exit). Fix Brother_DJF.bt and re-run."
    exit $p.ExitCode
}
Write-Host "OK"
exit 0
