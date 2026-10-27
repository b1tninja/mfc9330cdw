# Download all Brother MFC-9330CDW support artifacts catalogued from the HAR.
$ErrorActionPreference = "Stop"
$Root = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { "d:\code\mfc9330cdw" }
$CatalogPath = Join-Path $Root "downloads\meta\catalog.json"
$Downloads = Join-Path $Root "downloads"
$ResolvedPath = Join-Path $Downloads "meta\resolved-urls.json"
$ManifestPath = Join-Path $Downloads "meta\download-manifest.json"

$catalog = Get-Content $CatalogPath -Raw | ConvertFrom-Json
$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
$headers = @{
  "User-Agent" = $ua
  "Referer" = "https://support.brother.com/"
  "Accept-Language" = "en-US,en;q=0.9"
}

function Get-SafeName([string]$name) {
  ($name -replace '[<>:"/\\|?*]', '_' -replace '\s+', '_').Trim('_')
}

function Ensure-Dir([string]$path) {
  if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }
}

function Resolve-SoftwareUrl($item) {
  if ($item.known_url) { return [string]$item.known_url }
  $howto = "https://support.brother.com/g/b/downloadhowto.aspx?c=us&lang=en&prod=mfc9330cdw_us_eu_as&os=10068&dlid=$($item.dlid)&flang=$($item.flang)&type3=$($item.type3)"
  Write-Host "  resolve $($item.dlid) ..."
  try {
    $resp = Invoke-WebRequest -Uri $howto -Headers $headers -UseBasicParsing -TimeoutSec 60
  } catch {
    Write-Warning "howto failed for $($item.dlid): $_"
    return $null
  }
  $m = [regex]::Match($resp.Content, 'https://download\.brother\.com/welcome/[^"''\s<>]+')
  if ($m.Success) { return $m.Value }
  Write-Warning "no download URL in howto for $($item.dlid)"
  return $null
}

function Save-Url([string]$url, [string]$outPath) {
  Ensure-Dir (Split-Path $outPath -Parent)
  if ((Test-Path $outPath) -and ((Get-Item $outPath).Length -gt 0)) {
    Write-Host "  skip (exists): $(Split-Path $outPath -Leaf)"
    return @{ url = $url; path = $outPath; status = "exists"; bytes = (Get-Item $outPath).Length }
  }
  Write-Host "  GET $url"
  try {
    Invoke-WebRequest -Uri $url -Headers $headers -OutFile $outPath -UseBasicParsing -TimeoutSec 600
    $len = (Get-Item $outPath).Length
    Write-Host "  saved $len bytes -> $(Split-Path $outPath -Leaf)"
    return @{ url = $url; path = $outPath; status = "ok"; bytes = $len }
  } catch {
    Write-Warning "download failed: $url :: $_"
    return @{ url = $url; path = $outPath; status = "error"; error = "$_" }
  }
}

$categoryDir = @{
  full_package = "drivers"
  drivers = "drivers"
  firmware = "firmware"
  utilities = "utilities"
  management = "management"
}

$resolved = @()
$manifest = @()

Write-Host "=== Resolving software download URLs ==="
foreach ($item in $catalog.software) {
  $url = Resolve-SoftwareUrl $item
  $entry = [ordered]@{
    title = $item.title
    category = $item.category
    dlid = $item.dlid
    version = $item.version
    date = $item.date
    url = $url
  }
  $resolved += $entry
  Start-Sleep -Milliseconds 400
}
$resolved | ConvertTo-Json -Depth 5 | Set-Content -Path $ResolvedPath -Encoding UTF8
Write-Host "Wrote $ResolvedPath"

Write-Host "`n=== Downloading software ==="
foreach ($entry in $resolved) {
  if (-not $entry.url) {
    $manifest += @{ title = $entry.title; status = "unresolved"; dlid = $entry.dlid }
    continue
  }
  $subdir = $categoryDir[$entry.category]
  if (-not $subdir) { $subdir = "drivers" }
  $leaf = Split-Path ([uri]$entry.url).AbsolutePath -Leaf
  $safe = "$(Get-SafeName $entry.dlid)_$(Get-SafeName $entry.title)_$leaf"
  $out = Join-Path (Join-Path $Downloads $subdir) $safe
  $result = Save-Url $entry.url $out
  $manifest += ($result + @{ title = $entry.title; category = $entry.category; dlid = $entry.dlid })
  Start-Sleep -Milliseconds 300
}

Write-Host "`n=== Downloading manuals (PDFs) ==="
Ensure-Dir (Join-Path $Downloads "manuals")
foreach ($m in $catalog.manuals) {
  if ($m.url -notmatch '\.pdf($|\?)') {
    $manifest += @{ title = $m.title; url = $m.url; status = "skipped_html"; note = $m.note }
    continue
  }
  $leaf = Split-Path ([uri]$m.url).AbsolutePath -Leaf
  $out = Join-Path (Join-Path $Downloads "manuals") "$(Get-SafeName $m.title)_$leaf"
  $result = Save-Url $m.url $out
  $manifest += ($result + @{ title = $m.title; category = "manuals" })
  Start-Sleep -Milliseconds 250
}

$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $ManifestPath -Encoding UTF8
Write-Host "`nDone. Manifest: $ManifestPath"
$ok = @($manifest | Where-Object { $_.status -eq "ok" -or $_.status -eq "exists" }).Count
$err = @($manifest | Where-Object { $_.status -eq "error" -or $_.status -eq "unresolved" }).Count
Write-Host "OK/exists: $ok  errors/unresolved: $err"
