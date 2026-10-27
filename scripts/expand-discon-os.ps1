# Scrape discontinued-OS download lists (legacy Windows + macOS) and fetch new packages.
$ErrorActionPreference = "Stop"
$Root = "d:\code\mfc9330cdw"
$Downloads = Join-Path $Root "downloads"

$ua = @{
  "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
  "Referer" = "https://support.brother.com/"
}

$osMap = [ordered]@{
  "134" = "Windows 8.1 (32-bit)"
  "135" = "Windows 8.1 (64-bit)"
  "119" = "Windows 8 (32-bit)"
  "120" = "Windows 8 (64-bit)"
  "92"  = "Windows 7 (32-bit)"
  "93"  = "Windows 7 (64-bit)"
  "74"  = "Windows Vista (32-bit)"
  "84"  = "Windows Vista (64-bit)"
  "7"   = "Windows XP (32-bit)"
  "27"  = "Windows XP (64-bit)"
  "10060" = "macOS 10.15.x"
  "10052" = "macOS 10.14.x"
  "10045" = "macOS 10.13.x"
  "10030" = "macOS 10.12.x"
  "10018" = "OS X 10.11"
  "10006" = "OS X 10.10"
  "132" = "OS X 10.9"
  "115" = "OS X 10.8"
  "108" = "Mac OS X 10.7"
  "94"  = "Mac OS X 10.6"
}

$known = @{}
Get-ChildItem -Path $Downloads -Recurse -File | ForEach-Object {
  if ($_.Name -match '^(dlf\d+_\d+)_') { $known[$Matches[1]] = $true }
}
# also from all-os-packages
$allOsPath = Join-Path $Downloads "meta\all-os-packages.json"
if (Test-Path $allOsPath) {
  $prev = Get-Content $allOsPath -Raw | ConvertFrom-Json
  foreach ($p in $prev) { if ($p.dlid) { $known[$p.dlid] = $true } }
}

function Get-SafeName([string]$name) {
  ($name -replace '[<>:"/\\|?*]', '_' -replace '\s+', '_').Trim('_')
}

$allItems = @()
foreach ($os in $osMap.Keys) {
  $url = "https://support.brother.com/g/b/downloadlistdiscon.aspx?c=us&lang=en&prod=mfc9330cdw_us_eu_as&os=$os"
  Write-Host "`n=== DISCON OS $os ($($osMap[$os])) ==="
  try {
    $resp = Invoke-WebRequest -Uri $url -Headers $ua -UseBasicParsing -TimeoutSec 60
  } catch {
    Write-Warning "list failed: $_"
    continue
  }
  $resp.Content | Out-File (Join-Path $Downloads "meta\downloadlistdiscon-os$os.html") -Encoding utf8
  $matches = [regex]::Matches($resp.Content, 'href="/g/b/downloadend\.aspx\?([^"]+)"[^>]*>([^<]+)<')
  Write-Host "  found $($matches.Count) links"
  foreach ($m in $matches) {
    $qs = $m.Groups[1].Value
    $title = ($m.Groups[2].Value -replace '\s+', ' ').Trim()
    $params = @{}
    foreach ($pair in ($qs -split '&')) {
      $kv = $pair -split '=', 2
      if ($kv.Count -eq 2) { $params[$kv[0]] = [uri]::UnescapeDataString($kv[1]) }
    }
    $dlid = $params["dlid"]
    if (-not $dlid) { continue }
    $allItems += [pscustomobject]@{
      os = $os; os_name = $osMap[$os]; title = $title; dlid = $dlid
      flang = $params["flang"]; type3 = $params["type3"]
      is_new = -not $known.ContainsKey($dlid)
    }
  }
  Start-Sleep -Milliseconds 350
}

$newItems = @($allItems | Where-Object { $_.is_new } | Sort-Object dlid -Unique)
Write-Host "`nDiscon unique dlids: $((@($allItems | Select-Object -ExpandProperty dlid -Unique)).Count)"
Write-Host "New vs prior: $($newItems.Count)"
$allItems | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Downloads "meta\discon-os-packages.json") -Encoding UTF8

$resolved = @(); $manifest = @()
foreach ($item in $newItems) {
  # howto URL works with same params on current site; discon pages still use downloadend/howto
  $howto = "https://support.brother.com/g/b/downloadhowto.aspx?c=us&lang=en&prod=mfc9330cdw_us_eu_as&os=$($item.os)&dlid=$($item.dlid)&flang=$($item.flang)&type3=$($item.type3)"
  Write-Host "resolve $($item.dlid) [$($item.os_name)] $($item.title)"
  try {
    $h = Invoke-WebRequest -Uri $howto -Headers $ua -UseBasicParsing -TimeoutSec 60
    $urlMatch = [regex]::Match($h.Content, 'https://download\.brother\.com/welcome/[^"''\s<>]+')
    $fileUrl = if ($urlMatch.Success) { $urlMatch.Value } else { $null }
  } catch {
    Write-Warning "howto failed: $_"; $fileUrl = $null
  }
  $resolved += [ordered]@{ title=$item.title; os=$item.os; os_name=$item.os_name; dlid=$item.dlid; url=$fileUrl }
  if (-not $fileUrl) {
    $manifest += @{ title=$item.title; status="unresolved"; dlid=$item.dlid; os=$item.os }
    continue
  }
  $leaf = Split-Path ([uri]$fileUrl).AbsolutePath -Leaf
  $family = if ($item.os_name -match 'mac|OS X') { "drivers\macos" } else { "drivers\legacy-windows" }
  $dir = Join-Path $Downloads $family
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $out = Join-Path $dir "$(Get-SafeName $item.dlid)_os$($item.os)_$(Get-SafeName $item.title)_$leaf"
  if ((Test-Path $out) -and ((Get-Item $out).Length -gt 0)) {
    $manifest += @{ title=$item.title; url=$fileUrl; path=$out; status="exists"; dlid=$item.dlid; os=$item.os }
    Write-Host "  skip exists"
  } else {
    Write-Host "  GET $fileUrl"
    try {
      Invoke-WebRequest -Uri $fileUrl -Headers $ua -OutFile $out -UseBasicParsing -TimeoutSec 600
      $manifest += @{ title=$item.title; url=$fileUrl; path=$out; status="ok"; bytes=(Get-Item $out).Length; dlid=$item.dlid; os=$item.os }
      Write-Host "  saved $((Get-Item $out).Length)"
    } catch {
      Write-Warning "dl failed: $_"
      $manifest += @{ title=$item.title; url=$fileUrl; status="error"; error="$_"; dlid=$item.dlid; os=$item.os }
    }
  }
  Start-Sleep -Milliseconds 300
}

$resolved | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Downloads "meta\resolved-urls-discon.json") -Encoding UTF8
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Downloads "meta\download-manifest-discon.json") -Encoding UTF8
$ok = @($manifest | Where-Object { $_.status -in @("ok","exists") }).Count
$err = @($manifest | Where-Object { $_.status -in @("error","unresolved") }).Count
Write-Host "`nDiscon OK/exists: $ok  errors: $err"
