# Scrape download lists for other OS codes; download any new packages not already fetched.
$ErrorActionPreference = "Stop"
$Root = "d:\code\mfc9330cdw"
$Downloads = Join-Path $Root "downloads"
$ResolvedExtra = Join-Path $Downloads "meta\resolved-urls-extra.json"
$ManifestExtra = Join-Path $Downloads "meta\download-manifest-extra.json"

$ua = @{
  "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
  "Referer" = "https://support.brother.com/"
}

$osMap = [ordered]@{
  "10068" = "Windows 11"
  "10013" = "Windows 10 (64-bit)"
  "10012" = "Windows 10 (32-bit)"
  "10075" = "Windows Server 2022"
  "10062" = "Windows Server 2019"
  "10033" = "Windows Server 2016"
  "127"   = "Linux (rpm)"
  "128"   = "Linux (deb)"
}

# Already-known dlids from Win11 catalog
$known = @{}
$cat = Get-Content (Join-Path $Downloads "meta\catalog.json") -Raw | ConvertFrom-Json
foreach ($s in $cat.software) { $known[$s.dlid] = $true }
# Also mark already-downloaded files by dlid prefix
Get-ChildItem -Path $Downloads -Recurse -File | ForEach-Object {
  if ($_.Name -match '^(dlf\d+_\d+)_') { $known[$Matches[1]] = $true }
}

function Get-SafeName([string]$name) {
  ($name -replace '[<>:"/\\|?*]', '_' -replace '\s+', '_').Trim('_')
}

$allItems = @()

foreach ($os in $osMap.Keys) {
  $url = "https://support.brother.com/g/b/downloadlist.aspx?c=us&lang=en&prod=mfc9330cdw_us_eu_as&os=$os"
  Write-Host "`n=== OS $os ($($osMap[$os])) ==="
  $resp = Invoke-WebRequest -Uri $url -Headers $ua -UseBasicParsing -TimeoutSec 60
  $htmlPath = Join-Path $Downloads "meta\downloadlist-os$os.html"
  $resp.Content | Out-File $htmlPath -Encoding utf8

  $matches = [regex]::Matches($resp.Content, 'href="/g/b/downloadend\.aspx\?([^"]+)"[^>]*>([^<]+)<')
  Write-Host "  found $($matches.Count) downloadend links"
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
      os = $os
      os_name = $osMap[$os]
      title = $title
      dlid = $dlid
      flang = $params["flang"]
      type3 = $params["type3"]
      query = $qs
      is_new = -not $known.ContainsKey($dlid)
    }
  }
  Start-Sleep -Milliseconds 400
}

$newItems = @($allItems | Where-Object { $_.is_new } | Sort-Object dlid -Unique)
Write-Host "`nUnique packages across OS: $((@($allItems | Select-Object -ExpandProperty dlid -Unique)).Count)"
Write-Host "New (not in Win11 set): $($newItems.Count)"
$allItems | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Downloads "meta\all-os-packages.json") -Encoding UTF8

$resolved = @()
$manifest = @()

foreach ($item in $newItems) {
  $howto = "https://support.brother.com/g/b/downloadhowto.aspx?c=us&lang=en&prod=mfc9330cdw_us_eu_as&os=$($item.os)&dlid=$($item.dlid)&flang=$($item.flang)&type3=$($item.type3)"
  Write-Host "resolve $($item.dlid) [$($item.os_name)] $($item.title)"
  try {
    $h = Invoke-WebRequest -Uri $howto -Headers $ua -UseBasicParsing -TimeoutSec 60
    $urlMatch = [regex]::Match($h.Content, 'https://download\.brother\.com/welcome/[^"''\s<>]+')
    $fileUrl = if ($urlMatch.Success) { $urlMatch.Value } else { $null }
  } catch {
    Write-Warning "howto failed: $_"
    $fileUrl = $null
  }
  $resolved += [ordered]@{
    title = $item.title; os = $item.os; os_name = $item.os_name
    dlid = $item.dlid; flang = $item.flang; type3 = $item.type3; url = $fileUrl
  }
  if ($fileUrl) {
    $leaf = Split-Path ([uri]$fileUrl).AbsolutePath -Leaf
    $subdir = if ($item.os -in @("127","128")) { "drivers\linux" } else { "drivers\other-os" }
    $dir = Join-Path $Downloads $subdir
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $out = Join-Path $dir "$(Get-SafeName $item.dlid)_os$($item.os)_$(Get-SafeName $item.title)_$leaf"
    if ((Test-Path $out) -and ((Get-Item $out).Length -gt 0)) {
      Write-Host "  skip exists"
      $manifest += @{ title=$item.title; url=$fileUrl; path=$out; status="exists"; dlid=$item.dlid; os=$item.os }
    } else {
      Write-Host "  GET $fileUrl"
      try {
        Invoke-WebRequest -Uri $fileUrl -Headers $ua -OutFile $out -UseBasicParsing -TimeoutSec 600
        $manifest += @{ title=$item.title; url=$fileUrl; path=$out; status="ok"; bytes=(Get-Item $out).Length; dlid=$item.dlid; os=$item.os }
        Write-Host "  saved $((Get-Item $out).Length) bytes"
      } catch {
        Write-Warning "download failed: $_"
        $manifest += @{ title=$item.title; url=$fileUrl; status="error"; error="$_"; dlid=$item.dlid; os=$item.os }
      }
    }
  } else {
    $manifest += @{ title=$item.title; status="unresolved"; dlid=$item.dlid; os=$item.os }
  }
  Start-Sleep -Milliseconds 350
}

$resolved | ConvertTo-Json -Depth 5 | Set-Content $ResolvedExtra -Encoding UTF8
$manifest | ConvertTo-Json -Depth 5 | Set-Content $ManifestExtra -Encoding UTF8
Write-Host "`nExtra resolve: $ResolvedExtra"
Write-Host "Extra manifest: $ManifestExtra"
