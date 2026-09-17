<#
.SYNOPSIS
  Construit le XPI de FireFTP pour Pale Moon (equivalent Windows de build.sh).

.DESCRIPTION
  - genere install.rdf et content/js/etc/globals.js a partir des fichiers .in
  - copie chrome.manifest.master vers chrome.manifest
  - cree dist/fireftp-<version>-palemoon.xpi avec des chemins en "/" (obligatoire :
    Compress-Archive de Windows PowerShell 5.1 ecrit des "\" et produit un XPI invalide)

  Compatible Windows PowerShell 5.1 et PowerShell 7+.

.EXAMPLE
  cd src
  .\build.ps1
  .\build.ps1 -Version 2.0.35 -MaxVersion "36.*"
#>
[CmdletBinding()]
param(
  [string]$Version    = "2.0.34",
  [string]$MinVersion = "29.0",
  [string]$MaxVersion = "35.*",
  [string]$OutDir     = (Join-Path $PSScriptRoot "..\dist")
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Expand-Template([string]$InFile, [string]$OutFile) {
  $text = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot $InFile), $utf8NoBom)
  $text = $text.Replace("__l10n__", "all").Replace("__VERSION__", $Version)
  $text = $text.Replace("__MINVERSION__", $MinVersion).Replace("__MAXVERSION__", $MaxVersion)
  [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot $OutFile), $text, $utf8NoBom)
}

# --- verifications ------------------------------------------------------------
$paramiko = Join-Path $PSScriptRoot "content\js\connection\paramikojs\transport.js"
if (-not (Test-Path -LiteralPath $paramiko)) {
  throw "paramikojs est absent (content\js\connection\paramikojs). Sans lui, pas de SFTP."
}

# --- fichiers generes -----------------------------------------------------------
Copy-Item -LiteralPath "chrome.manifest.master" -Destination "chrome.manifest" -Force
Expand-Template "install.rdf.in" "install.rdf"
Expand-Template "content\js\etc\globals.js.in" "content\js\etc\globals.js"

# --- liste des fichiers ---------------------------------------------------------
# Les locales empaquetees sont celles declarees dans chrome.manifest.master.
$locales = Get-Content -LiteralPath "chrome.manifest.master" |
  Where-Object { $_ -match '^\s*locale\s+' } |
  ForEach-Object { ($_ -split '\s+')[2] }

$excludeNames = @('.DS_Store', '.gitignore')
$excludeExt   = @('.in', '.swp')

function Test-Excluded([System.IO.FileInfo]$f) {
  if ($excludeNames -contains $f.Name) { return $true }
  if ($excludeExt -contains $f.Extension) { return $true }
  if ($f.FullName -match '[\\/](CVS|\.git)[\\/]') { return $true }
  return $false
}

# table : chemin dans le XPI -> fichier sur disque
$entries = [ordered]@{}
function Add-Tree([string]$dir) {
  $root = (Resolve-Path -LiteralPath $dir).Path
  Get-ChildItem -LiteralPath $root -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
    if (-not (Test-Excluded $_)) {
      $rel = $dir.TrimEnd('\', '/') + '/' + $_.FullName.Substring($root.Length).TrimStart('\', '/')
      $entries[$rel.Replace('\', '/')] = $_.FullName
    }
  }
}
function Add-File([string]$zipPath, [string]$diskPath) {
  $full = (Resolve-Path -LiteralPath $diskPath).Path
  $entries[$zipPath] = $full
}

Add-Tree "content"
foreach ($l in $locales) { Add-Tree ("locale/" + $l) }
Add-Tree "skin"
Add-File "chrome/icons/default/fireftp-main-window.ico" "icons\default\fireftp-main-window.ico"
Add-File "chrome/icons/default/fireftp-main-window.xpm" "icons\default\fireftp-main-window.xpm"
Add-File "components/nsIFireFTPUtils.xpt"  "components\nsIFireFTPUtils.xpt"
Add-File "components/nsIFireFTPUtils.js"   "components\nsIFireFTPUtils.js"
Add-File "components/fireftp-service.js"   "components\fireftp-service.js"
Add-File "defaults/preferences/fireftp.js" "defaults\preferences\fireftp.js"
Add-File "chrome.manifest" "chrome.manifest"
Add-File "install.rdf"     "install.rdf"
Add-File "license.txt"     "license.txt"

# --- creation du XPI ------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$xpi = Join-Path (Resolve-Path -LiteralPath $OutDir).Path ("fireftp-" + $Version + "-palemoon.xpi")
if (Test-Path -LiteralPath $xpi) { Remove-Item -LiteralPath $xpi -Force }

$zip = [System.IO.Compression.ZipFile]::Open($xpi, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  foreach ($k in $entries.Keys) {
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip, $entries[$k], $k, [System.IO.Compression.CompressionLevel]::Optimal)
  }
} finally {
  $zip.Dispose()
}

Write-Host ("OK : {0} ({1} fichiers, {2:N0} octets)" -f $xpi, $entries.Count, (Get-Item -LiteralPath $xpi).Length)
