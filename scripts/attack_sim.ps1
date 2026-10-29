<#
.SYNOPSIS
  Safe FIM-IPL attack simulator for Windows.
.DESCRIPTION
  Creates harmless marker-only files. It never executes commands, contacts a
  C2, or runs against a directory containing wp-config.php by default.
#>
param(
  [Parameter(Mandatory=$true)][string]$TargetDir,
  [switch]$Spread,
  [int]$Count = 20,
  [switch]$Symlink
)
$ErrorActionPreference = 'Stop'
if (Test-Path (Join-Path $TargetDir 'wp-config.php')) { throw 'Refusing a directory containing wp-config.php.' }
if ($Count -lt 1 -or $Count -gt 200) { throw '-Count must be between 1 and 200.' }
$victim = Join-Path $TargetDir 'wp-content\plugins\victim-plugin\functions.php'
$decoy = Join-Path $TargetDir 'wp-content\plugins\victim-plugin\readme.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $victim) | Out-Null
if (-not $Spread -and -not (Test-Path $victim)) {
  @('<?php','// clean victim file','function victim_hello() { return "hello"; }') | Set-Content $victim -Encoding Ascii
  'decoy used to test DELETED detection' | Set-Content $decoy -Encoding Ascii
  Write-Host "setup complete: $TargetDir"
  exit 0
}
@('<?php // harmless simulated webshell marker','echo "[SIM] created";') | Set-Content (Join-Path $TargetDir 'wp-admin-load.php') -Encoding Ascii
if ($Spread) {
  $dirs = @('wp-content\uploads\2026\01\cache','wp-content\uploads\2026\02\cache','wp-content\plugins\cache','wp-content\themes\victim\inc','wp-admin\includes\cache')
  $names = @('index.php','cache.php','avatar.php.jpg','.htaccess','db.php')
  for ($i=1; $i -le $Count; $i++) {
    $dir = Join-Path $TargetDir ($dirs[$i % $dirs.Count]); $dir = Join-Path $dir ('bundle-{0:D3}' -f $i)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir $names[$i % $names.Count]
    @("<?php // harmless spread marker $i", "echo `"[SIM] spread-$i`";") | Set-Content $file -Encoding Ascii
    if ($i % 2 -eq 0) { (Get-Item $file).LastWriteTime = Get-Date '2023-01-05 03:14:07' }
  }
  '# harmless simulated root rule marker' | Set-Content (Join-Path $TargetDir '.htaccess') -Encoding Ascii
  $unreadable = Join-Path $TargetDir 'wp-content\uploads\unreadable-backdoor.php'
  '<?php // harmless unreadable marker' | Set-Content $unreadable -Encoding Ascii
  (Get-Item $unreadable).IsReadOnly = $true
  Remove-Item $decoy -Force -ErrorAction SilentlyContinue
  if ($Symlink) {
    try { New-Item -ItemType SymbolicLink -Path (Join-Path $TargetDir 'wp-content\uploads\link-to-system') -Target 'C:\Windows\win.ini' | Out-Null } catch { Write-Warning 'Symlink unavailable; continuing.' }
  }
}
Write-Host 'simulation complete; wait for one scan cycle and verify the ledger'
