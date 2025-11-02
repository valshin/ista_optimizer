<# 
ISTA-VM-Toolkit.ps1 - Single script to APPLY or REVERT BMW ISTA VM optimizations
Ultra-compatible: no 'param' / 'CmdletBinding' - manual $args parsing only.

USAGE (Run as Administrator):
  .\ISTA-VM-Toolkit.ps1 -help
  # Apply everything
  .\ISTA-VM-Toolkit.ps1 -all
  # Revert everything (uses latest backup CSV if present)
  .\ISTA-VM-Toolkit.ps1 -all -revert

  # Granular apply:
  .\ISTA-VM-Toolkit.ps1 -services
  .\ISTA-VM-Toolkit.ps1 -ui
  .\ISTA-VM-Toolkit.ps1 -defenderhard
  .\ISTA-VM-Toolkit.ps1 -removestore
  .\ISTA-VM-Toolkit.ps1 -autologin "PC\user" "password"
  .\ISTA-VM-Toolkit.ps1 -noautologin

  # Granular revert:
  .\ISTA-VM-Toolkit.ps1 -services -revert [-frombackup "C:\_VMOptimize\service-backup-*.csv"]
  .\ISTA-VM-Toolkit.ps1 -ui -revert
  .\ISTA-VM-Toolkit.ps1 -defenderhard -revert
  .\ISTA-VM-Toolkit.ps1 -removestore -revert

OPTIONS:
  -backupdir PATH   Where to store/read backups & logs (default C:\_VMOptimize)
  -frombackup CSV   Use a specific CSV for service restoration (revert mode)
  -reportonly       Dry-run (log what would be done)
  -norestart        Suppress restart prompts (informational only)
#>

$ErrorActionPreference = 'Continue'

# -------------------- manual argument parsing --------------------
$BackupDir = "C:\_VMOptimize"
$FromBackup = $null
$ReportOnly=$false; $NoRestart=$false; $Revert=$false
$DoAll=$false; $DoServices=$false; $DoUI=$false; $DoDefender=$false; $DoRemoveStore=$false
$AutoLoginUser=$null; $AutoLoginPass=$null; $RemoveAutoLogin=$false; $ShowHelp=$false

for ($i=0; $i -lt $args.Count; $i++) {
  $a = [string]$args[$i]
  if ([string]::IsNullOrWhiteSpace($a)) { continue }
  switch -regex ($a.ToLower()) {
    '^-help$'         { $ShowHelp=$true; continue }
    '^-all$'          { $DoAll=$true; continue }
    '^-services$'     { $DoServices=$true; continue }
    '^-ui$'           { $DoUI=$true; continue }
    '^-defenderhard$' { $DoDefender=$true; continue }
    '^-removestore$'  { $DoRemoveStore=$true; continue }
    '^-revert$'       { $Revert=$true; continue }
    '^-autologin$'    { if ($i+2 -lt $args.Count) { $AutoLoginUser=[string]$args[$i+1]; $AutoLoginPass=[string]$args[$i+2]; $i+=2 } ; continue }
    '^-noautologin$'  { $RemoveAutoLogin=$true; continue }
    '^-backupdir$'    { if ($i+1 -lt $args.Count) { $BackupDir=[string]$args[$i+1]; $i++ } ; continue }
    '^-frombackup$'   { if ($i+1 -lt $args.Count) { $FromBackup=[string]$args[$i+1]; $i++ } ; continue }
    '^-reportonly$'   { $ReportOnly=$true; continue }
    '^-norestart$'    { $NoRestart=$true; continue }
    '^[A-Za-z]:\\'    { $BackupDir=$a; continue } # positional backup dir
    default { }
  }
}

if ($ShowHelp -or (-not $DoAll -and -not $DoServices -and -not $DoUI -and -not $DoDefender -and -not $DoRemoveStore -and -not $AutoLoginUser -and -not $RemoveAutoLogin)) {
  Write-Host "ISTA-VM-Toolkit.ps1 - Help" -ForegroundColor Cyan
  Write-Host "  -all | -services | -ui | -defenderhard | -removestore | -autologin u p | -noautologin | -revert | -frombackup csv | -backupdir path | -reportonly | -norestart"
  Write-Host "  Examples:"
  Write-Host "    .\ISTA-VM-Toolkit.ps1 -all"
  Write-Host "    .\ISTA-VM-Toolkit.ps1 -all -revert"
  Write-Host "    .\ISTA-VM-Toolkit.ps1 -services -revert -frombackup \"C:\_VMOptimize\service-backup-*.csv\""
  exit 0
}

# -------------------- helpers --------------------
function Require-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run PowerShell as Administrator."
    exit 1
  }
}
function Write-Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Report($m){ if($ReportOnly){ Write-Host "[dry-run] $m" } else { Write-Host "$m" } }
function Do-Or-Report([ScriptBlock]$action,[string]$msg){ if($ReportOnly){ Write-Host "[dry-run] $msg" } else { & $action } }
function Ensure-Dir($path){ if ($ReportOnly) { Write-Host "[dry-run] mkdir $path" } else { New-Item -ItemType Directory -Force -Path $path | Out-Null } }

Require-Admin
if ([string]::IsNullOrWhiteSpace($BackupDir)) { $BackupDir="C:\_VMOptimize" }

Ensure-Dir $BackupDir
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupCsv = Join-Path $BackupDir ("service-backup-{0}.csv" -f $stamp)
$logPath   = Join-Path $BackupDir ("ista-vm-toolkit-{0}.txt" -f $stamp)

if (-not $ReportOnly) { Start-Transcript -Path $logPath -Force | Out-Null }
Write-Step ("Backup dir: {0}" -f $BackupDir)

# Backup services only when applying (not when reverting)
if (-not $Revert) {
  try {
    if (-not $ReportOnly) {
      Get-CimInstance Win32_Service | Select-Object Name,DisplayName,StartMode | Export-Csv -NoTypeInformation -Path $backupCsv
      Write-Host ("Service backup: {0}" -f $backupCsv)
    } else {
      Write-Host "[dry-run] Export service start modes -> $backupCsv"
    }
  } catch { Write-Warning "Service backup failed: $($_.Exception.Message)" }
}

# -------------------- targets & defaults --------------------
$Keep = @(
  "Dhcp","NlaSvc","Netman","Dnscache","nsi",
  "LanmanWorkstation","PlugPlay","RpcSs","DcomLaunch","RpcEptMapper","Winmgmt",
  "EventLog","W32Time","WlanSvc","Tcpip","lmhosts"
)

$DisableTargets = @(
  "SysMain","WSearch","DiagTrack","dmwappushservice","DoSvc","RetailDemo",
  "WMPNetworkSvc","XblAuthManager","XblGameSave","XboxGipSvc","XboxNetApiSvc",
  "Fax","MapsBroker","RemoteRegistry","WbioSrvc","seclogon","lfsvc","WiaRpc",
  "SharedAccess","icssvc","PhoneSvc","WalletService","SmsRouter","TabletInputService","FrameServer",
  "SSDPSRV","upnphost","WebClient","diagnosticshub.standardcollector.service","PimIndexMaintenanceSvc"
)
$ManualTargets = @("BITS","WerSvc","Themes","SCardSvr","TermService","TrkWks","SENS","SensorService","LanmanServer")

# -------------------- functional blocks --------------------
function Resolve-Names([string[]]$names){
  $r=@()
  foreach($n in $names){
    $r += (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $n -or $_.Name -like "$n*" } | Select-Object -ExpandProperty Name)
  }
  $r | Sort-Object -Unique
}
function Set-StartMode([string]$name,[string]$mode){
  try {
    switch($mode){
      "Disabled" { Set-Service -Name $name -StartupType Disabled -ErrorAction Continue }
      "Manual"   { Set-Service -Name $name -StartupType Manual -ErrorAction Continue }
      "Auto"     { Set-Service -Name $name -StartupType Automatic -ErrorAction Continue }
      default    { Set-Service -Name $name -StartupType Manual -ErrorAction Continue }
    }
  } catch { Write-Warning ("Set {0} -> {1} failed: {2}" -f $name,$mode,$_.Exception.Message) }
}

function Disable-DoSvcHard {
  Write-Step "Hardening Delivery Optimization (DoSvc)"
  if (-not $ReportOnly) {
    try { sc.exe stop DoSvc   | Out-Null } catch {}
    try { sc.exe config DoSvc start= disabled | Out-Null } catch {}
  } else { Write-Host "[dry-run] stop DoSvc; config DoSvc start= disabled" }
  try {
    if (-not $ReportOnly) {
      $tasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\DeliveryOptimization\" -ErrorAction SilentlyContinue
      if ($tasks) { $tasks | Disable-ScheduledTask | Out-Null }
    } else {
      Write-Host "[dry-run] Disable tasks under \Microsoft\Windows\DeliveryOptimization\"
    }
  } catch { Write-Warning "DoSvc scheduled task disable failed: $($_.Exception.Message)" }
  try {
    if (-not $ReportOnly) {
      reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f | Out-Null
    } else { Write-Host "[dry-run] Set DODownloadMode=0 policy" }
  } catch { Write-Warning "DoSvc policy edit failed: $($_.Exception.Message)" }
}

function Force-Disable-PimIndex {
  $svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "PimIndexMaintenanceSvc*" }
  foreach($s in $svcs){
    try {
      $key = ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $s.Name)
      if (Test-Path $key) {
        if (-not $ReportOnly) {
          New-ItemProperty -Path $key -Name "Start" -PropertyType DWord -Value 4 -Force | Out-Null
          Try { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue } Catch {}
        }
        Write-Host ("Forced Disabled (reg): {0}" -f $s.Name)
      }
    } catch { Write-Warning ("Failed to force-disable {0}: {1}" -f $s.Name, $_.Exception.Message) }
  }
}

function Do-Services {
  Write-Step "Stopping & Disabling non-essential services"
  $disableResolved = (Resolve-Names $DisableTargets) | Where-Object { $Keep -notcontains $_ }
  foreach($svc in $disableResolved){
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue){
      if (-not $ReportOnly) { Try{ Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } Catch {} }
      Set-StartMode $svc "Disabled"
      if ($svc -eq "DoSvc") { Disable-DoSvcHard }
      if ($svc -like "PimIndexMaintenanceSvc*") { Force-Disable-PimIndex }
      Write-Host ("Disabled: {0}" -f $svc)
    }
  }
  Write-Step "Setting some services to Manual (on-demand)"
  $manualResolved = (Resolve-Names $ManualTargets) | Where-Object { $Keep -notcontains $_ }
  foreach($svc in $manualResolved){
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue){
      Set-StartMode $svc "Manual"
      Write-Host ("Manual: {0}" -f $svc)
    }
  }
}

function Undo-Services {
  Write-Step "Restoring services"
  # Choose CSV if present
  $csvPath = $FromBackup
  if ([string]::IsNullOrWhiteSpace($csvPath)) {
    $latest = Get-ChildItem -Path $BackupDir -Filter "service-backup-*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) { $csvPath = $latest.FullName }
  }
  if ($csvPath -and (Test-Path $csvPath)) {
    Write-Host ("Using backup CSV: {0}" -f $csvPath)
    Import-Csv -Path $csvPath | ForEach-Object {
      try {
        $n = $_."Name"; $mode = $_."StartMode"
        if ([string]::IsNullOrWhiteSpace($n) -or [string]::IsNullOrWhiteSpace($mode)) { return }
        switch($mode){
          "Auto" { Set-Service -Name $n -StartupType Automatic -ErrorAction Continue }
          "Automatic" { Set-Service -Name $n -StartupType Automatic -ErrorAction Continue }
          "Auto Delayed Start" { 
            Set-Service -Name $n -StartupType Automatic -ErrorAction Continue
            $k="HKLM:\SYSTEM\CurrentControlSet\Services\${n}"
            if(Test-Path $k){ New-ItemProperty -Path $k -Name "DelayedAutoStart" -Value 1 -PropertyType DWord -Force | Out-Null }
          }
          "Manual" { Set-Service -Name $n -StartupType Manual -ErrorAction Continue }
          "Disabled" { Set-Service -Name $n -StartupType Disabled -ErrorAction Continue }
          default { Set-Service -Name $n -StartupType Manual -ErrorAction Continue }
        }
        Write-Host "Restored: $n -> $mode"
      } catch { Write-Warning "Restore failed for $($_.Name): $($_.Exception.Message)" }
    }
  } else {
    Write-Warning "No backup CSV found. Setting safe defaults: previously-disabled targets -> Manual."
    foreach($svc in (Resolve-Names $DisableTargets)){
      if (Get-Service -Name $svc -ErrorAction SilentlyContinue){
        Set-StartMode $svc "Manual"
        Write-Host ("Manual: {0}" -f $svc)
      }
    }
    foreach($svc in (Resolve-Names $ManualTargets)){
      if (Get-Service -Name $svc -ErrorAction SilentlyContinue){
        Set-StartMode $svc "Manual"
        Write-Host ("Manual: {0}" -f $svc)
      }
    }
  }
}

function Do-UI {
  Write-Step "UI tweaks: best performance & policies"
  if (-not $ReportOnly) {
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\DWM" /v Composition /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f | Out-Null
    reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f | Out-Null
  } else {
    Write-Host "[dry-run] Apply UI/Policy tweaks (visuals, background apps, tips, first-logon off, lock screen off)"
  }
  Write-Step "Disable indexing on C:"
  try {
    if (-not $ReportOnly) {
      $vol = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='C:'" -ErrorAction SilentlyContinue
      if ($vol -and $null -ne $vol.IndexingEnabled) {
        $vol.IndexingEnabled = $false
        $vol | Set-CimInstance -ErrorAction SilentlyContinue | Out-Null
      }
    } else { Write-Host "[dry-run] Disable indexing via CIM on C:" }
  } catch { Write-Warning "Indexing disable failed: $($_.Exception.Message)" }
  Write-Step "Set power scheme to High performance (if available)"
  if (-not $ReportOnly) {
    $high = (powercfg -L) 2>$null | Select-String -Pattern "High performance|High Performance"
    if ($high) { $guid = ($high -split '\s+')[3].Trim(); powercfg -S $guid | Out-Null }
  } else { Write-Host "[dry-run] powercfg -S <High Performance GUID>" }
}

function Undo-UI {
  Write-Step "Restore UI defaults & allow background apps"
  try {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 0 /f | Out-Null
  } catch {}
}

function Do-Defender {
  Write-Step "Disable Defender/ATP & SmartScreen (requires Tamper Protection OFF)"
  if (-not $ReportOnly) {
    Try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } Catch {}
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f | Out-Null
    sc.exe stop WinDefend | Out-Null
    sc.exe config WinDefend start= disabled | Out-Null
    sc.exe stop Sense | Out-Null
    sc.exe config Sense start= disabled | Out-Null
    $tasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -ErrorAction SilentlyContinue
    if ($tasks) { $tasks | Disable-ScheduledTask | Out-Null }
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f | Out-Null
  } else {
    Write-Host "[dry-run] Disable Defender services/tasks/policies & SmartScreen"
  }
}

function Undo-Defender {
  Write-Step "Re-enable Defender/ATP & SmartScreen"
  try {
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f 2>$null | Out-Null
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f 2>$null | Out-Null
  } catch {}
  try { sc.exe config WinDefend start= auto | Out-Null; sc.exe start WinDefend | Out-Null } catch {}
  try { sc.exe config Sense start= auto | Out-Null; sc.exe start Sense | Out-Null } catch {}
  try { $tasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -ErrorAction SilentlyContinue; if ($tasks) { $tasks | Enable-ScheduledTask | Out-Null } } catch {}
  try {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Warn /f | Out-Null
  } catch {}
}

function Do-Store {
  Write-Step "Remove Microsoft Store and UWP bloat; disable ClipSVC/WSService"
  function Try-StopDisable($name){
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
      if (-not $ReportOnly) {
        try { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue } catch {}
        try { sc.exe config $name start= disabled | Out-Null } catch {}
      }
      Write-Host ("Disabled service: {0}" -f $name)
    }
  }
  Try-StopDisable "ClipSVC"
  Try-StopDisable "WSService"
  if (-not $ReportOnly) {
    try { sc.exe config "AppXSVC" start= demand | Out-Null } catch {}
    try { Stop-Service -Name "AppXSVC" -Force -ErrorAction SilentlyContinue } catch {}
  } else {
    Write-Host "[dry-run] AppXSVC -> Manual & stop"
  }
  function Remove-AppxEverywhere([string]$pattern){
    if (-not $ReportOnly) {
      try { Get-AppxPackage -AllUsers $pattern | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue } catch {}
      try { Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $pattern } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    Write-Host ("Removed package(s): {0}" -f $pattern)
  }
  Remove-AppxEverywhere "Microsoft.WindowsStore"
  $apps = @(
    "Microsoft.GetHelp","Microsoft.Getstarted","Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People","Microsoft.SkypeApp","Microsoft.Xbox*","Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo","Microsoft.YourPhone","Microsoft.BingNews","Microsoft.BingWeather",
    "Microsoft.MicrosoftStickyNotes"
  )
  foreach($a in $apps){ Remove-AppxEverywhere $a }
}

function Undo-Store {
  Write-Step "Re-enable Store & related services"
  try { sc.exe config "ClipSVC" start= demand | Out-Null } catch {}
  try { sc.exe config "WSService" start= demand | Out-Null } catch {}
  try { sc.exe config "AppXSVC" start= demand | Out-Null } catch {}
  $store = Get-AppxPackage -AllUsers Microsoft.WindowsStore -ErrorAction SilentlyContinue
  if ($store) {
    try {
      Add-AppxPackage -DisableDevelopmentMode -Register "$($store.InstallLocation)\AppxManifest.xml"
      Write-Host "Microsoft Store re-registered."
    } catch { Write-Warning "Store re-register failed: $($_.Exception.Message)" }
  } else {
    Write-Warning "Store not present; you may need DISM capability add or in-place repair."
  }
}

function Do-AutoLogin($u,$p){
  Write-Step "Configure auto-login"
  if ([string]::IsNullOrWhiteSpace($u) -or [string]::IsNullOrWhiteSpace($p)) { Write-Warning "Auto-login skipped: missing user/password"; return }
  if (-not $ReportOnly) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "$u" /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "$p" /f | Out-Null
  }
  Write-Host "Auto-login configured for: $u"
}
function Undo-AutoLogin {
  Write-Step "Remove auto-login"
  if (-not $ReportOnly) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f 2>$null | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /f 2>$null | Out-Null
  }
  Write-Host "Auto-login disabled."
}

# -------------------- Orchestrate --------------------
if ($DoAll) { $DoServices=$true; $DoUI=$true; $DoDefender=$true; $DoRemoveStore=$true }

if (-not $Revert) {
  if ($DoServices)   { Do-Services }
  if ($DoUI)         { Do-UI }
  if ($DoDefender)   { Do-Defender }
  if ($DoRemoveStore){ Do-Store }
  if ($AutoLoginUser){ Do-AutoLogin $AutoLoginUser $AutoLoginPass }
  if ($RemoveAutoLogin) { Undo-AutoLogin }
} else {
  if ($DoServices -or $DoAll)   { Undo-Services }
  if ($DoUI       -or $DoAll)   { Undo-UI }
  if ($DoDefender -or $DoAll)   { Undo-Defender }
  if ($DoRemoveStore -or $DoAll){ Undo-Store }
  if ($AutoLoginUser -or $RemoveAutoLogin) { Undo-AutoLogin }
}

if (-not $ReportOnly) { Stop-Transcript | Out-Null }

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Green
Write-Host ("Mode: {0}" -f ($(if($Revert){"REVERT"}else{"APPLY"})))
Write-Host ("Backup dir: {0}" -f $BackupDir)
if (-not $Revert) { Write-Host ("Service backup (if created): {0}" -f $backupCsv) }
Write-Host ("Log file: {0}" -f $logPath)
Write-Host "Reboot recommended." -ForegroundColor Yellow
