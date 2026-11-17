@echo off
chcp 65001 >NUL
setlocal
echo ============================================
echo   ZCode Guard - deploy from this repo
echo ============================================
echo.

set "DST=%USERPROFILE%\zcode-guard"

if not exist "%DST%" mkdir "%DST%"
copy /Y "%~dp0zcode-guard.ps1"  "%DST%\" >NUL && echo [OK] zcode-guard.ps1
copy /Y "%~dp0guard-report.ps1" "%DST%\" >NUL && echo [OK] guard-report.ps1

echo.
echo Next steps:
echo   1. Edit %DST%\zcode-guard.ps1 top "User configuration" block if needed
echo   2. Run install (UAC will prompt once):
echo      powershell -NoProfile -ExecutionPolicy Bypass -File "%DST%\zcode-guard.ps1" -Action install
echo   3. Lock your API keys into the vault:
echo      powershell -NoProfile -ExecutionPolicy Bypass -File "%DST%\zcode-guard.ps1" -Action lock
echo   4. Double-click the desktop ZCode icon to start ZCode via the guard
echo.
echo NOTE: API keys are NOT included in this repo - re-create them from
echo       your provider websites and configure ZCode, then lock.
echo.
echo Create desktop report shortcut now? [Y/N]
choice /C YN /M "> "
if errorlevel 2 goto END

powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell;" ^
  "$l = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\ZCode 防护状态.lnk');" ^
  "$l.TargetPath = \"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe\";" ^
  "$l.Arguments = '-NoProfile -ExecutionPolicy Bypass -File \"%DST%\guard-report.ps1\"';" ^
  "$l.Save()"
echo [OK] ZCode 防护状态.lnk created

:END
pause
