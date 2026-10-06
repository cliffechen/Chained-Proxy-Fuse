@echo off
rem Emergency restore: remove every firewall rule created by Chained-Proxy-Fuse.
rem Keep this file ASCII-only with CRLF line endings, otherwise cmd.exe misparses it.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
taskkill /f /im ChainedProxyFuse.exe >nul 2>&1
netsh advfirewall firewall delete rule name=CPF-Lock
netsh advfirewall firewall delete rule name=CPF-Trip
echo.
echo Done. All Chained-Proxy-Fuse rules removed, network is back to normal.
pause
