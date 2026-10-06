@echo off
chcp 65001 >nul
rem Emergency: remove every firewall rule created by Chained-Proxy-Fuse (self-elevates).
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
taskkill /f /im ChainedProxyFuse.exe >nul 2>&1
netsh advfirewall firewall delete rule name=CPF-Lock
netsh advfirewall firewall delete rule name=CPF-Trip
echo.
echo 已解除所有封锁，网络恢复正常。
pause
