@echo off
rem Build ChainedProxyFuse.exe with the C# compiler that ships with Windows (no SDK needed).
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
cd /d "%~dp0"
"%CSC%" /nologo /target:winexe /out:ChainedProxyFuse.exe /win32manifest:src\app.manifest ^
  /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
  /r:System.Web.Extensions.dll /r:Microsoft.CSharp.dll src\*.cs
if errorlevel 1 (echo BUILD FAILED) else (echo BUILD OK: %~dp0ChainedProxyFuse.exe)
