@echo off
rem DNS Analyzer by Starkark98 - launcher
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "%~dp0DnsAnalyzer.ps1"
