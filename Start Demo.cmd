@echo off
rem DNS Analyzer by Starkark98 - demo with sample data
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "%~dp0DnsAnalyzer.ps1" -Demo
