@echo off
start PowerShell.exe -ExecutionPolicy Bypass -Command "& '%~dpn0.ps1' '%~dp0'"
exit