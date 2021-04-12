PowerShell.exe -ExecutionPolicy Bypass -Command "& '%~dpn0.ps1' -Path '%~dp0' -HKLMSwitch -HKDUSwitch -HKCUSwitch -Restart"
if NOT ["%errorlevel%"] == ["0"] pause
exit /b %errorlevel%
