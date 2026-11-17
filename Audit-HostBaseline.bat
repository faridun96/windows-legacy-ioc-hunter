@echo off
setlocal EnableDelayedExpansion
title Windows Host Security & IOC Triage Collector

set "REPORT_FILE=Host_Triage_%COMPUTERNAME%.txt"

echo ================================================================= > "%REPORT_FILE%"
echo WINDOWS INCIDENT RESPONSE ^& SECURITY BASELINE TRIAGE REPORT >> "%REPORT_FILE%"
echo Hostname : %COMPUTERNAME% >> "%REPORT_FILE%"
echo Date/Time: %DATE% %TIME% >> "%REPORT_FILE%"
echo ================================================================= >> "%REPORT_FILE%"

echo [*] Collecting System Information...
echo. >> "%REPORT_FILE%"
echo [1] OS AND HOTFIX BASELINE >> "%REPORT_FILE%"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Boot Time" /C:"Hotfix(s)" >> "%REPORT_FILE%"

echo [*] Auditing Active Network Connections ^& Listening Ports...
echo. >> "%REPORT_FILE%"
echo [2] ACTIVE ESTABLISHED CONNECTIONS ^& PIDs >> "%REPORT_FILE%"
netstat -ano | findstr /I "ESTABLISHED LISTEN" >> "%REPORT_FILE%"

echo [*] Auditing Running Processes ^& Services...
echo. >> "%REPORT_FILE%"
echo [3] RUNNING PROCESSES WITH SERVICES >> "%REPORT_FILE%"
tasklist /svc >> "%REPORT_FILE%"

echo [*] Checking Registry Run / RunOnce Persistence Keys...
echo. >> "%REPORT_FILE%"
echo [4] REGISTRY AUTORUN PERSISTENCE >> "%REPORT_FILE%"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" >> "%REPORT_FILE%" 2>nul
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" >> "%REPORT_FILE%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" >> "%REPORT_FILE%" 2>nul

echo [*] Auditing Local Administrators Group...
echo. >> "%REPORT_FILE%"
echo [5] LOCAL ADMINISTRATORS ENUMERATION >> "%REPORT_FILE%"
net localgroup Administrators >> "%REPORT_FILE%" 2>nul

echo [*] Checking Windows Firewall Status...
echo. >> "%REPORT_FILE%"
echo [6] FIREWALL PROFILE STATE >> "%REPORT_FILE%"
netsh advfirewall show allprofiles state >> "%REPORT_FILE%" 2>nul

echo.
echo [+] Triage collection complete. Output saved to: %REPORT_FILE%
endlocal
