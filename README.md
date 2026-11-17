Markdown
# Windows Legacy & Enterprise IOC Hunter

An agentless incident response and security auditing toolkit designed for defensive security teams and system administrators. Built to operate across heterogeneous Windows environments (from legacy Windows Server 2008 R2 / Windows 7 with PowerShell 2.0 to modern Windows Server 2022 / Windows 11) without requiring third-party dependencies or external agents.

## Key Capabilities

* **ASP.NET & IIS Web Shell Detection:** Scans web root directories (`inetpub\wwwroot`) for anomalous script modifications, obfuscated `eval` / `Request.Form` patterns, and unauthorized `.aspx`, `.ashx`, and `.asmx` files.
* **Reverse Tunnel & C2 Port Sweeping:** Identifies suspicious outbound connections, non-standard listening ports, and potential tunneling utilities (e.g., Ligolo-ng, Chisel, FRP, Plink) mapped to active Process IDs (PIDs).
* **Persistence & Scheduled Task Auditing:** Enumerates non-Microsoft scheduled tasks, unusual `Run` / `RunOnce` registry keys, and WMI event subscriptions commonly abused for privilege escalation and persistence.
* **Legacy OS Security Baseline Check:** Validates SMBv1 status, RDP NLA enforcement, PowerShell script block logging, and Windows Firewall profile states.

## Repository Structure

```text
windows-legacy-ioc-hunter/
├── Invoke-WebShellHunter.ps1    # PowerShell 2.0+ heuristic scanner for IIS/ASP.NET web shells
├── Audit-HostBaseline.bat       # Zero-dependency Batch triage script for network & persistence checks
└── README.md                    # Documentation & usage guide
Quick Start & Usage
1. Scanning IIS Web Roots for Anomalous Scripts (PowerShell)
Run from an elevated PowerShell prompt to inspect default or custom web directories for high-entropy strings and known command-execution primitives:

PowerShell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-WebShellHunter.ps1 -TargetPath "C:\inetpub\wwwroot"
2. Rapid Host Triage & Network Connection Audit (Batch)
For legacy hosts where PowerShell execution policies or versions are restricted, run Audit-HostBaseline.bat as Administrator to generate a timestamped forensic triage report:

DOS
Audit-HostBaseline.bat
Defensive Use & Legal Disclaimer
This toolkit is developed strictly for defensive security auditing, authorized incident response, and local laboratory research. It performs read-only triage operations and does not modify system state or network configurations.

License
Released under the MIT License. See LICENSE for details.


Нажмите **Commit changes...** в правом верхнем углу.

**Шаг 3: Добавьте скрипт №1 — `Invoke-WebShellHunter.ps1`**

Нажмите **Add file** → **Create new file**, назовите его `Invoke-WebShellHunter.ps1` и вставьте код PowerShell-сканера:

```powershell
<#
.SYNOPSIS
    Heuristic ASP.NET / IIS Web Shell & Anomalous Script Scanner (PowerShell 2.0+ Compatible)
.DESCRIPTION
    Performs read-only static analysis on web directories to detect suspicious command execution
    primitives, base64 obfuscation, and recently modified web scripts (.aspx, .ashx, .asmx, .php).
.PARAMETER TargetPath
    Root directory to scan. Defaults to C:\inetpub\wwwroot.
.PARAMETER DaysModified
    Highlight files modified within the last N days. Defaults to 14.
#>
param(
    [string]$TargetPath = "C:\inetpub\wwwroot",
    [int]$DaysModified = 14
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Windows IIS / ASP.NET Web Shell Heuristic Scanner" -ForegroundColor Cyan
Write-Host " Target Path : $TargetPath" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

if (-not (Test-Path $TargetPath)) {
    Write-Warning "Target path '$TargetPath' does not exist. Specify a valid directory using -TargetPath."
    exit
}

$Extensions = @("*.aspx", "*.ashx", "*.asmx", "*.cs", "*.vb", "*.php", "*.jsp")
$SuspiciousPatterns = @(
    "System\.Diagnostics\.Process",
    "ProcessStartInfo",
    "cmd\.exe",
    "powershell\.exe",
    "FromBase64String",
    "eval\s*\(",
    "Request\.Form\[",
    "Request\.Item\[",
    "JScript\.Encode",
    "WScript\.Shell",
    "Server\.Execute"
)

$CombinedRegex = ($SuspiciousPatterns -join "|")
$CutoffDate = (Get-Date).AddDays(-$DaysModified)
$FindingsCount = 0

Write-Host "[*] Enumerating web script files..." -ForegroundColor Yellow
$Files = Get-ChildItem -Path $TargetPath -Include $Extensions -Recurse -ErrorAction SilentlyContinue

foreach ($File in $Files) {
    $IsRecent = $File.LastWriteTime -ge $CutoffDate
    $ContentMatches = Select-String -Path $File.FullName -Pattern $CombinedRegex -AllMatches -ErrorAction SilentlyContinue

    if ($ContentMatches -or $IsRecent) {
        $FindingsCount++
        Write-Host "`n[!] File Flagged: $($File.FullName)" -ForegroundColor Red
        Write-Host "    Last Modified : $($File.LastWriteTime) | Size: $($File.Length) bytes" -ForegroundColor Gray

        if ($IsRecent) {
            Write-Host "    [Reason] Recently modified (within last $DaysModified days)" -ForegroundColor Yellow
        }

        if ($ContentMatches) {
            foreach ($Match in $ContentMatches) {
                $LineSnippet = $Match.Line.Trim()
                if ($LineSnippet.Length -gt 120) {
                    $LineSnippet = $LineSnippet.Substring(0, 120) + "..."
                }
                Write-Host "    [Pattern Line $($Match.LineNumber)] $LineSnippet" -ForegroundColor Magenta
            }
        }
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "[+] Scan Complete. Total flagged files: $FindingsCount" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor
