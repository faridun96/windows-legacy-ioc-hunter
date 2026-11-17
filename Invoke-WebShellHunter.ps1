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
Write-Host "================================================================" -ForegroundColor Cyan
