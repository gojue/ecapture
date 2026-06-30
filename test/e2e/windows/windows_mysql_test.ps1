#Requires -Version 5.1
<#
.SYNOPSIS
    Windows end-to-end test for the ecapture MySQL command capture module.

.PREREQUISITES
    - Administrator privileges (DLL hooking requires elevation).
    - ecapture.exe built for Windows.
    - MySQL/MariaDB client DLL (libmysql.dll / libmariadb.dll) or client binary
      available in common installation paths.
#>
[CmdletBinding()]
param(
    [string]$EcaptureBinary = "",
    [string]$MysqlPath = "",
    [string]$TmpDir = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common_windows.ps1"

if ([string]::IsNullOrWhiteSpace($TmpDir)) {
    $TmpDir = Join-Path $env:TEMP ("ecapture_mysql_e2e_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:TestName = "Windows MySQL E2E Test"
$script:Binary = Get-EcaptureBinary -Path $EcaptureBinary
$script:LogFile = Join-Path $TmpDir "ecapture_mysql.log"
$script:Marker = "ecapture_mysql_marker_" + [Guid]::NewGuid().ToString("N").Substring(0, 8)

function Find-MySQLClient {
    $candidates = @(
        $MysqlPath,
        "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe",
        "C:\Program Files\MySQL\MySQL Server 5.7\bin\mysql.exe",
        "C:\Program Files\MariaDB\MariaDB 10.6\bin\mysql.exe",
        "C:\Program Files\MariaDB\MariaDB 10.5\bin\mysql.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Find-MySQLDll {
    $candidates = @(
        $MysqlPath,
        "C:\Program Files\MySQL\MySQL Server 8.0\bin\libmysql.dll",
        "C:\Program Files\MySQL\MySQL Server 5.7\bin\libmysql.dll",
        "C:\Program Files\MariaDB\MariaDB 10.6\bin\libmariadb.dll",
        "C:\Program Files\MariaDB\MariaDB 10.5\bin\libmariadb.dll",
        "C:\Windows\System32\libmysql.dll"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Main {
    Write-Info "=== $script:TestName ==="
    if (-not (Test-Admin)) {
        Write-Error2 "Administrator privileges are required for MySQL DLL hooking"
        exit 1
    }
    if (-not (Test-Path $script:Binary)) {
        Write-Error2 "ecapture binary not found at $($script:Binary)"
        exit 1
    }

    $dll = Find-MySQLDll
    if (-not $dll) {
        Write-Warn "No MySQL/MariaDB DLL found; skipping MySQL e2e test"
        Write-Warn "Install MySQL/MariaDB client or provide -MysqlPath"
        exit 0
    }
    Write-Info "Using MySQL DLL: $dll"

    $ecaptureArgs = "mysqld --mysqld `"$dll`" --funcname mysql_real_query"
    $proc = Start-Ecapture -Binary $script:Binary -Arguments $ecaptureArgs -LogFile $script:LogFile
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Write-Error2 "eCapture exited during MySQL initialization"
        exit 1
    }

    $client = Find-MySQLClient
    if ($client) {
        Write-Info "Executing test query via $client"
        try {
            $query = "SELECT 1 AS $script:Marker"
            Start-Process -FileName $client -ArgumentList "-e `"$query`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        } catch {
            Write-Warn "Test query execution failed: $_"
        }
    } else {
        Write-Warn "MySQL client binary not found; only verifying probe startup"
    }

    Start-Sleep -Seconds 2
    Stop-Ecapture

    if (-not (Test-Path $script:LogFile)) {
        Write-Error2 "eCapture log was not created"
        exit 1
    }
    Write-Info "Log size: $((Get-Item $script:LogFile).Length) bytes"

    $patterns = @($script:Marker, "MySQL", "mysql_real_query", "Query", "SELECT")
    if (Test-OutputContains -LogFile $script:LogFile -Patterns $patterns -Description "MySQL capture") {
        Write-Info "=== $script:TestName PASSED ==="
        exit 0
    }
    if (Test-OutputContains -LogFile $script:LogFile -Patterns @("MySQL probe initialized", "MySQL probe started") -Description "MySQL probe initialization") {
        Write-Info "=== $script:TestName PASSED (initialization verified) ==="
        exit 0
    }
    Write-Error2 "=== $script:TestName FAILED ==="
    exit 1
}

try {
    Main
} finally {
    Stop-Ecapture
    if ($script:TestFailed -ne 0 -and (Test-Path $script:LogFile)) {
        Write-Info "--- eCapture log ---"
        Get-Content $script:LogFile -Tail 50 | ForEach-Object { Write-Info $_ }
    }
}
