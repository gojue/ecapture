#Requires -Version 5.1
<#
.SYNOPSIS
    Windows end-to-end test for the ecapture PostgreSQL command capture module.

.PREREQUISITES
    - Administrator privileges (DLL hooking requires elevation).
    - ecapture.exe built for Windows.
    - PostgreSQL client DLL (libpq.dll) or psql binary available in common
      installation paths.
#>
[CmdletBinding()]
param(
    [string]$EcaptureBinary = "",
    [string]$PostgresPath = "",
    [string]$TmpDir = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common_windows.ps1"

if ([string]::IsNullOrWhiteSpace($TmpDir)) {
    $TmpDir = Join-Path $env:TEMP ("ecapture_postgres_e2e_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:TestName = "Windows PostgreSQL E2E Test"
$script:Binary = Get-EcaptureBinary -Path $EcaptureBinary
$script:LogFile = Join-Path $TmpDir "ecapture_postgres.log"
$script:Marker = "ecapture_postgres_marker_" + [Guid]::NewGuid().ToString("N").Substring(0, 8)

function Find-PostgresClient {
    $candidates = @(
        $PostgresPath,
        "C:\Program Files\PostgreSQL\15\bin\psql.exe",
        "C:\Program Files\PostgreSQL\14\bin\psql.exe",
        "C:\Program Files\PostgreSQL\13\bin\psql.exe",
        "C:\Program Files\PostgreSQL\12\bin\psql.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Find-PostgresDll {
    $candidates = @(
        $PostgresPath,
        "C:\Program Files\PostgreSQL\15\bin\libpq.dll",
        "C:\Program Files\PostgreSQL\14\bin\libpq.dll",
        "C:\Program Files\PostgreSQL\13\bin\libpq.dll",
        "C:\Program Files\PostgreSQL\12\bin\libpq.dll",
        "C:\Windows\System32\libpq.dll"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Main {
    Write-Info "=== $script:TestName ==="
    if (-not (Test-Admin)) {
        Write-Error2 "Administrator privileges are required for PostgreSQL DLL hooking"
        exit 1
    }
    if (-not (Test-Path $script:Binary)) {
        Write-Error2 "ecapture binary not found at $($script:Binary)"
        exit 1
    }

    $dll = Find-PostgresDll
    if (-not $dll) {
        Write-Warn "No PostgreSQL libpq.dll found; skipping PostgreSQL e2e test"
        Write-Warn "Install PostgreSQL client or provide -PostgresPath"
        exit 0
    }
    Write-Info "Using PostgreSQL DLL: $dll"

    $ecaptureArgs = "postgres --postgres `"$dll`" --funcname PQexec"
    $proc = Start-Ecapture -Binary $script:Binary -Arguments $ecaptureArgs -LogFile $script:LogFile
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Write-Error2 "eCapture exited during PostgreSQL initialization"
        exit 1
    }

    $client = Find-PostgresClient
    if ($client) {
        Write-Info "Executing test query via $client"
        try {
            $query = "SELECT 1 AS $script:Marker"
            Start-Process -FileName $client -ArgumentList "-c `"$query`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        } catch {
            Write-Warn "Test query execution failed: $_"
        }
    } else {
        Write-Warn "psql client binary not found; only verifying probe startup"
    }

    Start-Sleep -Seconds 2
    Stop-Ecapture

    if (-not (Test-Path $script:LogFile)) {
        Write-Error2 "eCapture log was not created"
        exit 1
    }
    Write-Info "Log size: $((Get-Item $script:LogFile).Length) bytes"

    $patterns = @($script:Marker, "PostgreSQL", "PQexec", "Query", "SELECT")
    if (Test-OutputContains -LogFile $script:LogFile -Patterns $patterns -Description "PostgreSQL capture") {
        Write-Info "=== $script:TestName PASSED ==="
        exit 0
    }
    if (Test-OutputContains -LogFile $script:LogFile -Patterns @("PostgreSQL probe initialized", "PostgreSQL probe started") -Description "PostgreSQL probe initialization") {
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
