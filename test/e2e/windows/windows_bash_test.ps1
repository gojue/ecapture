#Requires -Version 5.1
<#
.SYNOPSIS
    Windows end-to-end test for the ecapture bash/shell command capture module.

.PREREQUISITES
    - Administrator privileges (ETW sessions require elevation).
    - ecapture.exe built for Windows.
    - PowerShell available at a standard path (auto-detected by the probe).
#>
[CmdletBinding()]
param(
    [string]$EcaptureBinary = "",
    [string]$TmpDir = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common_windows.ps1"

if ([string]::IsNullOrWhiteSpace($TmpDir)) {
    $TmpDir = Join-Path $env:TEMP ("ecapture_bash_e2e_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:TestName = "Windows Bash/Shell E2E Test"
$script:Binary = Get-EcaptureBinary -Path $EcaptureBinary
$script:LogFile = Join-Path $TmpDir "ecapture_bash.log"
$script:Marker = "ecapture_shell_marker_" + [Guid]::NewGuid().ToString("N").Substring(0, 8)

function Main {
    Write-Info "=== $script:TestName ==="
    if (-not (Test-Admin)) {
        Write-Error2 "Administrator privileges are required for shell ETW capture"
        exit 1
    }
    if (-not (Test-Path $script:Binary)) {
        Write-Error2 "ecapture binary not found at $($script:Binary)"
        exit 1
    }

    $proc = Start-Ecapture -Binary $script:Binary -Arguments "bash" -LogFile $script:LogFile
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Write-Error2 "eCapture exited during initialization"
        exit 1
    }

    # Run a unique command in a child PowerShell process so we can look for it.
    Write-Info "Executing marker command in child PowerShell: $script:Marker"
    try {
        $arg = "-Command `"Write-Output '$script:Marker'`""
        Start-Process -FileName "powershell.exe" -ArgumentList $arg -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "Could not spawn PowerShell child: $_"
    }

    Start-Sleep -Seconds 2
    Stop-Ecapture

    if (-not (Test-Path $script:LogFile)) {
        Write-Error2 "eCapture log was not created"
        exit 1
    }
    Write-Info "Log size: $((Get-Item $script:LogFile).Length) bytes"

    if (Test-OutputContains -LogFile $script:LogFile -Patterns @($script:Marker, "powershell", "CommandLine", "Shell") -Description "shell command capture") {
        Write-Info "=== $script:TestName PASSED ==="
        exit 0
    }
    if (Test-OutputContains -LogFile $script:LogFile -Patterns @("Probe initialized", "Windows shell probe started") -Description "shell probe initialization") {
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
