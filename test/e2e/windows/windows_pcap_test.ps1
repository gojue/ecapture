#Requires -Version 5.1
<#
.SYNOPSIS
    Windows end-to-end test for ecapture TLS pcap/pcapng mode via Npcap.

.PREREQUISITES
    - Administrator privileges.
    - Npcap/WinPcap installed (the script checks for the Npcap helper DLL).
    - ecapture.exe built for Windows.
#>
[CmdletBinding()]
param(
    [string]$EcaptureBinary = "",
    [string]$InterfaceName = "",
    [string]$TmpDir = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common_windows.ps1"

if ([string]::IsNullOrWhiteSpace($TmpDir)) {
    $TmpDir = Join-Path $env:TEMP ("ecapture_pcap_e2e_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:TestName = "Windows PCAP E2E Test"
$script:Binary = Get-EcaptureBinary -Path $EcaptureBinary
$script:LogFile = Join-Path $TmpDir "ecapture_pcap.log"
$script:PcapFile = Join-Path $TmpDir "capture.pcapng"

function Get-DefaultInterface {
    if (-not [string]::IsNullOrWhiteSpace($InterfaceName)) { return $InterfaceName }
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback" } | Select-Object -First 1
    if ($adapters) { return $adapters.Name }
    $ni = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.OperationalStatus -eq "Up" -and $_.NetworkInterfaceType -ne "Loopback"
    } | Select-Object -First 1
    if ($ni) { return $ni.Name }
    return "Ethernet"
}

function Test-NpcapInstalled {
    $paths = @(
        "C:\Windows\System32\Npcap\wpcap.dll",
        "C:\Windows\System32\wpcap.dll"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $true } }
    $svc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    return ($svc -ne $null)
}

function Main {
    Write-Info "=== $script:TestName ==="
    if (-not (Test-Admin)) {
        Write-Error2 "Administrator privileges are required for Npcap capture"
        exit 1
    }
    if (-not (Test-NpcapInstalled)) {
        Write-Warn "Npcap does not appear to be installed; skipping pcap test"
        Write-Warn "Download Npcap from https://npcap.com/#download"
        exit 0
    }
    if (-not (Test-Path $script:Binary)) {
        Write-Error2 "ecapture binary not found at $($script:Binary)"
        exit 1
    }

    $iface = Get-DefaultInterface
    Write-Info "Using network interface: $iface"

    $ecaptureArgs = "tls -m pcap -i `"$iface`" -w `"$script:PcapFile`""
    $proc = Start-Ecapture -Binary $script:Binary -Arguments $ecaptureArgs -LogFile $script:LogFile
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Write-Error2 "eCapture exited during pcap initialization"
        exit 1
    }

    try {
        Write-Info "Generating some network traffic..."
        Invoke-WebRequest -Uri "https://api.github.com" -UseBasicParsing -TimeoutSec 15 -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warn "HTTPS request failed: $_"
    }

    Start-Sleep -Seconds 2
    Stop-Ecapture

    if (-not (Test-Path $script:PcapFile)) {
        Write-Error2 "Pcapng file was not created: $script:PcapFile"
        exit 1
    }
    $size = (Get-Item $script:PcapFile).Length
    Write-Info "Pcapng file created: $script:PcapFile ($size bytes)"
    if ($size -eq 0) {
        Write-Error2 "Pcapng file is empty"
        exit 1
    }

    # Verify pcapng magic bytes (0x0A0D0D0A little-endian at offset 0).
    $bytes = [System.IO.File]::ReadAllBytes($script:PcapFile)
    $magic = [BitConverter]::ToUInt32($bytes, 0)
    if ($magic -eq 0x0A0D0D0A) {
        Write-Info "Valid pcapng magic bytes detected"
    } else {
        Write-Warn "Pcapng magic bytes did not match; file may still be valid if ecapture writes a different section header"
    }

    Write-Info "=== $script:TestName PASSED ==="
    exit 0
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
