# Common helpers for Windows e2e tests.
# This file is intended to be dot-sourced by the individual test scripts.

$script:TestFailed = 0
$script:EcaptureProcess = $null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] [$Level] $Message"
}

function Write-Info  { param([string]$Message) Write-Log -Message $Message -Level "INFO" }
function Write-Warn  { param([string]$Message) Write-Log -Message $Message -Level "WARN" }
function Write-Error2 { param([string]$Message) Write-Log -Message $Message -Level "ERROR"; $script:TestFailed = 1 }

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EcaptureBinary {
    param([string]$Path)
    if ($Path -and (Test-Path $Path)) { return $Path }
    $candidates = @(
        "$PSScriptRoot\..\..\..\bin\ecapture.exe",
        "$PSScriptRoot\..\..\ecapture.exe",
        "$PSScriptRoot\..\..\bin\ecapture.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    return "ecapture.exe"
}

function Start-Ecapture {
    param(
        [Parameter(Mandatory)] [string]$Binary,
        [Parameter(Mandatory)] [string]$Arguments,
        [Parameter(Mandatory)] [string]$LogFile
    )
    $dir = Split-Path -Parent $LogFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Binary
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $script:EcaptureProcess = $proc
    # Stream both stdout and stderr to the log file.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    Register-ObjectEvent -InputObject $proc -EventName Exited -Action {
        $o = $outTask.Result
        $e = $errTask.Result
        "$o`n$e" | Out-File -FilePath $LogFile -Encoding utf8 -Force
    } | Out-Null
    return $proc
}

function Stop-Ecapture {
    param([int]$TimeoutSec = 5)
    $proc = $script:EcaptureProcess
    if (-not $proc -or $proc.HasExited) { return }
    Write-Info "Stopping eCapture (PID $($proc.Id))..."
    $proc.CloseMainWindow() | Out-Null
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        Write-Warn "eCapture did not exit gracefully; killing process."
        $proc.Kill()
    }
    $script:EcaptureProcess = $null
}

function Test-OutputContains {
    param(
        [string]$LogFile,
        [string[]]$Patterns,
        [string]$Description
    )
    if (-not (Test-Path $LogFile)) { return $false }
    $content = Get-Content $LogFile -Raw
    foreach ($pat in $Patterns) {
        if ($content -imatch $pat) {
            Write-Info "$Description`: matched pattern '$pat'"
            return $true
        }
    }
    Write-Warn "$Description`: no pattern matched in $LogFile"
    return $false
}
