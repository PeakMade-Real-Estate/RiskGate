# Fix RiskGate Scheduled Task to use UNC paths
# Run this script as Administrator

param(
    [int]$IntervalHours = 1
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Fix RiskGate Scheduled Task" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# UNC path (not mapped drive)
$uncPath = "\\EgnyteDrive\peakcampus\Shared\Technology\AI Projects\RiskGate"
$pythonExe = "$uncPath\.venv\Scripts\python.exe"
$scriptPath = "run_security_scan.py"

Write-Host "Using UNC path: $uncPath" -ForegroundColor Green
Write-Host ""

# Verify files exist
if (-not (Test-Path $pythonExe)) {
    Write-Host "✗ Error: Python executable not found at $pythonExe" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path "$uncPath\$scriptPath")) {
    Write-Host "✗ Error: Script not found at $uncPath\$scriptPath" -ForegroundColor Red
    exit 1
}

$taskName = "RiskGate-SecurityScan"
$description = "Automatic security scan for RiskGate - scans Entra ID sign-ins for impossible travel"

# Remove existing task if it exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# Create action with UNC path
$action = New-ScheduledTaskAction `
    -Execute $pythonExe `
    -Argument $scriptPath `
    -WorkingDirectory $uncPath

# Create trigger for every N hours
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)

# Task settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

# Run as current user with highest privileges
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

# Register the task
Write-Host "Creating scheduled task with UNC paths..." -ForegroundColor Green
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description $description | Out-Null

Write-Host ""
Write-Host "✓ Task created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Task Name: $taskName"
Write-Host "  Python: $pythonExe"
Write-Host "  Script: $scriptPath"
Write-Host "  Working Dir: $uncPath"
Write-Host "  Schedule: Every $IntervalHours hour(s)"
Write-Host ""
Write-Host "To test the task now:" -ForegroundColor Yellow
Write-Host "  Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host ""
Write-Host "To view task status:" -ForegroundColor Yellow
Write-Host "  Get-ScheduledTask -TaskName '$taskName' | Get-ScheduledTaskInfo" -ForegroundColor White
Write-Host ""
