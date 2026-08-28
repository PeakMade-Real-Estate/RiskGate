# Schedule RiskGate Security Scan with Windows Task Scheduler
# This script creates a scheduled task to run security scans every hour

param(
    [string]$ScanTarget = "all_users",  # Options: all_users, group, user
    [string]$ScanValue = "",            # Group name or user email (leave empty for all_users)
    [int]$IntervalHours = 1             # How often to run (default: every 1 hour)
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RiskGate Automatic Scan Scheduler Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptDir "run_security_scan.py"
$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"

# Verify files exist
if (-not (Test-Path $pythonScript)) {
    Write-Host "✗ Error: run_security_scan.py not found" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $venvPython)) {
    Write-Host "✗ Error: Virtual environment not found at .venv\Scripts\python.exe" -ForegroundColor Red
    Write-Host "  Please create a virtual environment first: python -m venv .venv" -ForegroundColor Yellow
    exit 1
}

Write-Host "Configuration:" -ForegroundColor Green
Write-Host "  Scan Target: $ScanTarget"
Write-Host "  Scan Value: $(if ($ScanValue) { $ScanValue } else { '(all)' })"
Write-Host "  Interval: Every $IntervalHours hour$(if ($IntervalHours -ne 1) { 's' })"
Write-Host ""

# Task details
$taskName = "RiskGate-SecurityScan"
$description = "Automatic security scan for RiskGate - scans Entra ID sign-ins for impossible travel and suspicious activity"

# Build the command
$action = New-ScheduledTaskAction `
    -Execute $venvPython `
    -Argument $pythonScript `
    -WorkingDirectory $scriptDir

# Create trigger for every N hours
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)

# Task settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

# Run as current user
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

try {
    # Remove existing task if it exists
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "Removing existing task..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    
    # Register the new task
    Write-Host "Creating scheduled task..." -ForegroundColor Green
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description $description | Out-Null
    
    Write-Host ""
    Write-Host "✓ Scheduled task created successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Task Name: $taskName" -ForegroundColor Cyan
    Write-Host "Schedule: Every $IntervalHours hour$(if ($IntervalHours -ne 1) { 's' })" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To manage the task:" -ForegroundColor Yellow
    Write-Host "  • Open Task Scheduler: Press Win+R, type 'taskschd.msc', press Enter"
    Write-Host "  • Find '$taskName' in the Task Scheduler Library"
    Write-Host ""
    Write-Host "To run the scan manually right now:" -ForegroundColor Yellow
    Write-Host "  python run_security_scan.py" -ForegroundColor White
    Write-Host ""
    Write-Host "To test the scheduled task:" -ForegroundColor Yellow
    Write-Host "  Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
    Write-Host ""
    Write-Host "To remove the scheduled task:" -ForegroundColor Yellow
    Write-Host "  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor White
    Write-Host ""
    
    # Set environment variables in the task if needed
    if ($ScanTarget -or $ScanValue) {
        Write-Host "Note: To customize scan targets, edit the CONFIG section in run_security_scan.py" -ForegroundColor Cyan
    }
    
} catch {
    Write-Host ""
    Write-Host "✗ Failed to create scheduled task: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}
