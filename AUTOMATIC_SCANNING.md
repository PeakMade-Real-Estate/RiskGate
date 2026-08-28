# Automatic Security Scanning

Your RiskGate app now includes automatic security scanning that runs independently using Windows Task Scheduler.

## How It Works

- **Standalone Script**: `run_security_scan.py` runs scans without needing your Flask app to be running
- **Windows Task Scheduler**: Automatically runs the script every hour (or custom interval)
- **No App Changes**: Your Flask app remains unchanged - scans run separately
- **Database Storage**: Results are saved to your database and visible in the web dashboard

## What Gets Scanned

The automatic scan:
1. Fetches sign-in logs from Microsoft Entra ID (last 24 hours)
2. Analyzes for impossible travel patterns
3. Creates security alerts for suspicious activity
4. Stores all data in your database for review in the dashboard

## Quick Setup (Automatic)

Run this PowerShell command to set up automatic scanning every hour:

```powershell
.\setup_scheduled_scan.ps1 -ScanTarget "all_users" -IntervalHours 1
```

### Options

- **ScanTarget**: What to scan
  - `all_users` - Scan everyone in your Entra ID tenant
  - `group` - Scan members of a specific group (also set `-ScanValue "Group Name"`)
  - `user` - Scan a specific user (also set `-ScanValue "user@domain.com"`)

- **IntervalHours**: How often to run (default: 1 hour)
  - `1` - Every hour (recommended for active monitoring)
  - `6` - Every 6 hours
  - `24` - Once per day

### Examples

```powershell
# Scan all users every hour
.\setup_scheduled_scan.ps1 -ScanTarget "all_users" -IntervalHours 1

# Scan Technology group every 6 hours
.\setup_scheduled_scan.ps1 -ScanTarget "group" -ScanValue "Technology" -IntervalHours 6

# Scan specific user once per day
.\setup_scheduled_scan.ps1 -ScanTarget "user" -ScanValue "john@company.com" -IntervalHours 24
```

## Manual Setup (If Automatic Fails)

If the automated setup doesn't work due to permissions:

### 1. Open Task Scheduler
- Press `Win + R`
- Type `taskschd.msc`
- Press Enter

### 2. Create a New Task
- Click **"Create Task"** (not "Create Basic Task")
- Name: `RiskGate-SecurityScan`
- Description: `Automatic security scan for RiskGate`
- Check **"Run whether user is logged on or not"**
- Check **"Run with highest privileges"**

### 3. Set Trigger
- Go to **"Triggers"** tab
- Click **"New"**
- Begin the task: **"On a schedule"**
- Settings: **"Daily"**
- Advanced settings:
  - Check **"Repeat task every"**: **1 hour**
  - For a duration of: **Indefinitely**
- Click **OK**

### 4. Set Action
- Go to **"Actions"** tab
- Click **"New"**
- Action: **"Start a program"**
- **Program/script** (enter ONLY the Python path, no spaces or quotes):
  ```
  Z:\Shared\Technology\AI Projects\RiskGate\.venv\Scripts\python.exe
  ```
- **Add arguments (optional)** (enter ONLY the script name):
  ```
  run_security_scan.py
  ```
- **Start in (optional)**:
  ```
  Z:\Shared\Technology\AI Projects\RiskGate
  ```
- Click **OK**

> ⚠️ **Important**: Do NOT put the script name in the "Program/script" field. The Python executable path and script name must be in separate fields.

### 5. Configure Settings
- Go to **"Settings"** tab
- Check **"Allow task to be run on demand"**
- Check **"Run task as soon as possible after a scheduled start is missed"**
- Check **"If the task fails, restart every"**: **1 hour**
- Uncheck **"Stop the task if it runs longer than"**
- Click **OK**

### 6. Save and Test
- Click **OK** to save the task
- Right-click the task → **"Run"**
- Check the **"Last Run Result"** column (0x0 means success)

## Testing Your Setup

### Run a Manual Scan

```powershell
python run_security_scan.py
```

You should see output like:
```
======================================================================
RiskGate Security Scan - 2026-08-12 11:44:12
======================================================================
Target: all_users
======================================================================

[11:44:14] Scan started (ID: 1)
[11:44:14] Fetching all users from tenant...
[11:44:14] Found 42 users in tenant
[11:44:14] Scanning sign-in logs...
[11:44:25] Progress: 20/42 users scanned
[11:44:45] Analyzing for impossible travel...

----------------------------------------------------------------------
✓ Scan completed successfully
  Users scanned: 42
  Sign-in events: 156
  Impossible logins: 2
  Alerts created: 2
----------------------------------------------------------------------
```

### Test the Scheduled Task

```powershell
Start-ScheduledTask -TaskName 'RiskGate-SecurityScan'
```

### View Scan Results

1. Start your Flask app: `python run.py`
2. Open https://127.0.0.1:5003
3. Go to the dashboard - you'll see the latest scan results

## Customizing Scan Targets

Edit the **CONFIG** section at the top of `run_security_scan.py`:

```python
CONFIG = {
    'target_type': 'all_users',  # or 'group' or 'user'
    'target_value': '',          # group name or user email
}
```

Or set environment variables:
```powershell
$env:SCAN_TARGET = "group"
$env:SCAN_VALUE = "Technology"
python run_security_scan.py
```

## Managing the Scheduled Task

### View Task Status
```powershell
Get-ScheduledTask -TaskName 'RiskGate-SecurityScan' | Get-ScheduledTaskInfo
```

### Disable Scanning
```powershell
Disable-ScheduledTask -TaskName 'RiskGate-SecurityScan'
```

### Enable Scanning
```powershell
Enable-ScheduledTask -TaskName 'RiskGate-SecurityScan'
```

### Remove Scanning
```powershell
Unregister-ScheduledTask -TaskName 'RiskGate-SecurityScan' -Confirm:$false
```

### View Task Logs
Open Task Scheduler → Find the task → **"History"** tab (enable if disabled)

## Troubleshooting

### "Access is denied" when creating task
- Run PowerShell as Administrator
- Or use the Manual Setup instructions above

### "No module named..." errors
Make sure you're using the virtual environment Python:
```powershell
.\.venv\Scripts\Activate.ps1
python run_security_scan.py
```

### No users found / API errors
Check your Azure credentials in `.env`:
```
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

### Task runs but no data appears
- Check the database file exists: `securityscan.db`
- Verify Microsoft Graph API permissions are granted
- Run a manual scan to see detailed error messages

## Benefits of This Approach

✓ **Simple**: No app modifications needed  
✓ **Reliable**: Windows Task Scheduler is built-in and stable  
✓ **Independent**: Scans run even if the Flask app isn't running  
✓ **Flexible**: Easy to customize scan targets and frequency  
✓ **Visible**: All results appear in your web dashboard  

## Next Steps

1. Set up the scheduled task using the automatic or manual method
2. Test with a manual run to verify it works
3. Check your dashboard to see scan results
4. Adjust the frequency as needed for your organization

---

**Questions or Issues?**  
The scan logs are saved to the database with a `scan_type` of `'scheduled'` so you can track automated vs. manual scans.
