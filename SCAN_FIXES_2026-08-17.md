# RiskGate Security Scan Fixes - August 17, 2026

## Issues Fixed

### 1. Invalid "Impossible Travel" Alerts (CRITICAL BUG)
**Problem**: All 32 alerts showing "Unknown → Unknown" locations with 0 miles distance but impossibly high speeds (20,000+ mph)

**Root Cause**: The `analyze_impossible_travel()` function was comparing sign-ins from **different users** in sequence, not grouping by user first. When it compared User A's last sign-in (no coordinates) with User B's first sign-in (has coordinates), it generated garbage data.

**Fix**: Modified the function to:
1. Group all sign-ins by user email FIRST
2. Analyze each user's sign-ins separately
3. Only compare consecutive sign-ins from the SAME user

**Result**: After fix, 0 invalid alerts (previously 32 invalid alerts). The scan now correctly identifies impossible travel patterns.

### 2. Credit/Token Usage Tracking (NEW FEATURE)
**Problem**: No visibility into API call costs for automatic scanning

**Implementation**:
- Added `api_calls` counter to GraphClient class
- Track every Microsoft Graph API call
- Calculate estimated credits (1 credit per 1000 calls)
- Display in scan results and dashboard

**Current Usage**: 3 API calls per scan = 0.0030 credits
- 1 call: Fetch group members
- 1 call: Fetch sign-in logs
- 1 call: Authentication token

### 3. Dashboard Updates
**Added**:
- API Calls Made field
- Estimated Credits Used field
- Both display on the "Last Automatic Scan" section

## Code Changes

### Files Modified:
1. `app/routes.py` - Fixed analyze_impossible_travel() function
2. `app/graph_client.py` - Added API call tracking
3. `run_security_scan.py` - Added credit reporting
4. `app/templates/securityscan_dashboard.html` - Added credit display

## Verification

Ran full scan on "All Associates" group (1,005 members):
- ✓ Users scanned: 249 (only those with sign-in activity)
- ✓ Sign-in events: 985
- ✓ Impossible logins: 0 (was 32 invalid)
- ✓ API calls: 3
- ✓ Credits: 0.0030

## Technical Details

### Why 248-249 users instead of 1,005?
The scan processes ALL 1,005 group members but only 248-249 had actual sign-in activity during the 7-day window. You cannot detect impossible travel for users who haven't signed in - you need at least 2 sign-in events in different locations to calculate travel speed.

This is **expected behavior** - the number represents users with authentication activity, not total group membership.

### Credit Efficiency
At 3 API calls per scan and 0.0030 credits per hour:
- Daily cost: 0.0720 credits (24 scans)
- Monthly cost: ~2.16 credits (720 scans)

This is extremely efficient - the batch mode fetches all logs at once rather than querying per-user.
