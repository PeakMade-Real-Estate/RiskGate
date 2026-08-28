"""
Standalone security scan script for Windows Task Scheduler.

This script performs an automatic security scan without needing the Flask app to be running.
Schedule this script to run every hour using Windows Task Scheduler.

Usage:
    python run_security_scan.py

Configuration:
    Set environment variables or edit the CONFIG section below:
    - SCAN_TARGET: 'all_users', 'group', or 'user'
    - SCAN_VALUE: '' for all_users, group name/ID for group, or email for user
"""
import os
import sys
import time
import json
import re
from datetime import datetime
from pathlib import Path

# Add the project directory to the path
sys.path.insert(0, str(Path(__file__).parent))

# Configuration - customize these values
CONFIG = {
    'target_type': os.environ.get('SCAN_TARGET', 'group'),  # 'user', 'group', or 'all_users'
    'target_value': os.environ.get('SCAN_VALUE', 'c97a854d-19e4-49e5-8245-268e338bb190'),  # Object ID for "All Associates"
}

# Results file path
RESULTS_FILE = Path(__file__).parent / 'automatic_scan_results.json'

def retry_with_backoff(func, max_retries=3, initial_delay=2):
    """
    Retry a function with exponential backoff on rate limit errors.
    
    Args:
        func: Function to retry (should be a lambda or callable)
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds (doubles with each retry)
    
    Returns:
        Result of the function call, or None if all retries fail
    """
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            error_str = str(e)
            # Check if it's a rate limit error (429)
            if '429' in error_str or 'Too Many Requests' in error_str:
                if attempt < max_retries - 1:
                    print(f"    Rate limit hit, waiting {delay}s before retry {attempt + 1}/{max_retries}...")
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff
                    continue
                else:
                    print(f"    Rate limit exceeded after {max_retries} attempts, skipping...")
                    return None
            else:
                # Not a rate limit error, propagate it
                raise
    return None

def main():
    """Execute the security scan."""
    print(f"\n{'='*70}")
    print(f"RiskGate Security Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")
    print(f"Target: {CONFIG['target_type']}")
    if CONFIG['target_value']:
        print(f"Value: {CONFIG['target_value']}")
    print(f"{'='*70}\n")
    
    try:
        # Import dependencies
        from app import create_app
        from app.graph_client import GraphClient
        from app.routes import analyze_impossible_travel
        
        # Create Flask app context (needed for GraphClient logging)
        app = create_app()
        
        with app.app_context():
            target_type = CONFIG['target_type']
            target_value = CONFIG['target_value']
            
            scan_start_time = datetime.now()
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan started")
            
            try:
                graph_client = GraphClient()
                graph_client.reset_call_counter()  # Start tracking API calls
                
                # Determine which users to scan
                target_users = []
                
                if target_type == 'group':
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Fetching members of group: {target_value}")
                    
                    # Check if target_value is a GUID or group name
                    guid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
                    
                    group_name = target_value
                    if not guid_pattern.match(target_value):
                        # Search for group by name
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Looking up group by name...")
                        all_groups = graph_client.fetch_groups(max_results=999)
                        matching_groups = [g for g in all_groups if target_value.lower() in g.get('displayName', '').lower()]
                        
                        if not matching_groups:
                            raise Exception(f"Group not found: {target_value}")
                        elif len(matching_groups) > 1:
                            raise Exception(f"Multiple groups match '{target_value}' - be more specific")
                        
                        group_id = matching_groups[0]['id']
                        group_name = matching_groups[0]['displayName']
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Found group: '{group_name}' (ID: {group_id})")
                    else:
                        group_id = target_value
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Using group ID: {group_id}")
                    
                    members = graph_client.fetch_group_members(group_id)
                    target_users = [m.get('userPrincipalName') for m in members if m.get('userPrincipalName')]
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(target_users)} members in group '{group_name}'")
                    
                    # Show sample of users
                    if target_users:
                        sample_size = min(5, len(target_users))
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sample users ({sample_size} of {len(target_users)}):")
                        for user in target_users[:sample_size]:
                            print(f"    - {user}")
                    
                elif target_type == 'all_users':
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning all users (will fetch all sign-in logs)...")
                    # For all_users, we'll fetch logs without filtering and extract users from them
                    target_users = None  # Signal to scan everything
                    
                else:  # Single user
                    target_users = [target_value]
                
                # Fetch sign-in logs with rate limit handling
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Fetching sign-in logs...")
                all_signin_logs = []
                
                if target_users is None or (target_users and len(target_users) > 50):
                    # Batch mode - fetch all logs at once, then filter
                    # This is MUCH faster for large groups (1 API call vs 1,000+)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Using batch mode (fetching all logs, then filtering)...")
                    all_signin_logs = retry_with_backoff(
                        lambda: graph_client.fetch_signin_logs(hours_back=168),
                        max_retries=3,
                        initial_delay=2
                    ) or []
                    
                    # Filter to target users if specified
                    if target_users:
                        target_users_lower = [u.lower() for u in target_users]
                        all_signin_logs = [
                            log for log in all_signin_logs 
                            if log.get('userPrincipalName', '').lower() in target_users_lower
                        ]
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Filtered to {len(all_signin_logs)} events for group members")
                else:
                    # Per-user mode - only for small groups (< 50 users)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Using per-user mode ({len(target_users)} users)...")
                    for i, user_principal_name in enumerate(target_users):
                        if (i + 1) % 10 == 0:
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Progress: {i + 1}/{len(target_users)} users")
                        
                        # Fetch with retry
                        user_logs = retry_with_backoff(
                            lambda upn=user_principal_name: graph_client.fetch_signin_logs(hours_back=168, user_principal_name=upn),
                            max_retries=3,
                            initial_delay=2
                        )
                        
                        if user_logs:
                            all_signin_logs.extend(user_logs)
                        
                        # Rate limit protection
                        time.sleep(0.5)
                
                # Count unique users scanned
                users_scanned = len(set([log.get('userPrincipalName') for log in all_signin_logs if log.get('userPrincipalName')]))
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(all_signin_logs)} sign-in events for {users_scanned} users")
                
                # Show sample sign-in events
                if all_signin_logs:
                    sample_size = min(3, len(all_signin_logs))
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Sample sign-in events ({sample_size} of {len(all_signin_logs)}):")
                    for log in all_signin_logs[:sample_size]:
                        user = log.get('userPrincipalName', 'Unknown')
                        timestamp = log.get('createdDateTime', 'Unknown')
                        ip = log.get('ipAddress', 'Unknown')
                        location = log.get('location', {})
                        city = location.get('city', 'Unknown') if isinstance(location, dict) else 'Unknown'
                        state = location.get('state', '') if isinstance(location, dict) else ''
                        country = location.get('countryOrRegion', '') if isinstance(location, dict) else ''
                        loc_str = f"{city}, {state}, {country}".replace(', , ', ', ').strip(', ')
                        print(f"    • {user}")
                        print(f"      Time: {timestamp}")
                        print(f"      IP: {ip}")
                        print(f"      Location: {loc_str}")
                    print()
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyzing for impossible travel...")
                
                # Analyze for impossible travel
                impossible_logins = analyze_impossible_travel(all_signin_logs)
                
                # Show impossible travel details if found
                if impossible_logins:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ⚠️  Found {len(impossible_logins)} impossible travel incident(s):")
                    for i, incident in enumerate(impossible_logins[:5], 1):  # Show first 5
                        user = incident.get('userPrincipalName', 'Unknown')
                        speed = incident.get('required_speed') or incident.get('required_speed_mph', 0)
                        distance = incident.get('distance_miles', 0)
                        time_diff = incident.get('time_diff_hours', 0)
                        prev_city = incident.get('prev_city', 'Unknown')
                        current_city = incident.get('city', 'Unknown')
                        print(f"    {i}. {user}")
                        print(f"       Route: {prev_city} → {current_city}")
                        print(f"       Distance: {distance:.1f} miles")
                        print(f"       Time: {time_diff:.1f} hours")
                        print(f"       Required speed: {speed:.0f} mph")
                    if len(impossible_logins) > 5:
                        print(f"    ... and {len(impossible_logins) - 5} more")
                    print()
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ No impossible travel detected")
                
                # Create alerts
                alerts = []
                for impossible_login in impossible_logins:
                    speed_mph = impossible_login.get('required_speed') or impossible_login.get('required_speed_mph') or 0
                    alerts.append({
                        'id': impossible_login.get('id'),
                        'user': impossible_login.get('userPrincipalName'),
                        'severity': 'critical' if speed_mph > 1000 else 'high',
                        'reason': f"Impossible travel detected: {speed_mph:.0f} mph required",
                        'timestamp': impossible_login.get('createdDateTime'),
                        'locations': f"{impossible_login.get('prev_city', 'Unknown')} → {impossible_login.get('city', 'Unknown')}",
                        'distance_miles': impossible_login.get('distance_miles', 0),
                        'time_diff_hours': impossible_login.get('time_diff_hours', 0),
                        'required_speed_mph': speed_mph
                    })
                
                # Save results to JSON file
                api_calls_made = graph_client.get_call_count()
                scan_results = {
                    'scan_type': 'automatic',
                    'target_type': target_type,
                    'target_value': target_value,
                    'started_at': scan_start_time.isoformat(),
                    'completed_at': datetime.now().isoformat(),
                    'last_scan': datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'),
                    'users_scanned': users_scanned,
                    'signin_events': len(all_signin_logs),
                    'impossible_logins': len(impossible_logins),
                    'alerts_created': len(alerts),
                    'api_calls': api_calls_made,
                    'estimated_credits': api_calls_made * 0.001,  # Rough estimate: 1 credit per 1000 calls
                    'signin_logs': all_signin_logs,
                    'impossible_login_details': impossible_logins,
                    'alerts': alerts,
                    'scanned_users': target_users or []
                }
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Saving results to {RESULTS_FILE}...")
                with open(RESULTS_FILE, 'w') as f:
                    json.dump(scan_results, f, indent=2, default=str)
                
                print(f"\n{'-'*70}")
                print(f"✓ Scan completed successfully")
                print(f"  Users scanned: {users_scanned}")
                print(f"  Sign-in events: {len(all_signin_logs)}")
                print(f"  Impossible logins: {len(impossible_logins)}")
                print(f"  Alerts created: {len(alerts)}")
                print(f"  API calls made: {api_calls_made}")
                print(f"  Estimated credits: {api_calls_made * 0.001:.4f}")
                print(f"  Results saved to: {RESULTS_FILE}")
                print(f"{'-'*70}\n")
                
                # Track usage in separate log
                usage_file = Path(__file__).parent / 'automatic_scan_usage.json'
                try:
                    # Load existing usage data
                    if usage_file.exists():
                        with open(usage_file, 'r') as f:
                            usage_data = json.load(f)
                    else:
                        usage_data = {
                            'scans': [],
                            'daily_totals': {},
                            'monthly_totals': {},
                            'all_time_total': 0
                        }
                    
                    # Add this scan
                    scan_date = datetime.now().strftime('%Y-%m-%d')
                    scan_month = datetime.now().strftime('%Y-%m')
                    
                    usage_data['scans'].append({
                        'timestamp': datetime.now().isoformat(),
                        'api_calls': api_calls_made,
                        'users_scanned': users_scanned,
                        'signin_events': len(all_signin_logs),
                        'alerts': len(alerts)
                    })
                    
                    # Update daily total
                    usage_data['daily_totals'][scan_date] = usage_data['daily_totals'].get(scan_date, 0) + api_calls_made
                    
                    # Update monthly total
                    usage_data['monthly_totals'][scan_month] = usage_data['monthly_totals'].get(scan_month, 0) + api_calls_made
                    
                    # Update all-time total
                    usage_data['all_time_total'] = usage_data.get('all_time_total', 0) + api_calls_made
                    
                    # Keep only last 1000 scans
                    if len(usage_data['scans']) > 1000:
                        usage_data['scans'] = usage_data['scans'][-1000:]
                    
                    # Save usage data
                    with open(usage_file, 'w') as f:
                        json.dump(usage_data, f, indent=2)
                    
                    print(f"Usage tracking updated: {usage_file}")
                
                except Exception as usage_err:
                    print(f"Warning: Could not update usage tracking: {usage_err}")
                
            except Exception as e:
                print(f"\n✗ Scan failed: {e}\n")
                import traceback
                traceback.print_exc()
                sys.exit(1)
    
    except Exception as e:
        print(f"\n✗ Fatal error: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
