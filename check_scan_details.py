"""Quick script to check automatic scan details."""
import json

with open('automatic_scan_results.json', 'r') as f:
    data = json.load(f)

print(f"Scan Target Type: {data.get('target_type')}")
print(f"Scan Target Value (Group ID): {data.get('target_value')}")
print(f"Total Group Members in 'scanned_users' list: {len(data.get('scanned_users', []))}")
print(f"Users with actual sign-in events: {data.get('users_scanned')}")
print(f"Sign-in events found: {data.get('signin_events')}")
print(f"Impossible travel alerts: {data.get('impossible_logins')}")
print(f"\nConclusion:")
print(f"  - The group 'All Associates' has {len(data.get('scanned_users', []))} members")
print(f"  - Only {data.get('users_scanned')} of them signed in during the 7-day scan window")
print(f"  - The scan DID run for all group members, but only counts users with sign-in activity")
