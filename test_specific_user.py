"""
Test script to check sign-in logs for a specific user.
"""
import os
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

TENANT_ID = os.getenv('AZURE_TENANT_ID')
CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')

# Get access token
token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
token_data = {
    'grant_type': 'client_credentials',
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'scope': 'https://graph.microsoft.com/.default'
}

token_response = requests.post(token_url, data=token_data, timeout=30)
access_token = token_response.json().get('access_token')

headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

# Test different variations of the username
test_users = [
    'Jeckard@peakmade.com',
    'jeckard@peakmade.com',
    'JEckard@peakmade.com'
]

print("=" * 80)
print("Testing Sign-in Logs for Specific User")
print("=" * 80)

filter_time = (datetime.utcnow() - timedelta(hours=168)).strftime('%Y-%m-%dT%H:%M:%SZ')  # 7 days back

for test_user in test_users:
    print(f"\nSearching for: {test_user}")
    print("-" * 80)
    
    signin_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    params = {
        '$filter': f"createdDateTime ge {filter_time} and userPrincipalName eq '{test_user}'",
        '$top': 100
    }
    
    try:
        response = requests.get(signin_url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            logs = data.get('value', [])
            print(f"✅ Query successful - Found {len(logs)} sign-in logs in last 7 days")
            
            if logs:
                print(f"\nRecent sign-ins:")
                for i, log in enumerate(logs[:5], 1):
                    timestamp = log.get('createdDateTime', 'Unknown')
                    location = log.get('location', {})
                    city = location.get('city', 'Unknown')
                    country = location.get('countryOrRegion', 'Unknown')
                    print(f"  {i}. {timestamp} - {city}, {country}")
            else:
                print("  No sign-in activity found for this user in the last 7 days")
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text[:300]}")
    
    except Exception as e:
        print(f"❌ Request failed: {e}")

# Also search for users with similar names
print("\n" + "=" * 80)
print("Searching for users with 'jeckard' in their name...")
print("=" * 80)

users_url = "https://graph.microsoft.com/v1.0/users"
params = {
    '$filter': "startswith(userPrincipalName, 'jeckard') or startswith(userPrincipalName, 'Jeckard')",
    '$select': 'userPrincipalName,displayName,mail'
}

try:
    response = requests.get(users_url, headers=headers, params=params, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        users = data.get('value', [])
        
        if users:
            print(f"\nFound {len(users)} user(s):")
            for user in users:
                print(f"  - {user.get('userPrincipalName', 'Unknown')} ({user.get('displayName', 'Unknown')})")
        else:
            print("\n⚠️ No users found starting with 'jeckard'")
            print("\nSearching ALL users for similar names...")
            
            # Try broader search
            all_users_url = "https://graph.microsoft.com/v1.0/users"
            params = {'$top': 999, '$select': 'userPrincipalName,displayName'}
            response2 = requests.get(all_users_url, headers=headers, params=params, timeout=60)
            
            if response2.status_code == 200:
                all_users = response2.json().get('value', [])
                matching = [u for u in all_users if 'jeckard' in u.get('userPrincipalName', '').lower()]
                
                if matching:
                    print(f"\nFound {len(matching)} matching user(s):")
                    for user in matching:
                        print(f"  - {user.get('userPrincipalName', 'Unknown')} ({user.get('displayName', 'Unknown')})")
                else:
                    print("\n⚠️ No users found with 'jeckard' in username")
                    print("\nShowing first 10 users from your tenant:")
                    for user in all_users[:10]:
                        print(f"  - {user.get('userPrincipalName', 'Unknown')}")
    else:
        print(f"❌ Error: {response.status_code}")
        print(f"Response: {response.text[:300]}")

except Exception as e:
    print(f"❌ Request failed: {e}")

print("\n" + "=" * 80)
