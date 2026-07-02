"""
Test script to diagnose Microsoft Graph API connectivity and permissions.
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

print("=" * 80)
print("Microsoft Graph API Connection Test")
print("=" * 80)
print(f"\nTenant ID: {TENANT_ID}")
print(f"Client ID: {CLIENT_ID}")
print(f"Client Secret: {'*' * 20 if CLIENT_SECRET else 'NOT SET'}")
print()

# Step 1: Get access token
print("Step 1: Obtaining access token...")
token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
token_data = {
    'grant_type': 'client_credentials',
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'scope': 'https://graph.microsoft.com/.default'
}

try:
    token_response = requests.post(token_url, data=token_data, timeout=30)
    print(f"Token Response Status: {token_response.status_code}")
    
    if token_response.status_code != 200:
        print(f"ERROR: {token_response.text}")
        exit(1)
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    print("✅ Access token obtained successfully")
    print(f"Token expires in: {token_json.get('expires_in')} seconds")
    print()
    
except Exception as e:
    print(f"❌ Failed to get access token: {e}")
    exit(1)

# Step 2: Test sign-in logs endpoint
print("Step 2: Testing sign-in logs endpoint...")
filter_time = (datetime.utcnow() - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ')
signin_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
params = {
    '$filter': f"createdDateTime ge {filter_time}",
    '$top': 10
}

headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

try:
    signin_response = requests.get(signin_url, headers=headers, params=params, timeout=30)
    print(f"Sign-in Logs Response Status: {signin_response.status_code}")
    
    if signin_response.status_code == 200:
        data = signin_response.json()
        logs = data.get('value', [])
        print(f"✅ Successfully fetched {len(logs)} sign-in logs")
        if logs:
            print(f"\nSample user: {logs[0].get('userPrincipalName', 'Unknown')}")
            print(f"Sample timestamp: {logs[0].get('createdDateTime', 'Unknown')}")
    elif signin_response.status_code == 403:
        print("❌ PERMISSION DENIED (403 Forbidden)")
        print("\nThis means the app registration has insufficient permissions.")
        print("\nRequired permissions:")
        print("  - AuditLog.Read.All (Application permission)")
        print("  - Admin consent MUST be granted")
        print("\nError details:")
        error_data = signin_response.json()
        print(f"  {error_data.get('error', {}).get('message', 'No details')}")
    elif signin_response.status_code == 401:
        print("❌ AUTHENTICATION FAILED (401 Unauthorized)")
        print("\nThe access token is invalid or expired.")
        print("This usually means credentials are wrong or permissions not granted.")
    else:
        print(f"❌ Unexpected error: {signin_response.status_code}")
        print(f"Response: {signin_response.text[:500]}")
    
    print()
    
except Exception as e:
    print(f"❌ Request failed: {e}")

# Step 3: Test user endpoint (requires User.Read.All)
print("Step 3: Testing users endpoint...")
users_url = "https://graph.microsoft.com/v1.0/users"
params = {'$top': 5}

try:
    users_response = requests.get(users_url, headers=headers, params=params, timeout=30)
    print(f"Users Response Status: {users_response.status_code}")
    
    if users_response.status_code == 200:
        data = users_response.json()
        users = data.get('value', [])
        print(f"✅ Successfully fetched {len(users)} users")
        if users:
            print(f"\nSample user: {users[0].get('userPrincipalName', 'Unknown')}")
    elif users_response.status_code == 403:
        print("❌ PERMISSION DENIED for User.Read.All")
        error_data = users_response.json()
        print(f"  {error_data.get('error', {}).get('message', 'No details')}")
    else:
        print(f"❌ Error: {users_response.status_code}")
        print(f"Response: {users_response.text[:500]}")
    
    print()
    
except Exception as e:
    print(f"❌ Request failed: {e}")

print("=" * 80)
print("Test Complete")
print("=" * 80)
