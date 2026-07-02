"""
Check what RAW data the Technology group members API returns
"""
import os
import requests
from dotenv import load_dotenv
import json

load_dotenv()

# Get token
token_url = f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}/oauth2/v2.0/token"
token_data = {
    'grant_type': 'client_credentials',
    'client_id': os.getenv('AZURE_CLIENT_ID'),
    'client_secret': os.getenv('AZURE_CLIENT_SECRET'),
    'scope': 'https://graph.microsoft.com/.default'
}

token_response = requests.post(token_url, data=token_data)
token_response.raise_for_status()
access_token = token_response.json()['access_token']

# Technology group ID (from debug output)
group_id = '449e128c-909d-476d-945f-5d48d33d934e'

# Fetch members
url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}
params = {
    '$select': 'id,userPrincipalName,displayName,mail,accountEnabled',
    '$top': 5  # Just first 5 members for testing
}

print(f"Fetching members from: {url}")
print(f"Params: {params}\n")

response = requests.get(url, headers=headers, params=params)
response.raise_for_status()

data = response.json()

print("=" * 80)
print("RAW API RESPONSE")
print("=" * 80)
print(json.dumps(data, indent=2))

print("\n" + "=" * 80)
print("MEMBER FIELDS ANALYSIS")
print("=" * 80)
if 'value' in data:
    print(f"Total members in response: {len(data['value'])}\n")
    for i, member in enumerate(data['value'][:3], 1):
        print(f"Member {i}:")
        for key, value in member.items():
            print(f"  {key}: {value}")
        print()
