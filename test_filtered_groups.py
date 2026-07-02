"""
Test script to see filtered people groups from Entra.
"""
import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

TENANT_ID = os.getenv('AZURE_TENANT_ID')
CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')

def get_access_token():
    """Get access token for Microsoft Graph."""
    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }
    
    response = requests.post(token_url, data=data, timeout=30)
    response.raise_for_status()
    return response.json()['access_token']

def is_people_group(group_name):
    """Check if group is a people group, not a project/task group."""
    name_lower = group_name.lower()
    
    excluded_keywords = [
        'project tracking', 'tracking', 'scope of work', 'task list', 'checklist',
        'disposition', 'transition', 'planning', 'agenda', 'workorders', 'work orders',
        'planner', 'to do', 'todo', 'sow', '-dynamic', 'open enrollment', 'conference',
        'leasing license', 'lender chat', 'master task', 'operational task', 'goals',
        'learning plan', 'new developments', 'intern', 'RA team'
    ]
    
    # Exclude groups with project keywords
    if any(keyword in name_lower for keyword in excluded_keywords):
        return False
    # Exclude groups that are just property names with numbers
    if any(char.isdigit() for char in group_name) and len(group_name.split()) <= 3:
        return False
    return True

def fetch_filtered_groups():
    """Fetch and filter groups."""
    token = get_access_token()
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    url = "https://graph.microsoft.com/v1.0/groups"
    params = {
        '$select': 'id,displayName,mail,securityEnabled',
        '$top': 999
    }
    
    response = requests.get(url, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    all_groups = response.json().get('value', [])
    
    # Filter to people groups only
    people_groups = [g for g in all_groups if is_people_group(g['displayName'])]
    
    print("="*80)
    print(f"FILTERED PEOPLE GROUPS ({len(people_groups)} of {len(all_groups)} total)")
    print("="*80)
    
    for i, group in enumerate(people_groups[:50], 1):  # Show first 50
        group_type = "Security" if group.get('securityEnabled') else "Distribution"
        print(f"\n{i}. {group['displayName']}")
        print(f"   Type: {group_type}")
        print(f"   ID: {group['id']}")
    
    # Look for specific department groups
    print("\n" + "="*80)
    print("DEPARTMENT/TEAM GROUPS:")
    print("="*80)
    
    dept_keywords = ['technology', 'tech', 'it', 'accounting', 'finance', 'hr', 
                     'human resources', 'operations', 'ops', 'pops', 'people',
                     'executive', 'leadership', 'management', 'team', 'department']
    
    for keyword in dept_keywords:
        matches = [g for g in people_groups if keyword in g['displayName'].lower()]
        if matches:
            print(f"\n'{keyword.title()}' groups:")
            for g in matches[:5]:
                print(f"  - {g['displayName']}")

if __name__ == '__main__':
    fetch_filtered_groups()
