"""
Test script to verify Microsoft Graph permissions and fetch Entra groups.
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
    
    try:
        response = requests.post(token_url, data=data, timeout=30)
        response.raise_for_status()
        token_data = response.json()
        print("✅ Successfully authenticated to Microsoft Graph")
        return token_data['access_token']
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Response: {e.response.text}")
        return None

def test_groups_permission(token):
    """Test fetching groups to verify permissions."""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Try to fetch groups
    url = "https://graph.microsoft.com/v1.0/groups"
    params = {
        '$select': 'id,displayName,mail,securityEnabled',
        '$top': 50,
        '$orderby': 'displayName'
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        result = response.json()
        groups = result.get('value', [])
        
        print(f"\n✅ Successfully fetched {len(groups)} groups from Entra ID")
        print("\n" + "="*80)
        print("AVAILABLE GROUPS:")
        print("="*80)
        
        for i, group in enumerate(groups, 1):
            group_type = "Security" if group.get('securityEnabled') else "Distribution"
            mail = group.get('mail', 'N/A')
            print(f"\n{i}. {group['displayName']}")
            print(f"   ID: {group['id']}")
            print(f"   Type: {group_type}")
            print(f"   Mail: {mail}")
        
        # Look for specific groups mentioned by user
        print("\n" + "="*80)
        print("SEARCHING FOR SPECIFIC GROUPS:")
        print("="*80)
        
        search_terms = ['technology', 'tech', 'pops', 'it', 'department']
        for term in search_terms:
            matches = [g for g in groups if term.lower() in g['displayName'].lower()]
            if matches:
                print(f"\nGroups containing '{term}':")
                for g in matches:
                    print(f"  - {g['displayName']} (ID: {g['id']})")
        
        return True
        
    except requests.exceptions.HTTPError as e:
        print(f"\n❌ Failed to fetch groups: {e}")
        print(f"Status Code: {e.response.status_code}")
        print(f"Response: {e.response.text}")
        
        if e.response.status_code == 403:
            print("\n⚠️  PERMISSION ERROR:")
            print("The app registration needs 'Group.Read.All' permission.")
            print("\nTo fix this:")
            print("1. Go to Azure Portal > App Registrations")
            print("2. Find app: 99b0438f-6b8c-41ff-86ee-0116481883ea")
            print("3. Go to 'API Permissions'")
            print("4. Add 'Microsoft Graph' > 'Application permissions' > 'Group.Read.All'")
            print("5. Click 'Grant admin consent'")
        
        return False
        
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False

def check_token_permissions(token):
    """Decode token to see what permissions are granted."""
    import base64
    import json
    
    try:
        # JWT tokens have 3 parts separated by dots
        parts = token.split('.')
        if len(parts) != 3:
            print("Invalid token format")
            return
        
        # Decode the payload (second part)
        # Add padding if needed
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        token_data = json.loads(decoded)
        
        print("\n" + "="*80)
        print("TOKEN INFORMATION:")
        print("="*80)
        print(f"App ID: {token_data.get('appid', 'N/A')}")
        print(f"Tenant ID: {token_data.get('tid', 'N/A')}")
        
        if 'roles' in token_data:
            print(f"\nGranted Permissions (roles):")
            for role in token_data['roles']:
                print(f"  ✓ {role}")
        else:
            print("\n⚠️  No roles found in token")
            
    except Exception as e:
        print(f"\nCould not decode token: {e}")

if __name__ == '__main__':
    print("="*80)
    print("MICROSOFT ENTRA ID GROUP PERMISSION TEST")
    print("="*80)
    print(f"\nTenant ID: {TENANT_ID}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"Client Secret: {'*' * 20}{CLIENT_SECRET[-4:]}")
    
    # Get token
    token = get_access_token()
    if not token:
        exit(1)
    
    # Check what permissions the token has
    check_token_permissions(token)
    
    # Test fetching groups
    success = test_groups_permission(token)
    
    if success:
        print("\n" + "="*80)
        print("✅ VERIFICATION COMPLETE - Groups API is working!")
        print("="*80)
        print("\nYour RiskGate app can now:")
        print("  • Pull groups from Entra ID")
        print("  • Scan entire groups for impossible travel")
        print("  • Select any group from the dropdown")
    else:
        print("\n" + "="*80)
        print("❌ VERIFICATION FAILED - Check permissions above")
        print("="*80)
