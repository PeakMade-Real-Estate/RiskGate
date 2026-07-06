"""
Quick diagnostic test for Microsoft Graph API connection.
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def test_graph_connection():
    """Test if we can authenticate and query Microsoft Graph."""
    
    tenant_id = os.environ.get('AZURE_TENANT_ID')
    client_id = os.environ.get('AZURE_CLIENT_ID')
    client_secret = os.environ.get('AZURE_CLIENT_SECRET')
    
    print("="*60)
    print("Microsoft Graph Connection Test")
    print("="*60)
    
    # Check credentials
    print(f"\n✓ AZURE_TENANT_ID: {tenant_id[:8]}..." if tenant_id else "✗ AZURE_TENANT_ID: NOT SET")
    print(f"✓ AZURE_CLIENT_ID: {client_id[:8]}..." if client_id else "✗ AZURE_CLIENT_ID: NOT SET")
    print(f"✓ AZURE_CLIENT_SECRET: {'*' * 8}..." if client_secret else "✗ AZURE_CLIENT_SECRET: NOT SET")
    
    if not all([tenant_id, client_id, client_secret]):
        print("\n❌ Missing credentials! Cannot proceed.")
        return False
    
    # Try to get access token
    print("\n📡 Requesting access token from Microsoft...")
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    
    try:
        response = requests.post(token_url, data=data, timeout=30)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data['access_token']
        print("✅ Successfully obtained access token!")
        
        # Try to make a simple Graph API call
        print("\n📡 Testing Graph API call (fetching groups)...")
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        graph_url = "https://graph.microsoft.com/v1.0/groups?$top=5"
        graph_response = requests.get(graph_url, headers=headers, timeout=30)
        
        if graph_response.status_code == 200:
            groups = graph_response.json().get('value', [])
            print(f"✅ Successfully queried Graph API! Found {len(groups)} groups")
            if groups:
                print("\nSample groups:")
                for group in groups[:3]:
                    print(f"  - {group.get('displayName', 'Unknown')}")
        elif graph_response.status_code == 403:
            print("❌ Permission denied (403)!")
            print("\nYour app registration needs these API permissions:")
            print("  - Group.Read.All")
            print("  - User.Read.All")
            print("  - AuditLog.Read.All")
            print("  - UserAuthenticationMethod.Read.All")
            print("\nMake sure to grant ADMIN CONSENT after adding permissions!")
            return False
        else:
            print(f"❌ Graph API error: {graph_response.status_code}")
            print(f"Response: {graph_response.text[:500]}")
            return False
        
        # Try to fetch sign-in logs
        print("\n📡 Testing sign-in logs access...")
        signin_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1"
        signin_response = requests.get(signin_url, headers=headers, timeout=30)
        
        if signin_response.status_code == 200:
            signin_logs = signin_response.json().get('value', [])
            print(f"✅ Successfully accessed sign-in logs! Found {len(signin_logs)} recent sign-in(s)")
        elif signin_response.status_code == 403:
            print("❌ Cannot access sign-in logs (403) - Missing AuditLog.Read.All permission!")
            print("Add this permission in Azure Portal and grant admin consent.")
            return False
        else:
            print(f"⚠️  Sign-in logs returned: {signin_response.status_code}")
            print(f"Response: {signin_response.text[:500]}")
        
        print("\n" + "="*60)
        print("✅ All tests passed! Your Microsoft Graph connection is working.")
        print("="*60)
        return True
        
    except requests.exceptions.HTTPError as e:
        print(f"❌ Authentication failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Status: {e.response.status_code}")
            print(f"Response: {e.response.text[:500]}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == '__main__':
    test_graph_connection()
