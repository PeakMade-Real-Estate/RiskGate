"""
Debug script to check what the Technology group actually contains.
"""
from app import create_app
from app.graph_client import GraphClient

def test_technology_group():
    app = create_app()
    
    with app.app_context():
        client = GraphClient()
        
        # First, find all groups with "Technology" in the name
        print("=" * 80)
        print("SEARCHING FOR 'TECHNOLOGY' GROUPS")
        print("=" * 80)
        
        groups = client.fetch_groups(max_results=999)
        tech_groups = [g for g in groups if 'technology' in g.get('displayName', '').lower()]
        
        print(f"\nFound {len(tech_groups)} groups with 'Technology' in name:")
        for g in tech_groups:
            print(f"\n  Name: {g.get('displayName')}")
            print(f"  ID: {g.get('id')}")
            print(f"  Mail: {g.get('mail', 'N/A')}")
            print(f"  Type: {g.get('groupTypes', [])}")
            print(f"  Security Enabled: {g.get('securityEnabled', False)}")
            print(f"  Mail Enabled: {g.get('mailEnabled', False)}")
        
        # Now check members for each
        print("\n" + "=" * 80)
        print("CHECKING MEMBERS FOR EACH GROUP")
        print("=" * 80)
        
        for g in tech_groups:
            group_id = g.get('id')
            print(f"\n\nGroup: {g.get('displayName')}")
            print(f"Group ID: {group_id}")
            
            try:
                # Get members (filtered to users only)
                members = client.fetch_group_members(group_id)
                print(f"  Direct User Members: {len(members)}")
                
                if members:
                    for m in members[:5]:  # Show first 5
                        print(f"    - {m.get('displayName')} ({m.get('mail')})")
                    if len(members) > 5:
                        print(f"    ... and {len(members) - 5} more")
                
                # Try to get ALL members including groups
                print("\n  Checking ALL members (including nested groups):")
                response = client._make_request(f'https://graph.microsoft.com/v1.0/groups/{group_id}/members')
                all_members = response.get('value', [])
                print(f"  Total Members (all types): {len(all_members)}")
                
                for member in all_members[:10]:
                    member_type = member.get('@odata.type', 'unknown')
                    name = member.get('displayName', member.get('userPrincipalName', 'Unknown'))
                    print(f"    - {name} (Type: {member_type})")
                
            except Exception as e:
                print(f"  ERROR: {e}")

if __name__ == '__main__':
    test_technology_group()
