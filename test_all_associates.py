from app import create_app
from app.graph_client import GraphClient

app = create_app()
with app.app_context():
    gc = GraphClient()
    groups = gc.fetch_groups(999)
    
    print(f"Total groups returned: {len(groups)}\n")
    
    # Find "All Associates"
    all_assoc = [g for g in groups if 'assoc' in g.get('displayName', '').lower()]
    
    print(f"Found {len(all_assoc)} group(s) with 'assoc' in name:")
    for g in all_assoc:
        print(f"\n  Name: {g.get('displayName')}")
        print(f"  ID: {g.get('id')}")
        print(f"  mailEnabled: {g.get('mailEnabled')}")
        print(f"  securityEnabled: {g.get('securityEnabled')}")
        print(f"  groupTypes: {g.get('groupTypes')}")
        print(f"  mail: {g.get('mail')}")
    
    # Try to fetch the specific group by ID
    print("\n\n=== Trying to fetch All Associates by ID ===")
    try:
        members = gc.fetch_group_members('c97a854d-19e4-49e5-8245-268e338bb190')
        print(f"Successfully fetched group members: {len(members)} users")
    except Exception as e:
        print(f"Error: {e}")
