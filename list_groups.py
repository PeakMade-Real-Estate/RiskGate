"""
Helper script to list all Entra ID groups.
Use this to find the exact group name or ID for automatic scanning.

Usage:
    python list_groups.py                  # List all groups
    python list_groups.py "All"            # Search for groups containing "All"
"""
import sys
from pathlib import Path

# Add project directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app import create_app
from app.graph_client import GraphClient

def main():
    search_term = sys.argv[1].lower() if len(sys.argv) > 1 else None
    
    print("\n" + "="*70)
    if search_term:
        print(f"Searching Entra ID Groups for: '{sys.argv[1]}'")
    else:
        print("Available Entra ID Groups")
    print("="*70 + "\n")
    
    try:
        app = create_app()
        
        with app.app_context():
            graph_client = GraphClient()
            
            print("Fetching groups from Entra ID...\n")
            groups = graph_client.fetch_groups(max_results=999)
            
            if not groups:
                print("No groups found.")
                return
            
            # Filter by search term if provided
            if search_term:
                groups = [g for g in groups if search_term in g.get('displayName', '').lower()]
                if not groups:
                    print(f"No groups found matching '{sys.argv[1]}'")
                    return
            
            # Sort by display name
            groups.sort(key=lambda g: g.get('displayName', '').lower())
            
            print(f"Found {len(groups)} groups:\n")
            print(f"{'#':<4} {'Display Name':<45} {'Type':<20}")
            print("-" * 75)
            
            for i, group in enumerate(groups, 1):
                display_name = group.get('displayName', 'N/A')
                # Clean any problematic characters
                display_name = display_name.encode('ascii', 'replace').decode('ascii')
                display_name = display_name[:44]  # Truncate if too long
                
                group_types = group.get('groupTypes', [])
                
                # Determine type
                if 'Unified' in group_types:
                    group_type = 'Microsoft 365'
                elif group.get('mailEnabled') and group.get('securityEnabled'):
                    group_type = 'Mail-enabled Security'
                elif group.get('securityEnabled'):
                    group_type = 'Security'
                elif group.get('mailEnabled'):
                    group_type = 'Distribution'
                else:
                    group_type = 'Other'
                
                print(f"{i:<4} {display_name:<45} {group_type:<20}")
                
                # Show group ID (useful for exact matching)
                group_id = group.get('id', 'N/A')
                print(f"     ID: {group_id}")
                print(f"     Exact name: {group.get('displayName', 'N/A')}")
                print()
            
            print("="*70)
            print("To use a group for automatic scanning:")
            print("  Edit run_security_scan.py CONFIG section:")
            print("     CONFIG = {")
            print("         'target_type': 'group',")
            print("         'target_value': 'c97a854d-19e4-49e5-8245-268e338bb190',  # Use Group ID")
            print("     }")
            print("="*70 + "\n")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
