"""Check for invalid alerts in scan results."""
import json

with open('automatic_scan_results.json', 'r') as f:
    data = json.load(f)

print("Checking invalid alerts...\n")

invalid_alerts = []
for alert in data.get('impossible_login_details', []):
    locations = alert.get('location', {})
    prev_locations = alert.get('prev_location', {})
    
    city = locations.get('city', 'Unknown')
    prev_city = prev_locations.get('city', 'Unknown')
    distance = alert.get('distance_miles', 0)
    
    if (city == 'Unknown' or prev_city == 'Unknown') and distance == 0:
        invalid_alerts.append({
            'user': alert.get('userPrincipalName'),
            'city': city,
            'prev_city': prev_city,
            'distance': distance,
            'speed': alert.get('required_speed_mph', 0),
            'has_coords': bool(locations.get('geoCoordinates')),
            'has_prev_coords': bool(prev_locations.get('geoCoordinates'))
        })

print(f"Found {len(invalid_alerts)} invalid alerts out of {len(data.get('impossible_login_details', []))} total")
print("\nSample invalid alerts:")
for alert in invalid_alerts[:5]:
    print(f"  User: {alert['user']}")
    print(f"    Location: {alert['prev_city']} → {alert['city']}")
    print(f"    Distance: {alert['distance']} mi")
    print(f"    Speed: {alert['speed']:.0f} mph")
    print(f"    Has coords: prev={alert['has_prev_coords']}, current={alert['has_coords']}")
    print()
