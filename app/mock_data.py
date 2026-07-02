"""
Mock data generator for local testing without Azure Graph API.
Generates realistic sign-in logs with impossible travel scenarios.
"""
from datetime import datetime, timedelta
import random
import hashlib

# Configurable list of mock users - easily add/remove users for testing
MOCK_USERS = [
    {'userPrincipalName': 'tgaskins@peakmade.com', 'displayName': 'Tom Gaskins', 'department': 'IT'},
    {'userPrincipalName': 'jbehner@peakmade.com', 'displayName': 'John Behner', 'department': 'Finance'},
    {'userPrincipalName': 'mdoe@peakmade.com', 'displayName': 'Mary Doe', 'department': 'HR'},
    {'userPrincipalName': 'sjones@peakmade.com', 'displayName': 'Sarah Jones', 'department': 'Sales'},
    {'userPrincipalName': 'rsmith@peakmade.com', 'displayName': 'Robert Smith', 'department': 'Engineering'},
]

# Mock groups with members - matching organizational groups
MOCK_GROUPS = [
    {
        'id': 'mock-group-technology',
        'displayName': 'Technology',
        'mail': 'technology@peakmade.com',
        'members': ['tgaskins@peakmade.com', 'rsmith@peakmade.com']
    },
    {
        'id': 'mock-group-development',
        'displayName': 'Development',
        'mail': 'development@peakmade.com',
        'members': ['rsmith@peakmade.com']
    },
    {
        'id': 'mock-group-accounting',
        'displayName': 'Accounting',
        'mail': 'accounting@peakmade.com',
        'members': ['jbehner@peakmade.com']
    },
    {
        'id': 'mock-group-pops',
        'displayName': 'POPS',
        'mail': 'pops@peakmade.com',
        'members': ['sjones@peakmade.com', 'mdoe@peakmade.com']
    }
]


def get_mock_users():
    """
    Get list of available mock users.
    Returns list of dicts with userPrincipalName, displayName, department.
    """
    return MOCK_USERS


def get_mock_groups():
    """
    Get list of available mock groups with member counts.
    """
    return [
        {
            'id': g['id'],
            'displayName': g['displayName'],
            'mail': g.get('mail', ''),
            'memberCount': len(g['members'])
        }
        for g in MOCK_GROUPS
    ]


def get_mock_group_members(group_id):
    """
    Get members of a specific mock group.
    """
    for group in MOCK_GROUPS:
        if group['id'] == group_id:
            # Return full user info for members
            return [
                user for user in MOCK_USERS
                if user['userPrincipalName'] in group['members']
            ]
    return []


def _generate_user_id(email):
    """Generate consistent mock user ID from email using hash."""
    return 'mock-user-' + hashlib.md5(email.encode()).hexdigest()[:12]


def generate_mock_signin_logs(target_user, days_back=7):
    """
    Generate realistic mock sign-in logs for testing.
    Includes some impossible travel scenarios.
    """
    locations = [
        {'city': 'Seattle', 'state': 'Washington', 'countryOrRegion': 'US', 'lat': 47.6062, 'lon': -122.3321},
        {'city': 'New York', 'state': 'New York', 'countryOrRegion': 'US', 'lat': 40.7128, 'lon': -74.0060},
        {'city': 'London', 'state': None, 'countryOrRegion': 'GB', 'lat': 51.5074, 'lon': -0.1278},
        {'city': 'Tokyo', 'state': None, 'countryOrRegion': 'JP', 'lat': 35.6762, 'lon': 139.6503},
        {'city': 'Sydney', 'state': 'New South Wales', 'countryOrRegion': 'AU', 'lat': -33.8688, 'lon': 151.2093},
        {'city': 'Paris', 'state': None, 'countryOrRegion': 'FR', 'lat': 48.8566, 'lon': 2.3522},
        {'city': 'Dubai', 'state': None, 'countryOrRegion': 'AE', 'lat': 25.2048, 'lon': 55.2708},
    ]
    
    apps = [
        'Microsoft Teams',
        'Office 365',
        'Azure Portal',
        'Outlook Web App',
        'SharePoint',
        'Power BI',
        'Microsoft Graph'
    ]
    
    browsers = [
        'Edge 120.0',
        'Chrome 119.0',
        'Firefox 121.0',
        'Safari 17.1'
    ]
    
    logs = []
    current_time = datetime.utcnow()
    user_id = _generate_user_id(target_user)
    
    # Generate normal sign-ins
    for i in range(15):
        timestamp = current_time - timedelta(hours=random.randint(1, days_back * 24))
        location = random.choice(locations[:3])  # Mostly US locations
        
        log = {
            'id': f'mock-signin-{target_user}-{i}',
            'createdDateTime': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'userPrincipalName': target_user,
            'userId': user_id,
            'appDisplayName': random.choice(apps),
            'clientAppUsed': 'Browser',
            'deviceDetail': {
                'browser': random.choice(browsers),
                'operatingSystem': 'Windows 11'
            },
            'location': {
                'city': location['city'],
                'state': location['state'],
                'countryOrRegion': location['countryOrRegion'],
                'geoCoordinates': {
                    'latitude': location['lat'],
                    'longitude': location['lon']
                }
            },
            'ipAddress': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'status': {
                'errorCode': 0,
                'failureReason': None
            },
            'riskDetail': 'none',
            'riskLevelAggregated': 'none',
            'riskLevelDuringSignIn': 'none',
            'riskState': 'none'
        }
        logs.append(log)
    
    # Add IMPOSSIBLE TRAVEL scenarios (different countries within 2 hours)
    # Scenario 1: Seattle -> Tokyo (1 hour apart - impossible!)
    impossible_time_1 = current_time - timedelta(hours=5)
    logs.append({
        'id': f'mock-signin-impossible-1-{target_user}',
        'createdDateTime': impossible_time_1.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': user_id,
        'appDisplayName': 'Office 365',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Chrome 119.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[0],  # Seattle
        'ipAddress': '192.168.1.100',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    logs.append({
        'id': f'mock-signin-impossible-2-{target_user}',
        'createdDateTime': (impossible_time_1 + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': user_id,
        'appDisplayName': 'Azure Portal',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Chrome 119.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[3],  # Tokyo
        'ipAddress': '103.45.67.89',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    # Scenario 2: London -> Sydney (2 hours apart - impossible!)
    impossible_time_2 = current_time - timedelta(hours=12)
    logs.append({
        'id': f'mock-signin-impossible-3-{target_user}',
        'createdDateTime': impossible_time_2.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': user_id,
        'appDisplayName': 'Microsoft Teams',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Edge 120.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[2],  # London
        'ipAddress': '81.2.69.142',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    logs.append({
        'id': f'mock-signin-impossible-4-{target_user}',
        'createdDateTime': (impossible_time_2 + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': user_id,
        'appDisplayName': 'SharePoint',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Edge 120.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[4],  # Sydney
        'ipAddress': '1.129.88.15',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    # Sort by time (newest first)
    logs.sort(key=lambda x: x['createdDateTime'], reverse=True)
    
    return logs


def generate_mock_user_info(email):
    """Generate mock user information with consistent ID."""
    # Find user in MOCK_USERS list
    for user in MOCK_USERS:
        if user['userPrincipalName'] == email:
            return {
                'id': _generate_user_id(email),
                'userPrincipalName': email,
                'displayName': user['displayName'],
                'mail': email,
                'department': user.get('department', 'Unknown'),
                'accountEnabled': True
            }
    
    # If not in list, generate generic info
    return {
        'id': _generate_user_id(email),
        'userPrincipalName': email,
        'displayName': email.split('@')[0].title(),
        'mail': email,
        'accountEnabled': True
    }
