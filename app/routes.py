"""
Application routes - with Microsoft Graph API integration (in-memory storage).
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, flash, current_app
from datetime import datetime
import requests
import os
from app.graph_client import GraphClient
from app.mock_data import generate_mock_signin_logs, get_mock_users, get_mock_groups, get_mock_group_members, MOCK_GROUPS

bp = Blueprint('main', __name__)

# In-memory storage for scan results
scan_results = {
    'signin_logs': [],
    'impossible_logins': [],
    'alerts': [],
    'formatted_signin_logs': [],
    'last_scan': None,
    'scanned_users': [],  # List of all users that were scanned
    'users_with_activity': [],  # Users who had sign-ins
    'users_without_activity': []  # Users with no sign-ins in the period
}


@bp.route('/', methods=['GET'])
def root():
    """
    Root page - show dashboard with scan results from memory.
    """
    # Count impossible logins from memory
    impossible_count = len([log for log in scan_results['signin_logs'] 
                           if log.get('impossible_travel', False)])
    
    # Get current mode from session
    current_mode = 'MOCK DATA' if session.get('use_mock_data', False) else 'REAL DATA'
    
    # Get selected targets from session (default to first mock user if in mock mode)
    default_user = get_mock_users()[0]['userPrincipalName'] if session.get('use_mock_data', False) else None
    selected_targets = session.get('selected_targets', [default_user] if default_user else [])
    target_display = ', '.join(selected_targets) if isinstance(selected_targets, list) else selected_targets
    
    return render_template('riskgate_dashboard.html', 
                         impossible_logins_count=impossible_count,
                         target_user=target_display,
                         selected_targets=selected_targets,
                         recent_alerts=scan_results.get('alerts', [])[:10],
                         all_signin_logs=scan_results.get('formatted_signin_logs', []),
                         total_signin_count=len(scan_results.get('signin_logs', [])),
                         scan_triggered=False,
                         scanned_users=scan_results.get('scanned_users', []),
                         users_with_activity=scan_results.get('users_with_activity', []),
                         users_without_activity=scan_results.get('users_without_activity', []),
                         last_scan=scan_results['last_scan'],
                         current_mode=current_mode,
                         using_mock=session.get('use_mock_data', False))


@bp.route('/riskgate-dashboard', methods=['GET'])
def riskgate_dashboard():
    """
    Main RiskGate Dashboard.
    """
    return root()


@bp.route('/get-groups', methods=['GET'])
def get_groups():
    """
    AJAX endpoint to fetch groups from Entra ID.
    Returns JSON list of groups.
    """
    from flask import jsonify
    
    # Check if mock mode
    if session.get('use_mock_data', False):
        # Return mock groups from configurable list
        return jsonify({'groups': get_mock_groups()})
    
    try:
        graph_client = GraphClient()
        groups = graph_client.fetch_groups(max_results=999)
        
        # Get filtering configuration
        excluded_patterns = current_app.config.get('EXCLUDED_GROUP_PATTERNS', [])
        department_keywords = current_app.config.get('DEPARTMENT_KEYWORDS', None)
        exclude_dashes = current_app.config.get('EXCLUDE_GROUPS_WITH_DASHES', False)
        
        # Filter to show mail-enabled groups (same as what appears in Outlook)
        # This includes both Microsoft 365 groups and distribution lists
        formatted_groups = []
        for g in groups:
            # Must be mail-enabled (has an email address)
            if not g.get('mail') or not g.get('mailEnabled'):
                continue
            
            display_name = g.get('displayName', 'Unknown')
            display_lower = display_name.lower()
            
            # Exclude groups matching noise patterns (test, temp, archive, etc.)
            if any(pattern in display_lower for pattern in excluded_patterns):
                continue
            
            # Exclude groups with dashes (often property/project specific)
            if exclude_dashes and '-' in display_name:
                continue
            
            # If department keywords configured, only include groups matching keywords
            if department_keywords:
                # Check if any department keyword appears in the display name
                if not any(keyword in display_lower for keyword in department_keywords):
                    continue
            
            # Check member count - exclude groups with zero members
            member_count = graph_client.get_group_member_count(g.get('id'))
            if member_count == 0:
                continue
            
            # Add to results - only main department groups with members
            formatted_groups.append({
                'id': g.get('id'),
                'displayName': display_name,
                'mail': g.get('mail', ''),
                'securityEnabled': g.get('securityEnabled', False),
                'memberCount': member_count
            })
        
        return jsonify({'groups': formatted_groups})
    except Exception as e:
        current_app.logger.error(f"Failed to fetch groups: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/get-mock-users', methods=['GET'])
def get_available_mock_users():
    """
    AJAX endpoint to get list of available mock users.
    Only works in mock mode.
    Returns JSON list of mock users with email, name, department.
    """
    from flask import jsonify
    
    if session.get('use_mock_data', False):
        return jsonify({'users': get_mock_users()})
    else:
        return jsonify({'error': 'Only available in mock mode'}), 400


@bp.route('/get-group-members/<group_id>', methods=['GET'])
def get_group_members(group_id):
    """
    AJAX endpoint to fetch members of a specific group.
    Returns JSON list of users.
    """
    from flask import jsonify
    
    # Check if mock mode
    if session.get('use_mock_data', False):
        # Return mock users from configurable list
        members = get_mock_group_members(group_id)
        return jsonify({'members': members})
    
    try:
        graph_client = GraphClient()
        members = graph_client.fetch_group_members(group_id)
        
        # Format for list
        formatted_members = [
            {
                'userPrincipalName': m.get('userPrincipalName', ''),
                'displayName': m.get('displayName', 'Unknown'),
                'mail': m.get('mail', '')
            }
            for m in members
            if m.get('userPrincipalName')  # Only include if has UPN
        ]
        
        return jsonify({'members': formatted_members})
    except Exception as e:
        current_app.logger.error(f"Failed to fetch group members: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/toggle-mode', methods=['POST'])
def toggle_mode():
    """
    Toggle between real Entra data and mock test data.
    """
    current_mode = session.get('use_mock_data', False)
    session['use_mock_data'] = not current_mode
    
    if session['use_mock_data']:
        flash('🧪 Switched to MOCK DATA mode - will use test data with impossible travel scenarios', 'info')
    else:
        flash('🔐 Switched to REAL DATA mode - will query Microsoft Entra ID', 'info')
    
    return redirect(url_for('main.root'))


@bp.route('/clear-scan', methods=['POST'])
def clear_scan():
    """
    Clear all scan results from memory.
    """
    scan_results['signin_logs'] = []
    scan_results['impossible_logins'] = []
    scan_results['scanned_users'] = []
    scan_results['users_with_activity'] = []
    scan_results['users_without_activity'] = []
    scan_results['alerts'] = []
    scan_results['formatted_signin_logs'] = []
    scan_results['last_scan'] = None
    
    session.pop('selected_targets', None)
    
    flash('🗑️ Scan results cleared', 'info')
    return redirect(url_for('main.root'))


@bp.route('/scan', methods=['POST'])
def scan_entra():
    """
    Scan Microsoft Entra for sign-in logs and detect anomalies.
    Results stored in memory.
    
    Supports scanning:
    - Single user
    - Multiple users
    - Entire group (fetches all members)
    
    Uses mock data if:
    - Session toggle is set to mock mode
    - TESTING_MODE=true in .env
    - Graph API returns permission errors
    """
    # Get scan targets from form
    scan_type = request.form.get('scan_type', 'user')  # 'user' or 'group'
    default_user = get_mock_users()[0]['userPrincipalName'] if session.get('use_mock_data', False) else ''
    target_value = request.form.get('target_value', default_user)
    
    use_mock_data = False
    mock_reason = None
    
    # Check if mock mode is enabled via session toggle
    session_mock_mode = session.get('use_mock_data', False)
    
    # Check if testing mode is enabled in .env
    testing_mode = os.getenv('TESTING_MODE', 'false').lower() == 'true'
    
    try:
        # Determine target users
        target_users = []
        if scan_type == 'group':
            # Fetch group members
            if session_mock_mode or testing_mode:
                # Get members from mock group (supports ID or name search)
                members = get_mock_group_members(target_value)
                # If not found by ID, try searching by name
                if not members:
                    mock_groups = get_mock_groups()
                    for group in MOCK_GROUPS:
                        if target_value.lower() in group['displayName'].lower():
                            members = get_mock_group_members(group['id'])
                            break
                target_users = [m['userPrincipalName'] for m in members]
            else:
                graph_client = GraphClient()
                group_id = target_value
                
                # Check if target_value looks like a GUID (group ID)
                # If not, search for group by name
                import re
                guid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
                
                if not guid_pattern.match(target_value):
                    # Not a GUID - search for group by name
                    current_app.logger.info(f"Searching for group by name: {target_value}")
                    all_groups = graph_client.fetch_groups(max_results=999)
                    matching_groups = [g for g in all_groups if target_value.lower() in g.get('displayName', '').lower()]
                    
                    if not matching_groups:
                        flash(f'⚠️ No group found matching "{target_value}"', 'warning')
                        return redirect(url_for('main.root'))
                    elif len(matching_groups) > 1:
                        group_names = ', '.join([g['displayName'] for g in matching_groups[:5]])
                        flash(f'⚠️ Multiple groups found matching "{target_value}": {group_names}. Please be more specific.', 'warning')
                        return redirect(url_for('main.root'))
                    
                    # Use the matching group
                    group_id = matching_groups[0]['id']
                    current_app.logger.info(f"Found group: {matching_groups[0]['displayName']} (ID: {group_id})")
                
                members = graph_client.fetch_group_members(group_id)
                target_users = [m.get('userPrincipalName') for m in members if m.get('userPrincipalName')]
                current_app.logger.info(f"Group has {len(target_users)} members")
        else:
            # Single user or comma-separated list
            target_users = [u.strip() for u in target_value.split(',') if u.strip()]
        
        # Store selected targets in session
        session['selected_targets'] = target_users
        
        if not target_users:
            flash('⚠️ No users selected for scanning', 'warning')
            return redirect(url_for('main.root'))
        
        # Collect all sign-in logs for all target users
        all_signin_logs = []
        
        if session_mock_mode:
            current_app.logger.info("Session mock mode enabled - using mock data")
            use_mock_data = True
            mock_reason = "Mock data mode enabled via toggle"
            # Generate mock data for each user
            for user in target_users:
                all_signin_logs.extend(generate_mock_signin_logs(target_user=user, days_back=7))
            user_logs = all_signin_logs
        elif testing_mode:
            current_app.logger.info("TESTING_MODE enabled - using mock data")
            use_mock_data = True
            mock_reason = "Testing mode enabled in .env"
            # Generate mock data for each user
            for user in target_users:
                all_signin_logs.extend(generate_mock_signin_logs(target_user=user, days_back=7))
            user_logs = all_signin_logs
        else:
            # Production mode - only use real Graph API data
            use_mock_data = False
            graph_client = GraphClient()
            
            # Fetch sign-in logs for each target user
            current_app.logger.info(f"Scanning Entra ID for {len(target_users)} user(s)...")
            
            for user in target_users:
                try:
                    logs = graph_client.fetch_signin_logs(hours_back=24, max_results=1000, user_principal_name=user)
                    if logs:
                        all_signin_logs.extend(logs)
                        current_app.logger.info(f"Retrieved {len(logs)} sign-in logs for {user}")
                    else:
                        current_app.logger.info(f"No logs found for {user}")
                except Exception as e:
                    current_app.logger.error(f"Error fetching logs for {user}: {e}")
                    continue
            
            if not all_signin_logs:
                # No data from API
                current_app.logger.warning("No data returned from Graph API for any user")
                flash(f'⚠️ No sign-in logs returned from Microsoft Graph API. Check permissions and retry.', 'warning')
                return redirect(url_for('main.root'))
            
            current_app.logger.info(f"Retrieved {len(all_signin_logs)} total sign-in logs for {len(target_users)} users")
            user_logs = all_signin_logs
        
        # Analyze for impossible travel with smart baseline detection
        # The analysis automatically identifies frequently-used locations (home/office)
        # and suppresses alerts for travel to/from those trusted locations
        impossible_logins = analyze_impossible_travel(user_logs)
        
        # Store in memory
        scan_results['signin_logs'] = user_logs
        scan_results['impossible_logins'] = impossible_logins
        scan_results['last_scan'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        scan_results['using_mock_data'] = use_mock_data
        
        # Check for MFA changes after impossible travel (critical alert escalation)
        try:
            audit_logs = graph_client.fetch_audit_logs(hours_back=168) if not use_mock_data else []
            mfa_change_times = set()
            if audit_logs:
                for audit in audit_logs:
                    if audit.get('activityDisplayName') in ['User registered security info', 'User changed default security info', 
                                                              'User deleted security info']:
                        from dateutil import parser
                        mfa_change_times.add(parser.parse(audit.get('activityDateTime')))
        except Exception as e:
            current_app.logger.warning(f"Could not fetch MFA audit logs: {e}")
            mfa_change_times = set()
        
        # Generate detailed alerts with full location and device info
        alerts = []
        for login in impossible_logins:
            location = login.get('location', {})
            device = login.get('deviceDetail', {})
            city = location.get('city', 'Unknown')
            country = location.get('countryOrRegion', 'Unknown')
            
            # Get calculated risk metrics
            distance = login.get('travel_distance_miles', 0)
            time_between = login.get('time_between_hours', 0)
            speed = login.get('required_speed_mph', 0)
            risk_level = login.get('risk_level', 'Critical')
            prev_location = login.get('previous_location', 'Unknown')
            travel_type = login.get('travel_type', 'International')
            
            # Check if MFA change occurred shortly after this login
            from dateutil import parser
            login_time = parser.parse(login.get('createdDateTime'))
            mfa_changed_after = any(abs((mfa_time - login_time).total_seconds()) < 3600 for mfa_time in mfa_change_times)
            
            if mfa_changed_after:
                risk_level = 'CRITICAL - MFA Changed'
                finding = '🚨 CRITICAL: Impossible Travel + MFA Change'
            else:
                finding = f'Impossible Travel Detected ({risk_level})'
            
            alerts.append({
                'time': login.get('createdDateTime', 'N/A')[:19].replace('T', ' '),
                'user': login.get('userPrincipalName', 'N/A'),
                'finding': finding,
                'risk_level': risk_level,
                'travel_type': travel_type,
                'location': f"{city}, {country}",
                'previous_location': prev_location,
                'distance_miles': distance,
                'time_between_hours': time_between,
                'required_speed_mph': speed,
                'device': f"{device.get('operatingSystem', 'Unknown')} - {device.get('browser', 'Unknown')}",
                'ip_address': login.get('ipAddress', 'N/A'),
                'app': login.get('appDisplayName', 'N/A'),
                'details': f"Travel from {prev_location} to {city}, {country}: {distance} miles in {time_between} hrs ({speed} mph required)",
                'status': 'Open'
            })
        
        # Sort alerts by user first (alphabetically), then by time within each user
        # This groups all alerts for each person together for easier review
        alerts.sort(key=lambda x: (x['user'], x['time']), reverse=False)
        scan_results['alerts'] = alerts
        
        # Format ALL sign-in logs for display
        formatted_signin_logs = []
        for log in user_logs:
            location = log.get('location', {})
            device = log.get('deviceDetail', {})
            formatted_signin_logs.append({
                'time': log.get('createdDateTime', 'N/A')[:19].replace('T', ' '),
                'user': log.get('userPrincipalName', 'N/A'),
                'location': f"{location.get('city', 'Unknown')}, {location.get('countryOrRegion', 'Unknown')}",
                'device': f"{device.get('operatingSystem', 'Unknown')} / {device.get('browser', 'Unknown')}",
                'ip_address': log.get('ipAddress', 'N/A'),
                'app': log.get('appDisplayName', 'N/A'),
                'status': log.get('status', {}).get('errorCode', 0),
                'is_impossible': log.get('impossible_travel', False)
            })
        
        # Sort sign-in logs by user first (alphabetically), then by time within each user
        # This groups all logs for each person together for easier review
        # Track which users had activity
        users_with_logs = set(log['user'] for log in formatted_signin_logs)
        users_without_logs = [user for user in target_users if user not in users_with_logs]
        
        # Store results
        scan_results['formatted_signin_logs'] = formatted_signin_logs
        scan_results['scanned_users'] = target_users
        scan_results['users_with_activity'] = sorted(list(users_with_logs))
        scan_results['users_without_activity'] = sorted(users_without_logs)
        
        # Show appropriate message
        user_count_text = f"{len(target_users)} user{'s' if len(target_users) != 1 else ''}"
        activity_summary = f"{len(users_with_logs)} with activity, {len(users_without_logs)} without activity"
        
        if use_mock_data:
            flash(f'⚠️ DEMO MODE: Using mock data ({mock_reason}). Scanned {user_count_text} ({activity_summary}), found {len(user_logs)} sign-ins with {len(impossible_logins)} impossible travel events.', 'warning')
        else:
            flash(f'✅ Scan complete! Scanned {user_count_text} ({activity_summary}), found {len(user_logs)} sign-ins with {len(impossible_logins)} impossible travel events.', 'success')
        
    except Exception as e:
        current_app.logger.error(f"Scan failed: {e}")
        flash(f'Scan failed: {str(e)}', 'danger')
    
    return redirect(url_for('main.root'))


def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two points using Haversine formula.
    Returns distance in miles.
    """
    from math import radians, sin, cos, sqrt, atan2
    
    # Earth radius in miles
    R = 3959
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    distance = R * c
    
    return distance


def analyze_impossible_travel(signin_logs):
    """
    Analyze sign-in logs for impossible travel patterns.
    Calculates geographic distance and required travel speed.
    
    Risk Levels:
    - Normal: < 500 mph (realistic travel)
    - Suspicious: 500-1000 mph (flag for review)  
    - High Risk: 1000+ mph (impossible for commercial travel)
    - Critical: > 10,000 mph (extreme impossible travel)
    
    Smart Detection:
    - Domestic US travel: More lenient (threshold 1000+ mph) - recognizes remote workers
    - International travel: Strict (threshold 500+ mph) - likely account compromise
    - Trusted locations: Learns baseline locations for each user to prevent false positives
    """
    impossible = []
    
    # Track location frequency for each user to identify baseline locations
    user_locations = {}  # {user_email: {(lat, lon): count}}
    
    # First pass: Build location frequency map
    for log in signin_logs:
        user = log.get('userPrincipalName', '')
        loc = log.get('location', {})
        coords = loc.get('geoCoordinates', {})
        lat = coords.get('latitude')
        lon = coords.get('longitude')
        
        if lat and lon and user:
            if user not in user_locations:
                user_locations[user] = {}
            
            # Round coordinates to ~5 miles precision to group nearby logins
            rounded = (round(lat, 1), round(lon, 1))
            user_locations[user][rounded] = user_locations[user].get(rounded, 0) + 1
    
    # Determine trusted locations (appeared 3+ times)
    trusted_locations = {}  # {user_email: set of (lat, lon) tuples}
    min_logins_for_trust = 3
    
    for user, locations in user_locations.items():
        trusted_locations[user] = set()
        for coords, count in locations.items():
            if count >= min_logins_for_trust:
                trusted_locations[user].add(coords)
                current_app.logger.info(
                    f"Trusted location identified for {user}: {coords} ({count} logins)"
                )
    
    # Sort by time
    sorted_logs = sorted(signin_logs, key=lambda x: x.get('createdDateTime', ''))
    
    for i in range(1, len(sorted_logs)):
        current = sorted_logs[i]
        previous = sorted_logs[i-1]
        
        current_loc = current.get('location', {})
        previous_loc = previous.get('location', {})
        
        # Get coordinates
        curr_lat = current_loc.get('geoCoordinates', {}).get('latitude')
        curr_lon = current_loc.get('geoCoordinates', {}).get('longitude')
        prev_lat = previous_loc.get('geoCoordinates', {}).get('latitude')
        prev_lon = previous_loc.get('geoCoordinates', {}).get('longitude')
        
        # Get countries
        curr_country = current_loc.get('countryOrRegion', '')
        prev_country = previous_loc.get('countryOrRegion', '')
        
        # Skip if coordinates missing
        if not all([curr_lat, curr_lon, prev_lat, prev_lon]):
            continue
        
        # Calculate distance
        distance_miles = calculate_distance(prev_lat, prev_lon, curr_lat, curr_lon)
        
        # Skip if same location (within 10 miles)
        if distance_miles < 10:
            continue
        
        # Calculate time difference
        from dateutil import parser
        curr_time = parser.parse(current.get('createdDateTime'))
        prev_time = parser.parse(previous.get('createdDateTime'))
        time_diff_hours = (curr_time - prev_time).total_seconds() / 3600
        
        # Avoid division by zero
        if time_diff_hours < 0.01:  # Less than 36 seconds
            time_diff_hours = 0.01
        
        # Calculate required speed
        required_speed_mph = distance_miles / time_diff_hours
        
        # Check if either location is a trusted baseline for this user
        user = current.get('userPrincipalName', '')
        curr_rounded = (round(curr_lat, 1), round(curr_lon, 1))
        prev_rounded = (round(prev_lat, 1), round(prev_lon, 1))
        
        is_current_trusted = curr_rounded in trusted_locations.get(user, set())
        is_previous_trusted = prev_rounded in trusted_locations.get(user, set())
        
        if is_current_trusted or is_previous_trusted:
            # Suppress alert - user is returning to or leaving a trusted location
            location_name = current_loc.get('city', current_loc.get('countryOrRegion', 'location'))
            current_app.logger.info(
                f"Suppressed travel alert for {user}: {location_name} is a trusted baseline location "
                f"({required_speed_mph:.0f} mph would have triggered alert)"
            )
            continue  # Skip flagging this as impossible travel
        
        # Determine if domestic or international travel
        is_domestic_us = (curr_country == 'US' and prev_country == 'US')
        is_same_country = (curr_country == prev_country)
        
        # Apply different thresholds based on travel type
        # Domestic US travel: Allow up to 1000 mph (cross-country flights, remote workers)
        # International travel: Strict 500 mph threshold (likely compromise)
        threshold = 1000 if is_domestic_us else 500
        
        # Determine risk level
        if required_speed_mph > threshold:
            travel_type = 'Domestic' if is_same_country else 'International'
            
            risk_level = 'Suspicious'
            if required_speed_mph > 1000:
                risk_level = 'High Risk'
            if required_speed_mph > 10000:
                risk_level = 'Critical'
            
            # Add extra context for domestic US travel
            if is_domestic_us and required_speed_mph < 1500:
                risk_level = f'Suspicious ({travel_type} US)'
            
            current['impossible_travel'] = True
            current['travel_distance_miles'] = round(distance_miles, 1)
            current['time_between_hours'] = round(time_diff_hours, 2)
            current['required_speed_mph'] = round(required_speed_mph, 1)
            current['risk_level'] = risk_level
            current['travel_type'] = travel_type
            current['previous_location'] = f"{previous_loc.get('city', 'Unknown')}, {previous_loc.get('countryOrRegion', 'Unknown')}"
            impossible.append(current)
    
    return impossible


@bp.route('/report', methods=['POST'])
def report_findings():
    """
    Report findings (placeholder for SharePoint integration).
    """
    flash('Report feature - will integrate with SharePoint in future', 'info')
    return redirect(url_for('main.root'))


@bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    """
    return {
        'status': 'ok', 
        'message': 'RiskGate is running (in-memory mode)',
        'last_scan': scan_results['last_scan'],
        'signin_logs_count': len(scan_results['signin_logs'])
    }, 200


@bp.route('/test-graph', methods=['GET'])
def test_graph():
    """
    Test Microsoft Graph API connection.
    """
    try:
        graph_client = GraphClient()
        token = graph_client._get_access_token()
        
        if not token:
            return {
                'status': 'error',
                'message': 'Failed to get access token',
                'tenant_id': graph_client.tenant_id[:8] + '...',
                'client_id': graph_client.client_id[:8] + '...'
            }, 500
        
        # Test 1: Try to fetch sign-in logs (longer time range)
        logs = graph_client.fetch_signin_logs(hours_back=720, max_results=10)  # 30 days
        
        # Test 2: Try direct API call to check permissions
        headers = {'Authorization': f'Bearer {token}'}
        test_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1"
        test_response = requests.get(test_url, headers=headers, timeout=30)
        
        api_response = test_response.json() if test_response.ok else test_response.text
        
        return {
            'status': 'success' if test_response.ok else 'permission_error',
            'message': 'Graph API connection successful' if test_response.ok else 'Permission denied - need admin consent',
            'logs_found': len(logs),
            'sample_users': [log.get('userPrincipalName', 'Unknown') for log in logs[:3]] if logs else [],
            'api_status_code': test_response.status_code,
            'api_response': api_response if not test_response.ok else 'OK',
            'time_range': '30 days',
            'fix': 'Go to Azure Portal > App Registration > API Permissions > Add "AuditLog.Read.All" > Grant admin consent' if not test_response.ok else None
        }, 200 if test_response.ok else 403
        
    except Exception as e:
        current_app.logger.error(f"Graph API test failed: {e}")
        import traceback
        return {
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }, 500
