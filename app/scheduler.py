"""
Background scheduler for automatic Entra ID scanning.

Runs periodic scans of all associates to detect impossible travel and security anomalies.
Uses APScheduler to run background tasks without blocking the Flask app.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

scheduler = None


def perform_automatic_scan(app):
    """
    Execute an automatic scan of all configured users/groups.
    This function runs in the background via APScheduler.
    
    Args:
        app: Flask application instance (needed for app context)
    """
    with app.app_context():
        from app.models_new import ScanRun, UserIdentity, EntraSignInEvent, EntraSecurityAlert
        from app import db
        from app.graph_client import GraphClient
        from app.risk_detection import analyze_impossible_travel
        import json
        
        # Get scan target from configuration
        target_type = app.config.get('SCHEDULER_TARGET_TYPE', 'group')  # 'user', 'group', or 'all_users'
        target_value = app.config.get('SCHEDULER_TARGET_VALUE', '')  # User email or group name
        
        logger.info(f"Starting automatic scan - target: {target_type} = {target_value}")
        print(f"\n{'='*70}")
        print(f"[SCAN] Starting automatic scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[SCAN] Target: {target_type}")
        if target_value:
            print(f"[SCAN] Value: {target_value}")
        print(f"{'='*70}\n")
        
        # Create scan run record
        scan_run = ScanRun(
            scan_type='automatic',
            target_type=target_type,
            target_value=target_value,
            started_at=datetime.utcnow(),
            status='running',
            data_source='graph_api'
        )
        db.session.add(scan_run)
        db.session.commit()
        
        try:
            graph_client = GraphClient()
            
            # Determine which users to scan
            target_users = []
            
            if target_type == 'group':
                # Fetch group members
                logger.info(f"Fetching members of group: {target_value}")
                print(f"\n[SCAN] Fetching members of group: {target_value}")
                
                # If target_value is a group name (not GUID), search for it
                import re
                guid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
                
                group_name = target_value
                if not guid_pattern.match(target_value):
                    # Search for group by name
                    print(f"[SCAN] Looking up group by name...")
                    all_groups = graph_client.fetch_groups(max_results=999)
                    matching_groups = [g for g in all_groups if target_value.lower() in g.get('displayName', '').lower()]
                    
                    if not matching_groups:
                        raise Exception(f"Group not found: {target_value}")
                    elif len(matching_groups) > 1:
                        raise Exception(f"Multiple groups match '{target_value}' - be more specific")
                    
                    group_id = matching_groups[0]['id']
                    group_name = matching_groups[0]['displayName']
                    print(f"[SCAN] Found group: '{group_name}' (ID: {group_id})")
                else:
                    group_id = target_value
                    print(f"[SCAN] Using group ID: {group_id}")
                
                members = graph_client.fetch_group_members(group_id)
                target_users = [m.get('userPrincipalName') for m in members if m.get('userPrincipalName')]
                logger.info(f"Found {len(target_users)} members in group")
                print(f"[SCAN] Found {len(target_users)} members in group '{group_name}'")
                
                # Show sample of users
                if target_users:
                    sample_size = min(5, len(target_users))
                    print(f"[SCAN] Sample users ({sample_size} of {len(target_users)}):")
                    for user in target_users[:sample_size]:
                        print(f"    - {user}")
                
            elif target_type == 'all_users':
                # Fetch all users from tenant (use with caution - can be thousands)
                logger.info("Fetching all users from tenant...")
                all_users = graph_client.fetch_all_users(max_results=999)
                target_users = [u.get('userPrincipalName') for u in all_users if u.get('userPrincipalName')]
                logger.info(f"Found {len(target_users)} users in tenant")
                
            else:  # Single user
                target_users = [target_value]
            
            # Scan each user
            all_signin_logs = []
            users_scanned = 0
            
            for user in target_users:
                try:
                    logs = graph_client.fetch_signin_logs(hours_back=24, max_results=1000, user_principal_name=user)
                    
                    if logs:
                        all_signin_logs.extend(logs)
                        users_scanned += 1
                        
                        # Save signin events to database
                        for log in logs:
                            # Check if this event already exists (prevent duplicates)
                            existing = EntraSignInEvent.query.filter_by(
                                microsoft_event_id=log.get('id')
                            ).first()
                            
                            if not existing:
                                # Get or create user identity
                                user_identity = UserIdentity.query.filter_by(
                                    entra_user_id=log.get('userId')
                                ).first()
                                
                                if not user_identity:
                                    user_identity = UserIdentity(
                                        entra_user_id=log.get('userId'),
                                        user_principal_name=log.get('userPrincipalName'),
                                        display_name=log.get('userDisplayName'),
                                        created_at=datetime.utcnow(),
                                        last_seen_at=datetime.utcnow()
                                    )
                                    db.session.add(user_identity)
                                else:
                                    user_identity.last_seen_at = datetime.utcnow()
                                
                                # Extract location data
                                location = log.get('location', {})
                                
                                # Create signin event
                                signin_event = EntraSignInEvent(
                                    microsoft_event_id=log.get('id'),
                                    entra_user_id=log.get('userId'),
                                    user_principal_name=log.get('userPrincipalName'),
                                    created_at=datetime.fromisoformat(log.get('createdDateTime', '').replace('Z', '+00:00')),
                                    ip_address=log.get('ipAddress'),
                                    country=location.get('countryOrRegion'),
                                    state=location.get('state'),
                                    city=location.get('city'),
                                    latitude=location.get('geoCoordinates', {}).get('latitude'),
                                    longitude=location.get('geoCoordinates', {}).get('longitude'),
                                    browser=log.get('deviceDetail', {}).get('browser'),
                                    operating_system=log.get('deviceDetail', {}).get('operatingSystem'),
                                    device_id=log.get('deviceDetail', {}).get('deviceId'),
                                    app_display_name=log.get('appDisplayName'),
                                    status=log.get('status', {}).get('errorCode') == 0 and 'success' or 'failure',
                                    risk_level_aggregated=log.get('riskLevelAggregated'),
                                    risk_detail=log.get('riskDetail'),
                                    raw_json=json.dumps(log)
                                )
                                db.session.add(signin_event)
                        
                        # Commit after each user to prevent data loss
                        db.session.commit()
                        
                except Exception as e:
                    logger.error(f"Error scanning user {user}: {e}")
                    continue
            
            # Analyze for impossible travel
            logger.info(f"Analyzing {len(all_signin_logs)} sign-in events for impossible travel...")
            print(f"[SCAN] Analyzing {len(all_signin_logs)} sign-in events from {users_scanned} users...")
            
            # Show sample sign-in events
            if all_signin_logs:
                sample_size = min(3, len(all_signin_logs))
                print(f"[SCAN] Sample sign-in events ({sample_size} of {len(all_signin_logs)}):")
                for log in all_signin_logs[:sample_size]:
                    user = log.get('userPrincipalName', 'Unknown')
                    timestamp = log.get('createdDateTime', 'Unknown')
                    ip = log.get('ipAddress', 'Unknown')
                    location = log.get('location', {})
                    city = location.get('city', 'Unknown') if isinstance(location, dict) else 'Unknown'
                    state = location.get('state', '') if isinstance(location, dict) else ''
                    country = location.get('countryOrRegion', '') if isinstance(location, dict) else ''
                    loc_str = f"{city}, {state}, {country}".replace(', , ', ', ').strip(', ')
                    print(f"    • {user}")
                    print(f"      Time: {timestamp}")
                    print(f"      IP: {ip}")
                    print(f"      Location: {loc_str}")
            
            impossible_logins = analyze_impossible_travel(all_signin_logs)
            
            # Show impossible travel results
            if impossible_logins:
                print(f"\n[SCAN] ⚠️  Found {len(impossible_logins)} impossible travel incident(s):")
                logger.warning(f"Found {len(impossible_logins)} impossible travel incidents")
                for i, incident in enumerate(impossible_logins[:5], 1):  # Show first 5
                    user = incident.get('userPrincipalName', 'Unknown')
                    speed = incident.get('required_speed') or incident.get('required_speed_mph', 0)
                    distance = incident.get('distance_miles', 0)
                    time_diff = incident.get('time_diff_hours', 0)
                    prev_city = incident.get('prev_city', 'Unknown')
                    current_city = incident.get('city', 'Unknown')
                    print(f"    {i}. {user}")
                    print(f"       Route: {prev_city} → {current_city}")
                    print(f"       Distance: {distance:.1f} miles")
                    print(f"       Time: {time_diff:.1f} hours")
                    print(f"       Required speed: {speed:.0f} mph")
                if len(impossible_logins) > 5:
                    print(f"    ... and {len(impossible_logins) - 5} more")
                print()
            else:
                print(f"[SCAN] ✓ No impossible travel detected")
                logger.info("No impossible travel detected")
            
            # Update signin events with impossible travel detection
            alerts_created = 0
            for impossible_login in impossible_logins:
                event = EntraSignInEvent.query.filter_by(
                    microsoft_event_id=impossible_login.get('id')
                ).first()
                
                if event:
                    event.impossible_travel_detected = True
                    event.required_travel_speed_mph = impossible_login.get('required_speed')
                    event.local_risk_score = impossible_login.get('risk_score', 0)
                    event.local_risk_level = 'critical' if event.local_risk_score >= 90 else 'high'
                    
                    # Create security alert
                    alert = EntraSecurityAlert(
                        entra_user_id=event.entra_user_id,
                        user_principal_name=event.user_principal_name,
                        alert_type='impossible_login',
                        severity='critical' if event.required_travel_speed_mph > 1000 else 'high',
                        reason=f"Impossible travel detected: {event.required_travel_speed_mph:.0f} mph required",
                        status='open',
                        created_at=datetime.utcnow(),
                        related_signin_event_id=event.id
                    )
                    db.session.add(alert)
                    alerts_created += 1
            
            db.session.commit()
            
            # Update scan run with results
            scan_run.completed_at = datetime.utcnow()
            scan_run.status = 'completed'
            scan_run.users_scanned = users_scanned
            scan_run.signin_events_found = len(all_signin_logs)
            scan_run.impossible_logins_detected = len(impossible_logins)
            scan_run.alerts_created = alerts_created
            db.session.commit()
            
            logger.info(f"Automatic scan completed - {users_scanned} users, {len(all_signin_logs)} events, {len(impossible_logins)} impossible logins")
            print(f"\n[SCAN] ✓ Scan completed successfully")
            print(f"[SCAN]   Users scanned: {users_scanned}")
            print(f"[SCAN]   Sign-in events: {len(all_signin_logs)}")
            print(f"[SCAN]   Impossible logins: {len(impossible_logins)}")
            print(f"[SCAN]   Alerts created: {alerts_created}\n")
            
        except Exception as e:
            logger.error(f"Automatic scan failed: {e}")
            scan_run.status = 'failed'
            scan_run.error_message = str(e)
            scan_run.completed_at = datetime.utcnow()
            db.session.commit()


def start_scheduler(app):
    """
    Initialize and start the background scheduler.
    
    Args:
        app: Flask application instance
    """
    global scheduler
    
    if scheduler is not None:
        logger.warning("Scheduler already running")
        return
    
    # Create scheduler
    scheduler = BackgroundScheduler()
    
    # Get interval from config (default: 6 hours)
    interval_hours = app.config.get('SCHEDULER_INTERVAL_HOURS', 6)
    
    # Add job to run automatic scans
    scheduler.add_job(
        func=perform_automatic_scan,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id='automatic_scan',
        name='Automatic Entra ID Security Scan',
        replace_existing=True
    )
    
    # Start scheduler
    scheduler.start()
    logger.info(f"Scheduler started - scanning every {interval_hours} hours")
    
    # Run first scan immediately (optional - comment out if you don't want this)
    # perform_automatic_scan(app)


def stop_scheduler():
    """Stop the background scheduler."""
    global scheduler
    if scheduler is not None:
        scheduler.shutdown()
        scheduler = None
        logger.info("Scheduler stopped")
