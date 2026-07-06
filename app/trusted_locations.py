"""
Trusted Location Management for SecurityScan.

Learns baseline locations for users to prevent false positives for remote workers.
A user who consistently logs in from their home office won't trigger travel alerts.
"""
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models_new import UserTrustedLocation, EntraSignInEvent
from app.risk_detection import distance_miles


def get_location_name(country, city, state=None):
    """Format a readable location name."""
    if city:
        if state:
            return f"{city}, {state}, {country}"
        return f"{city}, {country}"
    return country


def find_trusted_location(entra_user_id, latitude, longitude):
    """
    Find a trusted location for a user that matches the given coordinates.
    
    Args:
        entra_user_id: User's Azure AD object ID
        latitude: Latitude of the location to check
        longitude: Longitude of the location to check
    
    Returns:
        UserTrustedLocation object or None if no match found
    """
    if latitude is None or longitude is None:
        return None
    
    radius_miles = current_app.config.get('TRUSTED_LOCATION_RADIUS_MILES', 50)
    
    # Get all trusted locations for this user
    trusted_locations = UserTrustedLocation.query.filter_by(
        entra_user_id=entra_user_id
    ).all()
    
    # Check if any location is within the radius
    for location in trusted_locations:
        distance = distance_miles(
            location.latitude, location.longitude,
            latitude, longitude
        )
        if distance <= radius_miles:
            return location
    
    return None


def is_location_trusted(entra_user_id, latitude, longitude):
    """
    Check if a location is trusted for the user.
    
    Args:
        entra_user_id: User's Azure AD object ID
        latitude: Latitude to check
        longitude: Longitude to check
    
    Returns:
        Boolean: True if location is trusted, False otherwise
    """
    location = find_trusted_location(entra_user_id, latitude, longitude)
    return location is not None and location.is_trusted


def update_trusted_location(signin_event):
    """
    Update or create trusted location based on a successful sign-in.
    
    This learns the user's baseline locations over time.
    After a user successfully logs in from the same location multiple times,
    it becomes a \"trusted\" location and won't trigger travel alerts.
    
    Args:
        signin_event: EntraSignInEvent object (must be successful)
    """
    # Only track successful sign-ins with valid coordinates
    if signin_event.status != 'success':
        return
    
    if signin_event.latitude is None or signin_event.longitude is None:
        return
    
    # Find existing trusted location nearby
    location = find_trusted_location(
        signin_event.entra_user_id,
        signin_event.latitude,
        signin_event.longitude
    )
    
    min_logins = current_app.config.get('TRUSTED_LOCATION_MIN_LOGINS', 3)
    
    if location:
        # Update existing location
        location.login_count += 1
        location.last_seen = signin_event.created_at
        
        # Mark as trusted if threshold reached
        if location.login_count >= min_logins and not location.is_trusted:
            location.is_trusted = True
            current_app.logger.info(
                f"Location {location.location_name} is now TRUSTED for "
                f"{signin_event.user_principal_name} ({location.login_count} logins)"
            )
    else:
        # Create new location
        location_name = get_location_name(
            signin_event.country or 'Unknown',
            signin_event.city,
            getattr(signin_event, 'state', None)
        )
        
        location = UserTrustedLocation(
            entra_user_id=signin_event.entra_user_id,
            user_principal_name=signin_event.user_principal_name,
            country=signin_event.country or 'Unknown',
            city=signin_event.city,
            latitude=signin_event.latitude,
            longitude=signin_event.longitude,
            login_count=1,
            first_seen=signin_event.created_at,
            last_seen=signin_event.created_at,
            is_trusted=False,
            location_name=location_name
        )
        db.session.add(location)
        current_app.logger.info(
            f"Started tracking new location {location_name} for "
            f"{signin_event.user_principal_name}"
        )
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update trusted location: {e}")


def learn_locations_from_history(entra_user_id, days_back=30):
    """
    Backfill trusted locations by analyzing historical successful sign-ins.
    
    Useful for initializing trusted locations for existing users or
    when first deploying the feature.
    
    Args:
        entra_user_id: User's Azure AD object ID
        days_back: Number of days of history to analyze (default 30)
    
    Returns:
        Number of trusted locations learned
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days_back)
    
    # Get all successful sign-ins for this user in the lookback period
    signin_events = EntraSignInEvent.query.filter(
        EntraSignInEvent.entra_user_id == entra_user_id,
        EntraSignInEvent.status == 'success',
        EntraSignInEvent.created_at >= cutoff_date,
        EntraSignInEvent.latitude.isnot(None),
        EntraSignInEvent.longitude.isnot(None)
    ).order_by(EntraSignInEvent.created_at.asc()).all()
    
    current_app.logger.info(
        f"Learning locations from {len(signin_events)} historical sign-ins "
        f"for user {entra_user_id}"
    )
    
    # Process each sign-in to build up location baselines
    for event in signin_events:
        update_trusted_location(event)
    
    # Count trusted locations
    trusted_count = UserTrustedLocation.query.filter(
        UserTrustedLocation.entra_user_id == entra_user_id,
        UserTrustedLocation.is_trusted == True
    ).count()
    
    current_app.logger.info(
        f"Learned {trusted_count} trusted locations for user {entra_user_id}"
    )
    
    return trusted_count


def get_user_trusted_locations(entra_user_id, trusted_only=True):
    """
    Get all trusted locations for a user.
    
    Args:
        entra_user_id: User's Azure AD object ID
        trusted_only: If True, only return is_trusted=True locations
    
    Returns:
        List of UserTrustedLocation objects
    """
    query = UserTrustedLocation.query.filter_by(entra_user_id=entra_user_id)
    
    if trusted_only:
        query = query.filter_by(is_trusted=True)
    
    return query.order_by(UserTrustedLocation.login_count.desc()).all()
