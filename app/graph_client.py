"""
Microsoft Graph API client for SecurityScan.

Authenticates to Microsoft Graph and fetches:
- Sign-in logs
- Directory audit logs (authentication method changes)
- Current authentication methods for users

Environment variables required:
- AZURE_TENANT_ID: Your Azure AD tenant ID
- AZURE_CLIENT_ID: App registration client ID
- AZURE_CLIENT_SECRET: App registration client secret

Required Microsoft Graph permissions:
- AuditLog.Read.All (sign-in logs and audit logs)
- UserAuthenticationMethod.Read.All (authentication methods)
- User.Read.All (user details)
"""
import os
import requests
from datetime import datetime, timedelta
from flask import current_app


class GraphClient:
    """Microsoft Graph API client with authentication."""
    
    def __init__(self):
        self.tenant_id = os.environ.get('AZURE_TENANT_ID')
        self.client_id = os.environ.get('AZURE_CLIENT_ID')
        self.client_secret = os.environ.get('AZURE_CLIENT_SECRET')
        self.access_token = None
        self.token_expires_at = None
        self.api_calls = 0  # Track API calls for credit usage
        self.reset_call_counter()
        
    def _get_access_token(self):
        """
        Obtain access token using client credentials flow.
        Caches token until expiration.
        """
        # Check if we have a valid cached token
        if self.access_token and self.token_expires_at:
            if datetime.utcnow() < self.token_expires_at:
                return self.access_token
        
        # Check configuration
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            current_app.logger.warning(
                "Microsoft Graph credentials not configured. "
                "Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."
            )
            return None
        
        # Request new token
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            token_data = response.json()
            
            self.access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 60)
            
            current_app.logger.info("Successfully obtained Microsoft Graph access token")
            return self.access_token
            
        except requests.exceptions.HTTPError as e:
            # Get detailed error from Microsoft
            error_detail = "No details"
            try:
                error_detail = response.json()
            except:
                error_detail = response.text
            current_app.logger.error(f"Failed to obtain access token: {e}")
            current_app.logger.error(f"Microsoft error response: {error_detail}")
            return None
        except Exception as e:
            current_app.logger.error(f"Failed to obtain access token: {e}")
            return None
    
    def _make_request(self, url, params=None, extra_headers=None):
        """
        Make authenticated request to Microsoft Graph.
        
        Args:
            url: Full Graph API URL
            params: Optional query parameters
            extra_headers: Optional additional headers to include
        
        Returns:
            Response JSON or None if error
        """
        token = self._get_access_token()
        if not token:
            return None
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Add any extra headers
        if extra_headers:
            headers.update(extra_headers)
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=300)
            response.raise_for_status()
            self.api_calls += 1  # Increment API call counter
            return response.json()
        except requests.exceptions.Timeout as e:
            current_app.logger.error(f"Graph API TIMEOUT for {url}: Query took longer than 300 seconds")
            current_app.logger.error(f"Query parameters: {params}")
            return None
        except requests.exceptions.HTTPError as e:
            current_app.logger.error(f"Graph API HTTP error for {url}: {e}")
            current_app.logger.error(f"Response status: {response.status_code}")
            current_app.logger.error(f"Response body: {response.text[:500]}")
            return None
        except Exception as e:
            current_app.logger.error(f"Graph API request failed for {url}: {e}")
            return None
    
    def reset_call_counter(self):
        """Reset the API call counter."""
        self.api_calls = 0
    
    def get_call_count(self):
        """Get the number of API calls made since last reset."""
        return self.api_calls
    
    def fetch_signin_logs(self, hours_back=24, max_results=1000, user_principal_name=None):
        """
        Fetch sign-in logs from Microsoft Graph.
        
        Args:
            hours_back: How many hours of history to fetch (default 24)
            max_results: Maximum number of results (default 1000)
            user_principal_name: Optional - filter for specific user (e.g., 'tgaskins@peakmade.com')
        
        Returns:
            List of sign-in log records
        """
        # Calculate filter timestamp
        filter_time = datetime.utcnow() - timedelta(hours=hours_back)
        filter_time_str = filter_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Build filter - add user filter if specified
        filter_parts = [f"createdDateTime ge {filter_time_str}"]
        if user_principal_name:
            filter_parts.append(f"userPrincipalName eq '{user_principal_name}'")
        
        url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        params = {
            '$filter': ' and '.join(filter_parts),
            '$top': min(max_results, 1000)
            # Removed orderby to avoid timeout issues
        }
        
        current_app.logger.info(f"Fetching sign-in logs from last {hours_back} hours...")
        if user_principal_name:
            current_app.logger.info(f"Filtering for user: {user_principal_name}")
        current_app.logger.info(f"Graph API filter: {params['$filter']}")
        
        signin_logs = []
        page = 0
        while url and len(signin_logs) < max_results:
            page += 1
            result = self._make_request(
                url, params if page == 1 else None
            )
            if not result or 'value' not in result:
                if not signin_logs:
                    current_app.logger.warning(
                        f"No sign-in logs retrieved. Result: {result}"
                    )
                break

            remaining = max_results - len(signin_logs)
            signin_logs.extend(result['value'][:remaining])
            url = result.get('@odata.nextLink')

        current_app.logger.info(
            f"Fetched {len(signin_logs)} sign-in log entries across {page} page(s)"
        )
        if signin_logs:
            sample_users = {
                log.get('userPrincipalName', 'Unknown')[:50]
                for log in signin_logs[:5]
            }
            current_app.logger.info(f"Sample users in logs: {sample_users}")
        return signin_logs
    
    def fetch_audit_logs(self, hours_back=24, category='UserManagement', max_results=1000):
        """
        Fetch directory audit logs from Microsoft Graph.
        
        Focus on authentication method changes:
        - User registered security info
        - Authentication method added/removed
        - Admin updated authentication method
        - Temporary Access Pass created
        
        Args:
            hours_back: How many hours of history to fetch (default 24)
            category: Audit log category (default 'UserManagement')
            max_results: Maximum number of results
        
        Returns:
            List of audit log records
        """
        filter_time = datetime.utcnow() - timedelta(hours=hours_back)
        filter_time_str = filter_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
        params = {
            '$filter': f"activityDateTime ge {filter_time_str} and category eq '{category}'",
            '$top': max_results,
            '$orderby': 'activityDateTime desc'
        }
        
        current_app.logger.info(f"Fetching audit logs from last {hours_back} hours...")
        
        result = self._make_request(url, params)
        if result and 'value' in result:
            audit_logs = result['value']
            current_app.logger.info(f"Fetched {len(audit_logs)} audit log entries")
            return audit_logs
        
        current_app.logger.warning("No audit logs retrieved")
        return []
    
    def fetch_user_authentication_methods(self, user_id):
        """
        Fetch current authentication methods for a specific user.
        
        Args:
            user_id: Entra user ID (object ID) or user principal name
        
        Returns:
            List of authentication method objects
        """
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods"
        
        current_app.logger.info(f"Fetching authentication methods for user {user_id}...")
        
        result = self._make_request(url)
        if result and 'value' in result:
            methods = result['value']
            current_app.logger.info(f"User {user_id} has {len(methods)} authentication methods")
            return methods
        
        current_app.logger.warning(f"Could not fetch authentication methods for {user_id}")
        return []
    
    def fetch_user_details(self, user_id):
        """
        Fetch user details from Microsoft Graph.
        
        Args:
            user_id: Entra user ID or user principal name
        
        Returns:
            User object or None
        """
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
        
        result = self._make_request(url)
        if result:
            current_app.logger.info(f"Fetched details for user {user_id}")
            return result
        
        return None
    
    def fetch_groups(self, max_results=999):
        """
        Fetch all groups from Microsoft Entra with pagination support.
        
        Args:
            max_results: Maximum number of groups to fetch per page (default 999)
        
        Returns:
            List of group objects with id, displayName, mail, etc.
        """
        url = "https://graph.microsoft.com/v1.0/groups"
        params = {
            '$select': 'id,displayName,mail,description,mailEnabled,securityEnabled,groupTypes,createdDateTime,renewedDateTime',
            '$top': max_results
        }
        
        current_app.logger.info("Fetching groups from Entra ID...")
        
        all_groups = []
        page_count = 0
        
        while url:
            page_count += 1
            result = self._make_request(url, params if page_count == 1 else None)
            
            if not result or 'value' not in result:
                current_app.logger.warning("No groups retrieved")
                break
            
            groups = result['value']
            all_groups.extend(groups)
            
            # Check for next page
            url = result.get('@odata.nextLink')
            if url:
                current_app.logger.info(f"Fetching page {page_count + 1} of groups...")
        
        current_app.logger.info(f"Fetched {len(all_groups)} total groups across {page_count} page(s)")
        return all_groups
    
    def get_group_member_count(self, group_id):
        """
        Get the number of members in a group.
        
        Args:
            group_id: Entra group ID
        
        Returns:
            Integer count of members
        """
        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$count"
        headers = {
            'ConsistencyLevel': 'eventual'
        }
        
        try:
            result = self._make_request(url, extra_headers=headers)
            # The $count endpoint returns a plain integer, not JSON
            if isinstance(result, int):
                return result
            # If it's a string, convert to int
            if isinstance(result, str):
                return int(result)
            return 0
        except Exception as e:
            current_app.logger.warning(f"Failed to get member count for group {group_id}: {e}")
            return 0
    
    def fetch_group_members(self, group_id):
        """
        Fetch all members of a specific group with pagination support.
        
        Args:
            group_id: Entra group ID
        
        Returns:
            List of user objects (group members)
        """
        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
        params = {
            '$select': 'id,userPrincipalName,displayName,mail,accountEnabled',
            '$top': 999  # Request up to 999 members per page
        }
        
        current_app.logger.info(f"Fetching members for group {group_id}...")
        
        all_users = []
        page_count = 0
        
        while url:
            page_count += 1
            result = self._make_request(url, params if page_count == 1 else None)
            
            if not result or 'value' not in result:
                current_app.logger.warning(f"Could not fetch members for group {group_id}")
                break
            
            members = result['value']
            # Filter to only users (not nested groups or other objects)
            users = [m for m in members if m.get('@odata.type') == '#microsoft.graph.user' or 'userPrincipalName' in m]
            all_users.extend(users)
            
            # Check for next page
            url = result.get('@odata.nextLink')
            if url:
                current_app.logger.info(f"Fetching page {page_count + 1} of group members...")
        
        current_app.logger.info(f"Group has {len(all_users)} total user members across {page_count} page(s)")
        return all_users


# Global instance
graph_client = GraphClient()
