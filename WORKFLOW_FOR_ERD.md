# RiskGate Security Monitoring Application - Complete Workflow

## Overview
RiskGate is an automated security monitoring application that continuously scans Entra ID (Azure AD) sign-in activity to detect impossible travel, suspicious logins, and MFA security events.

---

## 1. TRIGGER MECHANISMS (Entry Points)

### A. Manual Scan
- **Trigger**: User clicks "Run Security Scan" button in dashboard
- **Route**: `/scan` endpoint in `app/routes.py`
- **Input**: User selects scan target (group, specific user, or all users)
- **Process**: Executes scan immediately and displays results

### B. Automatic Hourly Scan
- **Trigger**: Power Automate cloud flow runs every 1 hour
- **Route**: `/api/trigger-scan` endpoint (POST request)
- **Authentication**: X-API-Key header validation
- **Input**: Preconfigured target (environment variable: `SCHEDULER_TARGET_TYPE` and `SCHEDULER_TARGET_VALUE`)
- **Process**: Runs scan in background thread, non-blocking

### C. Scheduled Background Job
- **Trigger**: APScheduler background task (optional, currently via Power Automate)
- **Function**: `perform_automatic_scan()` in `app/scheduler.py`
- **Input**: Configuration from environment variables
- **Process**: Executes full scan workflow in Flask app context

---

## 2. AUTHENTICATION & API CLIENT SETUP

### Microsoft Graph API Authentication
1. **Environment Variables**:
   - `AZURE_TENANT_ID` - Azure tenant identifier
   - `AZURE_CLIENT_ID` - App registration client ID
   - `AZURE_CLIENT_SECRET` - App registration secret

2. **Token Acquisition**:
   - OAuth 2.0 client credentials flow
   - Scope: `https://graph.microsoft.com/.default`
   - Token cached until expiration (59 minutes)

3. **Required Permissions**:
   - `AuditLog.Read.All` - Read sign-in and audit logs
   - `UserAuthenticationMethod.Read.All` - Read MFA methods
   - `User.Read.All` - Read user details
   - `Group.Read.All` - Read group memberships

4. **GraphClient Class** (`app/graph_client.py`):
   - Manages authentication token lifecycle
   - Makes authenticated requests to Graph API
   - Tracks API call count for monitoring

---

## 3. DATA COLLECTION (From Microsoft Graph API)

### A. Determine Scan Target
1. **Group Scan** (most common):
   - Target: "All Associates" group (ID: `c97a854d-19e4-49e5-8245-268e338bb190`)
   - Fetch group members: `GET /groups/{group-id}/members`
   - Returns list of user principal names (emails)
   - Current count: 1007 members

2. **Individual User Scan**:
   - Target: Specific user email (e.g., `tgaskins@peakmade.com`)
   - Direct query for that user's activity

3. **All Users Scan**:
   - Target: Entire tenant (performance intensive)
   - Used for comprehensive security audits

### B. Fetch Sign-In Logs
- **Endpoint**: `GET /auditLogs/signIns`
- **Time Window**: Last 24 hours (configurable)
- **Filter**: `createdDateTime ge {timestamp} and userPrincipalName eq '{user}'`
- **Per User**: Up to 1000 most recent sign-ins
- **Batch Mode**: For groups, fetches only users with recent activity (efficient)
- **Data Returned**:
  - User identity (ID, UPN, display name)
  - Timestamp of sign-in
  - Location (latitude, longitude, city, state, country)
  - IP address
  - Status (success, failure, interrupted)
  - Risk level (none, low, medium, high)
  - Authentication details
  - Device information
  - Application used

### C. Fetch Audit Logs (MFA Events)
- **Endpoint**: `GET /auditLogs/directoryAudits`
- **Category**: UserManagement
- **Time Window**: Last 24 hours
- **Activities Tracked**:
  - User registered security info
  - User started security info registration
  - Authentication method added
  - Authentication method removed
  - Admin updated authentication method
  - Temporary Access Pass created
- **Data Returned**:
  - Activity timestamp
  - Activity display name
  - Result status
  - Target user
  - Initiating user
  - IP address
  - Location

### D. Fetch Current Authentication Methods
- **Endpoint**: `GET /users/{user-id}/authentication/methods`
- **Purpose**: Snapshot of user's current MFA configuration
- **Data Returned**:
  - Method types (Phone, Email, Authenticator App, FIDO2, etc.)
  - Method details (phone number masked, email masked)
  - Creation timestamp

---

## 4. DATA INGESTION & NORMALIZATION

### A. User Identity Management
**Function**: `get_or_create_user_identity()` in `app/ingest.py`

**Process**:
1. Check if user exists in database (by `entra_user_id`)
2. If new user:
   - Create `UserIdentity` record
   - Store: Entra ID, email, display name, first seen timestamp
3. If existing user:
   - Update `last_seen_at` timestamp
   - Update display name if missing

**Database Table**: `user_identities`

### B. Sign-In Event Ingestion
**Function**: `ingest_signin_event()` in `app/ingest.py`

**Process**:
1. Check for duplicate (by `microsoft_event_id`)
2. Skip if already ingested (prevents duplicates)
3. Extract and normalize:
   - User information
   - Timestamp (convert to UTC)
   - Location coordinates
   - IP address
   - Status (success/failure)
   - Risk level
   - Authentication details
4. Create `EntraSignInEvent` record
5. Link to `UserIdentity` via foreign key

**Database Table**: `entra_signin_events`

### C. MFA Event Ingestion
**Function**: `ingest_audit_event()` in `app/ingest.py`

**Process**:
1. Check for duplicate (by `microsoft_event_id`)
2. Skip if already ingested
3. Extract and normalize:
   - Activity name
   - Result status
   - Target user
   - Initiating user (admin or self)
   - Timestamp
   - IP address and location
4. Create `EntraMfaEvent` record
5. Link to `UserIdentity` via foreign key

**Database Table**: `entra_mfa_events`

### D. Authentication Method Snapshot
**Function**: Captured during full user scans

**Process**:
1. Query current authentication methods for user
2. Create snapshot record with timestamp
3. Store method types and details
4. Used for historical tracking of MFA configuration changes

**Database Table**: `user_auth_method_snapshots`

---

## 5. RISK ANALYSIS & DETECTION

### A. Impossible Travel Detection
**Function**: `detect_impossible_travel()` in `app/risk_detection.py`

**Process**:
1. For each sign-in event:
   - Query previous successful sign-in for same user
   - Calculate geographic distance (Haversine formula)
   - Calculate time elapsed between sign-ins
   - Compute required travel speed (miles per hour)

2. **Impossible Travel Criteria**:
   - Distance > 100 miles AND
   - Speed > 500 mph (airplane speed threshold)
   - Exception: If time gap < 1 hour, use stricter thresholds

3. **Trusted Location Check**:
   - Query user's trusted baseline locations
   - If either location is trusted, suppress alert (prevents false positives)
   - Example: Remote worker consistently logs in from home office

4. **False Positive Considerations**:
   - VPN usage (appears to teleport when VPN connects)
   - Mobile device IP routing (cell towers route through data centers)
   - Cloud services/RDP (user connects to VM in different region)
   - Bad IP geolocation data
   - Shared accounts
   - Corporate proxy servers

**Output**: Boolean flag `impossible_travel` on sign-in event

### B. Security Alert Generation
**Function**: Part of risk analysis workflow

**Process**:
1. When impossible travel detected:
   - Create `EntraSecurityAlert` record
   - Set alert type: "Impossible Travel"
   - Set severity: "high" or "critical" based on distance/speed
   - Include context: locations, times, calculated speed

2. Other Alert Types (future):
   - Multiple failed logins
   - Login from risky IP
   - Login after MFA removal
   - Login from unusual location

**Database Table**: `entra_security_alerts`

### C. User Risk State Tracking
**Function**: Aggregate risk assessment per user

**Process**:
1. Calculate user's current risk level:
   - Count of impossible travel events (last 7 days)
   - Count of failed logins (last 24 hours)
   - Count of high-risk sign-ins
   - Recent MFA changes
   - Active security alerts

2. Update `UserRiskState` record:
   - Overall risk score (0-100)
   - Risk level (Low, Medium, High, Critical)
   - Last risk calculation timestamp
   - Active alerts count

**Database Table**: `user_risk_states`

### D. Trusted Location Learning
**Function**: Baseline normal behavior for users

**Process**:
1. Track locations user signs in from consistently
2. After N successful sign-ins from same location (e.g., 10):
   - Create `UserTrustedLocation` record
   - Store: coordinates, city, state, country
   - Mark as verified baseline location

3. Use trusted locations to suppress false positive alerts

**Database Table**: `user_trusted_locations`

---

## 6. SCAN EXECUTION & TRACKING

### A. Scan Run Record
**Function**: Track each scan execution for audit trail

**Process**:
1. At scan start:
   - Create `ScanRun` record
   - Store: scan type (manual/automatic), target type, target value
   - Set status: "running"
   - Record start timestamp

2. During scan:
   - Update progress metrics
   - Track API calls made
   - Track users scanned

3. At scan completion:
   - Set status: "completed" (or "failed" if error)
   - Record completion timestamp
   - Store final metrics:
     - Total users scanned
     - Sign-in events found
     - MFA events found
     - Impossible travel count
     - Alerts created
     - API calls made
   - Store any error messages

**Database Table**: `scan_runs`

### B. Batch Processing Optimization
**Strategy**: For large groups (1000+ users), use batch mode

**Process**:
1. **Initial Sign-In Query**:
   - Fetch sign-ins for entire time window (no user filter)
   - Group members: `$filter=createdDateTime ge {timestamp}`
   - Result: Only users with recent activity returned

2. **Identify Active Users**:
   - Extract unique user principal names from results
   - Cross-reference with target group membership
   - Result: 261 active users out of 1007 total

3. **Focused Scanning**:
   - Only query audit logs for active users
   - Skip users with no recent activity
   - Reduces API calls from 1007 to 3

**Performance**: 
- Traditional approach: 1 API call per user = 1007 calls
- Batch mode: 1 group call + 1 sign-in call + 1 audit call = 3 calls

---

## 7. DATA PERSISTENCE

### A. Database Configuration
**File**: `config.py`

**Options**:
1. **SQLite** (Development/Default):
   - File: `app.db` in project root
   - Portable, no setup required
   - LIMITATION: Ephemeral on Azure (wiped on restart)

2. **PostgreSQL** (Production):
   - Environment variable: `DATABASE_URL`
   - Format: `postgresql://user:pass@host:port/dbname`
   - Persistent, scalable, production-ready

**Current Status**: Using SQLite locally and in Azure (temporary solution until PostgreSQL deployed)

### B. Database Models
**File**: `app/models_new.py`

**Schema Overview**:
1. `user_identities` - Core user records
2. `entra_signin_events` - All sign-in activity
3. `entra_mfa_events` - MFA configuration changes
4. `user_auth_method_snapshots` - Point-in-time MFA config
5. `user_trusted_locations` - Learned baseline locations
6. `user_risk_states` - Aggregate risk assessment
7. `entra_security_alerts` - Generated alerts
8. `scan_runs` - Audit trail of scan executions

**Relationships**:
- All event tables reference `user_identities` via foreign key
- Alerts reference specific sign-in events
- Risk states reference user identities
- Scan runs are standalone (track execution metrics)

### C. Database Migrations
**Tool**: Flask-Migrate (Alembic)

**Process**:
1. Model changes detected: `flask db migrate -m "description"`
2. Migration script generated in `migrations/versions/`
3. Migration applied: `flask db upgrade`
4. Rollback if needed: `flask db downgrade`

**Existing Migrations**:
- Initial schema creation
- MSAL authentication fields
- Entra models for MFA detection
- Trusted locations
- Sign-in event state tracking

---

## 8. DISPLAY & USER INTERFACE

### A. Dashboard Route
**Route**: `/` (root)
**Template**: `securityscan_dashboard.html`
**File**: `app/routes.py` - `securityscan_dashboard()` function

**Data Flow**:
1. Check for Easy Auth user (Azure authentication)
2. Load automatic scan results from file (if exists)
3. Load in-memory scan results
4. Count impossible travel events
5. Prepare statistics:
   - Total users scanned
   - Users with activity
   - Users without activity
   - Total sign-in events
   - Impossible travel count
   - Active alerts
6. Render template with all data

### B. Dashboard Sections
**Layout**:
1. **Header Banner**:
   - PeakMade logo
   - Application title
   - Redpoint logo

2. **User Info Bar** (below banner):
   - Display name
   - Email address
   - Logout button

3. **Last Automatic Scan**:
   - Timestamp of last Power Automate scan
   - Scan statistics
   - Target group information

4. **Scan Controls**:
   - Target selection (group dropdown or user input)
   - "Run Security Scan" button
   - Manual scan trigger

5. **Recent Activity Summary**:
   - Users scanned
   - Sign-in events found
   - Impossible travel alerts
   - MFA events

6. **Impossible Travel Alerts** (if any):
   - User name
   - Locations (from → to)
   - Distance traveled
   - Time elapsed
   - Calculated speed
   - Alert severity

7. **Sign-In Event Log**:
   - Paginated table
   - Columns: User, Timestamp, Location, IP, Status, Risk Level
   - Filter options
   - Export capability

8. **MFA Monitoring**:
   - Recent MFA changes
   - Users without MFA
   - High-risk MFA events

### C. Additional Pages
1. **MFA Decision Log** (`/mfa-decisions`):
   - History of MFA enforcement decisions
   - Manual override tracking

2. **MFA Test Lab** (`/mfa-test-lab`):
   - Test environment for MFA scenarios
   - Development/debugging tool

3. **Scan Usage** (`/scan-usage`):
   - API call metrics
   - Usage statistics
   - Cost tracking

---

## 9. COMPLETE WORKFLOW SEQUENCE (End-to-End)

### Automatic Hourly Scan Example:

```
1. TRIGGER
   └─> Power Automate cloud flow executes (every 1 hour)
   └─> POST https://riskgate-e6f4c2gac0a3bjfr.eastus-01.azurewebsites.net/api/trigger-scan
   └─> Header: X-API-Key: {secret_key}

2. AUTHENTICATION
   └─> Validate API key against SCAN_API_KEY environment variable
   └─> If valid, proceed. If invalid, return 401 Unauthorized

3. SCAN INITIALIZATION
   └─> Create ScanRun record (status: running, started_at: now)
   └─> Read config: SCHEDULER_TARGET_TYPE = "group"
   └─> Read config: SCHEDULER_TARGET_VALUE = "c97a854d-19e4-49e5-8245-268e338bb190"

4. GRAPH API AUTHENTICATION
   └─> GraphClient initialized
   └─> Request OAuth token from Microsoft
   └─> Scope: https://graph.microsoft.com/.default
   └─> Cache token for 59 minutes

5. FETCH GROUP MEMBERS
   └─> GET /groups/{group-id}/members
   └─> Returns 1007 members (All Associates group)
   └─> Extract user principal names (emails)

6. FETCH SIGN-IN LOGS (BATCH MODE)
   └─> GET /auditLogs/signIns?$filter=createdDateTime ge {24h_ago}
   └─> Returns all recent sign-ins across tenant
   └─> Filter results to only group members
   └─> Result: 261 users with activity, 989 total events

7. INGEST SIGN-IN EVENTS
   └─> For each sign-in event:
       ├─> Check for duplicate (by microsoft_event_id)
       ├─> Skip if already ingested
       ├─> Get or create UserIdentity
       ├─> Normalize location data
       ├─> Create EntraSignInEvent record
       └─> Commit to database

8. FETCH AUDIT LOGS (MFA EVENTS)
   └─> GET /auditLogs/directoryAudits?category=UserManagement
   └─> Filter to active users only (261 users)
   └─> Returns MFA configuration changes

9. INGEST MFA EVENTS
   └─> For each audit event:
       ├─> Check for duplicate
       ├─> Skip if already ingested
       ├─> Extract activity details
       ├─> Create EntraMfaEvent record
       └─> Commit to database

10. RISK ANALYSIS
    └─> For each sign-in event:
        ├─> Query previous sign-in for same user
        ├─> If previous exists:
        │   ├─> Calculate distance between locations
        │   ├─> Calculate time elapsed
        │   ├─> Calculate required travel speed
        │   ├─> If speed > 500 mph AND distance > 100 miles:
        │   │   ├─> Check trusted locations
        │   │   ├─> If not trusted:
        │   │   │   ├─> Mark as impossible_travel = True
        │   │   │   ├─> Create EntraSecurityAlert
        │   │   │   └─> Update UserRiskState
        │   │   └─> If trusted: suppress alert
        │   └─> If normal travel: mark as impossible_travel = False
        └─> Commit all updates

11. TRUSTED LOCATION LEARNING
    └─> For each user:
        ├─> Query sign-ins from same location
        ├─> If >= 10 successful sign-ins from location:
        │   └─> Create or update UserTrustedLocation
        └─> Commit updates

12. SCAN COMPLETION
    └─> Update ScanRun record:
        ├─> status = "completed"
        ├─> completed_at = now
        ├─> users_scanned = 1007
        ├─> signin_events_found = 989
        ├─> mfa_events_found = {count}
        ├─> alerts_created = 0 (in this example)
        ├─> impossible_travel_count = 0
        ├─> api_calls_made = 3
        └─> Commit to database

13. SAVE RESULTS TO FILE (OPTIONAL)
    └─> Write scan summary to automatic_scan_results.json
    └─> Used for dashboard display when app restarts

14. RESPONSE
    └─> Return HTTP 200 OK
    └─> JSON: {"status": "Scan started", "timestamp": "{now}", "message": "..."}

15. DASHBOARD UPDATE
    └─> When user visits dashboard:
        ├─> Load scan results from database
        ├─> Display metrics
        ├─> Show alerts (if any)
        └─> Render sign-in event log
```

---

## 10. DATA FLOW DIAGRAM (Entities & Relationships)

```
EXTERNAL SYSTEMS                  APPLICATION LAYER                  DATABASE LAYER
─────────────────                 ─────────────────                  ──────────────

Power Automate          ─────>    API Endpoint                       scan_runs
Cloud Flow                        /api/trigger-scan                  └─> Audit trail
(Every 1 hour)                          │
                                        │
                                        ▼
Azure Active Directory  ─────>    GraphClient                        user_identities
(Entra ID)                        OAuth Authentication               ├─> Core user data
  │                                     │                            │
  ├─> User Sign-Ins                     │                            │
  ├─> Audit Logs                        │                            │
  ├─> Auth Methods                      ▼                            │
  └─> Group Members              Data Collection                     │
                                  ├─> fetch_signin_logs()            │
                                  ├─> fetch_audit_logs()             │
                                  ├─> fetch_group_members()          │
                                  └─> fetch_auth_methods()           │
                                        │                            │
                                        ▼                            │
                                  Data Ingestion                     │
                                  ├─> ingest.py                      │
                                  ├─> Normalize JSON                 │
                                  └─> Create Models                  │
                                        │                            │
                                        ├─────────────────────>  entra_signin_events
                                        │                        ├─> All login activity
                                        │                        └─> Links to users
                                        │                            │
                                        ├─────────────────────>  entra_mfa_events
                                        │                        ├─> MFA changes
                                        │                        └─> Links to users
                                        │                            │
                                        ▼                            │
                                  Risk Analysis                      │
                                  ├─> risk_detection.py              │
                                  ├─> Calculate travel               │
                                  ├─> Check thresholds               │
                                  └─> Generate alerts                │
                                        │                            │
                                        ├─────────────────────>  entra_security_alerts
                                        │                        ├─> Generated alerts
                                        │                        └─> Links to events
                                        │                            │
                                        ├─────────────────────>  user_risk_states
                                        │                        ├─> Aggregate risk
                                        │                        └─> Links to users
                                        │                            │
                                        └─────────────────────>  user_trusted_locations
                                                                 ├─> Baseline locations
                                                                 └─> Links to users

Web Browser             ─────>    Dashboard Routes
User Interface                    ├─> routes.py
                                  ├─> Load from database
                                  └─> Render templates
                                        │
                                        ▼
                                  HTML Templates
                                  ├─> securityscan_dashboard.html
                                  ├─> base.html
                                  └─> Display results
```

---

## 11. FUTURE ENHANCEMENTS (Planned Features)

1. **Interactive vs Non-Interactive Logins**:
   - Add fields: `is_interactive`, `client_app_used`, `resource_display_name`
   - Filter dashboard to show only human logins
   - Separate service account activity

2. **Advanced Risk Detection**:
   - Multiple failed login attempts
   - Login after MFA removal
   - Login from known malicious IPs
   - Anomalous login times (3am on Sunday)
   - First-time country logins

3. **Alerting & Notifications**:
   - Email alerts for high-severity events
   - Microsoft Teams notifications
   - Webhook integration
   - SMS for critical alerts

4. **Historical Trending**:
   - 30-day sign-in trends per user
   - MFA adoption rate over time
   - Geographic login heatmaps
   - Peak login times analysis

5. **Automated Response**:
   - Disable user account on critical alert
   - Require MFA enrollment
   - Force password reset
   - Revoke active sessions

6. **Compliance Reporting**:
   - Export audit logs for compliance
   - Generate monthly security reports
   - Track MFA coverage by department
   - Failed login attempt summaries

---

## 12. MONITORING & OBSERVABILITY

### Application Logging
- **Level**: INFO, WARNING, ERROR
- **Output**: Console (stdout) and Application Insights (Azure)
- **Key Events Logged**:
  - Scan start/completion
  - API authentication success/failure
  - Database operations
  - Risk detections
  - Errors and exceptions

### Performance Metrics
- **API Call Counter**: Tracks Graph API usage
- **Scan Duration**: Time to complete full scan
- **Users Scanned**: Count per scan run
- **Events Ingested**: Sign-ins and MFA events per scan
- **Database Query Time**: Monitor for slow queries

### Health Checks
- **Database Connection**: Verify connectivity on startup
- **Graph API Access**: Verify token acquisition
- **Scan Status**: Check last successful scan timestamp
- **Alert Queue**: Monitor unacknowledged alerts

---

## SUMMARY FOR ERD PRESENTATION

**Key Workflow Points**:
1. **Automated Triggers**: Power Automate cloud flow runs hourly
2. **Graph API Integration**: Fetches real-time data from Entra ID
3. **Efficient Batch Processing**: Reduces 1007 API calls to 3 calls
4. **Smart Risk Detection**: Identifies impossible travel with false positive prevention
5. **Persistent Storage**: PostgreSQL for production data persistence
6. **Real-Time Dashboard**: Live view of security posture
7. **Audit Trail**: Complete scan history in scan_runs table
8. **Scalable Architecture**: Handles 1000+ users efficiently

**Database Tables** (8 total):
1. `user_identities` - Core user records
2. `entra_signin_events` - Login activity
3. `entra_mfa_events` - MFA changes
4. `user_auth_method_snapshots` - MFA config snapshots
5. `user_trusted_locations` - Baseline locations
6. `user_risk_states` - Aggregate risk scores
7. `entra_security_alerts` - Generated alerts
8. `scan_runs` - Scan execution audit trail

**External Integrations**:
- Microsoft Entra ID (Azure AD)
- Microsoft Graph API
- Power Automate (cloud flows)
- Azure App Service (hosting)
- Azure Easy Auth (authentication)
