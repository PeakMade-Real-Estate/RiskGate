# RiskGate - Current Work Context

**Last Updated:** July 31, 2026  
**Status:** App running, recent UI/UX improvements completed and pushed to GitHub

---

## 📋 Quick Reference

### Running the App
```bash
# Activate virtual environment (if not already active)
.venv\Scripts\Activate.ps1

# Run the app
python run.py
```

**App URLs:**
- https://127.0.0.1:5003
- https://10.0.2.232:5003

**Debug PIN:** Changes on each restart (shown in terminal)

---

## 🎯 What This App Does

**RiskGate** (SecurityScan) is a Flask-based Microsoft Entra ID security monitoring tool that:
1. **Detects impossible travel** - analyzes sign-in logs for geographically impossible login patterns
2. **Prevents MFA fraud** - blocks risky sessions from adding/removing MFA during account takeovers
3. **Assigns risk scores** to login sessions based on location, time, and travel patterns
4. **Monitors security events** - provides dashboard for viewing alerts and user activity

### Core Security Feature
The app prevents attackers who steal passwords and pass MFA from permanently hijacking accounts by **blocking them from adding their own MFA methods** when impossible travel is detected.

---

## 🏗️ Architecture Overview

### Technology Stack
- **Backend:** Python Flask 3.x with Blueprints
- **Frontend:** Bootstrap 5, JavaScript (AJAX), Font Awesome icons
- **Authentication:** Microsoft Graph API + MSAL (Microsoft Authentication Library)
- **Database:** SQLAlchemy with SQLite (local) / PostgreSQL (Azure)
- **Deployment:** Azure App Service (configured for production)
- **Source Control:** GitHub (PeakMade/RiskGate, main branch)

### Key Files & Directories

#### Core Application Files
- **run.py** - App entry point, starts Flask server on port 5003 with HTTPS
- **config.py** - Configuration including aggressive group filtering rules
- **app/__init__.py** - Flask app factory with create_app()
- **app/routes.py** - Main routes and backend logic (scan, group fetch, member retrieval)
- **app/graph_client.py** - Microsoft Graph API client for Entra ID integration
- **app/mock_data.py** - Test data generator for development without real API calls

#### Templates (app/templates/)
- **securityscan_dashboard.html** - Main dashboard UI (extensively modified recently)
- **login.html** - Authentication page
- **base.html** - Base template with navigation
- **mfa_test_lab.html** - MFA testing interface
- **mfa_decision_log.html** - MFA decision audit log

#### Security & Detection (app/)
- **mfa_detection.py** / **mfa_detection_new.py** - MFA fraud detection logic
- **risk_detection.py** - Risk scoring algorithms
- **trusted_locations.py** - Trusted location management
- **alerts.py** / **alerts_new.py** - Alert generation and management

#### Configuration & Deployment
- **requirements.txt** - Python dependencies
- **cert.pem / key.pem** - Self-signed SSL certificates for local HTTPS
- **configure_azure_production.ps1** - Azure production deployment script
- **startup.sh** - Azure startup script
- **migrations/** - Database migration scripts (Alembic)

---

## 🎨 Recent UI/UX Improvements (Last Work Session)

### 1. **Timezone Handling - EST Conversion**
- **File:** app/routes.py (lines 13-27)
- **Implementation:** `convert_to_est()` helper function
- **Features:**
  - Parses UTC ISO 8601 timestamps from Graph API
  - Converts to EST (UTC-5)
  - Formats as 12-hour AM/PM: "07/08/2026 03:07:07 PM EST"
- **Applied to:** All timestamp displays (scan results, alerts, sign-in logs)

### 2. **Button Layout Optimization**
- **File:** app/templates/securityscan_dashboard.html (lines 46-96)
- **Changes:**
  - Restructured from multi-column to single row layout
  - All 4 buttons inline: Scan (100px) | REAL/MOCK (70px) | Clear (70px) | Report (75px)
  - Fixed widths with padding: 4px 8px for consistency
  - Removed "Click to toggle" text under REAL/MOCK button
  - Used d-flex, gap-1, flex-nowrap for alignment

### 3. **Group Type Input - Dropdown to Text Field**
- **File:** app/templates/securityscan_dashboard.html (lines 373-395)
- **Changes:**
  - Changed from `<select>` dropdown to `<input type="text">`
  - Enables users to type custom group names
  - Auto-search with 500ms debounce implemented
  - Enter key support for search

### 4. **Auto-Search & Member Display**
- **File:** app/templates/securityscan_dashboard.html (lines 484-548, 616-650)
- **Implementation:** `checkGroupMembers()` function with auto-trigger
- **Features:**
  - Automatic group search as user types (500ms debounce)
  - Exact match priority with partial fallback
  - Shows member count badge
  - Displays scrollable member list (max-height: 200px)
  - Lists member names and emails
  - No manual "Check" button required

### 5. **Enhanced Scan Progress Feedback**
- **File:** app/templates/securityscan_dashboard.html (lines 448-461)
- **Implementation:** 9-step progress message array
- **Messages:**
  1. "Initializing scan..."
  2. "Connecting to Microsoft Entra..."
  3. "Authenticating..."
  4. "Fetching sign-in logs..."
  5. "Analyzing locations..."
  6. "Calculating travel distances..."
  7. "Detecting impossible travel..."
  8. "Checking MFA status..."
  9. "Finalizing results..."
- **Rotation:** Every 2 seconds using setInterval

### 6. **Automatic Result Clearing**
- **Files:** 
  - app/routes.py (line 261) - Backend clearing
  - app/templates/securityscan_dashboard.html (lines 463-491, 568-614) - Frontend clearing
- **Triggers:**
  - **On Scan Start:** Clears last_scan timestamp, removes all result sections
  - **On Apply Selection:** Clears impossible logins count, removes alerts/results/timestamps, removes flash messages
- **DOM Elements Removed:**
  - `#impossibleLoginsCount` (reset to '0')
  - `#alertsSection`
  - `#scannedUsersSection`
  - `#allSignInLogsSection`
  - `#lastScanTimestamp`
  - All `.alert-dismissible` flash messages

### 7. **Conditional Alert Display**
- **File:** app/templates/securityscan_dashboard.html (line 108)
- **Change:** Recent Alerts section wrapped in `{% if recent_alerts %}`
- **Result:** Section only appears when alerts exist

---

## 🔧 Configuration & Filtering

### Group Filtering (config.py lines 106-134)
**Aggressive filtering is currently enabled:**
- **Activity Cutoff:** Groups must have activity since 2025
- **Excluded Patterns:** test, temp, old, archive, project-, sandbox, dev, staging, etc.
- **Department Keywords:** technology, accounting, hr, sales, marketing, etc.
- **Dash Exclusion:** `EXCLUDE_GROUPS_WITH_DASHES = True`

**Known Issue:** Users reported "Multiple groups found" warnings (e.g., "technology" vs "Technology")
**Status:** Not modified yet - may need adjustment if too restrictive

---

## 🚨 Known Issues & Behaviors

### App Stability
- **Crashes:** App occasionally exits with code 1 (cause unclear)
- **Recovery:** Restarts successfully with `python run.py`
- **SSL Errors:** `SSLEOFError` appears in logs but is non-fatal (browsers closing connections)
- **Debug Mode:** Auto-reloader can cause crashes on file saves

### Mock vs Real Data
- **Toggle:** REAL/MOCK button switches between live Graph API and test data
- **Session Variable:** `session.get('use_mock_data', False)`
- **Visual Indicator:** Orange (REAL) / Green (MOCK)

### Timezone Display
- **Backend:** All timestamps converted to EST before sending to frontend
- **Format:** 12-hour AM/PM format
- **Known Limitation:** Hardcoded to EST (UTC-5), doesn't adjust for DST

---

## 📊 Data Flow

### Scan Process
1. User selects target (email/group) and clicks "Scan"
2. Frontend shows spinner with rotating progress messages
3. Backend clears previous results (`scan_results['last_scan'] = None`)
4. If REAL mode: Calls Microsoft Graph API
5. If MOCK mode: Generates test data from mock_data.py
6. Analyzes sign-in logs for impossible travel patterns
7. Calculates distances and time between logins
8. Assigns risk scores to sessions
9. Returns results with EST-converted timestamps
10. Frontend displays alerts, user activity, and full logs

### Group Member Search
1. User types in group name input field
2. JavaScript debounces input (500ms delay)
3. AJAX call to `/get_group_members?name=<group_name>`
4. Backend queries Graph API or mock data
5. Returns JSON with member list and count
6. Frontend displays member count badge and scrollable member list
7. User clicks member to populate email field

---

## 🗄️ Database Models

### Key Tables (app/models.py)
- **SignInEvent** - Entra ID sign-in logs with location data
- **User** - User accounts and profiles
- **MFAMethod** - User authentication methods
- **Alert** - Security alerts for impossible travel
- **SecurityEvent** - Audit log of all security actions
- **TrustedLocation** - Approved locations for users/groups
- **MFADecision** - Log of MFA approval/block decisions

### Migrations
- Located in `migrations/versions/`
- Uses Alembic for version control
- Recent: `add_state_to_signin_events.py`, `add_entra_models_for_mfa_detection.py`

---

## 🔐 Microsoft Graph API Integration

### Required Permissions
- `AuditLog.Read.All` - Sign-in and audit logs
- `UserAuthenticationMethod.Read.All` - MFA methods
- `User.Read.All` - User details
- `Group.Read.All` - Group membership

### Environment Variables (.env)
```
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_CLIENT_SECRET=<client-secret>
SECRET_KEY=<flask-secret-key>
```

### Graph Client (app/graph_client.py)
- MSAL authentication with app-only flow
- Token caching and refresh
- Error handling for API rate limits
- Methods: get_signin_logs(), get_groups(), get_group_members(), get_user()

---

## 🚀 Deployment

### Azure App Service
- **Resource:** riskgate-app (or similar)
- **Region:** Configured in configure_azure_production.ps1
- **Startup:** Uses startup.sh to activate venv and run gunicorn
- **Database:** PostgreSQL (connection string in app settings)
- **SSL:** Azure-managed certificate

### GitHub Repository
- **URL:** github.com/PeakMade/RiskGate
- **Branch:** main
- **Latest Commit:** 10b65b7 ("Clear all results when applying new selection")
- **Previous Commits:**
  - a370fed - EST timezone conversion
  - 8f41f2c - Button layout improvements
  - e3507d9 - Group input and auto-search
  - 67062b8 - Progress messages

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env  # Edit with your Azure credentials

# Run migrations
flask db upgrade

# Generate SSL certificates (if needed)
python generate_cert.py

# Start app
python run.py
```

---

## 📝 Code Patterns & Conventions

### Backend (routes.py)
- Uses Flask Blueprints (`bp = Blueprint('main', __name__)`)
- Session-based state management for scan results
- GraphClient singleton for API calls
- Helper functions: `convert_to_est()`, `calculate_distance()`, `check_impossible_travel()`
- JSON responses for AJAX endpoints
- Flash messages for user feedback

### Frontend (securityscan_dashboard.html)
- Bootstrap 5 components (cards, modals, buttons, alerts)
- Vanilla JavaScript (no jQuery)
- AJAX fetch() calls with error handling
- Dynamic DOM manipulation with `.innerHTML` and `.remove()`
- Event listeners with debouncing for performance
- Responsive layout with Bootstrap grid (col-md-*)

### Naming Conventions
- Routes: `/scan_entra`, `/get_groups`, `/get_group_members`, `/clear_scan`
- Functions: snake_case (e.g., `get_group_members()`, `convert_to_est()`)
- JavaScript: camelCase (e.g., `showSpinner()`, `checkGroupMembers()`)
- CSS IDs: camelCase (e.g., `impossibleLoginsCount`, `scanButton`)

---

## 🎯 Where to Pick Up Work

### Immediate Next Steps
1. **Test Recent Changes:** Verify all UI improvements work in both REAL and MOCK modes
2. **Monitor Stability:** Watch for crashes and identify root cause of exit code 1
3. **Group Filtering:** Consider adjusting config.py if users report missing groups

### Potential Enhancements
1. **Timezone Selection:** Allow users to choose their timezone (not just EST)
2. **Alert Management:** Add ability to dismiss/archive alerts
3. **Export Functionality:** Implement CSV/Excel export for scan results
4. **Historical Trends:** Show impossible travel patterns over time
5. **User Profiles:** Add detailed view for user security history
6. **Performance:** Optimize large group scans (pagination, caching)
7. **Testing:** Add unit tests for core detection logic

### Bug Fixes / Technical Debt
1. **App Crashes:** Debug and fix exit code 1 crashes
2. **SSL Errors:** Investigate SSLEOFError logs
3. **DST Handling:** Fix timezone for daylight saving time
4. **Group Duplicates:** Handle case-insensitive group matching
5. **Error Messages:** Improve user-facing error messages
6. **API Rate Limits:** Better handling of Graph API throttling

### Features Not Yet Implemented
1. **Real-time Monitoring:** Auto-refresh dashboard for new alerts
2. **Email Notifications:** Send alerts to admins
3. **Risk Policies:** Define custom risk thresholds per group/user
4. **Integration:** Webhook support for SIEM systems
5. **Reporting:** Scheduled reports generation
6. **Multi-tenant:** Support for multiple Azure tenants

---

## 📚 Reference Documentation

### Internal Docs
- **README.md** - Overview and purpose
- **ARCHITECTURE.md** - Detailed architecture documentation
- **IMPLEMENTATION_SUMMARY.md** - Implementation notes
- **QUICKSTART.md** - Getting started guide
- **AGENTS.md** - GitHub Copilot repository instructions

### External Resources
- [Microsoft Graph API Docs](https://learn.microsoft.com/en-us/graph/)
- [MSAL Python Docs](https://msal-python.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Bootstrap 5 Docs](https://getbootstrap.com/docs/5.0/)

---

## 🧪 Testing

### Test Files
- **test_graph_api.py** - Graph API connection testing
- **test_entra_groups.py** - Group fetching tests
- **test_filtered_groups.py** - Group filtering logic tests
- **test_mfa_detection.py** - MFA detection tests
- **test_specific_user.py** - User-specific scan tests
- **verify_mfa_only.py** - MFA-only verification
- **verify_workflow.py** - End-to-end workflow tests
- **seed_test_data.py** - Database seeding for tests

### Running Tests
```bash
# Activate virtual environment
.venv\Scripts\Activate.ps1

# Run specific test
python test_graph_api.py

# Run all tests (if pytest configured)
pytest
```

---

## 🔑 Key Takeaways

1. **App is Working:** All recent UI improvements implemented and pushed to GitHub
2. **Stability Concern:** Occasional crashes require monitoring
3. **User Feedback:** Recent changes based on iterative user requests
4. **Next Priority:** Test thoroughly and address any stability issues
5. **Documentation:** Keep this file updated as work progresses

---

## 💡 Tips for Development

- **Use MOCK mode** for testing UI changes (faster, no API calls)
- **Check terminal output** for errors and request logs
- **Git commit frequently** with descriptive messages
- **Test in browser** after each change (https://127.0.0.1:5003)
- **Monitor console** for JavaScript errors (F12 Developer Tools)
- **Reference AGENTS.md** for Copilot coding guidelines
- **Ask for context** if uncertain about existing patterns

---

**Remember:** The app prevents MFA fraud during account takeovers by detecting impossible travel and blocking risky sessions from modifying authentication methods. Every feature should support this core security mission.

Good luck with your continued development! 🚀
