# RiskGate / SecurityScan — Formal Data Dictionary

**Scope of verification:** This document was built by reading the executable code in this repository only — SQLAlchemy model definitions (`app/models.py`, `app/models_new.py`), Alembic migrations (`migrations/versions/*.py`), route/service code (`app/routes.py`, `app/scheduler.py`, `app/ingest.py`, `app/graph_client.py`, `app/trusted_locations.py`, `app/risk_detection.py`, `app/risk.py`, `app/risk_new.py`, `app/alerts.py`, `app/alerts_new.py`, `app/mfa_detection.py`, `app/mfa_detection_new.py`, `app/auth_hooks.py`, `app/mfa_protection.py`, `app/security_events.py`, `app/utils.py`, `app/msal_auth.py`), and `config.py`. **No live database connection was made** — the production Microsoft Fabric SQL database was not queried. Every fact below is cited to a file/line/function. Anything that could not be confirmed this way is explicitly marked **NOT VERIFIED**.

---

## ✅ SCHEMA DISCREPANCY — RESOLVED BY LIVE DATABASE QUERY (2026-09-22)

The current model code and the Alembic migrations present in this repository disagree on how six tables link to `user_identity` (models declare an Integer `user_id` FK in the `riskgate` schema; migrations create a String `entra_user_id` FK with no schema). This was resolved by running a read-only verification query directly against the live Microsoft Fabric SQL database (via the app's own `create_app()`/`db.engine`, `DB_AUTHENTICATION=local` / `AzureCliCredential`), rather than assuming either side was correct:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_NAME IN ('user_identity','entra_signin_event','entra_mfa_event',
  'user_auth_method_snapshot','user_trusted_location','user_risk_state',
  'entra_security_alert','scan_run');
```
Result: all 8 tables physically exist in the **`riskgate`** schema — matching the models, not the schema-less migrations.

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME IN ('entra_signin_event','entra_mfa_event','user_auth_method_snapshot',
  'user_trusted_location','user_risk_state','entra_security_alert')
  AND COLUMN_NAME LIKE '%user_id%';
```
Result: `entra_mfa_event.user_id`, `entra_security_alert.user_id`, `entra_signin_event.user_id`, `user_auth_method_snapshot.user_id`, `user_risk_state.user_id`, `user_trusted_location.user_id` — every one of them is `int`, `NOT NULL`. **No `entra_user_id` column exists on any of these six tables.**

**Verified conclusion:** the live database matches `app/models_new.py` exactly (Integer `user_id` FK to `riskgate.user_identity.id`, `riskgate` schema throughout). The `entra_user_id`/default-schema design in `c34d5ec874d2_add_entra_models_for_mfa_detection.py` and `add_trusted_locations.py` **does not reflect the current live schema** — the live database was evidently altered by a migration or manual DDL not present in this repository's `migrations/versions/` folder. This is a real gap in the repo's migration history (worth investigating separately), but it is no longer a code-behavior risk: the ORM models are confirmed correct against production.

Separately, [migrations/versions/20260706_add_state_to_signin_events.py](migrations/versions/20260706_add_state_to_signin_events.py#L18) runs `op.add_column('entra_sign_in_event', ...)` (note: table name has an extra underscore, `entra_sign_in_event`, not the real `entra_signin_event`). Verified live: only `riskgate.entra_signin_event` exists (no `entra_sign_in_event` table), and `entra_signin_event.state` (varchar(100), nullable) **does exist**. Since a table named `entra_sign_in_event` does not exist, this migration file **could not have been what actually added the live `state` column** as written — the column must have been added by different/unlisted means (manual DDL or a migration not present in this repo). This confirms the repo's migration history does not fully match the deployed database, though the resulting column itself is present and correct.

Also still true: this migration and `add_trusted_locations.py` both declare `down_revision = 'c34d5ec874d2'` — two branch heads from the same parent with no merge migration present in this repo. **NOT VERIFIED** how/if these were reconciled in the deployed database (out of scope for a read-only table/column check).

---

## Part 1 — Live/Active Schema (`app/models_new.py`, intended schema `riskgate`)

These 8 tables are the ones actually queried/written by the live scan pipeline (`app/routes.py`, `app/scheduler.py`) or by modules confirmed to be called from it (`app/trusted_locations.py`). Table-level source: [app/models_new.py](app/models_new.py#L1).

### 1.1 `user_identity` (model `UserIdentity`)

**Structure**

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK | FK | FK Reference | Unique |
|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | Yes | No | — | Yes (PK) |
| entra_user_id | Entra Object ID | String | 100 | Required | No | No | — | Yes |
| user_principal_name | User Principal Name (UPN) | String | 255 | Required | No | No | — | No |
| display_name | Display Name | String | 255 | Nullable | No | No | — | No |
| created_at | Record Created At | DateTime | — | Nullable (defaults to now) | No | No | — | No |
| last_seen_at | Last Seen At | DateTime | — | Nullable (defaults to now) | No | No | — | No |

**Lineage / Governance** — cited: [app/models_new.py](app/models_new.py#L55-L69), created by [app/ingest.py](app/ingest.py#L23) `get_or_create_user_identity()` (called from that module only) and directly by [app/scheduler.py](app/scheduler.py#L216) inline construction.

| Field Name | Source System | Source Field/API Field | Stored/Calc | Example Value | Business Purpose | Data Classification | Related Business Rule | Notes |
|---|---|---|---|---|---|---|---|---|
| id | System | N/A (autoincrement) | Stored | 101 | Internal surrogate key | System Generated | — | — |
| entra_user_id | Microsoft Graph | `userId` (sign-in log) / `id` (user object) | Stored | `a1b2c3d4-...` | Correlates all records to one Entra identity | PII / Security Sensitive | — | Populated by [app/scheduler.py](app/scheduler.py#L219) inline; `get_or_create_user_identity` in ingest.py is not confirmed called live (see §4) |
| user_principal_name | Microsoft Graph | `userPrincipalName` | Stored | `jdoe@company.com` | Human-readable identity for alerts/dashboard | PII | — | — |
| display_name | Microsoft Graph | `userDisplayName` | Stored | `Jane Doe` | Display in UI | PII | — | — |
| created_at | System | N/A | Stored | 2026-01-01T10:00:00 | First-seen timestamp | Internal | — | — |
| last_seen_at | System | N/A | Stored | 2026-09-20T08:00:00 | Tracks recency of activity | Internal | — | Updated on every scan pass that sees this user, [app/scheduler.py](app/scheduler.py#L221) |

---

### 1.2 `entra_signin_event` (model `EntraSignInEvent`)

Cited: [app/models_new.py](app/models_new.py#L79-L134). Populated live by [app/scheduler.py](app/scheduler.py#L228-L246) (direct construction — **not** via `app/ingest.py::ingest_signin_event`, see §4). Read by [app/routes.py](app/routes.py#L932) `analyze_impossible_travel()` (indirectly, via the raw Graph log dict, not the ORM row) and by [app/trusted_locations.py](app/trusted_locations.py#L152) for historical backfill.

**Structure**

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK | FK | FK Reference | Unique |
|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | Yes | No | — | Yes (PK) |
| microsoft_event_id | Graph Sign-In ID | String | 100 | Required | No | No | — | Yes |
| user_id | User (internal) | Integer | — | Required | No | Yes (per model) | `user_identity.id` | No |
| created_at | Sign-In Time | DateTime | — | Nullable (defaults to now) | No | No | — | No |
| ip_address | IP Address | String | 50 | Nullable | No | No | — | No |
| country | Country | String | 100 | Nullable | No | No | — | No |
| state | State/Region | String | 100 | Nullable | No | No | — | No |
| city | City | String | 100 | Nullable | No | No | — | No |
| latitude | Latitude | Float | — | Nullable | No | No | — | No |
| longitude | Longitude | Float | — | Nullable | No | No | — | No |
| browser | Browser | String | 100 | Nullable | No | No | — | No |
| operating_system | Operating System | String | 100 | Nullable | No | No | — | No |
| device_id | Device ID | String | 100 | Nullable | No | No | — | No |
| app_display_name | Application Name | String | 255 | Nullable | No | No | — | No |
| status | Sign-In Result | String | 50 | Nullable | No | No | — | No |
| mfa_required | MFA Required | Boolean | — | Nullable | No | No | — | No |
| mfa_satisfied | MFA Satisfied | Boolean | — | Nullable | No | No | — | No |
| risk_level_aggregated | Microsoft Risk Level | String | 50 | Nullable | No | No | — | No |
| risk_detail | Microsoft Risk Detail | String | 50 | Nullable | No | No | — | No |
| local_risk_score | SecurityScan Risk Score | Integer | — | Nullable (default 0) | No | No | — | No |
| local_risk_level | SecurityScan Risk Level | String | 50 | Nullable (default 'low') | No | No | — | No |
| local_risk_reasons | SecurityScan Risk Reasons | Text (JSON) | — | Nullable | No | No | — | No |
| impossible_travel_detected | Impossible Travel Flag | Boolean | — | Nullable (default False) | No | No | — | No |
| required_travel_speed_mph | Required Travel Speed | Float | — | Nullable | No | No | — | No |
| raw_json | Raw Graph Payload | Text | — | Nullable | No | No | — | No |

**Lineage / Governance**

| Field Name | Source System | Source Field/API Field | Stored/Calc | Example Value | Business Purpose | Data Classification | Related Business Rule | Notes |
|---|---|---|---|---|---|---|---|---|
| id | System | N/A | Stored | 5001 | Surrogate key | System Generated | — | — |
| microsoft_event_id | Microsoft Graph | `id` | Stored | `Directory_xxxxx` | De-duplication key for ingestion | System Generated | Prevents re-processing the same sign-in | — |
| user_id | Internal | N/A | Stored | 101 | Links sign-in to a user | Internal | — | **Verified live** (2026-09-22, `INFORMATION_SCHEMA.COLUMNS` query): `riskgate.entra_signin_event.user_id` is `int NOT NULL`, matching the model. Migrations' `entra_user_id` design does not reflect the live database. |
| created_at | Microsoft Graph | `createdDateTime` | Stored | 2026-09-20T14:32:00 | When the sign-in occurred; drives impossible-travel time math | Internal | Used as `curr_time`/`prev_time` in [app/routes.py](app/routes.py#L1023) | — |
| ip_address | Microsoft Graph | `ipAddress` | Stored | `203.0.113.5` | Investigative context | Security Sensitive | — | — |
| country | Microsoft Graph | `location.countryOrRegion` | Stored | `US` | Used for domestic/international threshold | Internal | Threshold selection, [app/routes.py](app/routes.py#L1081) | — |
| state | Microsoft Graph | `location.state` | Stored | `GA` | Display only | Internal | — | Added by [migrations/versions/20260706_add_state_to_signin_events.py](migrations/versions/20260706_add_state_to_signin_events.py); **table-name mismatch noted above — NOT VERIFIED as applied** |
| city | Microsoft Graph | `location.city` | Stored | `Atlanta` | Display / route description | Internal | Used in [app/scheduler.py](app/scheduler.py#L20) `describe_travel_route()` | — |
| latitude | Microsoft Graph | `location.geoCoordinates.latitude` | Stored | 33.7490 | Distance calculation input | Internal | [app/routes.py](app/routes.py#L1019) `calculate_distance()` | **Verified live (2026-09-22):** 390 rows in `riskgate.entra_signin_event` have `latitude = 0 AND longitude = 0`. Confirmed handled safely: [app/routes.py](app/routes.py#L1022) uses `if not all([curr_lat, curr_lon, prev_lat, prev_lon]): continue`, and Python's `all()` treats `0.0` as falsy, so these rows are correctly skipped exactly like missing coordinates — not a bug. |
| longitude | Microsoft Graph | `location.geoCoordinates.longitude` | Stored | -84.3880 | Distance calculation input | Internal | Same as above | Same 0.0 caveat |
| browser | Microsoft Graph | `deviceDetail.browser` | Stored | `Chrome` | Device fingerprint component | Internal | Used to build device_name label, not part of the alert logic itself | — |
| operating_system | Microsoft Graph | `deviceDetail.operatingSystem` | Stored | `Windows` | Device fingerprint component | Internal | — | — |
| device_id | Microsoft Graph | `deviceDetail.deviceId` | Stored | `d290f1ee-...` | Same-device / different-device factor | Internal | `different_device` factor, [app/routes.py](app/routes.py#L1096-L1097) | — |
| app_display_name | Microsoft Graph | `appDisplayName` | Stored | `Office 365` | Display context | Internal | — | — |
| status | Microsoft Graph | `status.errorCode` | Stored (derived at ingest) | `success` / `failure` | Success/failure of the sign-in | Internal | Only `status == 'success'` sign-ins are used to learn trusted locations, [app/trusted_locations.py](app/trusted_locations.py#L83) | Computed as `'success' if errorCode == 0 else 'failure'`, [app/scheduler.py](app/scheduler.py#L237) |
| mfa_required | Microsoft Graph | `mfaDetail.authMethod` (presence) | Stored | `true` | Whether MFA was required | Internal | — | Only set by [app/ingest.py](app/ingest.py#L124) `ingest_signin_event()`, not confirmed called from the live scan (§4); [app/scheduler.py](app/scheduler.py#L228-L246) never sets this field. **Verified live (2026-09-22):** `SELECT COUNT(*) WHERE mfa_required IS NOT NULL OR mfa_satisfied IS NOT NULL OR local_risk_reasons IS NOT NULL` returned **0** across the whole table — confirmed always NULL in production. |
| mfa_satisfied | Microsoft Graph | `authenticationDetails[].succeeded` | Stored | `true` | Whether MFA was completed | Internal | — | Same query/result as `mfa_required` — confirmed always NULL in production |
| risk_level_aggregated | Microsoft Graph | `riskLevelAggregated` | Stored | `none` | Microsoft's own risk assessment | Security Sensitive | — | — |
| risk_detail | Microsoft Graph | `riskDetail` | Stored | `none` | Microsoft's risk explanation | Security Sensitive | — | — |
| local_risk_score | Calculated (SecurityScan) | N/A | Stored (calculated then persisted) | 70 | Drives severity of alert | Internal | Set from `config.RISK_SCORE_EXTREME_TRAVEL` (70) or `RISK_SCORE_IMPOSSIBLE_TRAVEL` (40), [app/scheduler.py](app/scheduler.py#L317-L321) | Only set when `impossible_travel_detected`; otherwise remains model default `0` |
| local_risk_level | Calculated (SecurityScan) | N/A | Stored (calculated) | `critical` | Human severity label | Internal | `'critical'` if `local_risk_score >= config.RISK_THRESHOLD_CRITICAL` (90) else `'high'`, [app/scheduler.py](app/scheduler.py#L322-L326) | — |
| local_risk_reasons | Calculated | N/A | Stored (JSON) | `["impossible_travel"]` | Explanation text | Internal | — | No assignment to this field found in [app/scheduler.py](app/scheduler.py) or [app/routes.py](app/routes.py). **Verified live: confirmed always NULL** (same query as `mfa_required`, above) |
| impossible_travel_detected | Calculated (SecurityScan) | N/A | Stored (calculated) | `true` | Flag consumed by dashboard | Internal | Set `True` only for events returned by `analyze_impossible_travel()`, [app/scheduler.py](app/scheduler.py#L316) | — |
| required_travel_speed_mph | Calculated (SecurityScan) | N/A | Stored (calculated) | 15000.0 | Displayed speed for the alert | Internal | `distance_miles / time_diff_hours`, [app/routes.py](app/routes.py#L1036) | — |
| raw_json | Microsoft Graph | Full sign-in record | Stored | `{...}` | Forensic/audit trail | Security Sensitive | — | — |

Also present per **migration** `c34d5ec874d2` but **absent from the current model class**: `conditional_access_status` (String(50)). **Verified live** (2026-09-22, `INFORMATION_SCHEMA.COLUMNS` query against `riskgate.entra_signin_event`): this column **does not exist** in the live database. It is not merely unmapped by the ORM — it was never created (or was later dropped) in the actual deployed table.

---

### 1.3 `entra_mfa_event` (model `EntraMfaEvent`)

Cited: [app/models_new.py](app/models_new.py#L137-L167). **Verified live (2026-09-22):** `SELECT COUNT(*) FROM riskgate.entra_mfa_event` returned **0 rows**. Confirmed dead in production — the only code that constructs this model is [app/ingest.py](app/ingest.py#L168) `ingest_audit_event()`, called only from `ingest_audit_logs_batch()` ([app/ingest.py](app/ingest.py#L381)), which has no confirmed caller in `app/routes.py` or `app/scheduler.py`.

**Structure**

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK | FK | FK Reference | Unique |
|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | Yes | No | — | Yes (PK) |
| microsoft_event_id | Graph Audit Log ID | String | 100 | Required | No | No | — | Yes |
| user_id | User (internal) | Integer | — | Required | No | Yes (per model) | `user_identity.id` | No |
| created_at | Event Time | DateTime | — | Nullable (defaults to now) | No | No | — | No |
| activity_name | Activity Name | String | 255 | Nullable | No | No | — | No |
| category | Audit Category | String | 100 | Nullable | No | No | — | No |
| operation_type | Operation Type | String | 100 | Nullable | No | No | — | No |
| method_type | MFA Method Type | String | 100 | Nullable | No | No | — | No |
| initiated_by | Initiated By | String | 255 | Nullable | No | No | — | No |
| target_user | Target User | String | 255 | Nullable | No | No | — | No |
| ip_address | IP Address | String | 50 | Nullable | No | No | — | No |
| country | Country | String | 100 | Nullable | No | No | — | No |
| city | City | String | 100 | Nullable | No | No | — | No |
| device_id | Device ID | String | 100 | Nullable | No | No | — | No |
| risk_score_at_time | Risk Score At Time | Integer | — | Nullable | No | No | — | No |
| related_recent_signin_id | Related Sign-In | Integer | — | Nullable | No | Yes | `entra_signin_event.id` | No |
| raw_json | Raw Graph Payload | Text | — | Nullable | No | No | — | No |

**Lineage / Governance**

| Field Name | Source System | Source Field/API Field | Stored/Calc | Example Value | Business Purpose | Data Classification | Related Business Rule | Notes |
|---|---|---|---|---|---|---|---|---|
| id | System | N/A | Stored | 900 | Surrogate key | System Generated | — | Table confirmed **empty (0 rows)** in production, 2026-09-22 |
| microsoft_event_id | Microsoft Graph | `id` (directoryAudits) | Stored | `abcd-...` | De-duplication | System Generated | [app/ingest.py](app/ingest.py#L183) | Table confirmed empty (0 rows) |
| user_id | Internal | N/A | Stored | 101 | Links event to user | Internal | — | Column verified live as `int NOT NULL` on `riskgate.entra_mfa_event`; table confirmed empty (0 rows) |
| created_at | Microsoft Graph | `activityDateTime` | Stored | 2026-09-19T09:00:00 | When the change happened | Internal | — | Table confirmed empty (0 rows) |
| activity_name | Microsoft Graph | `activityDisplayName` | Stored | `User registered security info` | What happened | Internal | Matched against keyword list, [app/ingest.py](app/ingest.py#L188-L194) | Table confirmed empty (0 rows) |
| category | Microsoft Graph | `category` | Stored | `UserManagement` | Grouping | Internal | — | Table confirmed empty (0 rows) |
| operation_type | Microsoft Graph | `operationType` | Stored | `Add` | Add/Delete/Update | Internal | Drives `operation` classification in [app/mfa_detection_new.py](app/mfa_detection_new.py#L120-L128) | Table confirmed empty (0 rows) |
| method_type | Microsoft Graph | `targetResources[].modifiedProperties[].newValue` | Stored | `microsoftAuthenticator` | Which MFA method changed | Internal | — | Table confirmed empty (0 rows) |
| initiated_by | Microsoft Graph | `initiatedBy.user.userPrincipalName` or `initiatedBy.app.displayName` | Stored | `jdoe@company.com` | Who made the change | PII | — | Table confirmed empty (0 rows) |
| target_user | Microsoft Graph | `targetResources[0].userPrincipalName` | Stored | `jdoe@company.com` | Whose MFA changed | PII | — | Table confirmed empty (0 rows) |
| ip_address | Microsoft Graph | `initiatedBy.user.ipAddress` | Stored | `203.0.113.5` | Investigative context | Security Sensitive | — | Table confirmed empty (0 rows) |
| country | Microsoft Graph | Not populated in `ingest_audit_event` | — | — | — | — | — | **Column exists on model; no assignment found in ingest.py's constructor call** |
| city | Microsoft Graph | Not populated in `ingest_audit_event` | — | — | — | — | — | Same as `country` |
| device_id | Microsoft Graph | Not populated in `ingest_audit_event` | — | — | — | — | — | Same as `country` |
| risk_score_at_time | Calculated | N/A | — | — | Intended to snapshot risk at time of MFA change | Internal | — | No assignment found anywhere in the repository; table confirmed empty (0 rows) live |
| related_recent_signin_id | Internal | N/A | Stored | 5001 | Correlate MFA change to a recent risky sign-in | Internal | Intended for `mfa_change_after_risky_login` rule | No assignment found; table confirmed empty (0 rows) live |
| raw_json | Microsoft Graph | Full audit record | Stored | `{...}` | Forensic trail | Security Sensitive | — | Table confirmed empty (0 rows) |

---

### 1.4 `user_auth_method_snapshot` (model `UserAuthMethodSnapshot`)

Cited: [app/models_new.py](app/models_new.py#L170-L190). **Verified live (2026-09-22):** `SELECT COUNT(*) FROM riskgate.user_auth_method_snapshot` returned **0 rows**. Confirmed dead in production — only constructed by [app/ingest.py](app/ingest.py#L290) `ingest_auth_method_snapshot()`, which has no confirmed caller anywhere in the repository (not even from `ingest.py`'s own batch functions).

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK/FK | Source Field/API Field | Stored/Calc | Data Classification | Notes |
|---|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | PK | N/A | Stored | System Generated | Table confirmed empty (0 rows) |
| user_id | User (internal) | Integer | — | Required | FK → `user_identity.id` (per model) | N/A | Stored | Internal | Column verified live as `int NOT NULL`; table confirmed empty (0 rows) |
| method_id | Graph Method ID | String | 100 | Nullable, Unique | — | `id` | Stored | System Generated | Table confirmed empty (0 rows) |
| method_type | Method Type | String | 100 | Nullable | — | `@odata.type` (suffix) | Stored | Internal | e.g. `microsoftAuthenticator`; table confirmed empty (0 rows) |
| display_name | Display Name | String | 255 | Nullable | — | `displayName` | Stored | Internal | Table confirmed empty (0 rows) |
| first_seen_at | First Seen | DateTime | — | Nullable | — | N/A | Stored | Internal | Table confirmed empty (0 rows) |
| last_seen_at | Last Seen | DateTime | — | Nullable | — | N/A | Stored | Internal | Table confirmed empty (0 rows) |
| status | Status | String | 50 | Nullable (default 'active') | — | N/A | Stored | Internal | Table confirmed empty (0 rows) |
| raw_json | Raw Payload | Text | — | Nullable | — | Full method record | Stored | Security Sensitive | Table confirmed empty (0 rows) |

---

### 1.5 `user_trusted_location` (model `UserTrustedLocation`)

Cited: [app/models_new.py](app/models_new.py#L193-L215), migration [migrations/versions/add_trusted_locations.py](migrations/versions/add_trusted_locations.py). Populated/read live by [app/trusted_locations.py](app/trusted_locations.py#L73-L143) — **but this module's `update_trusted_location()`/`find_trusted_location()` functions are only called by `app/risk_detection.py::detect_impossible_travel()` and `app/trusted_locations.py::learn_locations_from_history()` — neither of which was confirmed to be called from `app/scheduler.py` or `app/routes.py`.** The live impossible-travel path (`analyze_impossible_travel()` in `app/routes.py`) implements its own, separate, in-memory trusted-location logic (batch-frequency count, not this table). **Verified live (2026-09-22):** `SELECT COUNT(*) FROM riskgate.user_trusted_location` returned **0 rows** — confirmed this table is never populated in production, despite the code that would populate it existing in the repository.

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK/FK | Source Field/API Field | Stored/Calc | Data Classification | Notes |
|---|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | PK | N/A | Stored | System Generated | — |
| user_id | User (internal) | Integer | — | Required | FK → `user_identity.id` (per model) | N/A | Stored | Internal | Column verified live as `int NOT NULL` on `riskgate.user_trusted_location` |
| country | Country | String | 100 | Required | — | `EntraSignInEvent.country` | Stored | Internal | [app/trusted_locations.py](app/trusted_locations.py#L108) |
| city | City | String | 100 | Nullable | — | `EntraSignInEvent.city` | Stored | Internal | — |
| latitude | Latitude | Float | — | Required | — | `EntraSignInEvent.latitude` | Stored | Internal | — |
| longitude | Longitude | Float | — | Required | — | `EntraSignInEvent.longitude` | Stored | Internal | — |
| login_count | Login Count | Integer | — | Nullable (default 1) | — | N/A | Calculated then stored | Internal | Incremented each time a sign-in matches within 50 miles ([config.py](config.py#L164) `TRUSTED_LOCATION_RADIUS_MILES`), [app/trusted_locations.py](app/trusted_locations.py#L100) |
| first_seen | First Seen | DateTime | — | Nullable | — | N/A | Stored | Internal | — |
| last_seen | Last Seen | DateTime | — | Nullable | — | N/A | Stored | Internal | — |
| is_trusted | Is Trusted | Boolean | — | Nullable (default False) | — | N/A | Calculated then stored | Internal | `True` once `login_count >= config.TRUSTED_LOCATION_MIN_LOGINS` (3), [app/trusted_locations.py](app/trusted_locations.py#L104) |
| location_name | Location Display Name | String | 255 | Nullable | — | Formatted from city/state/country | Calculated then stored | Internal | [app/trusted_locations.py](app/trusted_locations.py#L15-L21) |

---

### 1.6 `user_risk_state` (model `UserRiskState`)

Cited: [app/models_new.py](app/models_new.py#L218-L236). Constructed/updated only by [app/risk_detection.py](app/risk_detection.py#L25) and [app/risk_new.py](app/risk_new.py) (both import `UserRiskState`), neither of which was confirmed called from `app/routes.py` or `app/scheduler.py`. **Verified live (2026-09-22):** `SELECT COUNT(*) FROM riskgate.user_risk_state` returned **0 rows** — confirmed dead in production.

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK/FK | Stored/Calc | Data Classification | Notes |
|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | PK | Stored | System Generated | Table confirmed empty (0 rows) |
| user_id | User (internal) | Integer | — | Required, Unique | FK → `user_identity.id` (per model) | Stored | Internal | Column verified live as `int NOT NULL`; table confirmed empty (0 rows) |
| current_risk_score | Current Risk Score | Integer | — | Nullable (default 0) | — | Calculated | Internal | Table confirmed empty (0 rows) |
| current_risk_level | Current Risk Level | String | 50 | Nullable (default 'low') | — | Calculated | Internal | Table confirmed empty (0 rows) |
| reasons | Reasons | Text (JSON) | — | Nullable | — | Calculated | Internal | Table confirmed empty (0 rows) |
| last_risky_signin_at | Last Risky Sign-In | DateTime | — | Nullable | — | Stored | Internal | Table confirmed empty (0 rows) |
| last_impossible_login_at | Last Impossible Login | DateTime | — | Nullable | — | Stored | Internal | Table confirmed empty (0 rows) |
| last_mfa_change_at | Last MFA Change | DateTime | — | Nullable | — | Stored | Internal | Table confirmed empty (0 rows) |
| updated_at | Updated At | DateTime | — | Nullable (auto on update) | — | Stored | Internal | Table confirmed empty (0 rows) |

---

### 1.7 `entra_security_alert` (model `EntraSecurityAlert`)

Cited: [app/models_new.py](app/models_new.py#L239-L269). **This table is confirmed live** — created directly by [app/scheduler.py](app/scheduler.py#L356-L372) for `alert_type='impossible_login'`, and queried by [app/routes.py](app/routes.py#L111) for the dashboard. A parallel creation path exists in [app/alerts_new.py](app/alerts_new.py#L52) `create_security_alert()` for the other documented alert types (`extreme_impossible_login`, `mfa_change_after_risky_login`, `possible_mfa_takeover`, `tap_created_after_risk`) — **but no caller of `app/alerts_new.py::create_security_alert()` was found anywhere in the repository. Verified live (2026-09-22):** `SELECT alert_type, COUNT(*) FROM riskgate.entra_security_alert GROUP BY alert_type` returned exactly one row: `('impossible_login', 83)` — confirmed no other alert type has ever been created in production.

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK/FK | Stored/Calc | Data Classification | Related Business Rule | Notes |
|---|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | PK | Stored | System Generated | — | — |
| user_id | User (internal) | Integer | — | Required | FK → `user_identity.id` (per model) | Stored | Internal | — | Column verified live as `int NOT NULL` on `riskgate.entra_security_alert`, and confirmed passed as `user_id=event.user_id` in live code, [app/scheduler.py](app/scheduler.py#L357) |
| alert_type | Alert Type | String | 100 | Required | — | Stored | Internal | — | **Verified live: only `impossible_login` exists (83 of 83 rows)** |
| severity | Severity | String | 50 | Required | — | Calculated then stored | Internal | `'critical'` if `speed > config.TRAVEL_SPEED_EXTREME` (1000) else `'high'`, [app/scheduler.py](app/scheduler.py#L360) | — |
| reason | Reason Text | Text | — | Required | — | Calculated then stored | Internal | Built from route description + risk factors, [app/scheduler.py](app/scheduler.py#L361-L367) | — |
| status | Status | String | 50 | Nullable (default 'open') | — | Stored | Internal | — | — |
| created_at | Created At | DateTime | — | Nullable (defaults to now) | — | Stored | Internal | — | — |
| resolved_at | Resolved At | DateTime | — | Nullable | — | Stored | Internal | — | **Verified live:** `SELECT COUNT(*) WHERE resolved_at IS NOT NULL OR related_mfa_event_id IS NOT NULL` returned **0** — confirmed never populated in any of the 83 existing rows |
| resolved_by | Resolved By | String | 255 | Nullable | — | Stored | Internal | — | Same query confirms 0 populated |
| resolution_notes | Resolution Notes | Text | — | Nullable | — | Stored | Internal | — | No dedicated count run, but no code sets it and `resolved_at` is confirmed always null, so this is consistent with never being populated |
| related_signin_event_id | Related Sign-In | Integer | — | Nullable | FK → `entra_signin_event.id` | Stored | Internal | Used for the duplicate-alert guard, [app/scheduler.py](app/scheduler.py#L349-L353) | — |
| related_mfa_event_id | Related MFA Event | Integer | — | Nullable | FK → `entra_mfa_event.id` | Stored | Internal | Intended for MFA-correlation alert types | **Verified live: 0 of 83 rows have this set** |

---

### 1.8 `scan_run` (model `ScanRun`)

Cited: [app/models_new.py](app/models_new.py#L272-L295). Confirmed live — created and updated by [app/scheduler.py](app/scheduler.py#L74-L80, #L381-L385) for every `/api/trigger-scan` invocation, and read by [app/routes.py](app/routes.py#L173) `/api/automatic-scan-status`.

| Field Name | Business-Friendly Name | Data Type | Length | Required/Nullable | PK | Stored/Calc | Data Classification | Notes |
|---|---|---|---|---|---|---|---|---|
| id | Record ID | Integer | — | Required | Yes | Stored | System Generated | — |
| scan_type | Scan Type | String | 50 | Required | No | Stored | Internal | Always `'automatic'` in observed call, [app/scheduler.py](app/scheduler.py#L75) |
| target_type | Target Type | String | 50 | Required | No | Stored | Internal | `'user'`, `'group'`, or `'all_users'`, from `config.SCHEDULER_TARGET_TYPE` |
| target_value | Target Value | String | 255 | Nullable | No | Stored | Internal | From `config.SCHEDULER_TARGET_VALUE` |
| started_at | Started At | DateTime | — | Required (defaults to now) | No | Stored | Internal | — |
| completed_at | Completed At | DateTime | — | Nullable | No | Stored | Internal | — |
| status | Status | String | 50 | Required (default 'running') | No | Stored | Internal | `running` → `completed`/`failed` |
| users_scanned | Users Scanned | Integer | — | Nullable | No | Calculated then stored | Internal | Count of target users, [app/scheduler.py](app/scheduler.py#L379) |
| events_found (property alias `signin_events_found`) | Sign-In Events Found | Integer | — | Nullable | No | Calculated then stored | Internal | Count of all fetched sign-in logs, [app/scheduler.py](app/scheduler.py#L380) |
| alerts_created | Alerts Created | Integer | — | Nullable | No | Calculated then stored | Internal | Count of new `EntraSecurityAlert` rows this run, [app/scheduler.py](app/scheduler.py#L381) |
| error_message | Error Message | Text | — | Nullable | No | Stored | Internal | Set on exception, [app/scheduler.py](app/scheduler.py#L400) |

Note: `signin_events_found` is a Python `@property`/setter alias for the physical `events_found` column ([app/models_new.py](app/models_new.py#L290-L295)) — there is only one stored column, not two.

---

## Part 2 — Legacy Schema (`app/models.py`) — **NOT confirmed live**

These 6 tables are registered with SQLAlchemy at app startup (`app/__init__.py` imports `app.models`, [app/__init__.py](app/__init__.py#L61)), and are created by the original migration [migrations/versions/219ba38d041b_initial_migration.py](migrations/versions/219ba38d041b_initial_migration.py). **However, a repository-wide search found zero query call sites (`.query`) against any of these models in `app/routes.py` or `app/scheduler.py`** — the only two confirmed live entry points. They are referenced solely by modules with no confirmed live callers:
- [app/auth_hooks.py](app/auth_hooks.py#L7) `after_login_attempt()` — zero call sites found anywhere (confirmed in a prior audit this session).
- [app/risk.py](app/risk.py#L8) — only called by `auth_hooks.py`.
- [app/mfa_protection.py](app/mfa_protection.py#L7) — no confirmed caller found.
- [app/security_events.py](app/security_events.py#L7) — no confirmed caller found.
- [app/utils.py](app/utils.py#L218) `require_existing_mfa()` — explicitly labeled `PLACEHOLDER IMPLEMENTATION` with a `TODO`; no confirmed caller found.
- Authentication itself is confirmed to run through Azure App Service Easy Auth headers ([app/routes.py](app/routes.py#L30-L38) `get_easy_auth_user()`), **not** this `User` table or Flask-Login (`login_manager.user_loader` is defined in [app/models.py](app/models.py#L13) but MSAL config is explicitly commented "DISABLED — not currently used" in [config.py](config.py#L88-L91)). **Confirmed live 2026-09-23** (user-attested, not re-verified against Azure by this document's queries): Easy Auth is enabled on the deployed App Service.

**Verified live (2026-09-22):** direct `SELECT COUNT(*)` queries against `users`, `login_events`, `mfa_methods`, `mfa_events`, `security_alerts`, and `trusted_devices` all returned **`Invalid object name`** errors — none of these 6 tables physically exist in the live database. This is a stronger finding than "no live callers": the initial migration (`219ba38d041b`) that would create them was never applied to this database. **Conclusion: this entire legacy schema does not exist in production.** Documented below for completeness only, since the models and migration exist in the repository even though the tables do not exist in the live database.

### 2.1 `users` (model `User`)
Cited: [app/models.py](app/models.py#L16-L60), [migrations/versions/219ba38d041b_initial_migration.py](migrations/versions/219ba38d041b_initial_migration.py#L21-L28), [migrations/versions/bd1983be119b_add_msal_authentication_fields.py](migrations/versions/bd1983be119b_add_msal_authentication_fields.py).

| Field | Type | Length | Nullable | PK/FK/Unique | Notes |
|---|---|---|---|---|---|
| id | Integer | — | No | PK | — |
| email | String | 120 | No | Unique, indexed | — |
| password_hash | String | 255 | No | — | Security Sensitive; werkzeug hash |
| role | String | 50 | Yes (default 'user') | — | `user`/`admin`/`finance`/`security` |
| created_at | DateTime | — | Yes | — | — |
| entra_user_id | String | 255 | Yes | Unique, indexed | Added by `bd1983be119b` migration |
| auth_method | String | 50 | Yes (default 'local') | — | `local`/`msal`/`both` |

### 2.2 `login_events` (model `LoginEvent`)
Cited: [app/models.py](app/models.py#L63-L95).

| Field | Type | Length | Nullable | PK/FK | Notes |
|---|---|---|---|---|---|
| id | Integer | — | No | PK | — |
| user_id | Integer | — | No | FK → `users.id` | — |
| timestamp | DateTime | — | Yes | — | indexed |
| success | Boolean | — | Yes (default False) | — | — |
| ip_address | String | 45 | Yes | — | IPv6-capable length |
| country, city | String | 100 | Yes | — | — |
| latitude, longitude | Float | — | Yes | — | — |
| user_agent | String | 500 | Yes | — | — |
| browser, operating_system | String | 100 | Yes | — | — |
| device_fingerprint | String | 255 | Yes | indexed | — |
| mfa_required | Boolean | — | Yes (default False) | — | — |
| mfa_success | Boolean | — | Yes (nullable=True, default None) | — | — |
| risk_score | Integer | — | Yes (default 0) | — | — |
| risk_reason | Text | — | Yes | — | JSON/CSV reasons |

### 2.3 `mfa_methods` (model `MfaMethod`)
Cited: [app/models.py](app/models.py#L98-L133).

| Field | Type | Length | Nullable | PK/FK | Notes |
|---|---|---|---|---|---|
| id | Integer | — | No | PK | — |
| user_id | Integer | — | No | FK → `users.id` | — |
| method_type | String | 50 | No | — | `totp`/`sms`/`hardware_key`/`backup_codes` |
| status | String | 50 | Yes (default 'pending') | — | `pending`/`restricted`/`active`/`disabled`/`removed` |
| created_at, activated_at, trusted_after | DateTime | — | Yes | — | `trusted_after` gates `is_fully_trusted()` (24h rule) |
| created_from_ip | String | 45 | Yes | — | — |
| created_from_device | String | 255 | Yes | — | — |

### 2.4 `mfa_events` (model `MfaEvent`)
Cited: [app/models.py](app/models.py#L146-L169).

| Field | Type | Length | Nullable | PK/FK | Notes |
|---|---|---|---|---|---|
| id | Integer | — | No | PK | — |
| user_id | Integer | — | No | FK → `users.id` | — |
| mfa_method_id | Integer | — | Yes | FK → `mfa_methods.id` | — |
| event_type | String | 50 | No | — | `create`/`remove`/`verify`/`block`/`reset` |
| timestamp | DateTime | — | Yes | indexed | — |
| ip_address, country, city | String | 45/100/100 | Yes | — | — |
| device_fingerprint | String | 255 | Yes | — | — |
| session_risk_score | Integer | — | Yes (default 0) | — | — |
| blocked | Boolean | — | Yes (default False) | — | — |
| reason | Text | — | Yes | — | — |

### 2.5 `security_alerts` (model `SecurityAlert`)
Cited: [app/models.py](app/models.py#L172-L191).

| Field | Type | Length | Nullable | PK/FK | Notes |
|---|---|---|---|---|---|
| id | Integer | — | No | PK | — |
| user_id | Integer | — | No | FK → `users.id` | — |
| alert_type | String | 100 | No | — | e.g. `impossible_travel`, `blocked_mfa_creation` |
| severity | String | 50 | No | — | `low`/`medium`/`high`/`critical` |
| reason | Text | — | No | — | — |
| created_at | DateTime | — | Yes | indexed | — |
| status | String | 50 | Yes (default 'active') | — | `active`/`acknowledged`/`resolved`/`false_positive` |

### 2.6 `trusted_devices` (model `TrustedDevice`)
Cited: [app/models.py](app/models.py#L194-L207).

| Field | Type | Length | Nullable | PK/FK | Notes |
|---|---|---|---|---|---|
| id | Integer | — | No | PK | — |
| user_id | Integer | — | No | FK → `users.id` | — |
| device_fingerprint | String | 255 | No | indexed | — |
| first_seen_at, last_seen_at | DateTime | — | Yes | — | — |
| trusted | Boolean | — | Yes (default False) | — | — |

---

## Part 3 — Calculated Values Not Physically Stored (or stored only after calculation)

All of these are computed inside [app/routes.py](app/routes.py#L932) `analyze_impossible_travel()` — the **only confirmed-live** impossible-travel detection function (called from [app/scheduler.py](app/scheduler.py#L293)). A second, structurally similar but **not confirmed live**, implementation exists in [app/risk_detection.py](app/risk_detection.py#L90) `detect_impossible_travel()`, used only by `app/risk_new.py`/`app/trusted_locations.py`, which have no confirmed live caller. A third, legacy implementation exists in [app/risk.py](app/risk.py#L48), used only by the confirmed-dead `app/auth_hooks.py`.

| Value | Definition (from live code) | Cited | Stored? |
|---|---|---|---|
| `distance_miles` | Haversine great-circle distance between previous and current sign-in coordinates, in miles | [app/routes.py](app/routes.py#L1019) `calculate_distance()`, defined at [app/routes.py](app/routes.py#L911) | Not stored raw; persisted as `EntraSignInEvent.travel_distance_miles`-style value only inside the in-memory `current['travel_distance_miles']` dict entry, which is **not** a column on `EntraSignInEvent` — it is only used to build the `EntraSecurityAlert.reason` text in [app/scheduler.py](app/scheduler.py#L361-L367). **Not persisted as its own column anywhere.** |
| `elapsed_hours` | `(curr_time - prev_time).total_seconds() / 3600`, floored to a minimum of `0.01` (36 seconds) to avoid division by zero | [app/routes.py](app/routes.py#L1023-L1033) (variable name `time_diff_hours`) | Same as above — used transiently, surfaced only in the alert `reason` text, not a dedicated column |
| `required_speed_mph` | `distance_miles / elapsed_hours` | [app/routes.py](app/routes.py#L1036) | **Stored** — `EntraSignInEvent.required_travel_speed_mph`, set in [app/scheduler.py](app/scheduler.py#L317) |
| `different_device` | `curr_device_id and prev_device_id and curr_device_id != prev_device_id` | [app/routes.py](app/routes.py#L1094-L1096) | Not stored as a column; only appears inside `risk_factors` list, itself not persisted as a dedicated column (see `local_risk_reasons` note in §1.2 — not confirmed populated) |
| `new_location` | (**Fixed this session**) `not was_seen_before`, where `was_seen_before` tracks whether the current rounded (1-decimal) coordinate pair appeared **earlier in this user's own chronologically sorted sign-in history within the current scan batch** — seeded from the user's first log in the batch and updated incrementally as each subsequent event is evaluated | [app/routes.py](app/routes.py#L1005-L1010) (`seen_locations` tracking), [app/routes.py](app/routes.py#L1098-L1101) (factor evaluation) | Not stored |
| `extreme_speed` | `required_speed_mph > 10000` | [app/routes.py](app/routes.py#L1103-L1104) | Not stored |
| `different_country` (referred to as `international` in code) | `curr_country != prev_country` (via `not is_same_country`) | [app/routes.py](app/routes.py#L1076), [app/routes.py](app/routes.py#L1106-L1107) | Not stored |
| `risk_factor_count` | `len(risk_factors)` where `risk_factors` accumulates any of the four factors above | [app/routes.py](app/routes.py#L1091), evaluated at [app/routes.py](app/routes.py#L1112) | Not stored |
| `impossible_login` | `current['impossible_travel'] = True`, set only when `required_speed_mph > threshold` (1000 domestic / 500 international) **and** `risk_factor_count >= 2` **and** neither the same-device nor trusted-location suppression short-circuits first (see §4 below for the exact gating order, fixed this session) | [app/routes.py](app/routes.py#L1136) | **Stored** — `EntraSignInEvent.impossible_travel_detected`, set in [app/scheduler.py](app/scheduler.py#L316) |

---

## Part 4 — Impossible Login Rule: Executable Logic vs. Your Stated Rule

Verified against the live function [app/routes.py](app/routes.py#L932) `analyze_impossible_travel()`, **as fixed earlier in this session** (previously had two confirmed defects — see below). Execution was verified by running 8+ isolated test scenarios directly against this function in an app context (no database, no production data touched).

### Your stated rule
> Same user **AND** locations are far enough apart **AND** required speed exceeds 1,000 mph (US-US) / 500 mph (different countries) **AND** at least 2 of {different device, new/untrusted location, speed > 10,000 mph, different countries}.

### Actual executable logic, in order

1. **Same user** — guaranteed structurally, not just empirically: sign-ins are grouped into `user_signin_groups` keyed by `userPrincipalName` before any comparison happens ([app/routes.py](app/routes.py#L983-L994)); the comparison loop only ever walks one user's own sorted list. **MATCHES** — cross-user comparison is architecturally impossible, not merely untested.
2. **Locations far enough apart** — `distance_miles < 10` → skip entirely ([app/routes.py](app/routes.py#L1022)). **MATCHES.**
3. **Required speed threshold** — `threshold = current_app.config.get('TRAVEL_SPEED_EXTREME', 1000) if is_domestic_us else current_app.config.get('TRAVEL_SPEED_IMPOSSIBLE', 500)` ([app/routes.py](app/routes.py#L1095-L1096)); alert path only continues if `required_speed_mph > threshold` ([app/routes.py](app/routes.py#L1099)). **MATCHES exactly** (1000 domestic / 500 international, as you specified). **Config-drift risk fixed this session**: these values are now read from `config.py`'s `TRAVEL_SPEED_EXTREME`/`TRAVEL_SPEED_IMPOSSIBLE`, the same config keys used in [app/scheduler.py](app/scheduler.py#L318-L326), instead of being duplicated as hardcoded literals.
4. **≥2 of 4 factors** — `different_device`, `new_location`, `extreme_speed` (>10,000 mph), `international` (different countries), gate at `len(risk_factors) < 2` → suppress ([app/routes.py](app/routes.py#L1089-L1122)). **MATCHES exactly**, using the same 4 factors and the same threshold (10,000 mph) you specified.

### Two additional gates your stated rule does not mention, that exist in the live code
5. **Same-device suppression** — if the same `deviceId` made both sign-ins, the event is suppressed **before** the 2-of-4 factor check ever runs ([app/routes.py](app/routes.py#L1050)). **As originally written this was unconditional** (suppressed even 15,000 mph international travel). **Fixed this session**: it now only suppresses when `required_speed_mph <= 10000` **and** the country is unchanged ([app/routes.py](app/routes.py#L1043-L1044, #L1050)) — i.e., extreme speed or a country change now bypasses this suppression and falls through to the normal 2-of-4 evaluation.
6. **Trusted-location suppression** — if either endpoint has been visited 3+ times in the current scan batch ([app/routes.py](app/routes.py#L969-L980)), the event is suppressed. **Also originally unconditional; also fixed this session** with the same extreme-speed/international bypass ([app/routes.py](app/routes.py#L1061-L1071)).

### Confirmed defects found and fixed this session (via actual execution, not just reading)
- **`new_location` could never fire.** It compared the current event's rounded coordinates against a map built from the *entire batch, including the current event itself* — so the current location was always already in that map. **Fixed** by tracking only locations seen earlier in the user's own chronological sequence within the batch ([app/routes.py](app/routes.py#L1005-L1010, #L1098-L1101)).
- **Same-device and trusted-location suppression were unconditional overrides**, suppressing even 15,000 mph international travel. **Fixed** as described in points 5–6 above.
- Both fixes were verified by direct execution against synthetic sign-in data (Atlanta/Los Angeles/London coordinates) with Flask logging enabled, confirming the exact suppression/alert reason for each scenario. No production data was used or modified; no other code was changed.

### Verdict
**MATCHES your stated rule for its 4 named requirements**, and the two additional device/trust suppression layers that exist beyond your stated rule now correctly yield to extreme-speed/international signals rather than silently overriding them.

---

## Part 5 — Microsoft Graph / Entra Fields Retrieved or Relied On

### 5.1 Sign-in logs — `GET https://graph.microsoft.com/beta/auditLogs/signIns`
Cited: [app/graph_client.py](app/graph_client.py#L140-L178) `fetch_signin_logs()`. Filter: `createdDateTime ge {time}` and `signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')`, optional `userPrincipalName eq '...'`. **No success/failure filter is applied at the Graph query level** — filtering by `status` happens after retrieval, in code.

| Graph Field | Consumed By | Purpose |
|---|---|---|
| `id` | [app/scheduler.py](app/scheduler.py#L229) | → `EntraSignInEvent.microsoft_event_id` (de-dup key) |
| `userId` | [app/scheduler.py](app/scheduler.py#L207) | → `UserIdentity.entra_user_id` |
| `userPrincipalName` | [app/scheduler.py](app/scheduler.py#L211), [app/routes.py](app/routes.py#L950) | User identity; grouping key for impossible-travel comparison |
| `userDisplayName` | [app/scheduler.py](app/scheduler.py#L212) | → `UserIdentity.display_name` |
| `createdDateTime` | [app/scheduler.py](app/scheduler.py#L230), [app/routes.py](app/routes.py#L1024-L1025) | Sign-in timestamp; drives elapsed-time/speed math |
| `ipAddress` | [app/scheduler.py](app/scheduler.py#L231) | → `EntraSignInEvent.ip_address` |
| `location.countryOrRegion` | [app/scheduler.py](app/scheduler.py#L232), [app/routes.py](app/routes.py#L1002) | → `country`; domestic/international threshold |
| `location.state` | [app/scheduler.py](app/scheduler.py#L233) | → `EntraSignInEvent.state` |
| `location.city` | [app/scheduler.py](app/scheduler.py#L234) | → `city`; display |
| `location.geoCoordinates.latitude` / `.longitude` | [app/scheduler.py](app/scheduler.py#L235-L236), [app/routes.py](app/routes.py#L1000-L1003) | Haversine distance calculation |
| `deviceDetail.browser` | [app/scheduler.py](app/scheduler.py#L237) | → `browser` (display, part of device fingerprint) |
| `deviceDetail.operatingSystem` | [app/scheduler.py](app/scheduler.py#L238) | → `operating_system` |
| `deviceDetail.deviceId` | [app/scheduler.py](app/scheduler.py#L239), [app/routes.py](app/routes.py#L1046-L1049) | `different_device` factor / same-device suppression |
| `appDisplayName` | [app/scheduler.py](app/scheduler.py#L240) | → `app_display_name` |
| `status.errorCode` | [app/scheduler.py](app/scheduler.py#L241) | Derives `success`/`failure` |
| `riskLevelAggregated` | [app/scheduler.py](app/scheduler.py#L242) | → `risk_level_aggregated` |
| `riskDetail` | [app/scheduler.py](app/scheduler.py#L243) | → `risk_detail` |
| `conditionalAccessStatus` | [app/ingest.py](app/ingest.py#L129) only | Extracted but never persisted (see §1.2 note) — **NOT VERIFIED as used live** |
| `mfaDetail.authMethod`, `authenticationDetails[].succeeded/authenticationMethod` | [app/ingest.py](app/ingest.py#L124-L125) only | Would drive `mfa_required`/`mfa_satisfied` — **NOT VERIFIED as used live** (ingest.py path not confirmed called) |
| `@odata.nextLink` | [app/graph_client.py](app/graph_client.py#L176) | Pagination |

### 5.2 Directory audit logs — `GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits`
Cited: [app/graph_client.py](app/graph_client.py#L215-L237) `fetch_audit_logs()`. **NOT VERIFIED as called from any live entry point** (no caller of this method found in `app/routes.py` or `app/scheduler.py`).

| Graph Field | Consumed By | Purpose |
|---|---|---|
| `id`, `activityDisplayName`, `activityDateTime`, `category`, `operationType`, `targetResources[].id/userPrincipalName/modifiedProperties`, `initiatedBy.user.userPrincipalName`/`initiatedBy.user.ipAddress`/`initiatedBy.app.displayName` | [app/ingest.py](app/ingest.py#L168-L280) `ingest_audit_event()` | MFA/auth-method change correlation — **entire path NOT VERIFIED live** |

### 5.3 User authentication methods — `GET https://graph.microsoft.com/v1.0/users/{id}/authentication/methods`
Cited: [app/graph_client.py](app/graph_client.py#L239-L253). **NOT VERIFIED as called live.** Fields: `id`, `@odata.type`, `displayName` — consumed only by [app/ingest.py](app/ingest.py#L290) `ingest_auth_method_snapshot()`.

### 5.4 User details — `GET https://graph.microsoft.com/v1.0/users/{id}`
Cited: [app/graph_client.py](app/graph_client.py#L255-L269) `fetch_user_details()`. **NOT VERIFIED as called live** — no caller found in this repository.

### 5.5 Groups — `GET https://graph.microsoft.com/v1.0/groups`
Cited: [app/graph_client.py](app/graph_client.py#L281-L299) `fetch_groups()`, `$select=id,displayName,mail,description,mailEnabled,securityEnabled,groupTypes,createdDateTime,renewedDateTime`. Confirmed live for the `SCHEDULER_TARGET_TYPE='group'` scan path — [app/scheduler.py](app/scheduler.py#L94) uses `displayName`, `id`.

### 5.6 Group members — `GET https://graph.microsoft.com/v1.0/groups/{id}/members`
Cited: [app/graph_client.py](app/graph_client.py#L364-L392) `fetch_group_members()`, `$select=id,userPrincipalName,displayName,mail,accountEnabled`. Confirmed live — [app/scheduler.py](app/scheduler.py#L107-L108) uses `userPrincipalName`.

### 5.7 `graph_client.fetch_all_users()` — was called but did not exist; **fixed this session**
[app/scheduler.py](app/scheduler.py#L102) calls `graph_client.fetch_all_users(max_results=999)` for the `SCHEDULER_TARGET_TYPE='all_users'` path. This method did not exist in [app/graph_client.py](app/graph_client.py), which would have raised an `AttributeError` if that scan target type were ever configured. **Fixed this session**: `fetch_all_users()` is now implemented ([app/graph_client.py](app/graph_client.py#L293-L323)), following the same paginated `@odata.nextLink` pattern as `fetch_groups()`/`fetch_group_members()`, selecting `id,userPrincipalName,displayName,mail,accountEnabled`.

---

## Summary of Verification Status (final pass, 2026-09-22)

**Fully resolved by live, read-only database queries** — no longer open:
1. Schema/model discrepancy — **the live database matches the models** (`user_id int NOT NULL`, `riskgate` schema, on all 6 affected tables). The migrations in this repo do not reflect how the live database actually got this way.
2. `entra_sign_in_event` (targeted by `20260706_add_state_to_signin_events.py`) — **confirmed not a real table.** Only `riskgate.entra_signin_event` exists; its `state` column is present and correct regardless, so it was added by means not captured in this repo's migration history.
3. `EntraSignInEvent.conditional_access_status` — **confirmed does not exist** in the live database at all (not just unmapped by the ORM).
4. `entra_mfa_event`, `user_auth_method_snapshot`, `user_risk_state`, `user_trusted_location` — **confirmed 0 rows in all four tables.** All the code that would populate them (`app/ingest.py` batch/audit functions, `app/risk_detection.py`, `app/risk_new.py`, `app/trusted_locations.py`'s live-population path) is confirmed dead in production, not merely "no caller found."
5. `EntraSignInEvent.mfa_required`, `mfa_satisfied`, `local_risk_reasons` — **confirmed always NULL** across the entire table (0 non-null rows).
6. `EntraSecurityAlert.alert_type` — **confirmed only `impossible_login` has ever been created** (83 of 83 rows); `resolved_at`, `resolved_by`, `related_mfa_event_id` — **confirmed always NULL** (0 of 83 rows).
7. The `latitude`/`longitude` exact-`0.0` edge case — **confirmed real** (390 rows in `entra_signin_event`) and **confirmed handled safely**: Python's `all([...])` truthiness check in `app/routes.py` treats `0.0` as falsy, so these rows are skipped identically to missing coordinates.
8. **New finding from this pass:** `SELECT COUNT(*) FROM users` (and the other 5 legacy tables) returned `Invalid object name` errors — **the entire legacy schema (`users`, `login_events`, `mfa_methods`, `mfa_events`, `security_alerts`, `trusted_devices`) does not physically exist in the live database.** This is stronger than "no live callers" — the tables were never created in production (the initial migration `219ba38d041b` was evidently never applied to this database).
9. **New finding from this pass:** `SELECT version_num FROM alembic_version` failed with `Invalid object name` in both the default and `riskgate` schemas — **this database has no Alembic version-tracking table at all.** None of the migrations in `migrations/versions/` have ever been applied via `flask db upgrade` against this database; every `riskgate`-schema table that does exist was created by some other means (manual DDL or a setup script not present in this repository). This explains why the live schema matches the models but not the migration files.

**Still genuinely open — not answerable by any code or database read, requires Azure/infrastructure access:**
- Whether `SCHEDULER_TARGET_TYPE=all_users` has ever been configured in the deployed App Service's application settings. (Note: the `AttributeError` risk this would previously have triggered is fixed — `fetch_all_users()` now exists in `app/graph_client.py`, see §5.7 — but this configuration question itself still requires Azure access to answer.)
- How/whether the two branching Alembic `down_revision = 'c34d5ec874d2'` heads were ever reconciled — moot in practice since finding 9 shows this database was never Alembic-managed at all, but the repo's migration history itself remains inconsistent.

**Confirmed 2026-09-23, direct check of this machine's Windows Task Scheduler (not a code/database read):**
- `RiskGate-SecurityScan` scheduled task exists, State = Ready, runs hourly, `NumberOfMissedRuns = 0`. Runs as user `tgaskins`, LogonType `Password`, RunLevel `Highest`.
- **Last run (2026-09-23 13:00) failed**: `LastTaskResult = 4294770688` (hex `0xFFFD0000`, signed `-196608`) — a non-zero result. Root cause **not fully confirmed** (the Task Scheduler Operational event log query returned no matching entries, and reproducing it live would trigger a real scan against production, not attempted), but strongly suspected: the registered task action (`powershell.exe -File "Z:\...\run_scan.bat"`) and [run_scan.bat](run_scan.bat) itself both still reference the mapped drive letter `Z:\`, not the UNC path (`\\EgnyteDrive\peakcampus\Shared\...`) that [fix_scheduled_task.ps1](fix_scheduled_task.ps1) exists specifically to switch to. Mapped drives are a well-known cause of silent Task Scheduler failures when a task runs non-interactively. **This needs remediation — re-run `fix_scheduled_task.ps1` or manually update the task action to the UNC path — before relying on the hourly automatic scan.**

All queries in this document were read-only `SELECT`/`COUNT`/`INFORMATION_SCHEMA` statements executed directly against the live Fabric SQL database via the application's own `create_app()`/`db.engine`/`AzureCliCredential` connection. No data was modified, and no application code was changed.
