# Scan Reliability and Lifecycle

## 1. Scan State Machine

The backend uses four canonical scan states:

- `pending` — scan created but execution has not started.
- `running` — scanner execution is in progress.
- `completed` — scan and finding persistence completed successfully.
- `failed` — scan execution or persistence failed.

### Allowed Transitions

```text
pending
   ├──> running ───> completed
   │       │
   │       └──────> failed
   │
   └──────────────> failed

2. Scan Execution Pipeline
Project
   ↓
Uploaded Files
   ↓
Create Scan (pending)
   ↓
Start Scan (running)
   ↓
Scanner Execution
   ↓
Finding Normalization
   ↓
Finding Validation
   ↓
AI Analysis / Risk Integration
   ↓
Finding Persistence
   ↓
Mark Scan Completed

If an exception occurs during execution or persistence, the transaction is rolled back and the scan is marked failed.

3. Idempotent Scan Creation

Only one pending or running scan is allowed for a project at a time.

If a project already has an active scan, a new scan request returns:

HTTP 409 Conflict

Completed and failed scans do not prevent future scans.

4. Transaction-Safe Finding Persistence

Vulnerability findings are added using SQLAlchemy flush() instead of an intermediate commit.

The findings and successful scan completion are committed together.

If finding persistence fails:

The database transaction is rolled back.
The scan is reloaded.
The scan is marked failed.
The failure state is committed.
A generic HTTP 500 response is returned.

This prevents partially committed scan results.

5. Finding Validation

Before persistence, every scanner finding is validated for:

Required file name
Required vulnerability type
Required severity
Positive line number when provided
Confidence between 0 and 100 when provided

Malformed findings are rejected before reaching the database.

6. AI Integration Boundary

The backend passes standardized scanner findings through the AI integration boundary.

The AI layer handles:

Vulnerability analysis
AI-generated explanations
Recommendations
Deterministic risk calculation
AI failure status

The scanner remains responsible for vulnerability detection, while the backend coordinates scanner and AI results.

AI integration failures are logged and propagated safely to the scan execution layer.

7. Timestamp Standardization

Scan lifecycle timestamps use timezone-aware UTC timestamps.

The backend records:

started_at
completed_at

This provides consistent timestamps for scan execution and failure tracking.

8. Failure Handling

Scanner execution is wrapped by the backend execution boundary.

When scanner execution fails:

Scanner Exception
       ↓
Log Failure
       ↓
Rollback Transaction
       ↓
Mark Scan Failed
       ↓
Persist Failure State
       ↓
Return HTTP 500

Internal exception details are logged server-side rather than exposed directly through the API response.

9. Regression Testing

The backend uses pytest.ini to restrict pytest discovery to the tests/ directory.

This prevents intentionally vulnerable scanner payloads and interactive scanner inputs from being executed during normal pytest collection.