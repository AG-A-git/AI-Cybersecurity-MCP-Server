# Backend Architecture

## 1. Overview

The backend of the AI-Cybersecurity-MCP-Server is implemented using FastAPI and SQLAlchemy.

Its responsibilities include:

- User authentication
- Project management
- Source-file uploads
- Scan lifecycle management
- Scanner integration
- AI analysis integration
- Vulnerability persistence
- Risk-score aggregation
- Scan-result retrieval
- Scan-history retrieval
- Ownership enforcement
- Report-data preparation
- API response standardization

The backend is designed as a modular service-oriented architecture so that scanner, AI, database, API, and reporting responsibilities remain separated.

---

## 2. High-Level Architecture

```text
                    Client / Frontend
                           |
                           v
                    FastAPI Routers
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
       Auth            Projects           Scans
                                           |
                                           v
                                  Scan Service Layer
                                           |
                         +-----------------+----------------+
                         |                                  |
                         v                                  v
                  Scanner Integration                 AI Analysis
                         |                                  |
                         +-----------------+----------------+
                                           |
                                           v
                                  Finding Validation
                                           |
                                           v
                                    Deduplication
                                           |
                                           v
                                    Persistence
                                           |
                                           v
                                  Scan Result Service
                                           |
                         +-----------------+----------------+
                         |                                  |
                         v                                  v
                  Result Retrieval                   Report Data
                         |
                         v
                    Frontend / MCP

Main Backend Layers
3.1 API Layer

Location:

backend/routers/

Responsibilities:

Receive HTTP requests
Authenticate users
Validate request data
Call service-layer functions
Return standardized API responses

Important routers include:

routers/auth.py
routers/projects.py
routers/upload.py
routers/scan.py

Routers should not contain complex scanning, AI, persistence, or aggregation logic.

4. Authentication and Authorization

Authentication is handled using bearer tokens.

The request flow is:

Client
  |
  v
Authorization Header
  |
  v
Authentication Validation
  |
  v
Current User
  |
  v
Ownership Validation
  |
  v
Protected Resource

Project and scan access is restricted to the authenticated user's resources.

Project ownership

get_owned_project() verifies:

The project exists.
The project belongs to the authenticated user.

Failure behavior:

Project missing       -> HTTP 404
Wrong owner           -> HTTP 403
Scan ownership

get_owned_scan() verifies:

The scan exists.
Its project exists.
The project belongs to the authenticated user.

Failure behavior:

Scan missing          -> HTTP 404
Project missing       -> HTTP 404
Wrong owner           -> HTTP 403

This prevents users from accessing another user's scan results.

5. Scan Lifecycle

Scan states are defined in:

backend/services/scan_states.py

Supported states:

PENDING
RUNNING
COMPLETED
FAILED

Allowed transitions:

PENDING
   |
   +----> RUNNING
   |
   +----> FAILED

RUNNING
   |
   +----> COMPLETED
   |
   +----> FAILED

FAILED
   |
   +----> PENDING

COMPLETED
   |
   +----> terminal state

Invalid state transitions are rejected.

The transition logic is centralized in:

backend/services/scan_lifecycle_service.py

This prevents different parts of the application from independently modifying scan state.

6. Scan Pipeline

The main scan pipeline is implemented in:

backend/services/scan_service.py

The production pipeline follows this order:

Uploaded Files
      |
      v
Scanner
      |
      v
Normalize Findings
      |
      v
Validate Findings
      |
      v
Deduplicate Findings
      |
      v
AI Analysis
      |
      v
Validate AI-Enriched Findings
      |
      v
Persist Findings
      |
      v
Completed Scan
Scanner stage

The scanner produces raw findings.

The backend normalizes them into a consistent internal structure.

Validation stage

The backend validates:

File name
Line number
Vulnerability type
Severity
Confidence
Risk score

Risk scores must be numeric and within:

0 - 100

Boolean values are explicitly rejected where numeric values are required.

Deduplication stage

Duplicate findings are removed using a stable finding identity.

Different:

files
lines
vulnerability types

remain separate findings.

AI stage

The AI layer enriches scanner findings with information such as:

Risk score
OWASP category
CWE
Explanation
Impact
Recommendation

The backend preserves the scanner finding while validating the AI-enriched result.

7. Risk Ownership

Finding-level risk calculation belongs to the AI/risk-analysis layer.

The backend does not replace the AI risk algorithm.

The backend is responsible for:

Validating the risk score
Persisting the score
Returning the score through the API
Aggregating persisted scores for scan-level results

The scan-level risk score is calculated as:

maximum finding risk score

Example:

Finding 1 -> 40
Finding 2 -> 81
Finding 3 -> 65

Scan Risk Score -> 81

If a scan has no findings:

Scan Risk Score -> 0
8. Finding Persistence

Validated findings are persisted only after:

Scanner execution succeeds.
Findings are normalized.
Findings pass validation.
Duplicate findings are removed.
AI enrichment succeeds.
AI-enriched findings pass validation.

This prevents malformed or incomplete findings from being stored as valid scan results.

9. Scan Result Service

Location:

backend/services/scan_result_service.py

Responsibilities:

Project ownership validation
Scan ownership validation
Scan-result serialization
Severity aggregation
Risk-score aggregation
Scan summary validation
Scan-history retrieval
Severity aggregation

Supported severity categories:

critical
high
medium
low
info

The severity counts are calculated from persisted ORM vulnerability objects before serialization.

This maintains a clear service contract:

ORM objects
    |
    +--> aggregation
    |
    +--> validation
    |
    v
serialized API dictionaries
10. Scan Summary Consistency

Every scan result contains:

total_findings
vulnerability_count
severity_counts
risk_score
vulnerabilities

The backend validates:

sum(severity_counts) == total_findings

If these values do not match, the service raises:

Scan summary severity counts do not match total findings

This prevents inconsistent dashboard and API data.

11. API Serialization

Database ORM objects are not returned directly from the result service.

Vulnerabilities are converted into the public API contract:

id
file_name
line_number
vulnerability_type
severity
confidence
code
risk_score
owasp_category
cwe_id
explanation
impact
recommendation

Serialization happens after ORM-level calculations have completed.

This keeps internal database representation separate from the public API response structure.

12. Report Data

Location:

backend/services/report_service.py

The report service reuses the standardized scan-result service.

Report Request
      |
      v
get_scan_result()
      |
      v
Standardized Scan Data
      |
      +----> JSON
      +----> HTML
      +----> PDF

This avoids maintaining separate result-generation logic for each report format.

13. Error Handling

Scan failures are handled through the scan lifecycle.

A failed scan records:

status = failed
completed_at
error_message

The backend avoids silently treating failed scans as successful scans.

This allows the frontend and future MCP layer to distinguish:

pending
running
completed
failed
14. Database Layer

Database configuration is located in:

backend/database.py

SQLAlchemy is used for:

Database engine
Session management
ORM models
Transactions

The main database models include:

User
Project
UploadedFile
Scan
Vulnerability

Database sessions are provided through FastAPI dependencies.

15. Testing Architecture

Backend tests are organized into:

backend/tests/

Testing currently covers:

Authentication
Registration
Login
Protected endpoints
Project security
Project creation
Ownership isolation
Project listing
Upload security
File upload
Ownership isolation
Scan lifecycle
Pending → Running
Running → Completed
Running → Failed
Invalid transitions
Scan service
Finding normalization
Finding validation
Risk-score validation
Finding identity
Deduplication
AI-enriched findings
Scan result service
Scan risk calculation
Empty-scan risk
Severity aggregation
Summary validation
Vulnerability serialization
Backend integration
Complete scan flow
Scan result retrieval
Scan history
Risk-score integration
Scan ownership isolation
16. Reliability Verification

The backend test suite currently verifies the integrated behavior of the major backend components.

The full test suite must pass before considering this backend reliability checkpoint complete.

The reliability goal is:

All automated tests passing
+
No unhandled application exceptions
+
Consistent API contracts
+
Ownership isolation
+
Valid scan lifecycle
+
Validated persisted findings
17. Architectural Principles

The backend follows these principles:

Separation of concerns

Routers handle HTTP concerns.

Services handle business logic.

Models handle persistence.

Scanner handles vulnerability discovery.

AI handles vulnerability enrichment and finding-level risk calculation.

Single responsibility

Each service should have a clearly defined responsibility.

Centralized state management

Scan transitions are controlled by the lifecycle service.

Contract validation

Scanner and AI output is validated before persistence.

Ownership enforcement

Protected resources are always checked against the authenticated user.

Defensive persistence

Invalid findings are rejected before database persistence.

Reusable result contract

Scan results are standardized and reused by history and reporting.

Test-driven reliability

Critical backend behavior is covered by automated tests.

18. Current Backend Request Flow

A complete scan request follows:

POST /scans/
       |
       v
Authenticate User
       |
       v
Validate Project Ownership
       |
       v
Create Scan
       |
       v
PENDING
       |
       v
RUNNING
       |
       v
Execute Scanner
       |
       v
Normalize Findings
       |
       v
Validate Findings
       |
       v
Deduplicate
       |
       v
AI Analysis
       |
       v
Validate AI Findings
       |
       v
Persist Vulnerabilities
       |
       v
COMPLETED
       |
       v
GET /scans/{scan_id}
       |
       v
Ownership Validation
       |
       v
Calculate Summary
       |
       v
Serialize Result
       |
       v
Frontend / MCP / Reports
19. Backend Reliability Checkpoint

At the end of the backend hardening phase, the following areas have been verified:

Authentication
Authorization
Project ownership
Scan ownership
Scan lifecycle
Scanner integration
Finding normalization
Finding validation
Finding deduplication
AI enrichment contract
Risk-score validation
Finding persistence
Scan-level risk aggregation
Severity aggregation
Result serialization
Scan history
Report data reuse
Integration testing

This document should be updated whenever a major backend architectural change is introduced.