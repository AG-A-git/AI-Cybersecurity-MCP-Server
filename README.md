# AI Cybersecurity MCP Server

AI-powered, multi-language static code vulnerability analysis platform with a secure backend, local AI analysis using Llama 3, risk scoring, scan history, and MCP-ready service architecture.

---

## 1. Project Overview

AI Cybersecurity MCP Server is a security-focused static code analysis platform designed to identify vulnerabilities in uploaded source-code projects.

The system combines:

- Multi-language static code scanning
- Vulnerability finding normalization
- Severity and confidence information
- AI-assisted vulnerability analysis
- Risk-score calculation
- OWASP and CWE mapping
- Persistent scan results
- Scan history
- Project and user isolation
- Reliable scan lifecycle management
- Local Llama 3 integration through Ollama
- MCP-oriented backend service architecture

The project is designed as an industry-oriented cybersecurity platform rather than a simple scanner prototype.

---

## 2. High-Level Architecture

```text
                         ┌──────────────────────┐
                         │      Frontend        │
                         │   React Application  │
                         └──────────┬───────────┘
                                    │
                                    │ HTTP / REST
                                    ▼
                         ┌──────────────────────┐
                         │     FastAPI Backend  │
                         │     backend/app.py   │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
      ┌─────────────┐       ┌──────────────┐       ┌──────────────┐
      │ Auth / User │       │   Projects   │       │    Uploads   │
      │ Management  │       │   & Access   │       │   Management │
      └─────────────┘       └──────────────┘       └──────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Scan Service       │
                         │ Scan Orchestration   │
                         └──────────┬───────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
        ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
        │   Scanner    │    │  AI Service  │    │ Risk / Finding│
        │ Multi-language│    │ Llama 3/Ollama│    │  Processing   │
        └──────────────┘    └──────────────┘    └──────────────┘
                │                   │                   │
                └───────────────────┼───────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ Finding Persistence  │
                         │     SQLite / ORM     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Scan Result Service  │
                         │ History / Ownership  │
                         └─────────────────────--
Backend Architecture

The backend is implemented using FastAPI and is organized around service responsibilities.

backend/
│
├── app.py
├── database.py
├── models.py
├── schemas.py
├── auth.py
├── logging_config.py
│
├── routers/
│   ├── auth.py
│   ├── projects.py
│   ├── uploads.py
│   └── scans.py
│
├── services/
│   ├── scan_service.py
│   ├── scan_result_service.py
│   ├── scan_lifecycle_service.py
│   ├── scan_states.py
│   ├── ai_client.py
│   └── time_service.py
│
├── scanner/
│   ├── scan.py
│   ├── severity.py
│   └── rules/
│
├── tests/
│   ├── test_backend_integration.py
│   ├── test_scan_lifecycle.py
│   ├── test_scan_service.py
│   └── sample_upload.py
│
└── pytest.ini
4. Scan Execution Pipeline

A scan follows a controlled backend pipeline:

Project
   │
   ▼
Uploaded Files
   │
   ▼
Scan Creation
   │
   ▼
PENDING
   │
   ▼
RUNNING
   │
   ▼
Static Scanner
   │
   ▼
Finding Normalization
   │
   ▼
Finding Validation
   │
   ▼
AI Analysis
   │
   ▼
Risk / Metadata Processing
   │
   ▼
Finding Persistence
   │
   ▼
COMPLETED
   │
   ▼
Scan Result / History

If a failure occurs during execution:

RUNNING
   │
   ▼
Failure
   │
   ▼
FAILED
   │
   ▼
Error persisted safely
5. Scan Lifecycle

The backend uses an explicit scan state machine.

Supported states
PENDING
RUNNING
COMPLETED
FAILED
Valid transitions
PENDING ───────► RUNNING
   │                │
   │                ├────────► COMPLETED
   │                │
   └───────────────►└────────► FAILED

Completed and failed scans are terminal states.

Invalid transitions are rejected by the lifecycle service.

This prevents inconsistent scan states and makes scan execution easier to reason about and test.

6. Idempotent Scan Execution

The backend prevents multiple active scans from being created for the same project.

An active scan is defined as:

PENDING
RUNNING

A database-level partial unique index is used to enforce this constraint:

uq_active_scan_per_project

This provides protection even if multiple requests attempt to start scans concurrently.

The database therefore acts as an additional reliability layer rather than relying only on application-level checks.

7. Finding Normalization

Scanner output is normalized before it enters the persistence pipeline.

Normalized finding fields include:

file
line
vulnerability
severity
confidence
code

Normalization provides a consistent contract between scanner components and backend services.

Example:

{
  "file": "app.py",
  "line": 42,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "cursor.execute(query)"
}
8. Finding Validation

Before persistence, findings are validated.

The backend validates:

File name
Vulnerability type
Severity
Line number
Confidence
Risk score
Required fields
Supported severity values

Supported severity values include:

Critical
High
Medium
Low
Info

Numeric security values are constrained to the expected range:

0 - 100

Boolean values are explicitly rejected where integer values are expected.

This prevents malformed scanner or AI output from silently entering the database.

9. AI Analysis

AI analysis is isolated behind a dedicated service boundary.

The backend sends normalized findings to the AI service and combines the returned security metadata with the original finding.

The AI layer can provide:

Risk score
OWASP category
CWE identifier
Explanation
Impact
Recommendation

The project is designed around local AI processing using:

Ollama
Llama 3

This architecture allows AI analysis to remain isolated from the main scan orchestration logic.

10. Risk Scoring

Each persisted vulnerability may contain a risk score between:

0 - 100

The scan result service calculates the overall scan risk score from persisted vulnerability risk values.

The current aggregation strategy uses the highest vulnerability risk score:

Scan Risk Score = Maximum Vulnerability Risk Score

This ensures that a severe individual vulnerability is not hidden by averaging it with lower-risk findings.

11. Finding Persistence

Validated findings are converted into persistent vulnerability records.

Stored information includes:

File
Line
Vulnerability Type
Severity
Confidence
Code
Risk Score
OWASP Category
CWE ID
Explanation
Impact
Recommendation

Each vulnerability is associated with its scan:

Scan
 └── Vulnerabilities

Cascade relationships ensure scan-owned vulnerability records remain associated with their parent scan.

12. Transaction and Failure Protection

Scan execution uses transaction protection to prevent partially persisted scan states.

When a pipeline failure occurs:

Database changes are rolled back.
The scan is reloaded.
The scan is transitioned to FAILED.
The failure message is persisted.
The transaction is committed safely.
A generic API error is returned to the client.

This prevents a failed scan from being incorrectly reported as completed.

13. Scan Result Service

The scan result service provides a consistent representation of scan information.

A scan result contains:

Scan ID
Project ID
Project Name
Status
Created Time
Started Time
Completed Time
Error Message
Vulnerability Count
Risk Score
Vulnerability Details

The service also provides deterministic scan history ordering.

History supports:

Pagination
Ownership filtering
Maximum page size
Stable ordering
14. User and Project Isolation

Security-sensitive resources are checked against the authenticated user.

The backend enforces ownership for:

Projects
Uploaded Files
Scans
Scan Results
Scan History

Unauthorized access to an existing resource returns:

HTTP 403 Forbidden

Non-existent resources return:

HTTP 404 Not Found

This distinction is intentionally preserved as part of the API contract.

15. Failed Scan Recovery

The backend contains a retry mechanism for failed scans.

Only scans in:

FAILED

state can be retried.

A retry reuses the existing scan record and executes the same scan pipeline again.

The retry mechanism is designed so that future background execution can reuse the same pipeline without duplicating scan logic.

16. Database Model

The current backend uses SQLAlchemy ORM.

Core entities include:

User
 │
 ├── Projects
 │      │
 │      ├── Uploaded Files
 │      │
 │      └── Scans
 │             │
 │             └── Vulnerabilities
 │
 └── Uploaded Files

Primary database entities:

users
projects
uploaded_files
scans
vulnerabilities

Development and integration testing currently use SQLite.

17. API Layer

The FastAPI application provides REST endpoints for:

Authentication
Projects
File Uploads
Scanning
Scan Results
Scan History

FastAPI also exposes automatically generated API documentation through:

/docs
/openapi.json

The backend is currently started from the backend directory using:

uvicorn app:app --reload
18. Testing

The backend contains unit and integration tests covering:

Authentication
Registration
Login
Authenticated profile
Authentication requirements
Project Security
Project creation
Project listing
Project ownership isolation
File Security
File upload
Upload ownership isolation
Scan Processing
Scan creation
Scan lifecycle
Scan result retrieval
Risk score
Scan history
Security Isolation
Unauthorized scan access
Cross-user resource isolation
Service Validation
Finding normalization
Finding validation
Invalid line numbers
Invalid confidence
Invalid risk scores
Invalid severities
Boolean validation

The current backend integration and service test suite contains:

33 passing tests
19. Reliability Principles

The backend follows several reliability principles:

Explicit State Management

Scan states are controlled through a dedicated state machine.

Database Constraints

Important invariants are also enforced at the database level.

Transaction Safety

Failed operations are rolled back before failure state persistence.

Service Separation

Scanning, AI analysis, lifecycle handling, and result serialization are separated into services.

Ownership Enforcement

Resources are always checked against the authenticated user.

Deterministic Testing

External AI behavior is mocked in integration tests where appropriate.

Reusable Scan Pipeline

The core scan pipeline is isolated from request handling so it can later be executed by background workers.

20. Current Development Status

Implemented backend capabilities include:

User registration
Authentication
User profiles
Project management
File uploads
Multi-language scanner integration
Scan lifecycle management
Active scan protection
Finding normalization
Finding validation
Finding persistence
AI analysis integration
Risk scoring
Scan result serialization
Scan history
Ownership isolation
Failure handling
Failed scan retry support
Backend integration testing
Local Llama 3/Ollama integration

The architecture is being extended toward:

MCP tool integration
Professional reporting
Advanced dashboard integration
Background scan execution
Final system integration
Production-oriented reliability and security hardening
21. Team Architecture

The project is developed as a multi-member system.

Backend & System Architecture

Responsible for:

FastAPI backend
Database integration
Scan orchestration
API contracts
Persistence
Authentication integration
Ownership isolation
Reliability
Backend testing
Scanner Engineering

Responsible for:

Multi-language static analysis
Vulnerability detection rules
Severity mapping
Scanner consistency
AI, MCP & Risk Analysis

Responsible for:

Local Llama 3 integration
AI vulnerability explanations
Risk analysis
OWASP/CWE enrichment
MCP integration
Frontend & User Experience

Responsible for:

React interface
Dashboard
Scan interface
Vulnerability visualization
Scan history
Reports and user experience
22. Security Goals

The project is designed around the following security goals:

Secure authentication
        +
User isolation
        +
Project isolation
        +
Controlled file handling
        +
Static vulnerability detection
        +
AI-assisted analysis
        +
Risk assessment
        +
Reliable persistence
        +
Auditable scan history

The platform is intended to analyze source code while keeping the architecture suitable for local security analysis workflows.

23. Development Environment

Current backend development environment:

Python 3.13
FastAPI
SQLAlchemy
SQLite
Pytest
Uvicorn
Ollama
Llama 3

Frontend:

React
Vite
24. Running the Backend

Activate the project virtual environment:

.\venv\Scripts\Activate.ps1

Navigate to the backend:

cd backend

Start FastAPI:

uvicorn app:app --reload

Open the API documentation:

http://127.0.0.1:8000/docs
25. Running Tests

From the backend directory:

pytest -v

Expected current result:

33 passed
26. Project Objective

The long-term objective is to provide an integrated cybersecurity analysis platform capable of:

Upload Source Code
        ↓
Analyze Multiple Languages
        ↓
Detect Security Vulnerabilities
        ↓
Normalize Findings
        ↓
Validate Findings
        ↓
Use Local AI for Explanation
        ↓
Map OWASP / CWE
        ↓
Calculate Risk
        ↓
Persist Results
        ↓
Display Security Dashboard
        ↓
Generate Reports
        ↓
Expose Security Analysis through MCP

The architecture is intentionally modular so individual components can evolve without requiring a complete rewrite of the system.


