# Backend ↔ Scanner Integration

## Overview

The backend integrates with the vulnerability scanner through a clearly defined scanner interface.

The backend is responsible for:

- Managing users and projects
- Managing uploaded files
- Creating scans
- Calling the scanner
- Storing vulnerability results
- Providing scan history and results through REST APIs

The scanner is responsible for:

- Reading supported source files
- Running vulnerability detection rules
- Returning standardized vulnerability findings

## Architecture

```text
Client / Swagger
       ↓
FastAPI Backend
       ↓
POST /scans/
       ↓
Find Project Files
       ↓
scanner_client.py
       ↓
Member 2 Scanner
       ↓
Vulnerability Results
       ↓
Vulnerability Database
       ↓
GET /scans/{scan_id}

API Endpoints
1. Create Scan

POST /scans/

Request:

{
  "project_id": 1
}

Workflow:

Verify that the project exists.
Find uploaded files belonging to the project.
Create a scan record.
Call the scanner through scanner_client.py.
Receive vulnerability results.
Store vulnerabilities in the database.
Mark the scan as completed.
Return the results.

Example response:

{
  "scan_id": 4,
  "project_id": 1,
  "status": "completed",
  "results": [
    {
      "file": "uploads\\login.py",
      "line": 2,
      "vulnerability": "SQL Injection",
      "severity": "Critical",
      "confidence": 95,
      "code": "cursor.execute(query)"
    }
  ]
}
2. Get Scan History

GET /scans/

Returns the available scans.

Example:

[
  {
    "id": 4,
    "project_id": 1,
    "status": "completed",
    "created_at": "2026-08-11T14:07:50",
    "vulnerability_count": 1
  }
]

This endpoint can be used by the frontend History page.

3. Get Scan Results

GET /scans/{scan_id}

Example:

GET /scans/4

Example response:

{
  "id": 4,
  "project_id": 1,
  "status": "completed",
  "created_at": "2026-08-11T14:07:50",
  "vulnerability_count": 1,
  "vulnerabilities": [
    {
      "id": 2,
      "file_name": "uploads\\login.py",
      "line_number": 2,
      "vulnerability_type": "SQL Injection",
      "severity": "Critical",
      "confidence": 95,
      "code": "cursor.execute(query)"
    }
  ]
}

This endpoint can be used by the frontend Results page.

Backend → Scanner

The backend does not copy the scanner rules into the backend.

Instead, it uses the scanner interface:

results = run_scanner(file_path)

The backend passes the uploaded file path to the scanner.

Scanner → Backend

The scanner returns standardized vulnerability findings.

Example:

[
  {
    "file": "uploads\\login.py",
    "line": 2,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
  }
]

The backend converts each result into a Vulnerability database record.

Database Relationship
Project
   ↓
Scan
   ↓
Vulnerability

A project can have multiple scans.

A scan can contain multiple vulnerabilities.

Each vulnerability belongs to one scan.

Supported Scanner Files

The current scanner supports:

.py
.js

The backend upload service may support additional file types, but the scanner currently scans the extensions supported by its implementation.

Error Handling

The backend returns an error when:

The project does not exist.
The project has no uploaded files.
The scanner fails.

When scanner execution fails, the scan status is changed to:

failed
Integration Status

The following workflow has been tested successfully:

Project
   ↓
Upload File
   ↓
Create Scan
   ↓
Backend calls Scanner
   ↓
Scanner detects vulnerability
   ↓
Backend stores result
   ↓
Get Scan Results

The backend and scanner are now ready for the next stage of AI and risk-analysis integration.