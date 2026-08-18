# Backend Integration Plan

AI Cybersecurity MCP Server

Week 1 - Day 2
## Overall Architecture

```
                User
                  │
                  ▼
          React Frontend
                  │
          HTTP (REST API)
                  │
                  ▼
          FastAPI Backend
         /      |       \
        /       |        \
       ▼        ▼         ▼
 Scanner     AI Module   Database
   │             │
   ▼             ▼
 Vulnerabilities AI Analysis
        │
        ▼
     Reports
```
## Scanner Input

The backend sends the scanner:

```json
{
  "project_id": 1,
  "file_path": "uploads/project.zip",
  "language": "Python"
}
```
## Scanner Output

The scanner returns:

```json
[
  {
    "file": "login.py",
    "line": 42,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 96,
    "code": "cursor.execute(query)"
  }
]
```
## AI Input

The backend sends the scanner result to the AI module.

```json
{
  "file": "login.py",
  "line": 42,
  "vulnerability": "SQL Injection",
  "code": "cursor.execute(query)"
}
```
## AI Output

The AI module returns:

```json
{
  "severity": "Critical",
  "risk_score": 98,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "explanation": "The SQL query directly concatenates user input allowing attackers to manipulate database queries.",
  "recommendation": "Use parameterized queries or prepared statements."
}
```
## Frontend Response

The backend sends the final response to React.

```json
{
  "project": "Banking System",
  "critical": 3,
  "high": 4,
  "medium": 6,
  "low": 2,
  "results": [
    {
      "file": "login.py",
      "line": 42,
      "severity": "Critical",
      "risk_score": 98,
      "vulnerability": "SQL Injection"
    }
  ]
}
```
## API Flow

```
User Uploads Project

↓

Frontend

↓

POST /upload

↓

Backend

↓

Scanner

↓

Scanner Results

↓

AI Module

↓

AI Explanation

↓

Store Results in Database

↓

Return JSON

↓

Frontend Dashboard

↓

Generate PDF / HTML / JSON Reports
```
## Planned Backend APIs

POST /auth/register

POST /auth/login

POST /upload

POST /scan

GET /dashboard

GET /history

GET /reports

GET /users

GET /projects