# AI - Backend Integration Contract

## 1. Purpose

Defines the interface between the scanner/backend and the AI vulnerability analysis layer.

---

## 2. Input Contract

The backend sends one standardized vulnerability finding to the AI analysis layer.

### Required Fields

| Field | Type | Constraints |
|---|---|---|
| file | string | 1-500 characters |
| line | integer | >= 1 |
| vulnerability | string | 1-200 characters |
| severity | string | 1-50 characters |
| confidence | float | 0-100 |
| code | string | <= 10000 characters |

### Example

```json
{
  "file": "app.py",
  "line": 42,
  "vulnerability": "SQL Injection",
  "severity": "High",
  "confidence": 95,
  "code": "query = 'SELECT * FROM users WHERE id=' + user_id"
}