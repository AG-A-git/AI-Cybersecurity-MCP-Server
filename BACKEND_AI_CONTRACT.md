# Backend-AI Integration Contract

## Endpoint

POST `/analyze`

The backend sends scanner vulnerability information to the AI
analysis service.

---

## Request

### Content-Type

`application/json`

### Required Fields

| Field | Type | Description |
|---|---|---|
| `file` | string | Source file containing the vulnerability |
| `line` | integer | Line number of the vulnerability |
| `vulnerability` | string | Vulnerability type |
| `severity` | string | Scanner-provided severity |
| `confidence` | number | Scanner confidence from 0 to 100 |
| `code` | string | Vulnerable source code |

### Example

```json
{
  "file": "login.py",
  "line": 22,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "cursor.execute(query)"
}
```

---

## Successful Response

### HTTP Status

`200 OK`

### Response

```json
{
  "severity": "Critical",
  "risk_score": 90.25,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "explanation": "AI-generated vulnerability explanation",
  "recommendation": "AI-generated remediation recommendation"
}
```

The exact `risk_score` is calculated by the deterministic risk-scoring implementation and must not be hard-coded.

### Response Fields

| Field | Type | Description |
|---|---|---|
| `severity` | string | Final vulnerability severity |
| `risk_score` | number | Calculated risk score |
| `owasp` | string | OWASP classification |
| `cwe` | string | CWE classification |
| `explanation` | string | AI-generated vulnerability explanation |
| `recommendation` | string | AI-generated remediation recommendation |

---

## Error Responses

### Invalid Request

If required request fields are missing or invalid:

**HTTP Status:**

`422 Unprocessable Entity`

FastAPI/Pydantic performs request validation.

Example invalid request:

```json
{
  "file": "login.py",
  "vulnerability": "SQL Injection"
}
```

The missing fields are:

- `line`
- `severity`
- `confidence`
- `code`

---

### AI Unavailable

If the AI/Ollama service is unavailable:

**HTTP Status:**

`503 Service Unavailable`

Example:

```json
{
  "detail": "AI analysis unavailable"
}
```

The API must return a controlled error instead of exposing an internal traceback.

---

## Integration Flow

Scanner

↓

Backend

↓

POST `/analyze`

↓

FastAPI MCP Server

↓

Vulnerability Validation

↓

Existing AI Analysis Pipeline

↓

Risk Score

↓

OWASP/CWE Mapping

↓

AI Explanation

↓

AI Recommendation

↓

Response Formatter

↓

Backend

---

## Supported Vulnerabilities

The current vulnerability mapping supports:

- SQL Injection
- XSS
- Cross Site Scripting
- Hardcoded Credentials
- Weak Cryptography

---

## Example: SQL Injection

### Request

```json
{
  "file": "login.py",
  "line": 22,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "cursor.execute(query)"
}
```

### Response

```json
{
  "severity": "Critical",
  "risk_score": 90.25,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "explanation": "...",
  "recommendation": "..."
}
```

---

## Example: Cross Site Scripting

### Request

```json
{
  "file": "script.js",
  "line": 15,
  "vulnerability": "Cross Site Scripting",
  "severity": "High",
  "confidence": 90,
  "code": "element.innerHTML=data"
}
```

### Response

```json
{
  "severity": "High",
  "risk_score": 72,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-79",
  "explanation": "...",
  "recommendation": "..."
}
```