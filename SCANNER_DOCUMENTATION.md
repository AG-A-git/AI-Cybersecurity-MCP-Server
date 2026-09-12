

\# Scanner Documentation



\## 1. Overview



The vulnerability scanner analyzes uploaded source-code projects and produces standardized security findings.



The scanner currently focuses on Python and JavaScript source files and integrates multiple vulnerability detection rules into a central scanning pipeline.



\## 2. Supported File Types



The scanner currently supports:



\- `.py` — Python

\- `.js` — JavaScript



The scanner ignores common directories such as:



\- `venv`

\- `node\_modules`

\- `.git`

\- `\_\_pycache\_\_`



\## 3. Standard Finding Format



Each detected vulnerability is returned using a standardized finding structure:



```json

{

&#x20; "file\_name": "example.py",

&#x20; "line\_number": 10,

&#x20; "vulnerability\_type": "SSRF",

&#x20; "severity": "High",

&#x20; "confidence": 85,

&#x20; "code": "requests.get(url)",

&#x20; "owasp": "A10: Server-Side Request Forgery",

&#x20; "cwe": "CWE-918"

}
