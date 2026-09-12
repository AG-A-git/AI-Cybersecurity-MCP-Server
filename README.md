\# AI Cybersecurity MCP Server



An AI-assisted cybersecurity vulnerability scanning system that combines

static analysis, vulnerability classification, risk scoring, OWASP/CWE

mapping, AI analysis, and report generation.



\## Features



\- Project vulnerability scanning

\- Static analysis

\- Vulnerability detection

\- Severity classification

\- Confidence scoring

\- Risk score calculation

\- Risk level classification

\- OWASP mapping

\- CWE mapping

\- AI vulnerability analysis

\- Security report generation

\- REST API

\- Python client

\- Web dashboard



\## Project Structure



AI-Cybersecurity-MCP-Server/



├── backend/

│   └── mcp\_server/

│       └── server.py

│

├── scanner/

│   ├── \_\_init\_\_.py

│   └── scanner.py

│

├── ai/

│   └── vulnerability\_mapping.py

│

├── dashboard/

│   └── index.html

│

├── reports/

│

├── client.py

├── report\_summary.py

├── client\_report.json

└── README.md



\## Requirements



Python 3.x



Create and activate a virtual environment:



```powershell

python -m venv venv

.\\venv\\Scripts\\Activate.ps1

