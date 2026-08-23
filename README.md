# AI-Cybersecurity-MCP-Server

AI-powered multi-language static code vulnerability analyzer exposed through an MCP server.

## Features

- Static analysis of Python and JavaScript source files
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Hardcoded credential detection
- Weak cryptography detection
- Improper input validation detection
- Severity classification
- Confidence scores for findings
- Recursive project-directory scanning
- MCP tool integration through scan_code

## Project Structure

AI-Cybersecurity-MCP-Server/
|-- scanner/
|   |-- engine.py
|   |-- parser.py
|   |-- scan.py
|   |-- severity.py
|   |-- utils.py
|   `-- rules/
|       |-- credentials.py
|       |-- crypto.py
|       |-- input_validation.py
|       |-- sql.py
|       `-- xss.py
|-- tests/
|-- docs/
|   `-- scanner_api.md
|-- mcp_server.py
|-- requirements.txt
`-- README.md

## Supported Vulnerabilities

| Vulnerability | Severity |
|---|---|
| SQL Injection | Critical |
| Cross-Site Scripting | High |
| Hardcoded Credentials | High |
| Weak Cryptography | Medium |
| Improper Input Validation | Medium |

## Usage

### Run the scanner

python scanner\scan.py tests

### Use the MCP server

python mcp_server.py

The MCP server exposes the scan_code tool. It accepts a source file or project directory and returns security findings.

## MCP Verification

The MCP integration has been verified for:

- Server import
- Tool registration
- Single-file scanning
- Recursive project scanning
- Unsupported-file handling
- Safe-file handling
- Invalid-path handling

Expected registered tool:

scan_code

## Requirements

Python 3.11+ and the MCP Python package are required.

Install dependencies with:

pip install -r requirements.txt

## License

See LICENSE.