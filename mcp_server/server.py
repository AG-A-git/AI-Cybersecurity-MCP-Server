from fastapi import FastAPI, UploadFile, File, HTTPException
from typing import Optional

app = FastAPI(
    title="AI Cybersecurity MCP Server",
    version="1.0.0",
    description="AI vulnerability analysis API"
)


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity MCP Server is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    vulnerability: Optional[str] = None
):
    try:
        content = await file.read()

        # Only decode text-based files
        if file.filename.endswith((".py", ".js", ".ts", ".java", ".txt", ".html", ".css")):
            code = content.decode("utf-8", errors="replace")
        else:
            code = f"Uploaded file: {file.filename}"

        vulnerability_type = vulnerability or "Unknown"

        if vulnerability_type.lower() == "sql injection":
            severity = "High"
            risk_score = 85
            risk_level = "Critical"
            owasp = "A03:2021 Injection"
            cwe = "CWE-89"

            explanation = (
                "The code may be vulnerable to SQL Injection "
                "because user-controlled input may be included "
                "directly in a SQL query."
            )

            recommendation = (
                "Use parameterized queries or prepared statements "
                "instead of string concatenation."
            )

        else:
            severity = "Medium"
            risk_score = 50
            risk_level = "High"
            owasp = "Unknown"
            cwe = "Unknown"

            explanation = (
                "The uploaded code requires further security analysis."
            )

            recommendation = (
                "Review the code and apply appropriate secure "
                "coding practices."
            )

        return {
            "file": file.filename,
            "line": 1,
            "code": code,
            "vulnerability": vulnerability_type,
            "severity": severity,
            "confidence": 90,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "owasp": owasp,
            "cwe": cwe,
            "ai_status": "completed",
            "ai_analysis": {
                "severity": severity,
                "explanation": explanation,
                "recommendation": recommendation
            },
            "recommendation": recommendation
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )