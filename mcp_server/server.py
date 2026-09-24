from fastapi import FastAPI, UploadFile, File, HTTPException
from typing import Optional

from ai.analysis import analyze_finding


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

        # Decode text-based files
        if file.filename.endswith(
            (".py", ".js", ".ts", ".java", ".txt", ".html", ".css")
        ):
            code = content.decode("utf-8", errors="replace")
        else:
            code = f"Uploaded file: {file.filename}"

        vulnerability_type = vulnerability or "Unknown"

        # Use the centralized AI/risk analysis pipeline.
        scanner_result = {
            "file": file.filename,
            "line": 1,
            "vulnerability": vulnerability_type,
            "severity": "Medium",
            "confidence": 90,
            "code": code
        }

        analysis = analyze_finding(scanner_result)

        return {
            "file": analysis["file"],
            "line": analysis["line"],
            "code": code,
            "vulnerability": analysis["vulnerability"],
            "severity": analysis["severity"],
            "confidence": analysis["confidence"],
            "risk_score": analysis["risk_score"],
            "risk_level": analysis["risk_level"],
            "owasp": analysis["owasp"],
            "cwe": analysis["cwe"],
            "ai_status": analysis["ai_status"],
            "ai_analysis": {
                "explanation": analysis["explanation"],
                "impact": analysis["impact"]
            },
            "recommendation": analysis["recommendation"]
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )