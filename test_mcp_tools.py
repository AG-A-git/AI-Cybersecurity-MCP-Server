from backend.mcp_server.server import (
    scan_project_tool,
    get_scan_results_tool,
    get_risk_score_tool,
    analyze_vulnerability_tool,
    generate_report_tool,
)

PROJECT = r"C:\Users\hemavathi\OneDrive\Desktop\AI-Cybersecurity-MCP-Server"


print("\n=== SCAN PROJECT ===")

scan = scan_project_tool(PROJECT)

print(scan)


if scan["status"] == "success":

    scan_id = scan["scan_id"]

    print("\n=== GET SCAN RESULTS ===")

    results = get_scan_results_tool(scan_id)

    print(results)


    print("\n=== GET RISK SCORE ===")

    risk = get_risk_score_tool(
        file="login.py",
        line=22,
        vulnerability="SQL Injection",
        severity="Critical",
        confidence=95
    )

    print(risk)


    print("\n=== GENERATE REPORT ===")

    report = generate_report_tool(
        scan_id=scan_id,
        format="json"
    )

    print(report)


print("\n=== ANALYZE VULNERABILITY ===")

analysis = analyze_vulnerability_tool(
    file="login.py",
    line=22,
    vulnerability="SQL Injection",
    severity="Critical",
    confidence=95,
    code="cursor.execute(query)"
)

print(analysis)