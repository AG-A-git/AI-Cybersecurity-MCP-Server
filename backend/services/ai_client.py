import requests

AI_SERVICE_URL = "http://127.0.0.1:8000/analyze"


def analyze_vulnerability(finding):
    try:
        response = requests.post(
            AI_SERVICE_URL,
            json={
                "file": finding.get("file"),
                "line": finding.get("line"),
                "vulnerability": finding.get("vulnerability"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "code": finding.get("code"),
            },
            timeout=60
        )

        response.raise_for_status()
        return response.json()

    except requests.exceptions.Timeout:
        raise RuntimeError("AI analysis service timed out")

    except requests.exceptions.ConnectionError:
        raise RuntimeError("AI analysis service is unavailable")

    except requests.exceptions.HTTPError as e:
        raise RuntimeError(
            f"AI analysis service returned an error: {e}"
        )

    except requests.exceptions.RequestException as e:
        raise RuntimeError(
            f"AI analysis request failed: {e}"
        )


def analyze_vulnerabilities(findings):
    results = []

    for finding in findings:
        analysis = analyze_vulnerability(finding)

        combined_result = {
            **finding,
            **analysis
        }

        results.append(combined_result)

    return results