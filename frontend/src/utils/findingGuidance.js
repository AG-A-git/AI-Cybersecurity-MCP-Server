
const guidanceRules = [
    {
        matches: [
            "sql injection",
            "sql-injection",
            "sqli",
        ],
        explanation:
            "The query may combine user-controlled input directly with SQL instructions. If exploitable, an attacker could alter the query and access or modify data without authorization.",
        recommendation:
            "Use parameterized queries or prepared statements. Avoid building SQL statements by concatenating user input. Apply least-privilege database permissions and retest the affected code.",
    },
    {
        matches: [
            "cross-site scripting",
            "cross site scripting",
            "xss",
        ],
        explanation:
            "Untrusted data may be inserted into a web page without appropriate context-aware output encoding, potentially allowing attacker-controlled scripts to execute in a user's browser.",
        recommendation:
            "Use context-aware output encoding and safe DOM APIs. Avoid inserting untrusted content with innerHTML. Use your framework's escaping features and consider a Content Security Policy as an additional layer.",
    },
    {
        matches: [
            "hardcoded credentials",
            "hardcoded password",
            "hardcoded secret",
            "hard-coded credentials",
            "hard-coded password",
            "hard-coded secret",
            "exposed credentials",
        ],
        explanation:
            "A password, token, or other secret may be stored directly in source code. People with access to the code could discover and misuse it.",
        recommendation:
            "Remove the secret from source code, rotate the exposed credential, and load secrets from environment variables or a dedicated secret manager. Check repository history for exposure.",
    },
    {
        matches: [
            "command injection",
            "os command injection",
            "operating system command injection",
        ],
        explanation:
            "User-controlled data may reach an operating-system command. If the input is not safely handled, an attacker could alter the command that executes.",
        recommendation:
            "Prefer APIs that avoid shell execution. If a command is necessary, use safe argument-list APIs rather than shell string concatenation, validate inputs against an allowlist, and restrict process permissions.",
    },
    {
        matches: [
            "path traversal",
            "directory traversal",
        ],
        explanation:
            "A file path may be influenced by user input, potentially allowing access to files outside the intended directory.",
        recommendation:
            "Resolve paths against a fixed trusted base directory, verify that the resolved path remains inside that directory, and avoid relying on string checks alone. Restrict filesystem permissions.",
    },
    {
        matches: [
            "insecure deserialization",
            "unsafe deserialization",
        ],
        explanation:
            "Deserializing untrusted data using an unsafe format or mechanism may cause unexpected object creation or code execution, depending on the technology used.",
        recommendation:
            "Avoid unsafe deserialization of untrusted data. Prefer data-only formats with schema validation, restrict allowed types, and authenticate inputs where appropriate.",
    },
    {
        matches: [
            "weak cryptography",
            "weak encryption",
            "insecure cryptography",
        ],
        explanation:
            "The application may use an outdated or unsuitable cryptographic algorithm or configuration, weakening the protection of sensitive information.",
        recommendation:
            "Use well-maintained cryptographic libraries and currently recommended algorithms and settings. Avoid custom cryptography and verify key generation, storage, and rotation practices.",
    },
    {
        matches: [
            "sensitive data exposure",
            "exposure of sensitive information",
            "sensitive information disclosure",
        ],
        explanation:
            "Sensitive information may be accessible to people or systems that should not receive it. Confirm what data is exposed and under which conditions.",
        recommendation:
            "Minimize sensitive data collection, enforce authorization, protect data in transit and at rest, and avoid exposing secrets or personal information in logs and error messages.",
    },
    {
        matches: [
            "broken access control",
            "missing authorization",
            "improper authorization",
            "privilege escalation",
        ],
        explanation:
            "Access-control checks may be missing or incorrectly applied, potentially allowing a user to access another user's data or perform unauthorized actions.",
        recommendation:
            "Enforce authorization on the server for every protected operation. Apply least privilege and test access using accounts with different permissions.",
    },
    {
        matches: [
            "insecure random",
            "weak random",
            "predictable random",
        ],
        explanation:
            "The application may use predictable random values in a security-sensitive context, making tokens or other values easier to guess.",
        recommendation:
            "Use the platform's cryptographically secure random generator for tokens and security-sensitive values. Do not use ordinary pseudorandom functions for secrets.",
    },
];

const defaultGuidance = {
    explanation:
        "The scanner detected a potential security issue. Review the affected code and validate the finding to determine whether it is exploitable.",
    recommendation:
        "Inspect the affected code, follow secure coding practices appropriate to the vulnerability, apply a targeted fix, and rerun the scan to verify the result.",
};

function getFindingType(finding = {}) {
    return String(
        finding.vulnerability_type ||
        finding.vulnerability ||
        finding.type ||
        finding.title ||
        ""
    )
        .trim()
        .toLowerCase()
        .replace(/[_\s]+/g, " ");
}

export const getFindingGuidance = (finding = {}) => {
    const type = getFindingType(finding);

    const rule = guidanceRules.find(({ matches }) =>
        matches.some((term) => type.includes(term))
    );

    if (!rule) {
        return {
            ...defaultGuidance,
            source: "rule-based",
            matchedRule: null,
        };
    }

    return {
        explanation: rule.explanation,
        recommendation: rule.recommendation,
        source: "rule-based",
        matchedRule: rule.matches[0],
    };
};

export const getAnalysisSource = (finding = {}) => {
    const analysis = String(
        finding.ai_analysis ||
        finding.aiAnalysis ||
        ""
    ).trim();

    if (!analysis) {
        return {
            available: false,
            label: "AI analysis unavailable",
            message:
                "The backend did not provide a separate AI analysis for this finding. Rule-based guidance may still be available.",
        };
    }

    return {
        available: true,
        label: "Backend analysis available",
        message:
            "Analysis text was supplied by the backend. Its presence alone does not verify which model generated it.",
    };
};

export const getRemediation = (finding = {}) => {
    const recommendation = String(
        finding.recommendation ||
        finding.remediation ||
        finding.ai_recommendation ||
        ""
    ).trim();

    if (recommendation) {
        return {
            recommendation,
            source: "backend",
            available: true,
        };
    }

    const guidance = getFindingGuidance(finding);

    return {
        recommendation: guidance.recommendation,
        source: "rule-based",
        available: true,
    };
};
