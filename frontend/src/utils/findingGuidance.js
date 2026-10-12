
export const getFindingGuidance = (finding = {}) => {
    const type = String(
        finding.vulnerability_type ||
        finding.vulnerability ||
        finding.type ||
        ""
    ).toLowerCase();

    if (type.includes("sql injection")) {
        return {
            explanation:
                "The SQL query appears to concatenate input directly into the query string. If that input is controlled by a user, an attacker may manipulate the query and access or modify data without authorization.",

            recommendation:
                "Use parameterized queries or prepared statements instead of concatenating user input. Validate inputs and apply least-privilege database permissions."
        };
    }

    if (
        type.includes("hardcoded credentials") ||
        type.includes("hardcoded password")
    ) {
        return {
            explanation:
                "A password or secret appears to be stored directly in the source code. Anyone who can access the code may be able to discover and misuse the credential.",

            recommendation:
                "Remove the secret from the source code, rotate the exposed credential, and load secrets from environment variables or a secure secret manager."
        };
    }

    return {
        explanation:
            "The scanner detected a potential security issue. Review the affected code and validate the finding to determine whether it is exploitable.",

        recommendation:
            "Review the affected code, follow secure coding practices, and apply a fix appropriate to the vulnerability. Retest after making changes."
    };
};
