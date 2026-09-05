import re

from scanner.finding import create_finding
from scanner.confidence import calculate_confidence


OS_SYSTEM_PATTERN = re.compile(
    r'\bos\.system\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)',
    re.IGNORECASE
)

SUBPROCESS_PATTERN = re.compile(
    r'\bsubprocess\.(call|run|Popen)\s*\((.*?)\)',
    re.IGNORECASE
)

USER_INPUT_NAMES = {
    "user_input",
    "input",
    "command",
    "cmd",
    "user_command",
}


def scan_command(file_path):
    """
    Detect potentially dangerous command execution
    involving suspicious or user-controlled input.
    """

    results = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            lines = file.readlines()

    except (FileNotFoundError, OSError):
        return results

    for line_number, line in enumerate(lines, start=1):

        # --------------------------------------------------
        # os.system(variable)
        # --------------------------------------------------
        os_match = OS_SYSTEM_PATTERN.search(line)

        if os_match:

            variable_name = os_match.group(1)

            # Directly recognized user-controlled variable
            if variable_name.lower() in {
                name.lower() for name in USER_INPUT_NAMES
            }:
                confidence = calculate_confidence(
                    direct_source=True
                )
            else:
                # Variable reaches os.system(), but the scanner
                # cannot prove where the variable came from.
                confidence = calculate_confidence()

            results.append(
                create_finding(
                    file_name=file_path,
                    line_number=line_number,
                    vulnerability_type="Command Injection",
                    severity="High",
                    confidence=confidence,
                    code=line.strip(),
                    owasp="A03: Injection",
                    cwe="CWE-78"
                )
            )

            continue

        # --------------------------------------------------
        # subprocess(..., shell=True)
        # --------------------------------------------------
        subprocess_match = SUBPROCESS_PATTERN.search(line)

        if not subprocess_match:
            continue

        arguments = subprocess_match.group(2)

        # Only investigate shell=True
        if not re.search(
            r'\bshell\s*=\s*True\b',
            arguments,
            re.IGNORECASE
        ):
            continue

        # Remove shell=True before checking the command input
        command_arguments = re.sub(
            r',?\s*shell\s*=\s*True',
            "",
            arguments,
            flags=re.IGNORECASE
        )

        # Look for obvious variable-controlled input
        variable_found = any(
            re.search(
                rf'\b{re.escape(name)}\b',
                command_arguments,
                re.IGNORECASE
            )
            for name in USER_INPUT_NAMES
        )

        if not variable_found:
            continue

        # shell=True combined with an obvious user-controlled
        # variable is a strong command-injection indicator.
        confidence = calculate_confidence(
            direct_source=True
        )

        results.append(
            create_finding(
                file_name=file_path,
                line_number=line_number,
                vulnerability_type="Command Injection",
                severity="Critical",
                confidence=confidence,
                code=line.strip(),
                owasp="A03: Injection",
                cwe="CWE-78"
            )
        )

    return results