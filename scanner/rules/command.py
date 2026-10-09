import re

from scanner.context import build_rule_context, get_source_context, is_variable_derived_from
from scanner.finding import create_finding
from scanner.confidence import calculate_confidence


OS_SYSTEM_PATTERN = re.compile(
    r'\bos\.(?:system|popen)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)',
    re.IGNORECASE
)

SUBPROCESS_PATTERN = re.compile(
    r'\bsubprocess\.(call|run|Popen)\s*\((.*?)\)',
    re.IGNORECASE
)

USER_INPUT_NAMES = {
    "user_input",
    "input",

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

    try:
        context = build_rule_context(file_path)

    except (
        SyntaxError,
        ValueError,
        OSError,
        UnicodeError
    ):
        context = {
            "lines": [
                line.rstrip("\n")
                for line in lines
            ]
        }

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
            elif is_variable_derived_from(
                context,
                variable_name,
                {name.lower() for name in USER_INPUT_NAMES},
            ):
                confidence = calculate_confidence(
                    tracked_source=True
                )
            else:
                # Variable reaches os.system(), but the scanner
                # cannot prove where the variable came from.
                confidence = calculate_confidence()

            finding = create_finding(
                file_name=file_path,
                line_number=line_number,
                vulnerability_type="Command Injection",
                severity="High",
                confidence=confidence,
                code=line.strip(),
                owasp="A03: Injection",
                cwe="CWE-78"
            )

            finding["source_context"] = get_source_context(
                context,
                line_number
            )

            results.append(finding)

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

        # Look for direct or recursively tracked user-controlled input.
        variable_matches = re.findall(
            r'\b[A-Za-z_][A-Za-z0-9_]*\b',
            command_arguments,
        )

        direct_source = any(
            variable_name.lower() in {
                name.lower() for name in USER_INPUT_NAMES
            }
            for variable_name in variable_matches
        )

        tracked_source = any(
            is_variable_derived_from(
                context,
                variable_name,
                {name.lower() for name in USER_INPUT_NAMES},
            )
            for variable_name in variable_matches
            if variable_name.lower() not in {
                name.lower() for name in USER_INPUT_NAMES
            }
        )

        if direct_source:
            confidence = calculate_confidence(
                direct_source=True
            )
        elif tracked_source:
            confidence = calculate_confidence(
                tracked_source=True
            )
        else:
            continue
        finding = create_finding(
            file_name=file_path,
            line_number=line_number,
            vulnerability_type="Command Injection",
            severity="Critical",
            confidence=confidence,
            code=line.strip(),
            owasp="A03: Injection",
            cwe="CWE-78"
        )

        finding["source_context"] = get_source_context(
            context,
            line_number
        )

        results.append(finding)

    return results
