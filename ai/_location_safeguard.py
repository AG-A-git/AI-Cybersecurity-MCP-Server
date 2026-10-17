import re


def remove_unverified_code_locations(text, scanner_file, scanner_line):
    """
    Replace explicit file:line references that differ from
    the scanner-provided location.
    """
    if not text:
        return text

    pattern = re.compile(
        r"(?<![\w.-])"
        r"([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_-]+)"
        r":(\d+)\b"
    )

    expected_file = scanner_file.replace("\\", "/").casefold()

    def replace_location(match):
        mentioned_file = match.group(1).replace("\\", "/").casefold()
        mentioned_line = int(match.group(2))

        if (
            mentioned_file == expected_file
            and mentioned_line == scanner_line
        ):
            return match.group(0)

        return "[unverified code location]"

    return pattern.sub(replace_location, text)
