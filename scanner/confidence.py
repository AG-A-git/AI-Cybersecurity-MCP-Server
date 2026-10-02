CONFIDENCE_VERY_HIGH = 95
CONFIDENCE_HIGH = 90
CONFIDENCE_MEDIUM = 75
CONFIDENCE_LOW = 60
CONFIDENCE_AMBIGUOUS = 70


def calculate_confidence(
    direct_source=False,
    tracked_source=False,
    validated=False
):
    """
    Calculate confidence on a 0-100 scale.

    Confidence represents how certain the scanner is
    that a detected pattern is actually vulnerable.
    """

    if direct_source:
        confidence = CONFIDENCE_VERY_HIGH

    elif tracked_source:
        confidence = CONFIDENCE_HIGH

    else:
        confidence = CONFIDENCE_AMBIGUOUS

    if validated:
        confidence -= 20

    return max(0, min(confidence, 100))
