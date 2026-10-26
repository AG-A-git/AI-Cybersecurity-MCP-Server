# ============================================================
# Finding Evidence Helpers
# ============================================================


def build_evidence(
    source=None,
    source_line=None,
    tainted_variable=None,
    sink=None,
    sink_line=None,
    reason=None,
    context=None,
    quality=None,
):
    """
    Build structured evidence for a vulnerability finding.

    Evidence is optional scanner metadata that explains why
    a finding was reported.
    """

    evidence = {}

    if source is not None:
        evidence["source"] = source

    if source_line is not None:
        evidence["source_line"] = source_line

    if tainted_variable is not None:
        evidence["tainted_variable"] = tainted_variable

    if sink is not None:
        evidence["sink"] = sink

    if sink_line is not None:
        evidence["sink_line"] = sink_line

    if reason is not None:
        evidence["reason"] = reason

    if context is not None:
        evidence["context"] = context

    if quality is not None:
        evidence["quality"] = quality

    return evidence

def build_explainability(
    reason=None,
    source_type=None,
    sink_type=None,
    data_flow=None,
    confidence_basis=None,
):
    """
    Build structured explainability metadata for a finding.
    """

    explanation = {}

    if reason is not None:
        explanation["reason"] = reason

    if source_type is not None:
        explanation["source_type"] = source_type

    if sink_type is not None:
        explanation["sink_type"] = sink_type

    if data_flow is not None:
        explanation["data_flow"] = data_flow

    if confidence_basis is not None:
        explanation["confidence_basis"] = confidence_basis

    return explanation
