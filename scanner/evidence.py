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
):
    """
    Build structured evidence for a vulnerability finding.

    Evidence is optional scanner metadata that explains why
    a finding was reported.

    Example:

        source:
            request.args.get("username")

        tainted_variable:
            username

        sink:
            cursor.execute(query)

        This represents:

            request input -> username -> query -> database sink
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

    return evidence