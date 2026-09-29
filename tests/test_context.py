from scanner.context import build_rule_context, get_source_context


def test_build_rule_context():
    context = build_rule_context("tests/xss_test.py")

    assert context["language"] == "python"
    assert len(context["lines"]) > 0
    assert isinstance(context["imports"], list)
    assert isinstance(context["functions"], list)
    assert isinstance(context["variables"], dict)
    assert isinstance(context["references"], dict)
    assert isinstance(context["variable_lines"], dict)


def test_get_source_context():
    context = build_rule_context("tests/xss_test.py")

    result = get_source_context(
        context,
        line_number=1,
        before=2,
        after=2,
    )

    assert result["start_line"] == 1
    assert result["end_line"] <= len(context["lines"])
    assert isinstance(result["lines"], list)


def test_variable_references(tmp_path):
    test_file = tmp_path / "context_flow_test.py"

    test_file.write_text(
        """username = request.args.get("username")
query = "SELECT * FROM users WHERE name='" + username + "'"
""",
        encoding="utf-8",
    )

    context = build_rule_context(str(test_file))

    references = context["references"]

    assert references["username"] == ["request"]
    assert references["query"] == ["username"]


def test_variable_lines(tmp_path):
    test_file = tmp_path / "context_flow_test.py"

    test_file.write_text(
        """username = request.args.get("username")
query = "SELECT * FROM users WHERE name='" + username + "'"
""",
        encoding="utf-8",
    )

    context = build_rule_context(str(test_file))

    variable_lines = context["variable_lines"]

    assert variable_lines["username"] == 1
    assert variable_lines["query"] == 2
