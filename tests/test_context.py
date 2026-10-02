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

def test_recursive_variable_references(tmp_path):
    test_file = tmp_path / "recursive_context_flow_test.py"

    test_file.write_text(
        """username = request.args.get("username")
user = username
query = "SELECT * FROM users WHERE name='" + user + "'"
""",
        encoding="utf-8",
    )

    context = build_rule_context(str(test_file))

    references = context["references"]

    assert references["username"] == ["request"]
    assert references["user"] == ["username"]
    assert references["query"] == ["user"]


def test_is_variable_derived_from():
    from scanner.context import is_variable_derived_from

    context = {
        "references": {
            "username": ["request"],
            "user": ["username"],
            "query": ["user"],
        }
    }

    assert is_variable_derived_from(
        context,
        "query",
        {"username"},
    )

    assert not is_variable_derived_from(
        context,
        "query",
        {"password"},
    )


def test_is_variable_derived_from_handles_cycles():
    from scanner.context import is_variable_derived_from

    context = {
        "references": {
            "a": ["b"],
            "b": ["a"],
        }
    }

    assert not is_variable_derived_from(
        context,
        "a",
        {"username"},
    )

def test_build_project_context_isolates_files(tmp_path):
    from scanner.context import build_project_context

    first_file = tmp_path / "first.py"
    second_file = tmp_path / "second.py"

    first_file.write_text(
        """user_input = request.args.get("name")
query = user_input
""",
        encoding="utf-8",
    )

    second_file.write_text(
        """user_input = "safe"
query = user_input
""",
        encoding="utf-8",
    )

    project_context = build_project_context(
        [str(first_file), str(second_file)]
    )

    assert str(first_file) in project_context
    assert str(second_file) in project_context

    assert (
        project_context[str(first_file)]["variables"]["user_input"]
        == 'request.args.get("name")'
    )

    assert (
        project_context[str(second_file)]["variables"]["user_input"]
        == '"safe"'
    )

    assert (
        project_context[str(first_file)]["references"]["query"]
        == ["user_input"]
    )

    assert (
        project_context[str(second_file)]["references"]["query"]
        == ["user_input"]
    )
