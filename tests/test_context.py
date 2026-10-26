import ast
from scanner.context import build_rule_context, get_source_context, get_function_context, get_vulnerability_context, classify_sink, get_sql_injection_context
from scanner.context import get_command_injection_context
from scanner.context import get_xss_context
from scanner.context import get_ssrf_context
from scanner.context import get_auth_context


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


def test_vulnerability_context_with_source_and_sink(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """def search(request):
    query = request.args.get("q")
    result = db.execute(query)
    return result
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    result = get_vulnerability_context(
        context,
        source_line=2,
        sink_line=3,
    )

    assert result["source"]["line"] == 2
    assert result["sink"]["line"] == 3

    assert any(
        "query = request.args.get" in line
        for line in result["source"]["context"]["lines"]
    )

    assert any(
        "result = db.execute(query)" in line
        for line in result["sink"]["context"]["lines"]
    )

    assert (
        result["source"]["function"]["function_name"]
        == "search"
    )

    assert (
        result["sink"]["function"]["function_name"]
        == "search"
    )


def test_vulnerability_context_with_only_sink(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """def search(request):
    query = request.args.get("q")
    result = db.execute(query)
    return result
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    result = get_vulnerability_context(
        context,
        sink_line=3,
    )

    assert result["source"] is None
    assert result["sink"]["line"] == 3

    assert any(
        "result = db.execute(query)" in line
        for line in result["sink"]["context"]["lines"]
    )


def test_vulnerability_context_custom_window(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """line_one = 1
line_two = 2
line_three = 3
line_four = 4
line_five = 5
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    result = get_vulnerability_context(
        context,
        source_line=3,
        before=1,
        after=1,
    )

    assert result["source"]["line"] == 3
    assert result["source"]["context"]["lines"] == [
        "line_two = 2",
        "line_three = 3",
        "line_four = 4",
    ]

def test_function_details(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """def greet(name):
    message = "Hello " + name
    return message
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert len(context["functions_detail"]) == 1

    function = context["functions_detail"][0]

    assert function["name"] == "greet"
    assert function["line"] == 1
    assert function["end_line"] == 3


def test_class_details(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """class User:
    def __init__(self, name):
        self.name = name
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert len(context["classes"]) == 1

    class_info = context["classes"][0]

    assert class_info["name"] == "User"
    assert class_info["line"] == 1
    assert class_info["end_line"] == 3


def test_function_decorators(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """class Example:
    @staticmethod
    def run():
        return True
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    function = context["functions_detail"][0]

    assert "staticmethod" in function["decorators"]
    assert "staticmethod" in context["decorators"]


def test_variable_reassignment_tracks_latest_value(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = "first"
value = "second"
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert context["variables"]["value"] == '"second"'
    assert len(context["assignment_history"]) == 2


def test_constant_variable_has_no_external_reference(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = "hello"
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert context["variables"]["value"] == '"hello"'
    assert context["references"]["value"] == []


def test_function_context_for_top_level_function(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """def greet(name):
    return name
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    result = get_function_context(context, 2)

    assert result["function_name"] == "greet"
    assert result["class_name"] is None


def test_function_context_for_class_method(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """class User:
    def greet(self):
        return "hello"
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    result = get_function_context(context, 3)

    assert result["function_name"] == "greet"
    assert result["class_name"] == "User"


def test_function_context_for_top_level_code(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = 10
print(value)
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    result = get_function_context(context, 2)

    assert result["function_name"] is None
    assert result["class_name"] is None


def test_classify_http_request_source(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = request.args.get("name")
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert context["variable_sources"]["value"]["source_type"] == "http_request"


def test_classify_environment_source(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = os.environ.get("SECRET")
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert context["variable_sources"]["value"]["source_type"] == "environment"


def test_classify_constant_source(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = "hello"
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert context["variable_sources"]["value"]["source_type"] == "constant"


def test_unknown_source_is_not_marked_tainted(tmp_path):
    file_path = tmp_path / "app.py"

    file_path.write_text(
        """value = get_value()
""",
        encoding="utf-8",
    )

    context = build_rule_context(file_path)

    assert context["variable_sources"]["value"]["source_type"] == "unknown"


def test_classify_sql_sinks():
    import ast

    nodes = [
        ast.parse("db.execute(query)").body[0].value,
        ast.parse("cursor.execute(query)").body[0].value,
    ]

    for node in nodes:
        result = classify_sink(node)
        assert result["sink_type"] == "sql"


def test_classify_command_sinks():
    import ast

    nodes = [
        ast.parse("os.system(command)").body[0].value,
        ast.parse("subprocess.run(command)").body[0].value,
    ]

    for node in nodes:
        result = classify_sink(node)
        assert result["sink_type"] == "command"


def test_classify_network_sinks():
    import ast

    node = ast.parse("requests.get(url)").body[0].value

    result = classify_sink(node)

    assert result["sink_type"] == "network"


def test_classify_html_and_ldap_sinks():
    import ast

    html_node = ast.parse("render_template(template)").body[0].value
    ldap_node = ast.parse("ldap.search(query)").body[0].value

    assert classify_sink(html_node)["sink_type"] == "unknown"
    assert classify_sink(ldap_node)["sink_type"] == "ldap"


def test_unknown_sink_is_not_classified_as_dangerous():
    import ast

    node = ast.parse("print(value)").body[0].value

    result = classify_sink(node)

    assert result["sink_type"] == "unknown"






# ==============================================================
# Task 8 - SQL Injection Context
# ==============================================================

def test_sql_injection_context_constant_query():
    source = 'cursor.execute("SELECT * FROM users")'
    tree = ast.parse(source)
    node = tree.body[0].value

    result = get_sql_injection_context(node)

    assert result["sink_type"] == "sql"
    assert result["query_argument"] in ("'SELECT * FROM users'", '"SELECT * FROM users"')
    assert result["query_argument_type"] == "constant"
    assert result["dynamic_query"] is False


def test_sql_injection_context_variable_query(tmp_path):
    source = '''
query = "SELECT * FROM users"
cursor.execute(query)
'''

    tree = ast.parse(source)
    node = tree.body[1].value

    test_file = tmp_path / "sql_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)
    result = get_sql_injection_context(node, context)

    assert result["sink_type"] == "sql"
    assert result["query_argument"] == "query"
    assert result["query_argument_type"] == "variable"
    assert result["dynamic_query"] is True


def test_sql_injection_context_http_derived_query(tmp_path):
    source = '''
query = request.args.get("query")
cursor.execute(query)
'''

    tree = ast.parse(source)
    node = tree.body[1].value

    test_file = tmp_path / "sql_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)
    result = get_sql_injection_context(node, context)

    assert result["sink_type"] == "sql"
    assert result["query_argument_type"] == "variable"
    assert result["dynamic_query"] is True
    assert result["source_type"] == "http_request"


def test_sql_injection_context_dynamic_expression(tmp_path):
    source = '''
user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
'''

    tree = ast.parse(source)
    node = tree.body[2].value

    test_file = tmp_path / "sql_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)
    result = get_sql_injection_context(node, context)

    assert result["sink_type"] == "sql"
    assert result["query_argument"] == "query"
    assert result["query_argument_type"] == "variable"
    assert result["dynamic_query"] is True


def test_sql_injection_context_non_sql_sink():
    source = 'os.system(command)'
    tree = ast.parse(source)
    node = tree.body[0].value

    result = get_sql_injection_context(node)

    assert result["sink_type"] == "unknown"
    assert result["dynamic_query"] is False

# ==============================================================
# Task 9 - XSS Context
# ==============================================================

def test_xss_context_constant_html():
    source = 'Markup("<p>Hello</p>")'
    tree = ast.parse(source)
    node = tree.body[0].value

    result = get_xss_context(node)

    assert result["sink_type"] == "html"
    assert result["html_argument"] in ("'<p>Hello</p>'", '"<p>Hello</p>"')
    assert result["html_argument_type"] == "constant"
    assert result["dynamic_html"] is False


def test_xss_context_variable_html(tmp_path):
    source = 'html = "<p>Hello</p>"' + "\n" + 'Markup(html)'

    tree = ast.parse(source)
    node = tree.body[1].value

    test_file = tmp_path / "xss_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)

    result = get_xss_context(node, context)

    assert result["sink_type"] == "html"
    assert result["html_argument"] == "html"
    assert result["html_argument_type"] == "variable"
    assert result["dynamic_html"] is True


def test_xss_context_http_derived_html(tmp_path):
    source = 'html = request.args.get("html")' + "\n" + 'Markup(html)'

    tree = ast.parse(source)
    node = tree.body[1].value

    test_file = tmp_path / "xss_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)

    result = get_xss_context(node, context)

    assert result["sink_type"] == "html"
    assert result["html_argument_type"] == "variable"
    assert result["dynamic_html"] is True
    assert result["source_type"] == "http_request"


def test_xss_context_dynamic_expression(tmp_path):
    source = 'name = request.args.get("name")' + "\n" + 'html = "<p>" + name + "</p>"' + "\n" + 'Markup(html)'

    tree = ast.parse(source)
    node = tree.body[2].value

    test_file = tmp_path / "xss_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)

    result = get_xss_context(node, context)

    assert result["sink_type"] == "html"
    assert result["html_argument"] == "html"
    assert result["html_argument_type"] == "variable"
    assert result["dynamic_html"] is True


def test_xss_context_non_html_sink():
    source = "cursor.execute(query)"
    tree = ast.parse(source)
    node = tree.body[0].value

    result = get_xss_context(node)

    assert result["sink_type"] == "unknown"
    assert result["dynamic_html"] is False

# ==============================================================
# Task 10 - Command Injection Context
# ==============================================================

def test_command_injection_context_constant_command():
    source = 'os.system("ls -la")'
    tree = ast.parse(source)
    node = tree.body[0].value

    result = get_command_injection_context(node)

    assert result["sink_type"] == "command"
    assert result["command_argument"] in ('"ls -la"', "'ls -la'")
    assert result["command_argument_type"] == "constant"
    assert result["dynamic_command"] is False


def test_command_injection_context_variable_command(tmp_path):
    source = 'command = "ls -la"' + "\n" + 'os.system(command)'

    tree = ast.parse(source)
    node = tree.body[1].value

    test_file = tmp_path / "command_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)

    result = get_command_injection_context(node, context)

    assert result["sink_type"] == "command"
    assert result["command_argument"] == "command"
    assert result["command_argument_type"] == "variable"
    assert result["dynamic_command"] is True


def test_command_injection_context_http_derived_command(tmp_path):
    source = 'command = request.args.get("cmd")' + "\n" + 'os.system(command)'

    tree = ast.parse(source)
    node = tree.body[1].value

    test_file = tmp_path / "command_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)

    result = get_command_injection_context(node, context)

    assert result["sink_type"] == "command"
    assert result["command_argument_type"] == "variable"
    assert result["dynamic_command"] is True
    assert result["source_type"] == "http_request"


def test_command_injection_context_dynamic_expression(tmp_path):
    source = 'name = request.args.get("name")' + "\n" + 'command = "ping " + name' + "\n" + 'os.system(command)'

    tree = ast.parse(source)
    node = tree.body[2].value

    test_file = tmp_path / "command_test.py"
    test_file.write_text(source, encoding="utf-8")
    context = build_rule_context(test_file)

    result = get_command_injection_context(node, context)

    assert result["sink_type"] == "command"
    assert result["command_argument"] == "command"
    assert result["command_argument_type"] == "variable"
    assert result["dynamic_command"] is True


def test_command_injection_context_non_command_sink():
    source = "cursor.execute(query)"
    tree = ast.parse(source)
    node = tree.body[0].value

    result = get_command_injection_context(node)

    assert result["sink_type"] == "unknown"
    assert result["dynamic_command"] is False
def test_ssrf_context_constant_url(tmp_path):
    source = '''
import requests
requests.get("https://example.com")
'''

    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")

    context = build_rule_context(str(file_path))
    tree = ast.parse(source)

    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "get"
    )

    result = get_ssrf_context(node, context)

    assert result["sink_type"] == "network"
    assert result["url_argument"] == repr("https://example.com")
    assert result["url_argument_type"] == "constant"
    assert result["dynamic_url"] is False


def test_ssrf_context_variable_url(tmp_path):
    source = '''
import requests

url = "https://example.com"
requests.get(url)
'''

    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")

    context = build_rule_context(str(file_path))
    tree = ast.parse(source)

    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "get"
    )

    result = get_ssrf_context(node, context)

    assert result["sink_type"] == "network"
    assert result["url_argument"] == "url"
    assert result["url_argument_type"] == "variable"
    assert result["dynamic_url"] is True


def test_ssrf_context_http_derived_url(tmp_path):
    source = '''
import requests

url = request.args.get("url")
requests.get(url)
'''

    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")

    context = build_rule_context(str(file_path))
    tree = ast.parse(source)

    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "get"
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "requests"
    )

    result = get_ssrf_context(node, context)

    assert result["sink_type"] == "network"
    assert result["url_argument"] == "url"
    assert result["url_argument_type"] == "variable"
    assert result["dynamic_url"] is True
    assert result["source_type"] == "http_request"


def test_ssrf_context_requests_request_uses_url_argument(tmp_path):
    source = '''
import requests

url = request.args.get("url")
requests.request("GET", url)
'''

    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")

    context = build_rule_context(str(file_path))
    tree = ast.parse(source)

    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )

    result = get_ssrf_context(node, context)

    assert result["sink_type"] == "network"
    assert result["url_argument"] == "url"
    assert result["url_argument_type"] == "variable"
    assert result["dynamic_url"] is True
    assert result["source_type"] == "http_request"


def test_ssrf_context_non_network_sink(tmp_path):
    source = '''
value = "hello"
print(value)
'''

    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")

    context = build_rule_context(str(file_path))
    tree = ast.parse(source)

    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "print"
    )

    result = get_ssrf_context(node, context)

    assert result["sink_type"] == "unknown"
    assert result["url_argument"] is None
    assert result["dynamic_url"] is False





def test_auth_context_login_required():
    node = ast.parse("login_required").body[0].value

    result = get_auth_context(node)

    assert result["auth_type"] == "authentication"
    assert result["evidence"] == "login_required"


def test_auth_context_authenticate_call():
    node = ast.parse("authenticate(user, password)").body[0].value

    result = get_auth_context(node)

    assert result["auth_type"] == "authentication"
    assert result["evidence"] == "authenticate"


def test_auth_context_permission_call():
    node = ast.parse("check_permission(user, 'admin')").body[0].value

    result = get_auth_context(node)

    assert result["auth_type"] == "authentication"
    assert result["evidence"] == "check_permission"


def test_auth_context_is_authenticated():
    node = ast.parse("user.is_authenticated").body[0].value

    result = get_auth_context(node)

    assert result["auth_type"] == "authorization"
    assert result["evidence"] == "is_authenticated"


def test_auth_context_is_admin():
    node = ast.parse("user.is_admin").body[0].value

    result = get_auth_context(node)

    assert result["auth_type"] == "authorization"
    assert result["evidence"] == "is_admin"
