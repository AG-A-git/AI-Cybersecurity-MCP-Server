from unittest.mock import patch

import pytest

from scanner import utils


@pytest.fixture
def empty_rule_context():
    return {
        "language": "python",
        "lines": [],
        "imports": [],
        "functions": [],
        "variables": [],
    }


def test_rule_failure_is_logged_and_remaining_rules_continue(
    caplog,
    empty_rule_context,
):
    def failing_rule(file_path):
        raise ValueError("simulated rule failure")

    def working_rule(file_path):
        return [{"finding": "from working rule"}]

    with (
        patch.object(
            utils,
            "build_rule_context",
            return_value=empty_rule_context,
        ),
        patch.object(
            utils,
            "load_rules",
            return_value=[failing_rule, working_rule],
        ),
    ):
        results = utils.run_all_rules("example.py")

    assert results == [{"finding": "from working rule"}]
    assert "simulated rule failure" in caplog.text
    assert "findings may be incomplete" in caplog.text


def test_unexpected_rule_error_is_not_silently_ignored(
    empty_rule_context,
):
    def broken_rule(file_path):
        raise TypeError("simulated unexpected error")

    with (
        patch.object(
            utils,
            "build_rule_context",
            return_value=empty_rule_context,
        ),
        patch.object(
            utils,
            "load_rules",
            return_value=[broken_rule],
        ),
    ):
        with pytest.raises(
            TypeError,
            match="simulated unexpected error",
        ):
            utils.run_all_rules("example.py")


def test_successful_scan_does_not_warn_findings_may_be_incomplete(
    caplog,
    empty_rule_context,
):
    def working_rule(file_path):
        return [{"finding": "valid result"}]

    with (
        patch.object(
            utils,
            "build_rule_context",
            return_value=empty_rule_context,
        ),
        patch.object(
            utils,
            "load_rules",
            return_value=[working_rule],
        ),
    ):
        results = utils.run_all_rules("example.py")

    assert results == [{"finding": "valid result"}]
    assert "findings may be incomplete" not in caplog.text
