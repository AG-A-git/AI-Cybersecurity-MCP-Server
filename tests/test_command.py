from scanner.rules.command import scan_command


def test_command_injection_from_multi_hop_user_input(tmp_path):
    test_file = tmp_path / "command_multi_hop.py"

    test_file.write_text(
        """from flask import request
import os

user_command = request.args.get("command")
command = user_command
final_command = command

os.system(final_command)
""",
        encoding="utf-8",
    )

    findings = scan_command(str(test_file))

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings
    assert command_findings[0]["confidence"] == 90
from scanner.rules.command import scan_command


def test_subprocess_command_injection_from_multi_hop_user_input(tmp_path):
    test_file = tmp_path / "subprocess_multi_hop.py"

    test_file.write_text(
        """from flask import request
import subprocess

user_command = request.args.get("command")
command = user_command
final_command = command

subprocess.run(final_command, shell=True)
""",
        encoding="utf-8",
    )

    findings = scan_command(str(test_file))

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings
    assert command_findings[0]["confidence"] == 90

def test_command_unknown_source_uses_default_confidence(tmp_path):
    test_file = tmp_path / "command_unknown_source.py"

    test_file.write_text(
        """import os

command = "date"
os.system(command)
""",
        encoding="utf-8",
    )

    findings = scan_command(str(test_file))

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings
    assert command_findings[0]["confidence"] == 70

def test_subprocess_unknown_source_not_reported(tmp_path):
    test_file = tmp_path / "subprocess_unknown_source.py"

    test_file.write_text(
        """import subprocess

command = "date"
subprocess.run(command, shell=True)
""",
        encoding="utf-8",
    )

    findings = scan_command(str(test_file))

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert not command_findings

def test_command_generic_command_name_is_not_treated_as_user_input(tmp_path):
    test_file = tmp_path / "command_generic_name.py"

    test_file.write_text(
        """import os

command = "date"
os.system(command)
""",
        encoding="utf-8",
    )

    findings = scan_command(str(test_file))

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings
    assert command_findings[0]["confidence"] == 70


def test_os_popen_command_injection_from_user_input(tmp_path):
    test_file = tmp_path / "command_popen.py"
    test_file.write_text(
        """import os
from flask import request

user_command = request.args.get("command")
os.popen(user_command)
""",
        encoding="utf-8",
    )

    findings = scan_command(str(test_file))
    command_findings = [
        finding for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings
    assert command_findings[0]["severity"] in {"High", "Critical"}
    assert 0 <= command_findings[0]["confidence"] <= 100
    assert command_findings[0]["line_number"] == 5
    assert command_findings[0]["source_context"]
