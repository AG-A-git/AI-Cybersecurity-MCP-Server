from types import SimpleNamespace

import pytest

import services.mcp_server as mcp_server


@pytest.mark.parametrize("bad_format", [None, 123, [], {}])
def test_generate_report_rejects_non_string_format(
    monkeypatch,
    bad_format,
):
    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )

    with pytest.raises(
        ValueError,
        match="Report format must be a string",
    ):
        mcp_server.generate_report(
            scan_id=123,
            report_format=bad_format,
        )
