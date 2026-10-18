import asyncio
import time

import pytest

import services.mcp_auth as mcp_auth


async def invoke_middleware(middleware, authorization=None):
    headers = []
    if authorization is not None:
        headers.append(
            (b"authorization", authorization.encode("latin-1"))
        )

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/mcp/",
        "raw_path": b"/mcp/",
        "query_string": b"",
        "headers": headers,
        "server": ("testserver", 80),
        "client": ("testclient", 12345),
    }

    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    async def downstream(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        })
        await send({
            "type": "http.response.body",
            "body": b"ok",
        })

    middleware = mcp_auth.MCPJWTAuthMiddleware(downstream)
    await middleware(scope, receive, send)

    return next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic abc", "Bearer", "Bearer token extra"],
)
def test_mcp_auth_rejects_missing_or_malformed_bearer_header(
    monkeypatch,
    authorization,
):
    monkeypatch.setattr(
        mcp_auth,
        "verify_token",
        lambda token: pytest.fail("Token verification must not run"),
    )

    status = asyncio.run(
        invoke_middleware(
            mcp_auth.MCPJWTAuthMiddleware,
            authorization,
        )
    )

    assert status == 401


def test_mcp_auth_rejects_invalid_token(monkeypatch):
    monkeypatch.setattr(mcp_auth, "verify_token", lambda token: None)

    status = asyncio.run(
        invoke_middleware(
            mcp_auth.MCPJWTAuthMiddleware,
            "Bearer invalid-token",
        )
    )

    assert status == 401


@pytest.mark.parametrize(
    "claims",
    [
        None,
        [],
        {},
        {"sub": "user@example.com"},
        {"sub": "user@example.com", "exp": True},
        {"sub": "user@example.com", "exp": time.time() - 60},
        {"sub": "", "exp": time.time() + 60},
        {"sub": 123, "exp": time.time() + 60},
    ],
)
def test_mcp_auth_rejects_invalid_claims_without_database_lookup(
    monkeypatch,
    claims,
):
    monkeypatch.setattr(mcp_auth, "verify_token", lambda token: claims)
    monkeypatch.setattr(
        mcp_auth,
        "SessionLocal",
        lambda: pytest.fail("Database must not be queried for invalid claims"),
    )

    status = asyncio.run(
        invoke_middleware(
            mcp_auth.MCPJWTAuthMiddleware,
            "Bearer test-token",
        )
    )

    assert status == 401
from types import SimpleNamespace

from sqlalchemy.exc import SQLAlchemyError


class FakeQuery:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def filter(self, *args):
        return self

    def first(self):
        if self.error:
            raise self.error
        return self.result


class FakeSession:
    def __init__(self, user=None, query_error=None):
        self.user = user
        self.query_error = query_error
        self.closed = False

    def query(self, model):
        return FakeQuery(self.user, self.query_error)

    def close(self):
        self.closed = True


def valid_claims():
    return {
        "sub": "user@example.com",
        "exp": time.time() + 300,
    }


def test_mcp_auth_rejects_unknown_user_and_closes_session(monkeypatch):
    session = FakeSession(user=None)
    monkeypatch.setattr(mcp_auth, "verify_token", lambda token: valid_claims())
    monkeypatch.setattr(mcp_auth, "SessionLocal", lambda: session)

    status = asyncio.run(
        invoke_middleware(
            mcp_auth.MCPJWTAuthMiddleware,
            "Bearer valid-token",
        )
    )

    assert status == 401
    assert session.closed


def test_mcp_auth_returns_503_on_database_error_and_closes_session(
    monkeypatch,
):
    session = FakeSession(query_error=SQLAlchemyError("database unavailable"))
    monkeypatch.setattr(mcp_auth, "verify_token", lambda token: valid_claims())
    monkeypatch.setattr(mcp_auth, "SessionLocal", lambda: session)

    status = asyncio.run(
        invoke_middleware(
            mcp_auth.MCPJWTAuthMiddleware,
            "Bearer valid-token",
        )
    )

    assert status == 503
    assert session.closed


def test_mcp_auth_sets_identity_during_request_and_resets_afterward(
    monkeypatch,
):
    session = FakeSession(
        user=SimpleNamespace(id=9, email="user@example.com")
    )
    monkeypatch.setattr(mcp_auth, "verify_token", lambda token: valid_claims())
    monkeypatch.setattr(mcp_auth, "SessionLocal", lambda: session)

    observed = {}

    async def downstream(scope, receive, send):
        user = mcp_auth.get_authenticated_mcp_user()
        observed["user_id"] = user.user_id
        observed["email"] = user.email
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        })
        await send({
            "type": "http.response.body",
            "body": b"ok",
        })

    original = mcp_auth.MCPJWTAuthMiddleware(downstream)

    async def invoke_with_downstream():
        headers = [(b"authorization", b"Bearer valid-token")]
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/mcp/",
            "raw_path": b"/mcp/",
            "query_string": b"",
            "headers": headers,
            "server": ("testserver", 80),
            "client": ("testclient", 12345),
        }
        messages = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        await original(scope, receive, send)
        return messages

    messages = asyncio.run(invoke_with_downstream())

    assert observed == {"user_id": 9, "email": "user@example.com"}
    assert session.closed
    assert mcp_auth.current_mcp_user.get() is None
    assert any(
        message["type"] == "http.response.start"
        and message["status"] == 200
        for message in messages
    )
