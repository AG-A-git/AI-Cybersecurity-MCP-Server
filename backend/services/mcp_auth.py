"""Authentication middleware for the backend MCP endpoint."""

import time
from contextvars import ContextVar
from dataclasses import dataclass

from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse

from auth import verify_token
from database import SessionLocal
from logging_config import get_logger
from models import User

logger = get_logger(__name__)


@dataclass(frozen=True)
class AuthenticatedMCPUser:
    user_id: int
    email: str


current_mcp_user: ContextVar[AuthenticatedMCPUser | None] = ContextVar(
    "current_mcp_user",
    default=None,
)


class MCPJWTAuthMiddleware:
    """Require a valid existing backend JWT on MCP HTTP requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return

        headers = {
            key.lower(): value
            for key, value in scope.get("headers", [])
        }
        authorization = headers.get(b"authorization", b"").decode(
            "latin-1"
        )
        parts = authorization.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            await JSONResponse(
                {"detail": "Missing or invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return

        claims = verify_token(parts[1])

        if not isinstance(claims, dict):
            await JSONResponse(
                {"detail": "Invalid or expired token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return

        expiry = claims.get("exp")
        email = claims.get("sub")

        if (
            not isinstance(expiry, (int, float))
            or isinstance(expiry, bool)
            or expiry <= time.time()
            or not isinstance(email, str)
            or not email.strip()
        ):
            await JSONResponse(
                {"detail": "Invalid or expired token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return

        db = SessionLocal()

        try:
            user = db.query(User).filter(User.email == email).first()

            if user is None:
                await JSONResponse(
                    {"detail": "Authenticated user not found"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )(scope, receive, send)
                return

            authenticated_user = AuthenticatedMCPUser(
                user_id=user.id,
                email=user.email,
            )

        except SQLAlchemyError:
            logger.exception("Failed to resolve MCP token subject")
            await JSONResponse(
                {"detail": "Authentication service unavailable"},
                status_code=503,
            )(scope, receive, send)
            return

        finally:
            db.close()

        context_token = current_mcp_user.set(authenticated_user)

        try:
            await self.app(scope, receive, send)
        finally:
            current_mcp_user.reset(context_token)


def get_authenticated_mcp_user() -> AuthenticatedMCPUser:
    """Return the identity established by MCP HTTP middleware."""

    user = current_mcp_user.get()

    if user is None:
        raise PermissionError("Authenticated MCP user is unavailable")

    return user
