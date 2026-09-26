from datetime import datetime, timedelta
from jose import JWTError, jwt

from config import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

from logging_config import get_logger

logger = get_logger(__name__)


def create_access_token(data: dict):
    """
    Generate a JWT access token.
    """
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    token = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    logger.info(
        "Access token created | user=%s",
        data.get("sub")
    )

    return token


def verify_token(token: str):
    """
    Verify and decode a JWT token.
    """
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload

    except JWTError:
        logger.warning("JWT verification failed")
        return None


def get_current_user(token: str):
    """
    Decode the JWT and return the email.
    """
    payload = verify_token(token)

    if payload is None:
        return None

    return payload.get("sub")