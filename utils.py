
from passlib.context import CryptContext
from scanner.rules.sql import detect_sql_injection


# Password hashing configuration
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    """Hash a password before storing it in the database."""
    if not password:
        raise ValueError("Password cannot be empty")

    # bcrypt supports a maximum of 72 bytes.
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise ValueError("Password must be 72 bytes or fewer")

    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    """Verify a plain password against its stored hash."""
    if not plain_password or not hashed_password:
        return False

    password_bytes = plain_password.encode("utf-8")
    if len(password_bytes) > 72:
        return False

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as error:
        print("Password verification error:", error)
        return False


def load_rules():
    """Load all vulnerability detection rules."""
    return [
        detect_sql_injection
    ]


def run_all_rules(file_path, code):
    """Execute all loaded rules and collect their findings."""
    findings = []

    for rule in load_rules():
        result = rule(file_path, code)
        findings.extend(result)

    return findings

