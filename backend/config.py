# ==========================
# Project Information
# ==========================

PROJECT_NAME = "AI Cybersecurity MCP Server"

PROJECT_VERSION = "1.0.0"

PROJECT_DESCRIPTION = "AI Powered Static Code Vulnerability Scanner"


# ==========================
# Database Configuration
# ==========================

DATABASE_URL = "sqlite:///./scanner.db"


# ==========================
# Authentication
# ==========================

SECRET_KEY = "change_this_secret_key_before_deployment"

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ==========================
# File Paths
# ==========================

UPLOAD_FOLDER = "uploads"

REPORT_FOLDER = "reports"

LOG_FOLDER = "logs"


# ==========================
# Scanner Settings
# ==========================

MAX_UPLOAD_SIZE = 100 * 1024 * 1024

SUPPORTED_EXTENSIONS = [
    ".py",
    ".java",
    ".js",
    ".cpp",
    ".c",
    ".cs",
    ".php",
    ".go"
]