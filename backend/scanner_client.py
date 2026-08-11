import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.engine import scan_project


def run_scanner(project_path):
    """
    Run the vulnerability scanner.

    Args:
        project_path: Path to a file or project directory.

    Returns:
        List of vulnerability findings.
    """
    return scan_project(project_path)