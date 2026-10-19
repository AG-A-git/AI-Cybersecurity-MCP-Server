import os
from pathlib import Path


ALLOWED_ROOTS_ENV = "SCANNER_ALLOWED_ROOTS"


def ensure_allowed_path(path):
    """Resolve a requested path and require it to be inside an approved root."""
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("Scan path must be a string or path-like value")

    configured = os.environ.get(ALLOWED_ROOTS_ENV, "").strip()
    if not configured:
        raise PermissionError(
            f"Scanning denied: configure {ALLOWED_ROOTS_ENV} "
            "with one or more approved directories"
        )

    target = Path(path)

    try:
        resolved_target = target.resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError(f"Path does not exist: {target}")
    except (OSError, RuntimeError, ValueError) as exc:
        raise PermissionError("Scanning denied: path cannot be resolved") from exc

    # Windows uses semicolons; Unix-like systems use colons.
    for entry in configured.split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry:
            continue

        try:
            root = Path(entry).resolve(strict=True)
            if not root.is_dir():
                continue

            common = os.path.commonpath((str(root), str(resolved_target)))
            if os.path.normcase(common) == os.path.normcase(str(root)):
                return resolved_target
        except (OSError, RuntimeError, ValueError):
            continue

    raise PermissionError(
        f"Scanning denied: path is outside configured "
        f"{ALLOWED_ROOTS_ENV} directories"
    )
