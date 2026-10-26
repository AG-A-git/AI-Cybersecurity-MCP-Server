# Task 3 — Deduplication and Finding Metadata Verification

## Test results
- Focused regression suite: 33 expected tests; record the actual result from the latest run.
- Full project suite: 314 passed, 1 skipped, 0 failed in 13.16 seconds.
- The skipped symlink-escape test reports that symlinks are unavailable in the environment.

## Verified behavior
- Duplicate findings are removed.
- Distinct findings across files, lines, vulnerability types, and code are preserved.
- Higher confidence wins; severity breaks equal-confidence ties.
- Selected findings retain evidence and optional remediation metadata.
- Equal-priority duplicates are selected deterministically regardless of input order.
- Deduplication is idempotent.
- Equivalent slash styles and redundant dot path segments deduplicate correctly.
- Repeated and concurrent scans return consistent results without leaking findings.

## Modified tracked files
- scanner/utils.py
- tests/test_deduplication.py

## Limitations
- The symlink-escape test could not execute in this Windows environment.
- Full-suite success does not by itself establish production release readiness.

## Review
- Preserve unrelated untracked files.
- Record the final git diff --check result after cleanup.
