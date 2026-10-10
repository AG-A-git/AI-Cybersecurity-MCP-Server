# Day 26 — Scanner Security Audit

## Fix completed
Fixed source-file discovery when the selected project is inside an
ancestor directory named `venv`.

## Regression coverage
Added a test verifying that the project's source file is discovered.

## ZIP security review
Reviewed invalid archive handling, path traversal checks, the
1,000-entry limit, and the 100 MiB declared uncompressed-size limit.
Compression-ratio and execution-time limits are not implemented.
No production ZIP changes were made during this review.

## Test results
Focused tests: 15 passed.
Full test suite: 208 passed in 11.38 seconds.

## Detection-quality validation
- Vulnerable samples: 7 findings across 6 vulnerability categories.
- Safe samples: 0 findings.
- Full test suite: 208 passed.
- Limitation: Results cover the available samples and do not guarantee
  detection completeness or real-world false-positive rates.
