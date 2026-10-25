# Day 36 — Task 8: Malformed and Unsupported Input Verification

Date: 25 October 2026
Component: AI Cybersecurity MCP Server — Scanner

## Objective

Verify that malformed, empty, unsupported, oversized, and problematic input files are handled safely without crashing the scanner or preventing valid files from being scanned.

## Test Execution Summary

- `python -m pytest -q tests/test_parser.py tests/test_task11_file_handling.py`
  - Result: 24 passed in 1.35 seconds.
- `python -m pytest -q tests/test_parser.py tests/test_project_scanning.py tests/test_task11_file_handling.py tests/test_scanner_terminal_states.py tests/test_scanner_failure_handling.py`
  - Result: 59 passed, 1 skipped.
  - The skipped test required symlink permissions unavailable in the Windows environment.
- Additional direct checks confirmed that directory input, binary bytes disguised as Python, Unicode source, and source without a final newline did not cause uncaught exceptions.
- Separate detection checks confirmed that Unicode source and source without a final newline each produced one Insecure Deserialization finding.
- A simulated PermissionError from read_file() was handled without an uncaught exception; real Windows access denial was not confirmed.

## Scenario Results

| # | Scenario | Observed result | Status |
|---|---|---|---|
| 1 | Empty source file | Project scan returned an empty list and completed | PASS |
| 2 | Malformed Python syntax | Malformed file did not prevent a separate vulnerable file from being detected | PASS |
| 3 | Unsupported extension | Unsupported file was skipped | PASS |
| 4 | Binary data renamed as source | Returned an empty findings list; explicit binary rejection was not verified | PARTIAL |
| 5 | Invalid encoding | Parser test expects UnicodeDecodeError; scan_file catches Unicode errors and returns an empty list | PASS |
| 6 | Missing path | Missing-file checks exist; scan_project intentionally raises FileNotFoundError | PASS |
| 7 | Directory passed to scan_file | Returned an empty list | PASS |
| 8 | Unreadable file | Simulated PermissionError was handled safely; real Windows access denial was not confirmed | PARTIAL |
| 9 | Oversized file | Parser tests cover rejection and scan_file skipping | PASS |
| 10 | Unusual Unicode | Detected Insecure Deserialization; one finding | PASS |
| 11 | No final newline | Detected Insecure Deserialization; one finding | PASS |
| 12 | Multiple files, one malformed | Valid vulnerable file was still detected | PASS |

## Findings and Limitations

1. The tested malformed and unsupported input scenarios did not produce an observed uncaught exception.
2. Binary input returned no findings, but the test did not establish whether the file was explicitly rejected or safely analyzed.
3. Unreadable-file handling remains inconclusive because the Windows permission test did not establish that read access was actually denied.
4. An empty findings list does not, by itself, prove successful analysis or correct rejection.
5. The symlink-related test skip is an environment limitation and is not evidence of a scanner failure.
6. No confirmed scanner defect was established by these tests.

## Conclusion

The scanner passed the executed regression tests and the tested Unicode and no-final-newline detection checks. Binary handling is partially verified, and unreadable-file handling is partially verified through a simulated PermissionError; explicit binary rejection and real OS-level access denial remain unconfirmed.

Task 8 should be considered substantially verified but not fully closed until the binary-handling and unreadable-file limitations are either tested further or explicitly accepted by the integration lead.
