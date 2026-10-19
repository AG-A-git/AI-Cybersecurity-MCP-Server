# Day 35 ? Member 2 ? Task 9: Persistence Integrity

Status: Implemented and tested.

## Implementation
- Added `scanner/scan_persistence.py` for SQLite scan-history storage and retrieval.
- Stores project path, terminal status, UTC timestamps, files scanned, error count, total findings, severity counts, and serialized finding records.
- Added `scanner/persistent_scanner.py` as an opt-in wrapper; the existing `scan_project()` list-returning API remains unchanged.
- Existing `app.db` and `test.db` were not used or reset by the persistence tests.

## Evidence
- `tests/test_scan_persistence.py`: 8 tests pass.
- Covers round-trip finding integrity, severity summaries, terminal statuses, timestamps, missing IDs, history ordering, failed scans, and concurrent real scans.
- Database tests use temporary databases.

## Notes
Call `scan_project_and_persist(project_path, db_path)` to opt into persistence. Existing callers of `scan_project()` are not automatically persisted.
