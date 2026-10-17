# Day 25 — Task 1: Frontend Baseline Report

## 1. Repository Status

- Repository: AI-Cybersecurity-MCP-Server
- Current branch: member4-frontend
- Tracking branch: origin/member4-frontend
- Latest commit: 058b31e — fix: align frontend API port with backend
- Working tree: Contains pre-existing uncommitted backend changes and untracked files.
- No backend changes or untracked artifacts were intentionally modified during this audit.

## 2. Day 24 Evidence

- Report: frontend/DAY24_TEST_RESULTS.md
- Reported result: Production build and tested scan-results workflow passed.
- Findings: The frontend displayed two unique findings despite duplicate records from the backend.
- Day 24 limitations: Project switching and error/empty-state scenarios were not fully verified at that time.
- Day 24 metrics are historical and are separate from today's build.

## 3. Current Frontend Build

- Working directory: frontend/
- Command: npm run build
- Result: PASSED
- Vite version: 5.4.21
- Build duration: 3.79 seconds
- JavaScript bundle: 297.81 kB
- Gzipped JavaScript bundle: 94.30 kB
- Build errors: None reported.

## 4. Backend Connectivity

- Configured frontend API base URL: http://127.0.0.1:8002
- Root endpoint: GET /
- Result: PASSED; returned "Welcome to AI Cybersecurity MCP Server!"
- Backend was reachable on port 8002 during runtime verification.
- The root endpoint check confirms connectivity, not that every API route is correct.

## 5. Runtime Verification

| Check | Result | Evidence |
|---|---|---|
| Login and logout | PASS | User confirmed working |
| Project selection/switching | PASS | User confirmed working |
| File upload and scan initiation | PASS | User confirmed working |
| Scan results and refresh | PASS | User confirmed working |
| Reports and report export | PASS | User confirmed working |
| Error handling | PASS - user reported | User reported working; detailed failure cases are not documented |
| Empty states | NOT VERIFIED | No project without scans was available for testing |

These are user-reported runtime results; they are not automated test results.

## 6. Test Configuration

Available frontend scripts:
- dev: vite
- build: vite build
- preview: vite preview

- Dedicated test script: Not configured.
- Dedicated lint script: Not configured.
- Automated test suite: Not run because no test script is configured.
- A successful production build does not prove that all runtime workflows pass.

## 7. Existing Working-Tree Changes to Preserve

Modified:
- backend/app.py
- backend/models.py
- backend/schemas.py

Untracked:
- DAY25_BASELINE_REPORT.md
- backend/app.py.pre_scan_test.bak
- backend/routers/
- backend/services/
- frontend/src/pages/Reports.jsx.day25-backup
- frontend/src/pages/ScanResults.jsx.day24-backup
- scanner.db
- vulnerable.py

Do not stage, delete, revert, or commit these files as a group. Review ownership and scope before any future changes.

## 8. Remaining Verification Gaps

- Empty-state behavior remains unverified.
- Detailed error cases and individual API failure responses need further testing.
- MCP tool visibility and connection/execution status remain unverified.
- Keyboard navigation, accessible labels, contrast, and narrow-screen layouts need a dedicated audit.
- Duplicate vulnerability records were reported in the Day 24 results; the frontend displayed two unique findings in that test.
- Earlier reports described a scan-list/404 issue. Its current status has not been independently re-established in this audit.
- No dedicated frontend test or lint command is configured.

These are pending checks or previously reported limitations, not all confirmed current defects.

## 9. Recommended Next Steps

1. Test an empty state safely when a suitable project or scan becomes available.
2. Test representative API failures and verify readable frontend error messages.
3. Audit accessibility and responsive layouts.
4. Investigate duplicate backend findings only with reproducible evidence and the backend owner's coordination.
5. Keep unrelated working-tree changes untouched.

## 10. Baseline Conclusion

The production build passed, the backend root endpoint responded on port 8002, and the user confirmed the main login, project, upload, scan, results, reports/export, and error-handling workflows were working.

Empty-state behavior and several broader quality checks remain unverified. The frontend has no configured test or lint script. This report records the current baseline without claiming that every integration or quality check has passed.
