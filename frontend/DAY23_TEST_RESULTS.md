# Day 23 – Frontend Integration Test Results

## 1. Objective

Verify frontend-to-backend integration, confirm scan API behavior, run a production build, and document remaining issues for Day 24.

## 2. Environment

- Frontend: React + Vite
- Backend: FastAPI
- Backend URL: `http://127.0.0.1:8001`
- Frontend URL: `http://localhost:5173`
- Frontend role: Member 4 – Frontend and Dashboard Engineer

## 3. Tests Performed

| Test | Result | Observation |
|---|---|---|
| Frontend startup | PASS | Vite development server started successfully. |
| Dashboard access | PASS | Dashboard displayed in the browser. |
| Project listing | PASS | Projects were displayed in the frontend. |
| Project details | PASS | Test Security Project, ID 1, was displayed. |
| Project navigation | PASS | Open Project navigated to the Upload page. |
| File upload API | PASS | Backend returned successful upload response for `vulnerable.py`, project ID 1. |
| Scan creation API | PASS | Backend created scan ID 9 for project ID 1. |
| Scan retrieval API | PASS | GET `/scans/9` returned completed scan details. |
| Uploaded-file listing | BLOCKED | Backend does not currently expose a GET endpoint to list uploaded files. |
| Frontend uploaded-file display | BLOCKED | Upload page cannot retrieve existing files through a supported listing endpoint. |
| Frontend scan-results display | NOT VERIFIED | Existing scan API response was verified, but the frontend results display has not yet been confirmed. |
| Production build | PASS | `npm run build` completed successfully; 125 modules transformed. |

## 4. Confirmed Scan Response

- Scan ID: 9
- Project ID: 1
- Status: completed
- Reported vulnerability count: 28
- Reported risk score: 8
- Reported risk level: Medium
- Reported medium count: 2

## 5. Issues Requiring Follow-up

### Issue 1: Missing uploaded-file listing endpoint

The frontend's `getProjectFiles()` function currently returns an empty array because the backend does not expose a GET endpoint for listing files by project.

**Required follow-up:** Coordinate with the backend developer to implement a project-file listing endpoint. Then connect the frontend service to the confirmed route.

### Issue 2: Duplicate vulnerability findings

The scan response includes repeated findings for the same source lines in `vulnerable.py`. The response reports 28 findings, although the sample includes two distinct source-line findings.

**Required follow-up:** Backend developer should investigate repeated uploads, repeated scanning, finding persistence, and duplicate handling.

### Issue 3: Risk summary needs verification

The response reports an overall risk score of 8 and a medium count of 2, while the individual findings shown have risk scores of 50. The calculation and counting rules need verification.

**Required follow-up:** Confirm the backend risk-scoring formula and ensure the summary matches the intended calculation.

### Issue 4: Frontend scan-results display not yet verified

The API returns scan results, but the browser workflow still needs to be checked to confirm that the correct scan ID, project ID, status, and findings are displayed.

**Required follow-up:** Verify the results page using an existing scan without creating unnecessary additional scans.

## 6. Production Build

Command:

`npm run build`

Result: PASS

- Vite version: 5.4.21
- Modules transformed: 125
- Build completed successfully.

## 7. Day 24 Plan

1. Coordinate with the backend developer about the missing file-list endpoint.
2. Verify the frontend displays scan results from the real API.
3. Test loading, empty, success, and error states.
4. Check project-to-scan association and duplicate-click behavior.
5. Re-test the risk summary after backend clarification.
6. Run `npm run build` again after any frontend changes.

## 8. Conclusion

The dashboard, project navigation, upload API, scan creation API, scan retrieval API, and production build have been verified. Uploaded-file listing and frontend scan-results display remain incomplete or unverified. Duplicate findings and risk-summary consistency require further investigation. These items are recorded for follow-up rather than marked as completed.
