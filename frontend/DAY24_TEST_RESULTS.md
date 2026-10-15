# Day 24 — Frontend Scan Results Integration Test Report

## Objective
Verify the frontend scan-results workflow against the backend API.

## Tests Completed

| Test | Result | Details |
|---|---|---|
| Production build | PASS | `npm run build` completed successfully with Vite 5.4.21; 125 modules transformed. |
| Start Scan navigation | PASS | Starting a scan opened the results page and displayed findings. |
| Refresh results | PASS | Findings remained visible after refreshing the results page. |
| Scan and project association | PASS | Scan ID 13 was associated with Project ID 1 and had status `completed`. |
| Duplicate finding display | PASS | The API returned 36 raw records representing two unique logical findings. The frontend displayed two findings, at lines 4 and 7 of `vulnerable.py`. |
| Severity summary | PASS | The page displayed two Medium findings and zero Critical, High, and Low findings. |
| Risk summary | PASS | The page displayed risk score 8/100 and risk level Medium. |

## Build Details
- Command: `npm run build`
- Vite version: 5.4.21
- Modules transformed: 125
- Build time: 4.61 seconds
- JavaScript bundle: 295.57 kB (93.66 kB gzipped)

## Known Issues and Limitations
- The backend response contains duplicate vulnerability records. The frontend currently displays the two unique findings correctly.
- The backend does not currently provide a project uploaded-file listing endpoint, so uploaded-file listing cannot be fully verified through that API.
- Project switching and all error/empty-state scenarios have not been fully verified.

## Conclusion
The tested scan-results workflow and production build passed. Additional testing is still needed for project switching and error/empty states.
