# Day 16 Integration Notes

## Backend Changes
- Verify the currently available FastAPI endpoints.
- Confirm request and response formats with Member 1.
- Identify missing or changed endpoints.

## Scanner Changes
- Confirm how uploaded files are scanned.
- Verify the scan-start endpoint and scan status response with Member 2.
- Confirm how scan findings are returned.

## AI Changes
- Confirm how AI analysis is triggered.
- Verify the AI response fields with Member 3.
- Ensure findings remain visible if AI analysis is unavailable.

## Risk Changes
- Confirm the risk score and risk level response.
- Verify severity counts if supported.
- Display risk data returned by the backend.

## Authentication Changes
- Verify login and registration.
- Confirm JWT token storage and protected API requests.
- Verify logout and unauthorized-response handling.

## Reports
- Confirm which report formats and endpoints are supported.
- Verify the scan ID and report response.
- Do not generate fake report downloads.

## MCP
- Confirm the frontend requirements for MCP integration.
- Keep MCP business logic in the backend.

## Frontend Changes Required
- Audit the complete login-to-results workflow.
- Standardize API error messages.
- Verify project and upload services.
- Verify scan status and results handling.
- Standardize finding data mapping.
- Check dashboard statistics, history, and reports.
- Test responsive layout and error states.

## Review Status
- Pending verification against the current backend.
