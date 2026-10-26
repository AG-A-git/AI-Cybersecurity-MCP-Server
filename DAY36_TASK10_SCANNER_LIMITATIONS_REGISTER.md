# Day 36 — Task 10: Scanner Limitations Register

- **Project:** AI-Cybersecurity-MCP-Server
- **Role:** Member 2 — Scanner Development/Verification
- **Branch:** `member2-scanner`
- **Review date:** 2026-10-25
- **Scope:** Detection limitations, false-positive and false-negative risks, finding quality, integration issues, and release readiness.

## 1. Executive Summary

**Overall status: REVIEW COMPLETE — RELEASE BLOCKED.**

The supplied verification reports document passing regression runs and selected positive and negative cases across 12 vulnerability categories. These results apply only to the tests and working repository states described in those reports. They do not establish complete vulnerability coverage or production readiness.

The Task 14 review identifies a report-generation compatibility defect in tracked `mcp_server.py`, an unexercised symlink-escape test on Windows, and untracked repository artifacts requiring review. These remain release blockers until resolved and verified.

No confirmed real-world false-positive or false-negative rate has been established by the available evidence.

## 2. Evidence Reviewed

| Evidence | Observed result | Interpretation |
|---|---|---|
| `DAY36_TASK2_MEMBER2_POSITIVE_DETECTION_VERIFICATION.md` | 91 passed in 4.03 seconds | Selected positive and safe-code regressions passed; category coverage remains partial. |
| `DAY36_TASK2_VULNERABILITY_DETECTION_AUDIT.md` | Historical run: 90 focused tests passed; 271 passed, 1 skipped in full suite | Historical results from a different run; do not combine with other test totals. |
| `DAY36_TASK3_MEMBER2_NEGATIVE_TEST_VERIFICATION.md` | 79 negative-subset tests passed; full suite 300 passed, 1 skipped | The tested parameterized SQL case produced no findings; unsafe concatenation produced a finding at the expected line. |
| `DAY36_TASK8_FINDING_QUALITY_REPORT.md` | 279 passed, 1 skipped; 34 focused tests passed | Selected schema, location, confidence, and deduplication behavior passed; several quality properties remain unverified. |
| `DAY36_TASK13_FINAL_REGRESSION_REPORT.md` | 263 passed, 1 skipped, 0 failed; 264 collected | Reported full regression run passed, with one warning. |
| `DAY36_TASK14_FULL_TEST_AND_DIFF_REVIEW.md` | 263 passed, 1 skipped, 0 failed; release recommendation BLOCKED | Documents integration, environment, and repository-hygiene blockers. |

**Important:** These are separate runs against potentially different repository states. Their counts must not be added or presented as one unified run. Rerun the current intended test suite after any changes before making a final release decision.

## 3. Detection Coverage and Limitations

All 12 agreed categories have selected positive regression evidence in the supplied Task 2 report. All remain partially implemented because pattern matching, supported APIs, and limited data-flow tracking constrain coverage.

| Vulnerability category | Known limitation or remaining verification need |
|---|---|
| SQL Injection | Parameterized-query recognition and taint tracking are limited. A dynamic query with an unconfirmed input source was reported as Critical with 85% confidence; the appropriateness of this classification requires review. |
| Cross-Site Scripting (XSS) | Tests cover selected input patterns and HTML sinks, not comprehensive JavaScript and template flows. |
| Command Injection | Pattern recognition and taint propagation do not cover all command-execution paths. |
| LDAP Injection | Detection covers selected LDAP search calls and input construction patterns. |
| Hardcoded Credentials / Secrets | Recognized names and assignment patterns may miss secrets stored or exposed in other forms. |
| Weak Cryptography | Selected MD5, SHA-1, DES, and RC4/ARC4 patterns are covered; other unsafe cryptographic uses may be missed. |
| Broken Access Control | Heuristic authorization patterns cannot prove that authorization is correct on every route and execution path. |
| Security Misconfiguration | Selected debug and configuration patterns are covered; other misconfigurations may be missed. |
| Insecure Authentication | Selected weak password literals and comparison patterns are tested, not every authentication weakness. |
| Insecure Deserialization | Tests focus on recognized pickle APIs; other deserialization mechanisms and flows may be missed. |
| Sensitive Data Exposure | Selected print/logging cases are tested. API-key assignment detection is not established because a test named `test_api_key_returned_is_detected` asserts that the findings list is empty. |
| Server-Side Request Forgery (SSRF) | Selected request sources, assignment chains, and network sinks are covered. Comprehensive interprocedural and whole-program data-flow analysis is not established. |

## 4. False-Positive Register

### FP-01 — Dynamic SQL severity and confidence require review

- **Status:** Potential false-positive / severity-calibration risk; not confirmed as a false positive.
- **Evidence:** Task 8 reports a dynamic SQL query with an unconfirmed user-input source receiving Critical severity and 85% confidence.
- **Impact:** A finding may be presented with greater urgency than its available source evidence warrants.
- **Next action:** Review the fixture and source-to-sink evidence; define expected behavior for unconfirmed sources; add a regression assertion for severity and confidence.
- **Owner:** Scanner team.

### FP-02 — Cross-rule severity consistency

- **Status:** Unverified.
- **Evidence:** Task 8 notes that the SQL detector assigns Critical severity while the input-validation SQL rule assigns High.
- **Impact:** Similar or duplicate findings could receive inconsistent severity.
- **Next action:** Test overlapping rules on the same fixture and verify the final deduplicated severity.

**Confirmed false positives:** None established by the supplied reports. The safe-code tests passed for the specific fixtures they exercised, but that is not proof that false positives are absent.

## 5. False-Negative Register

### FN-01 — API-key exposure test does not verify detection

- **Status:** Confirmed test-assertion inconsistency; actual detector behavior remains unverified.
- **Evidence:** `tests/test_sensitive.py::test_api_key_returned_is_detected` reportedly asserts `len(findings) == 0`.
- **Impact:** A passing test cannot support a claim that API-key exposure through assignment is detected.
- **Next action:** Inspect the fixture and intended behavior, correct the assertion, and rerun the focused test. Record the observed scanner output.

### FN-02 — Unsupported or untested data-flow variants

- **Status:** Coverage limitation; specific missed vulnerabilities have not been demonstrated by the supplied reports.
- **Evidence:** The category audit describes pattern-based detection and limited data-flow tracking across several detectors.
- **Impact:** Variants outside the implemented source, sink, API, or propagation patterns may be missed.
- **Next action:** Expand positive fixtures and record any reproducible missed detections with input, expected finding, actual output, and source location.

**Confirmed false negatives:** No specific production vulnerability missed by the scanner has been demonstrated in the supplied evidence. FN-01 is a verification gap, not proof that the detector itself misses the case.

## 6. Finding Quality and Deduplication

### Verified within the reported test scope

- Required finding fields and supported severity values are validated.
- Confidence is checked for finiteness and the 0–100 range.
- Tested source-location assertions verify the SQL finding path, line, and source line.
- Unit tests cover duplicate removal and selection by confidence, with severity used as a tie-breaker.
- The deduplication key reported in Task 8 is vulnerability type, file name, line number, and code.

### Not fully verified

- Location accuracy across every active detector.
- Structured evidence completeness across all findings.
- Consistent severity across overlapping detectors.
- Availability and completeness of descriptions and remediation guidance.
- Full separation of static scanner results from AI-generated enrichment.

### FQ-01 — Finding-field compatibility in MCP report generation

- **Status:** Release blocker reported by Task 14.
- **Evidence:** The tracked `mcp_server.py` report-generation path uses legacy finding keys rather than canonical schema keys. The reproduced output lacked finding type, file, and line information.
- **Impact:** The generated report may omit important finding details.
- **Next action:** Coordinate with the owner of `mcp_server.py`, align the report-generation path with the canonical finding schema, and add a regression test against the tracked implementation.
- **Release condition:** The regression must pass against the actual tracked implementation, not only an untracked working copy.

## 7. Malformed Input, Archive Handling, and Environment Limitations

Task 14 records that the inspected archive/path-handling code includes checks for archive traversal, absolute paths, symbolic-link entries, archive size and entry-count limits, extraction destinations, and configured allowed roots. This was a targeted code review, not exhaustive security certification.

- **ENV-01 — Symlink-escape test skipped:** The test `test_scan_denies_symlink_escape` could not run because symlink capability was unavailable on the Windows environment (`WinError 1314`). The security property therefore remains unverified by that test run.
- **INT-01 — Task 11 working-copy mismatch:** Some Task 11 tests use untracked `mcp_server_task11_working.py`. Their results do not independently establish equivalent behavior in tracked `mcp_server.py`.
- **PATCH-01 — Candidate patch unapplied:** `task14_review.patch` was reported as invalid by `git apply --stat`. Its candidate tests were not included in the verified regression result.
- **API-01 — External/production behavior:** Live external API behavior and production deployment have not been established by these local test reports.

## 8. Repository Hygiene

Task 14 reports numerous untracked files, including test fixtures, verification scripts, local databases, reports, backups, and working copies.

- **Status:** Review required.
- **Risk:** Accidental inclusion of temporary, sensitive, generated, or inconsistent artifacts in a commit or release.
- **Next action:** Classify each untracked file as an intended deliverable, required fixture, local-only artifact, backup, or discard candidate. Preserve evidence and backups until the team approves any cleanup.
- **Restriction:** Do not stage everything with `git add .`; do not delete or commit backups and databases without reviewing them.

## 9. Readiness Checklist

- [x] Selected positive regression tests documented for all 12 categories.
- [x] Selected negative and safe-code test evidence documented.
- [x] Finding schema and deduplication behavior tested in reported runs.
- [x] Known coverage and test-quality limitations recorded.
- [x] Release blockers recorded from the Task 14 review.
- [ ] Correct the tracked MCP report-generation compatibility issue.
- [ ] Verify the correction with a regression test against tracked `mcp_server.py`.
- [ ] Fix and rerun the API-key exposure test with an assertion matching the intended behavior.
- [ ] Exercise symlink-escape protection in a suitable environment.
- [ ] Review and classify all untracked repository artifacts.
- [ ] Run the full intended regression suite on the final candidate and record exact results.
- [ ] Reassess release readiness after blockers are resolved.

## 10. Final Recommendation

**RELEASE BLOCKED — DO NOT CLAIM PRODUCTION READINESS.**

The available reports demonstrate passing tests for selected detector and finding-quality behaviors. They do not establish comprehensive detection across all 12 vulnerability categories or a measured real-world false-positive/false-negative rate.

The tracked MCP report-generation mismatch, skipped symlink-escape test, API-key test inconsistency, and unreviewed untracked artifacts require follow-up. Reassess readiness only after the applicable fixes and verification steps are complete.

No implementation code was changed while preparing this register.
