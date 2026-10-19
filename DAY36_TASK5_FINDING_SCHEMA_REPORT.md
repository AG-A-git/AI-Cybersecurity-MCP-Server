# Day 36 — Task 5: Finding Schema Freeze Report

## Status

**Contract documented; downstream compatibility partially verified.**

This task documents the existing finding contract. It does not rename fields,
change severity values, restructure findings, or introduce a new risk-scoring
model.

## 1. Canonical Finding Contract

### Required fields

| Field | Type and constraints |
|---|---|
| `file_name` | Non-empty string |
| `line_number` | Integer >= 1; booleans are rejected |
| `vulnerability_type` | Non-empty string |
| `severity` | One of `Critical`, `High`, `Medium`, `Low` |
| `confidence` | Finite integer or float from 0 through 100; booleans are rejected |
| `code` | String |

The canonical field names are `file_name`, `line_number`, and
`vulnerability_type`. Do not substitute legacy aliases such as `file`, `line`,
or `vulnerability`.

### Standard creator fields

`scanner/finding.py:create_finding()` also supplies:

- `owasp`
- `cwe`
- `fingerprint`

These fields are produced by the standard creator but are not all members of
the validator's required-field set. Do not infer that every optional or
rule-specific field is required for every valid finding.

### Optional and additional fields

- `evidence`, when present, must be a dictionary.
- Rule-specific fields such as `source_context` may also appear.
- Consumers should tolerate additional fields unless a separately verified
  consumer contract states otherwise.

## 2. Fingerprint Contract

`create_finding_fingerprint()` produces a SHA-256 hexadecimal digest from the
stringified values of:

1. `file_name`
2. `line_number`
3. `vulnerability_type`
4. `code`

The components are joined with `|` before hashing. Confidence and evidence do
not contribute to the fingerprint. Existing fingerprint behavior is frozen
for this task.

## 3. Scanner and MCP Compatibility

`scanner/engine.py:scan_project()` returns a list of findings. For ordinary
source scans, it validates findings and skips invalid findings.

`mcp_server.py:scan_code(path)` directly returns `scan_project(path)` without
an explicit field transformation.

`tests/test_mcp_integration.py` covers vulnerability detection, safe-file
results, directory scans, invalid findings, invalid path types, missing paths,
and JSON round-trip equality for findings.

**Verification limitation:** the ZIP scan branch in `scanner/engine.py`
returns the ZIP scanner's findings directly. Its validation behavior must be
verified separately before claiming that every scanner path enforces the
same validation boundary.

## 4. Persistence Compatibility

`scanner/persistent_scanner.py` forwards the scanner's findings to
`save_scan()` and returns the findings.

`scanner/scan_persistence.py` serializes each finding as JSON and restores it
with JSON deserialization. `tests/test_scan_persistence.py` checks equality
after storage and retrieval, summary data, timestamps, concurrent records,
and failed-scan persistence.

Persistence round-trip success does not by itself prove that every stored
finding satisfies the canonical schema.

## 5. Risk Score Ownership

A tracked-source and documentation search for `risk_score` and `risk score`
did not identify an implementation of risk-score or risk-level calculation.

Therefore:

- Do not add `risk_score` to the canonical finding schema based on assumption.
- Its ownership and any downstream expectations remain unverified.
- The AI layer, backend consumer, and frontend consumer were not established
  from the tracked files inspected for this task.

## 6. Confirmed Inconsistency

`tests/test_scan_persistence.py` constructs a synthetic finding with
`confidence: 0.9`, while the canonical contract defines confidence on a
0–100 scale.

The persistence test passes these synthetic findings directly to persistence,
which does not validate them. This is a test-fixture inconsistency, not
evidence that the canonical confidence scale is 0–1.

This task records the discrepancy without changing the contract.

## 7. Frozen Invariants

1. Preserve all canonical field names.
2. Preserve severity values and capitalization.
3. Preserve the confidence scale of 0–100.
4. Preserve fingerprint inputs and behavior.
5. Preserve optional and rule-specific fields rather than stripping them.
6. Do not add or claim ownership of `risk_score` without verified evidence.
7. Do not claim AI, backend, or frontend compatibility until those consumers
   are identified and checked.
8. Keep scan status and persistence metadata separate from individual finding
   fields unless an existing verified contract specifies otherwise.

## 8. Files Inspected

- `scanner/finding.py`
- `scanner/engine.py`
- `scanner/persistent_scanner.py`
- `scanner/scan_persistence.py`
- `mcp_server.py`
- `docs/scanner_api.md`
- `tests/test_finding_schema.py`
- `tests/test_mcp_integration.py`
- `tests/test_scan_persistence.py`
- Tracked-source search results for `risk_score`, confidence, OWASP, and
  fingerprints

## 9. Remaining Verification

- Verify ZIP finding validation at the ZIP scanner boundary.
- Identify and inspect any external AI, backend, or frontend consumer.
- Establish risk-score ownership only if an actual implementation or contract
  is found.
- Reconcile the synthetic `confidence: 0.9` fixture separately, without
  changing the canonical schema.

No scanner implementation files were changed as part of this report.
