"""SQLite persistence for scanner history. Uses only the database path supplied by the caller."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter


def initialize_database(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_path TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                files_scanned INTEGER NOT NULL,
                error_count INTEGER NOT NULL,
                total_findings INTEGER NOT NULL,
                severity_counts TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scan_runs(id)
                    ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                finding_json TEXT NOT NULL
            )
        """)


def save_scan(db_path, project_path, findings, outcome,
              started_at=None, finished_at=None):
    """Persist one completed scanner invocation and its exact findings."""
    initialize_database(db_path)
    started_at = started_at or datetime.now(timezone.utc).isoformat()
    finished_at = finished_at or datetime.now(timezone.utc).isoformat()
    counts = Counter(
        str(f.get("severity", "Unknown")) for f in findings
    )
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute("""
            INSERT INTO scan_runs (
                project_path, status, started_at, finished_at,
                files_scanned, error_count, total_findings,
                severity_counts, message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(project_path),
            getattr(outcome.status, "value", str(outcome.status)),
            started_at,
            finished_at,
            int(outcome.files_scanned),
            int(outcome.error_count),
            len(findings),
            json.dumps(dict(sorted(counts.items())), sort_keys=True),
            str(outcome.message),
        ))
        scan_id = cursor.lastrowid
        conn.executemany("""
            INSERT INTO scan_findings (scan_id, fingerprint, finding_json)
            VALUES (?, ?, ?)
        """, [
            (
                scan_id,
                str(f.get("fingerprint", "")),
                json.dumps(f, sort_keys=True),
            )
            for f in findings
        ])
    return scan_id


def get_scan(db_path, scan_id):
    """Return a scan record with decoded summary and findings, or None."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["severity_counts"] = json.loads(result["severity_counts"])
        result["findings"] = [
            json.loads(item["finding_json"])
            for item in conn.execute(
                "SELECT finding_json FROM scan_findings "
                "WHERE scan_id = ? ORDER BY id", (scan_id,)
            )
        ]
        return result


def list_scans(db_path, limit=100):
    """List recent scan summaries without loading finding payloads."""
    if limit < 1:
        raise ValueError("limit must be positive")
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    results = [dict(row) for row in rows]
    for item in results:
        item["severity_counts"] = json.loads(item["severity_counts"])
    return results
