"""
CSV export — the format a security team actually pastes into a
spreadsheet for a stakeholder meeting or feeds into another tool. Kept
completely separate from the PDF generator (report_pdf.py) since a CSV's
job is machine/spreadsheet consumption, not presentation.
"""
import csv
import io
from typing import List


def generate_vulnerabilities_csv(rows: List[dict]) -> str:
    """
    rows: list of dicts with keys matching the header below — produced by
    the caller from a VulnerabilityRepository query, kept as plain dicts
    here so this function has zero ORM/session dependency and is trivially
    testable with hand-built fixtures.
    """
    output = io.StringIO()
    fieldnames = [
        "title", "cve_id", "asset_hostname", "scanner_severity", "status",
        "composite_risk_score", "port", "first_detected_at", "last_detected_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return output.getvalue()
