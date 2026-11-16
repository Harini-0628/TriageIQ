"""
Scan file parsers.

Design decision: Nessus and OpenVAS export wildly different column names
for conceptually identical data (Nessus: "Risk", OpenVAS: "Severity"). We
normalize both into the same ParsedFinding shape here, at the edge, so
every downstream piece of code (dedup logic, DB writes, the eventual risk
engine) only ever deals with one consistent representation — it never
needs to know or care which scanner a finding originally came from.

Deliberately tolerant parsing: real-world scanner CSV exports are messy
(inconsistent quoting, optional columns, multiple CVEs jammed into one
cell). A parser that throws on the first malformed row is useless against
a 50,000-row Nessus export — we skip and record unparseable rows instead
of aborting the whole import.
"""
import csv
import io
from dataclasses import dataclass, field
from typing import List, Optional

from app.models.vulnerability import ScannerSeverity


@dataclass
class ParsedFinding:
    hostname: str
    ip_address: Optional[str]
    title: str
    description: Optional[str]
    scanner_severity: ScannerSeverity
    cve_ids: List[str] = field(default_factory=list)  # a finding may reference 0, 1, or several CVEs
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    plugin_id: Optional[str] = None
    raw_row: dict = field(default_factory=dict)


class ParseResult:
    def __init__(self):
        self.findings: List[ParsedFinding] = []
        self.total_rows = 0
        self.skipped_rows = 0
        self.errors: List[str] = []


_NESSUS_RISK_MAP = {
    "critical": ScannerSeverity.CRITICAL,
    "high": ScannerSeverity.HIGH,
    "medium": ScannerSeverity.MEDIUM,
    "low": ScannerSeverity.LOW,
    "none": ScannerSeverity.INFO,
    "": ScannerSeverity.INFO,
}

# OpenVAS reports severity as a free-text label OR a raw CVSS-like float
# depending on export settings — we handle both.
_OPENVAS_SEVERITY_LABEL_MAP = {
    "critical": ScannerSeverity.CRITICAL,
    "high": ScannerSeverity.HIGH,
    "medium": ScannerSeverity.MEDIUM,
    "low": ScannerSeverity.LOW,
    "log": ScannerSeverity.INFO,
}


def _split_cves(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    # Handles "CVE-2024-1234, CVE-2024-5678" and "CVE-2024-1234;CVE-2024-5678"
    parts = raw.replace(";", ",").split(",")
    return [p.strip().upper() for p in parts if p.strip().upper().startswith("CVE-")]


def _safe_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def parse_nessus_csv(file_bytes: bytes) -> ParseResult:
    """
    Expects the standard Nessus CSV export column set:
    Plugin ID, CVE, CVSS v3.0 Base Score, Risk, Host, Protocol, Port,
    Name, Synopsis, Description, Solution
    """
    result = ParseResult()
    text = file_bytes.decode("utf-8-sig", errors="replace")  # utf-8-sig strips a BOM if Excel added one
    reader = csv.DictReader(io.StringIO(text))

    for row in reader:
        result.total_rows += 1
        try:
            host = (row.get("Host") or "").strip()
            if not host:
                result.skipped_rows += 1
                result.errors.append(f"Row {result.total_rows}: missing Host, skipped")
                continue

            risk = (row.get("Risk") or "").strip().lower()
            severity = _NESSUS_RISK_MAP.get(risk, ScannerSeverity.INFO)

            finding = ParsedFinding(
                hostname=host,
                ip_address=host if _looks_like_ip(host) else None,
                title=(row.get("Name") or "Untitled finding").strip(),
                description=(row.get("Synopsis") or row.get("Description") or "").strip() or None,
                scanner_severity=severity,
                cve_ids=_split_cves(row.get("CVE")),
                port=_safe_int(row.get("Port")),
                protocol=(row.get("Protocol") or "").strip() or None,
                plugin_id=(row.get("Plugin ID") or "").strip() or None,
                raw_row=row,
            )
            result.findings.append(finding)
        except Exception as e:  # noqa: BLE001 — deliberately broad: one bad row must not kill the import
            result.skipped_rows += 1
            result.errors.append(f"Row {result.total_rows}: {e}")

    return result


def parse_openvas_csv(file_bytes: bytes) -> ParseResult:
    """
    Expects a standard OpenVAS/GVM CSV export column set:
    NVT Name, Hostname, IP, Port, Port Protocol, Severity, CVEs, Summary
    """
    result = ParseResult()
    text = file_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    for row in reader:
        result.total_rows += 1
        try:
            host = (row.get("Hostname") or row.get("IP") or "").strip()
            if not host:
                result.skipped_rows += 1
                result.errors.append(f"Row {result.total_rows}: missing Hostname/IP, skipped")
                continue

            severity_raw = (row.get("Severity") or "").strip().lower()
            severity = _OPENVAS_SEVERITY_LABEL_MAP.get(severity_raw)
            if severity is None:
                # Not a label — try treating it as a numeric CVSS-style score
                try:
                    score = float(severity_raw)
                    severity = _cvss_score_to_severity(score)
                except ValueError:
                    severity = ScannerSeverity.INFO

            port_raw = (row.get("Port") or "").strip()
            port = _safe_int(port_raw.split("/")[0]) if port_raw else None

            finding = ParsedFinding(
                hostname=host,
                ip_address=(row.get("IP") or "").strip() or None,
                title=(row.get("NVT Name") or "Untitled finding").strip(),
                description=(row.get("Summary") or "").strip() or None,
                scanner_severity=severity,
                cve_ids=_split_cves(row.get("CVEs")),
                port=port,
                protocol=(row.get("Port Protocol") or "").strip() or None,
                plugin_id=(row.get("NVT OID") or "").strip() or None,
                raw_row=row,
            )
            result.findings.append(finding)
        except Exception as e:  # noqa: BLE001
            result.skipped_rows += 1
            result.errors.append(f"Row {result.total_rows}: {e}")

    return result


def _cvss_score_to_severity(score: float) -> ScannerSeverity:
    if score >= 9.0:
        return ScannerSeverity.CRITICAL
    if score >= 7.0:
        return ScannerSeverity.HIGH
    if score >= 4.0:
        return ScannerSeverity.MEDIUM
    if score > 0.0:
        return ScannerSeverity.LOW
    return ScannerSeverity.INFO


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
