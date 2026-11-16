"""Pure unit tests for the Nessus/OpenVAS CSV parsers — no DB needed."""
from app.services.csv_parsers import parse_nessus_csv, parse_openvas_csv
from app.models.vulnerability import ScannerSeverity


def test_parse_nessus_csv_maps_risk_to_severity_correctly():
    with open("samples/nessus_sample.csv", "rb") as f:
        result = parse_nessus_csv(f.read())

    assert result.total_rows == 6
    assert len(result.findings) == 6
    critical_findings = [f for f in result.findings if f.scanner_severity == ScannerSeverity.CRITICAL]
    assert len(critical_findings) == 2  # PAN-OS and BlueKeep


def test_parse_nessus_csv_extracts_cve_correctly():
    with open("samples/nessus_sample.csv", "rb") as f:
        result = parse_nessus_csv(f.read())
    pan_os = next(f for f in result.findings if "PAN-OS" in f.title)
    assert pan_os.cve_ids == ["CVE-2024-3400"]


def test_parse_openvas_csv_splits_multiple_cves():
    with open("samples/openvas_sample.csv", "rb") as f:
        result = parse_openvas_csv(f.read())
    log4shell = next(f for f in result.findings if "Log4Shell" in f.title)
    assert log4shell.cve_ids == ["CVE-2021-44228", "CVE-2021-45046"]


def test_parse_openvas_csv_handles_log_severity_as_info():
    with open("samples/openvas_sample.csv", "rb") as f:
        result = parse_openvas_csv(f.read())
    timestamps_finding = next(f for f in result.findings if "Timestamps" in f.title)
    assert timestamps_finding.scanner_severity == ScannerSeverity.INFO


def test_parse_nessus_csv_skips_rows_with_no_host():
    malformed_csv = b"Plugin ID,CVE,Risk,Host,Port,Name\n1,,High,,80,No host here\n2,,High,realhost,80,Valid row\n"
    result = parse_nessus_csv(malformed_csv)
    assert result.total_rows == 2
    assert len(result.findings) == 1
    assert result.skipped_rows == 1
