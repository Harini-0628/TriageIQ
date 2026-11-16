"""
Scan import orchestration.

Design decision: the actual parse-and-write work runs as a FastAPI
BackgroundTask, not inline in the upload request. A real Nessus export can
have tens of thousands of rows; blocking the HTTP response on that would
time out the client and tie up a worker. This is a deliberately simple
stand-in for what a production system would do with a real task queue
(Celery/RQ + Redis) — worth naming explicitly as a known scaling
limitation in an interview, not something to pretend isn't there.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

import app.db.session as db_session_module
from app.models.scan_import import ScanImport, ScannerType, ImportStatus
from app.repositories.asset_repository import AssetRepository
from app.repositories.cve_repository import CVERepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.csv_parsers import parse_nessus_csv, parse_openvas_csv, ParsedFinding

logger = logging.getLogger("triageiq.scan_import")


def create_scan_import_record(db: Session, org_id: str, uploaded_by_id: str, filename: str, scanner_type: ScannerType) -> ScanImport:
    scan_import = ScanImport(
        org_id=org_id,
        uploaded_by_id=uploaded_by_id,
        filename=filename,
        scanner_type=scanner_type,
        status=ImportStatus.UPLOADED,
        uploaded_at=datetime.now(timezone.utc),
    )
    db.add(scan_import)
    db.commit()
    db.refresh(scan_import)
    return scan_import


def process_scan_import(scan_import_id: str, file_bytes: bytes, session_factory=None) -> None:
    """
    Runs in a background task, so it opens its OWN database session rather
    than reusing the request's session — the request's session is closed
    (via get_db's `finally`) the moment the HTTP response is sent, long
    before this function finishes running.

    session_factory is resolved from app.db.session.SessionLocal AT CALL
    TIME (via module attribute lookup), not bound as a default argument —
    a default argument evaluates once at import time and would silently
    ignore any later monkeypatching. This matters specifically because the
    test suite patches app.db.session.SessionLocal to point at an isolated
    in-memory test database (see tests/conftest.py); an eagerly-bound
    default would have captured the real DB's session factory at import
    time and made background-task-driven tests fail in a confusing way —
    which is exactly what happened until this was caught and fixed.
    """
    db = (session_factory or db_session_module.SessionLocal)()
    try:
        scan_import = db.query(ScanImport).filter(ScanImport.id == scan_import_id).first()
        if scan_import is None:
            logger.error(f"ScanImport {scan_import_id} vanished before processing started")
            return

        scan_import.status = ImportStatus.PROCESSING
        db.commit()

        if scan_import.scanner_type == ScannerType.NESSUS:
            result = parse_nessus_csv(file_bytes)
        else:
            result = parse_openvas_csv(file_bytes)

        asset_repo = AssetRepository(db)
        cve_repo = CVERepository(db)
        vuln_repo = VulnerabilityRepository(db)

        now = datetime.now(timezone.utc)
        assets_created = 0
        findings_created = 0

        for finding in result.findings:
            asset, was_created = asset_repo.get_or_create(scan_import.org_id, finding.hostname, finding.ip_address)
            if was_created:
                assets_created += 1

            # A finding with multiple CVEs becomes one Vulnerability row per
            # CVE (our schema's cve_id FK is singular) — matches how a
            # security team actually needs to track and remediate each CVE.
            cve_ids = finding.cve_ids or [None]
            for cve_id in cve_ids:
                if cve_id:
                    cve_repo.get_or_create_stub(cve_id)

                _, was_new = vuln_repo.upsert_from_scan(
                    org_id=scan_import.org_id,
                    asset_id=asset.id,
                    scan_import_id=scan_import.id,
                    title=finding.title,
                    description=finding.description,
                    scanner_severity=finding.scanner_severity,
                    cve_id=cve_id,
                    plugin_id=finding.plugin_id,
                    port=finding.port,
                    protocol=finding.protocol,
                    now=now,
                    raw_row=finding.raw_row,
                )
                if was_new:
                    findings_created += 1

        scan_import.status = ImportStatus.COMPLETED
        scan_import.total_rows = result.total_rows
        scan_import.findings_created = findings_created
        scan_import.assets_created = assets_created
        scan_import.completed_at = datetime.now(timezone.utc)
        if result.errors:
            scan_import.error_message = f"{len(result.errors)} row(s) skipped: " + "; ".join(result.errors[:5])
        db.commit()

        logger.info(
            f"Scan import {scan_import_id} completed",
            extra={"context": {
                "total_rows": result.total_rows,
                "findings_created": findings_created,
                "assets_created": assets_created,
                "skipped_rows": result.skipped_rows,
            }},
        )

    except Exception as e:  # noqa: BLE001 — a background task's exception is otherwise silently swallowed by FastAPI
        logger.exception(f"Scan import {scan_import_id} failed")
        db.rollback()
        scan_import = db.query(ScanImport).filter(ScanImport.id == scan_import_id).first()
        if scan_import:
            scan_import.status = ImportStatus.FAILED
            scan_import.error_message = str(e)
            db.commit()
    finally:
        db.close()
