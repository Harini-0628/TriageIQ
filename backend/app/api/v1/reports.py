"""
Reports routes.

Design decision: CSV export is synchronous and streamed directly (no
Report DB record) — it's cheap to regenerate and nobody needs to
"re-download yesterday's CSV," they just re-export. PDF generation DOES
create a Report record and persists the file to disk, because an
executive report is the kind of artifact a GRC/compliance workflow
actually wants to reference later ("show me the report we sent the board
in March") — CSV and PDF have different real-world lifecycles, and the
code reflects that rather than treating both identically for consistency's
own sake.
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
import io

from app.db.session import get_db
from app.models.user import User, UserRole
from app.models.report_audit_notification import Report, ReportType, ReportFormat
from app.api.v1.deps import get_current_user, require_roles
from app.schemas.report import ReportOut
from app.services.dashboard_service import get_dashboard_summary
from app.services.risk_engine_service import get_ranked_queue
from app.services.report_csv import generate_vulnerabilities_csv
from app.services.report_pdf import generate_executive_pdf

router = APIRouter(prefix="/reports", tags=["reports"])

REPORTS_DIR = Path(__file__).resolve().parents[3] / "storage" / "reports"


@router.get("/export/vulnerabilities.csv")
def export_vulnerabilities_csv(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = get_ranked_queue(db, current_user.org_id, limit=1000)
    csv_rows = [
        {
            "title": r["title"], "cve_id": r["cve_id"] or "", "asset_hostname": r["asset_hostname"],
            "scanner_severity": "", "status": r["status"],
            "composite_risk_score": r["composite_score"], "port": "",
            "first_detected_at": "", "last_detected_at": r["calculated_at"],
        }
        for r in rows
    ]
    csv_content = generate_vulnerabilities_csv(csv_rows)
    return StreamingResponse(
        io.StringIO(csv_content),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_export.csv"},
    )


@router.post("/generate", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def generate_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Currently supports the executive PDF report. Technical/compliance
    report types (Module 2's schema already anticipates them) are a
    straightforward extension of this same pattern — different content in
    generate_executive_pdf-equivalent functions, same storage/DB flow."""
    now = datetime.now(timezone.utc)
    summary = get_dashboard_summary(db, current_user.org_id)
    top_vulns = get_ranked_queue(db, current_user.org_id, limit=10)

    org_name = current_user.organization.name
    pdf_bytes = generate_executive_pdf(org_name, summary, top_vulns, now)

    org_dir = REPORTS_DIR / current_user.org_id
    org_dir.mkdir(parents=True, exist_ok=True)

    report = Report(
        org_id=current_user.org_id,
        generated_by_id=current_user.id,
        report_type=ReportType.EXECUTIVE,
        format=ReportFormat.PDF,
        file_path="",  # set below once we have the report id for the filename
        generated_at=now,
    )
    db.add(report)
    db.flush()  # assigns report.id without committing yet

    file_path = org_dir / f"{report.id}.pdf"
    file_path.write_bytes(pdf_bytes)
    report.file_path = str(file_path)
    db.commit()

    return report


@router.get("", response_model=List[ReportOut])
def list_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (
        db.query(Report)
        .filter(Report.org_id == current_user.org_id)
        .order_by(Report.generated_at.desc())
        .limit(50)
        .all()
    )


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    report = db.query(Report).filter(Report.id == report_id, Report.org_id == current_user.org_id).first()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Report file is no longer available on disk")

    media_type = "application/pdf" if report.format == ReportFormat.PDF else "text/csv"
    return FileResponse(path, media_type=media_type, filename=f"triageiq_{report.report_type.value}_report.pdf")
