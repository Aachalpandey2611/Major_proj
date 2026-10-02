"""
routers/reports.py — Aggregate batch red-team report (all prompts per category,
not just one), for an authorized target.

Also includes audit trail reports showing summary-level testing logs per attack type.
Includes PDF compliance report generation.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from attack_engine.batch_runner import run_batch_report
from database import get_db
from models import AttackLog, Scan, Finding, Target
from report_generator import PDFReportBuilder

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/batch")
def batch_report(target_url: str, sample_size: int = 10, auth_token: str = None):
    """
    Run up to `sample_size` prompts per attack category against target_url
    (must be a target you own/control — e.g. test_chatbot or generic_llm_target)
    and return an aggregate detection-rate report.

    NOT gated behind Target/ownership_verified — this is meant for quick,
    ad-hoc evaluation against your own local dev/demo targets, not for
    unauthenticated scanning of arbitrary third-party URLs. Do not point this
    at a service you do not control.
    """
    sample_size = max(1, min(sample_size, 50))
    try:
        return run_batch_report(target_url=target_url, auth_token=auth_token, sample_size=sample_size)
    except Exception as exc:
        raise HTTPException(500, f"Batch report failed: {exc}")


# ---------------------------------------------------------------------------
# Audit Trail Report (Priority 1.4)
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/audit")
def get_audit_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Fetch audit trail for a scan: summary-level logs showing how many prompts
    were tested per attack type, the worst-case result, and pass/fail verdict.
    
    Returns 15 entries (one per attack type) showing:
    - attack_type: e.g. "prompt_injection"
    - layer_name: e.g. "Layer 1 — Prompt Injection"
    - prompts_tested: number of prompts tested (up to MAX_PROMPTS_PER_TYPE)
    - worst_confidence: highest detection confidence seen
    - verdict: "PASSED" (bypassed) or "FAILED" (blocked)
    - timestamp: when the attack was tested
    """
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    # Fetch all audit logs for this scan, ordered by created_at
    logs = (
        db.query(AttackLog)
        .filter(AttackLog.scan_id == scan_id)
        .order_by(AttackLog.created_at.asc())
        .all()
    )
    
    if not logs:
        return {
            "scan_id": scan_id,
            "scan_status": scan.status.value,
            "total_entries": 0,
            "message": "No audit logs found. This scan may have been run before audit logging was enabled.",
            "logs": []
        }
    
    return {
        "scan_id": scan_id,
        "scan_status": scan.status.value,
        "target_id": str(scan.target_id),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "total_entries": len(logs),
        "logs": [
            {
                "attack_type": log.attack_type,
                "layer_name": log.layer_name,
                "prompts_tested": log.prompts_tested,
                "worst_confidence": round(log.confidence, 3),
                "verdict": log.verdict,
                "detection_method": log.detection_method,
                "timestamp": log.created_at.isoformat(),
            }
            for log in logs
        ]
    }


# ---------------------------------------------------------------------------
# PDF Compliance Report (Priority 2.1)
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/pdf")
def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Generate and download a comprehensive PDF security audit report.
    
    Report includes:
    - Cover page with target info, scan date, overall verdict
    - Executive summary (findings by severity)
    - Full audit trail (all 15 attack layers with test details)
    - Compliance mapping table (OWASP, EU AI Act, NIST AI RMF)
    - Code fixes for each vulnerability (if findings exist)
    
    Returns PDF file as downloadable attachment.
    """
    # Fetch scan
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    # Fetch target
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    
    # Fetch findings (vulnerabilities)
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    # Fetch audit logs (all 15 attack layers)
    audit_logs = (
        db.query(AttackLog)
        .filter(AttackLog.scan_id == scan_id)
        .order_by(AttackLog.created_at.asc())
        .all()
    )
    
    if not audit_logs:
        raise HTTPException(
            400, 
            "No audit logs found for this scan. Report generation requires audit trail data."
        )
    
    # Generate PDF
    try:
        pdf_builder = PDFReportBuilder(
            scan=scan,
            target=target,
            findings=findings,
            audit_logs=audit_logs
        )
        pdf_buffer = pdf_builder.generate()
        
        # Generate filename
        target_name_safe = target.name.replace(" ", "_").replace("/", "-")
        scan_date = scan.created_at.strftime("%Y%m%d") if scan.created_at else "unknown"
        filename = f"SentinelLoop_SecurityAudit_{target_name_safe}_{scan_date}.pdf"
        
        # Return as downloadable file
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as exc:
        raise HTTPException(500, f"PDF generation failed: {exc}")
