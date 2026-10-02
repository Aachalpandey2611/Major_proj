"""Findings router stub — full implementation in Component 3."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import Finding, Target, User, Scan
from routers.auth import get_current_user
from fix_engine.compliance_mapper import get_compliance_mapping

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/{finding_id}")
def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    f = (
        db.query(Finding)
        .join(Target)
        .filter(Finding.id == finding_id, Target.user_id == current_user.id)
        .first()
    )
    if not f:
        raise HTTPException(404, "Finding not found or access denied")
    return {
        "id": str(f.id),
        "scan_id": str(f.scan_id),
        "target_id": str(f.target_id),
        "attack_type": f.attack_type.value,
        "severity": f.severity.value,
        "status": f.status.value,
        "attack_payload": f.attack_payload,
        "attack_response": f.attack_response,
        "layer_failed": f.layer_failed,
        "risk_score": f.risk_score,
        "fix_recommendation": f.fix_recommendation,
        "fix_code_snippet": f.fix_code_snippet,
        "owasp_category": f.owasp_category,
        "detection_method": f.detection_method,
        "confidence": f.confidence,
        "retest_history": f.retest_history or [],
        "created_at": f.created_at.isoformat(),
        "compliance": get_compliance_mapping(f.owasp_category) if f.owasp_category else None,
    }


@router.get("/")
def list_findings(
    target_id: str,
    status: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(404, "Target not found or access denied")
    
    q = db.query(Finding).filter(Finding.target_id == target_id)
    if status:
        q = q.filter(Finding.status == status)
    findings = q.order_by(Finding.risk_score.desc()).all()
    return [
        {
            "id": str(f.id),
            "scan_id": str(f.scan_id) if f.scan_id else None,
            "target_id": str(f.target_id),
            "attack_type": f.attack_type.value,
            "severity": f.severity.value,
            "status": f.status.value,
            "layer_failed": f.layer_failed,
            "risk_score": f.risk_score,
            "confidence": f.confidence,
            "owasp_category": f.owasp_category,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]
