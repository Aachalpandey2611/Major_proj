"""
report_generator.py — Consolidates scan results and findings into structured JSON report objects.

Prepares exportable audits containing security findings, OWASP mappings,
and regulatory guidance.
"""

from typing import Any, Dict
from sqlalchemy.orm import Session

from models import Scan, Finding, Target
from fix_engine.compliance_mapper import get_compliance_mapping


def generate_scan_report(scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Consolidate scan results and mapped findings into an audit report.

    Args:
        scan_id: Scan UUID.
        db: DB Session.

    Returns:
        dict: consolidated report structure.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    target = db.query(Target).filter(Target.id == scan.target_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Aggregate counts by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings_list = []

    for f in findings:
        severity_counts[f.severity.value] += 1

        # Enrich compliance mapping info
        compliance = get_compliance_mapping(f.owasp_category) if f.owasp_category else None

        findings_list.append(
            {
                "id": str(f.id),
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
                "compliance": compliance,  # Includes "guidance_only": True and plain-text disclaimer
                "detection_method": f.detection_method,
                "confidence": f.confidence,
                "retest_history": f.retest_history or [],
                "created_at": f.created_at.isoformat(),
            }
        )

    return {
        "report_id": f"rep_{scan_id}",
        "scan_id": str(scan.id),
        "target": {
            "id": str(target.id) if target else None,
            "name": target.name if target else None,
            "url": target.url if target else None,
            "environment": target.environment.value if target else None,
        },
        "scan_type": scan.scan_type.value,
        "triggered_by": scan.triggered_by.value,
        "status": scan.status.value,
        "total_attacks": scan.total_attacks,
        "completed_attacks": scan.completed_attacks,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "created_at": scan.created_at.isoformat(),
        "summary": {
            "findings_count": len(findings),
            "severity_breakdown": severity_counts,
            "fully_secure": len(findings) == 0,
        },
        "findings": findings_list,
    }
