"""
retest_comparator.py — Compares two scans to track resolved vs. regressed vulnerabilities.
"""

from typing import Any, Dict
from sqlalchemy.orm import Session
from models import Finding, Scan, FindingStatus


def compare_scans(original_scan_id: str, retest_scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Compare original findings against retest results.

    Args:
        original_scan_id: The UUID of the initial scan.
        retest_scan_id: The UUID of the subsequent retest scan.
        db: DB Session.

    Returns:
        dict: comparison summary.
    """
    original_findings = db.query(Finding).filter(Finding.scan_id == original_scan_id).all()
    retest_findings = db.query(Finding).filter(Finding.scan_id == retest_scan_id).all()

    orig_map = {f.attack_type: f for f in original_findings}
    ret_map = {f.attack_type: f for f in retest_findings}

    resolved = []
    still_open = []
    regressed = []

    for attack_type, orig_f in orig_map.items():
        ret_f = ret_map.get(attack_type)

        if not ret_f:
            # If it wasn't retested or wasn't found in the retest, check its DB status
            # If DB status is resolved, mark it as resolved
            if orig_f.status == FindingStatus.resolved:
                resolved.append(str(orig_f.id))
            else:
                still_open.append(str(orig_f.id))
        else:
            if ret_f.status == FindingStatus.resolved:
                resolved.append(str(orig_f.id))
            elif ret_f.status == FindingStatus.open:
                still_open.append(str(orig_f.id))
            elif ret_f.status == FindingStatus.regressed:
                regressed.append(str(orig_f.id))

    return {
        "original_scan_id": original_scan_id,
        "retest_scan_id": retest_scan_id,
        "comparison": {
            "total_original_findings": len(original_findings),
            "resolved_count": len(resolved),
            "still_open_count": len(still_open),
            "regressed_count": len(regressed),
            "resolved_finding_ids": resolved,
            "still_open_finding_ids": still_open,
            "regressed_finding_ids": regressed,
            "status": "fully_secure" if len(resolved) == len(original_findings) else "partially_secure",
        },
    }
