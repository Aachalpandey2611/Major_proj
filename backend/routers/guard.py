"""
routers/guard.py — Real-time inline prompt firewall.

    User -> POST /api/v1/guard/check -> LLM (if ALLOWed) -> User

Distinct from routers/scans.py (the async red-team scanner that attacks a
registered Target over time): this endpoint classifies ONE incoming prompt,
synchronously, and optionally forwards it to a real downstream LLM.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from detection_engine.prompt_guard import check_prompt, call_downstream_llm
from models import GuardLog

router = APIRouter(prefix="/guard", tags=["guard"])


class GuardCheckRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=8000)
    forward: bool = True  # if ALLOWed, call the downstream LLM and include its response


class GuardCheckResponse(BaseModel):
    risk_score: int
    attack_type: str
    decision: str
    method: str
    reason: str
    llm_response: str | None = None


@router.post("/check", response_model=GuardCheckResponse)
def guard_check(req: GuardCheckRequest, db: Session = Depends(get_db)):
    result = check_prompt(req.prompt)

    llm_response = None
    forwarded = False
    if result["decision"] == "ALLOW" and req.forward:
        llm_response = call_downstream_llm(req.prompt)
        forwarded = True

    log = GuardLog(
        prompt=req.prompt,
        risk_score=result["risk_score"],
        attack_type=result["attack_type"],
        decision=result["decision"],
        method=result["method"],
        reason=result["reason"],
        forwarded=forwarded,
        llm_response=llm_response,
    )
    db.add(log)
    db.commit()

    return GuardCheckResponse(**result, llm_response=llm_response)


@router.get("/logs")
def guard_logs(limit: int = 25, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    logs = (
        db.query(GuardLog)
        .order_by(GuardLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": str(l.id),
            "prompt": l.prompt,
            "risk_score": l.risk_score,
            "attack_type": l.attack_type,
            "decision": l.decision,
            "method": l.method,
            "reason": l.reason,
            "forwarded": l.forwarded,
            "llm_response": l.llm_response,
            "created_at": l.created_at.isoformat(),
        }
        for l in logs
    ]


@router.get("/stats")
def guard_stats(db: Session = Depends(get_db)):
    """Aggregate counts for the guard dashboard header (total / blocked / allowed)."""
    total = db.query(GuardLog).count()
    blocked = db.query(GuardLog).filter(GuardLog.decision == "BLOCK").count()
    allowed = total - blocked
    return {"total": total, "blocked": blocked, "allowed": allowed}
