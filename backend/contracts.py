"""
contracts.py — Pydantic models: single source of truth for API request/response shapes.

Enums here mirror models.py exactly. When adding a new enum value, update BOTH files.
AttackType has exactly 15 values (one per dataset file in backend/dataset/).

Note: guidance_only and compliance fields appear in Component 3 (fix_engine outputs).
They are stubbed here so downstream code can import them without circular deps.
"""

from __future__ import annotations

import enum
from typing import Any, List, Optional

from pydantic import BaseModel, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AttackType(str, enum.Enum):
    prompt_injection = "prompt_injection"
    jailbreak = "jailbreak"
    system_prompt_leak = "system_prompt_leak"
    data_leakage = "data_leakage"
    role_override = "role_override"
    indirect_injection = "indirect_injection"
    rag_poisoning = "rag_poisoning"
    tool_abuse = "tool_abuse"
    denial_of_wallet = "denial_of_wallet"
    sql_injection = "sql_injection"
    api_abuse = "api_abuse"
    context_manipulation = "context_manipulation"
    training_data_extraction = "training_data_extraction"
    sponge_attack = "sponge_attack"
    few_shot_leakage = "few_shot_leakage"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, enum.Enum):
    open = "open"
    resolved = "resolved"
    partial = "partial"
    regressed = "regressed"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"
    partial = "partial"


class ScanType(str, enum.Enum):
    full = "full"
    retest = "retest"


class ScanTrigger(str, enum.Enum):
    manual = "manual"
    deployment_detected = "deployment_detected"
    scheduled = "scheduled"


class DetectionMethod(str, enum.Enum):
    rule = "rule"
    ml = "ml"
    llm_judge = "llm_judge"


# ---------------------------------------------------------------------------
# Internal data-transfer objects (not HTTP response models)
# ---------------------------------------------------------------------------

class AttackResult(BaseModel):
    """Returned by attack_engine.runner.run_attack() — not serialised to HTTP directly."""
    attack_type: AttackType
    payload: str
    response: str
    success: bool
    confidence: float  # 0.0–1.0
    layer_failed: Optional[str] = None
    detection_method: DetectionMethod = DetectionMethod.rule
    raw_judge_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# HTTP response models
# ---------------------------------------------------------------------------

class FindingOut(BaseModel):
    """Shape returned by GET /findings/{id} and embedded in ScanOut."""
    id: str
    scan_id: str
    target_id: str
    attack_type: AttackType
    severity: Severity
    status: FindingStatus
    attack_payload: str
    attack_response: str
    layer_failed: Optional[str] = None
    risk_score: float
    fix_recommendation: Optional[str] = None
    fix_code_snippet: Optional[str] = None
    owasp_category: Optional[str] = None
    # Stub fields for Component 3 compliance output
    compliance: Optional[dict] = None       # {"owasp_llm": ..., "eu_ai_act": ..., "guidance_only": True, "disclaimer": ...}
    detection_method: str
    confidence: float
    retest_history: List[Any] = []
    created_at: str

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """Shape returned by GET /scans/{id}."""
    id: str
    target_id: str
    scan_type: ScanType
    triggered_by: ScanTrigger
    status: ScanStatus
    total_attacks: int
    completed_attacks: int
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str
    findings: List[FindingOut] = []

    model_config = {"from_attributes": True}


class TargetOut(BaseModel):
    """
    Shape returned by GET /targets and GET /targets/{id}.

    INVARIANT: NEVER include auth_token_encrypted or management_token_hash.
    If you add a field here, double-check it's not a secret.
    """
    id: str
    name: str
    url: str
    environment: str
    ownership_verified: bool
    watcher_enabled: bool
    last_probed_at: Optional[str] = None
    created_at: str

    model_config = {"from_attributes": True}
