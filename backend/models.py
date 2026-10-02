"""
models.py — SQLAlchemy ORM tables for SentinelLoop.

Security invariants enforced here:
- Target.auth_token_encrypted stores ONLY the output of crypto.encrypt_token().
  The column is named "_encrypted" to make accidental plaintext storage obvious in code review.
- Target.management_token_hash stores ONLY a bcrypt hash. The raw token is returned
  once at registration and never stored.
- APIKey.key_hash stores ONLY a bcrypt hash of the raw CI key.
"""

import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Enum as SAEnum,
    Float, ForeignKey, Integer, String, Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from database import Base


# ---------------------------------------------------------------------------
# Enums (mirrored in contracts.py for Pydantic — keep in sync)
# ---------------------------------------------------------------------------

class Environment(str, enum.Enum):
    dev = "dev"
    staging = "staging"
    prod = "prod"


class ScanType(str, enum.Enum):
    full = "full"
    retest = "retest"


class ScanTrigger(str, enum.Enum):
    manual = "manual"
    deployment_detected = "deployment_detected"
    scheduled = "scheduled"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"
    partial = "partial"


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


# ---------------------------------------------------------------------------
# ORM Tables
# ---------------------------------------------------------------------------

class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )  # nullable=True for backward compatibility with existing targets
    name = Column(String(255), nullable=False)
    url = Column(String(2048), nullable=False)
    environment = Column(
        SAEnum(Environment, name="environment_enum"),
        nullable=False,
        default=Environment.staging,
    )
    ownership_verified = Column(Boolean, default=False, nullable=False)
    # Token placed in /.well-known/sentinelloop-verify.txt to prove ownership
    verification_token = Column(String(64), nullable=False)

    # bcrypt hash of the management token shown ONCE at registration.
    # The raw token is NEVER stored — only this hash. Set to NULL if not yet generated
    # (should never be NULL after registration completes).
    management_token_hash = Column(String(128), nullable=True)

    # Output of crypto.encrypt_token() — format: "salt_b64:fernet_ciphertext"
    # NULL if the target has no auth token (public chatbot endpoints).
    auth_token_encrypted = Column(Text, nullable=True)

    watcher_enabled = Column(Boolean, default=True, nullable=False)

    # SHA-256 of the most recent stable probe response (for change detection)
    last_fingerprint = Column(String(64), nullable=True)
    # First 500 chars of the raw probe response text, for cosine-sim comparison.
    # Stored so we can compare semantic similarity across probe cycles without
    # re-querying the target.
    last_fingerprint_text = Column(Text, nullable=True)
    last_probed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scan_type = Column(
        SAEnum(ScanType, name="scan_type_enum"), nullable=False, default=ScanType.full
    )
    triggered_by = Column(
        SAEnum(ScanTrigger, name="scan_trigger_enum"),
        nullable=False,
        default=ScanTrigger.manual,
    )
    status = Column(
        SAEnum(ScanStatus, name="scan_status_enum"),
        nullable=False,
        default=ScanStatus.pending,
    )
    # For retest scans: the scan_id of the original full scan
    parent_scan_id = Column(UUID(as_uuid=True), nullable=True)
    # Commit SHA or content-hash fingerprint that triggered this scan
    deployment_fingerprint = Column(String(128), nullable=True)

    total_attacks = Column(Integer, default=0, nullable=False)
    completed_attacks = Column(Integer, default=0, nullable=False)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    target_id = Column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    attack_type = Column(SAEnum(AttackType, name="attack_type_enum"), nullable=False)
    severity = Column(SAEnum(Severity, name="severity_enum"), nullable=False)
    status = Column(
        SAEnum(FindingStatus, name="finding_status_enum"),
        nullable=False,
        default=FindingStatus.open,
    )
    attack_payload = Column(Text, nullable=False)
    attack_response = Column(Text, nullable=False)
    layer_failed = Column(String(255), nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    fix_recommendation = Column(Text, nullable=True)
    fix_code_snippet = Column(Text, nullable=True)
    owasp_category = Column(String(255), nullable=True)
    # "rule" | "ml" | "llm_judge"
    detection_method = Column(String(64), nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)
    # List of {retest_scan_id, timestamp, verdict, confidence} dicts
    retest_history = Column(JSONB, default=list, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")


class GuardLog(Base):
    """
    One row per real-time prompt-guard check (POST /api/v1/guard/check).

    This is the inline "User -> Guard -> LLM -> User" firewall log — distinct
    from Scan/Finding, which belong to the async red-team scanner that attacks
    a registered Target over time.
    """
    __tablename__ = "guard_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    prompt = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    attack_type = Column(String(64), nullable=False, default="None")
    decision = Column(String(16), nullable=False)  # "BLOCK" | "ALLOW"
    method = Column(String(32), nullable=False)  # "rule" | "ml" | "ml+llm_judge"
    reason = Column(Text, nullable=True)
    forwarded = Column(Boolean, default=False, nullable=False)
    llm_response = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    # bcrypt hash of the raw "sl_..." key shown once at creation.
    # Raw key is NEVER stored — only this hash.
    key_hash = Column(String(128), nullable=False)
    label = Column(String(255), nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("Target", back_populates="api_keys")


class AttackLog(Base):
    """
    Comprehensive audit trail: records EVERY attack attempt (pass + fail).
    
    Critical for panel demos and compliance:
    - When chatbot is secure → proves what was tested (no findings = no proof otherwise)
    - When chatbot is vulnerable → shows which specific prompts succeeded
    - Full evidence trail: prompt sent + response received + verdict + confidence
    
    One row per prompt tested. A full scan with 85 prompts per attack type × 15 attacks
    = ~1,275 AttackLog entries proving comprehensive testing.
    """
    __tablename__ = "attack_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    attack_type = Column(String(64), nullable=False)  # e.g. "prompt_injection"
    layer_name = Column(String(255), nullable=False)  # e.g. "Layer 1 — Prompt Injection"
    prompt_used = Column(Text, nullable=False)  # Exact prompt sent to target
    chatbot_response = Column(Text, nullable=False)  # Exact response received
    verdict = Column(String(16), nullable=False)  # "PASSED" (blocked) or "FAILED" (vulnerable)
    confidence = Column(Float, nullable=False, default=0.0)  # Detection confidence (0.0-1.0)
    detection_method = Column(String(64), nullable=False)  # "rule" | "ml" | "llm_judge"
    prompts_tested = Column(Integer, default=1, nullable=False)  # Count for this attack type
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    scan = relationship("Scan")

class User(Base):
    """
    User authentication model for JWT-based login.
    
    - email is unique and serves as the username
    - password_hash stores ONLY bcrypt hash (never plaintext)
    - is_active allows account deactivation without deletion
    - created_at tracks registration time
    
    Relationships:
    - One user can own multiple targets (Target.user_id foreign key)
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(128), nullable=False)  # bcrypt hash
    is_active = Column(Boolean, default=True, nullable=False)
    subscription_tier = Column(String(50), default="free", nullable=False)  # free, startup, scale, enterprise
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    targets = relationship("Target", back_populates="user")
