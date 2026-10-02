"""initial schema — targets, scans, findings, api_keys

Baseline migration capturing the full v3+v4 schema (including
last_fingerprint_text, management_token_hash, watcher_enabled on Target,
and the api_keys table) in one place, so future schema changes have a
proper migration chain to build on instead of relying on
Base.metadata.create_all() alone.

If your DB was already created via create_all() (the MVP default in
main.py), run `alembic stamp 1b211f432ae8` instead of `alembic upgrade
head` — the tables already exist and stamping just records that this
revision is satisfied. A genuinely fresh DB should use `alembic upgrade
head` to create everything from scratch.

Revision ID: 1b211f432ae8
Revises:
Create Date: 2026-09-03
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "1b211f432ae8"
down_revision = None
branch_labels = None
depends_on = None

environment_enum = postgresql.ENUM("dev", "staging", "prod", name="environment_enum")
scan_type_enum = postgresql.ENUM("full", "retest", name="scan_type_enum")
scan_trigger_enum = postgresql.ENUM(
    "manual", "deployment_detected", "scheduled", name="scan_trigger_enum"
)
scan_status_enum = postgresql.ENUM(
    "pending", "running", "done", "failed", "partial", name="scan_status_enum"
)
attack_type_enum = postgresql.ENUM(
    "prompt_injection", "jailbreak", "system_prompt_leak", "data_leakage",
    "role_override", "indirect_injection", "rag_poisoning", "tool_abuse",
    "denial_of_wallet", "sql_injection", "api_abuse", "context_manipulation",
    "training_data_extraction", "sponge_attack", "few_shot_leakage",
    name="attack_type_enum",
)
severity_enum = postgresql.ENUM(
    "critical", "high", "medium", "low", "info", name="severity_enum"
)
finding_status_enum = postgresql.ENUM(
    "open", "resolved", "partial", "regressed", name="finding_status_enum"
)


def upgrade() -> None:
    bind = op.get_bind()
    environment_enum.create(bind, checkfirst=True)
    scan_type_enum.create(bind, checkfirst=True)
    scan_trigger_enum.create(bind, checkfirst=True)
    scan_status_enum.create(bind, checkfirst=True)
    attack_type_enum.create(bind, checkfirst=True)
    severity_enum.create(bind, checkfirst=True)
    finding_status_enum.create(bind, checkfirst=True)

    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("environment", environment_enum, nullable=False),
        sa.Column("ownership_verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("verification_token", sa.String(64), nullable=False),
        sa.Column("management_token_hash", sa.String(128), nullable=True),
        sa.Column("auth_token_encrypted", sa.Text, nullable=True),
        sa.Column("watcher_enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_fingerprint", sa.String(64), nullable=True),
        sa.Column("last_fingerprint_text", sa.Text, nullable=True),
        sa.Column("last_probed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("scan_type", scan_type_enum, nullable=False),
        sa.Column("triggered_by", scan_trigger_enum, nullable=False),
        sa.Column("status", scan_status_enum, nullable=False),
        sa.Column("parent_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("deployment_fingerprint", sa.String(128), nullable=True),
        sa.Column("total_attacks", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completed_attacks", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("attack_type", attack_type_enum, nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("status", finding_status_enum, nullable=False),
        sa.Column("attack_payload", sa.Text, nullable=False),
        sa.Column("attack_response", sa.Text, nullable=False),
        sa.Column("layer_failed", sa.String(255), nullable=True),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("fix_recommendation", sa.Text, nullable=True),
        sa.Column("fix_code_snippet", sa.Text, nullable=True),
        sa.Column("owasp_category", sa.String(255), nullable=True),
        sa.Column("detection_method", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("retest_history", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")

    bind = op.get_bind()
    finding_status_enum.drop(bind, checkfirst=True)
    severity_enum.drop(bind, checkfirst=True)
    attack_type_enum.drop(bind, checkfirst=True)
    scan_status_enum.drop(bind, checkfirst=True)
    scan_trigger_enum.drop(bind, checkfirst=True)
    scan_type_enum.drop(bind, checkfirst=True)
    environment_enum.drop(bind, checkfirst=True)
