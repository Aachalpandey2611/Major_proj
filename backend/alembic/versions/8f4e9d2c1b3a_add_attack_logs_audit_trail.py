"""add attack_logs table for comprehensive audit trail

Revision ID: 8f4e9d2c1b3a
Revises: 7d3a9c1f5e02
Create Date: 2026-10-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "8f4e9d2c1b3a"
down_revision = "7d3a9c1f5e02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attack_type", sa.String(64), nullable=False),
        sa.Column("layer_name", sa.String(255), nullable=False),
        sa.Column("prompt_used", sa.Text, nullable=False),
        sa.Column("chatbot_response", sa.Text, nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("detection_method", sa.String(64), nullable=False),
        sa.Column("prompts_tested", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    # Add index on scan_id for faster audit report queries
    op.create_index("ix_attack_logs_scan_id", "attack_logs", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_attack_logs_scan_id", "attack_logs")
    op.drop_table("attack_logs")
