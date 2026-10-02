"""add guard_logs table — real-time inline prompt-guard checks

Revision ID: 7d3a9c1f5e02
Revises: 1b211f432ae8
Create Date: 2026-09-03
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "7d3a9c1f5e02"
down_revision = "1b211f432ae8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guard_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("prompt", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("attack_type", sa.String(64), nullable=False, server_default="None"),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("method", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("forwarded", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("llm_response", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("guard_logs")
