"""Create core tables
Revision ID: 0001
Revises: 
Create Date: 2026-04-16 18:00:00
"""
from alembic import op
import sqlalchemy as sa
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None
def upgrade():
    op.create_table("users", sa.Column("id", sa.Integer(), nullable=False), sa.Column("username", sa.String(length=120), nullable=False), sa.Column("password_hash", sa.String(length=255), nullable=False), sa.Column("role", sa.String(length=50), nullable=False), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("username"))
    op.create_table("analysis_sessions", sa.Column("session_id", sa.String(length=255), nullable=False), sa.Column("sample_name", sa.String(length=255), nullable=False), sa.Column("sha256", sa.String(length=128), nullable=False), sa.Column("status", sa.String(length=64), nullable=False), sa.Column("assignee", sa.String(length=120), nullable=True), sa.Column("severity", sa.String(length=32), nullable=False), sa.Column("confidence", sa.String(length=32), nullable=False), sa.Column("static_score", sa.Integer(), nullable=False), sa.Column("dynamic_score", sa.Integer(), nullable=False), sa.Column("mitre_json", sa.Text(), nullable=False), sa.Column("iocs_json", sa.Text(), nullable=False), sa.Column("findings_json", sa.Text(), nullable=False), sa.Column("events_json", sa.Text(), nullable=False), sa.Column("artifacts_json", sa.Text(), nullable=False), sa.Column("comments_json", sa.Text(), nullable=False), sa.Column("meta_json", sa.Text(), nullable=False), sa.PrimaryKeyConstraint("session_id"))
    op.create_table("job_records", sa.Column("job_id", sa.String(length=255), nullable=False), sa.Column("celery_id", sa.String(length=255), nullable=False), sa.Column("trace_id", sa.String(length=255), nullable=False), sa.Column("status", sa.String(length=64), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False), sa.PrimaryKeyConstraint("job_id"))
def downgrade():
    op.drop_table("job_records")
    op.drop_table("analysis_sessions")
    op.drop_table("users")
