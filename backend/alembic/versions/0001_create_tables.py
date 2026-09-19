"""create tables

Revision ID: 0001
Revises:
Create Date: 2026-09-19

Creates the full Network Mapper schema: targets, scans, ports, services,
findings, cves, assets and audit_logs.
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("importance", sa.String(length=20), nullable=False, server_default="low"),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("tags", sa.Text(), nullable=True),
    )
    op.create_index("ix_assets_ip", "assets", ["ip"])

    op.create_table(
        "cves",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_v3", sa.Float(), nullable=True),
        sa.Column("cvss_v4", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ok"),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("authorized", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_targets_ip", "targets", ["ip"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "ports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(length=10), nullable=False, server_default="open"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )

    op.create_table(
        "services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("port_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False, server_default="unknown"),
        sa.Column("product", sa.String(length=100), nullable=True),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("cpe", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["port_id"], ["ports.id"], ondelete="CASCADE"),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=500), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(length=20), nullable=False, server_default="low"),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_scan_cve", "findings", ["scan_id", "cve_id"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("services")
    op.drop_table("ports")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_table("audit_logs")
    op.drop_table("cves")
    op.drop_table("assets")