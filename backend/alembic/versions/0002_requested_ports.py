"""add requested_ports to scans

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-19

Stores the user's ``ports_to_scan`` payload (canonical comma-separated list or
range-expanded list) so the worker scans exactly the requested ports instead of
the built-in defaults.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("requested_ports", sa.String(length=4096), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "requested_ports")