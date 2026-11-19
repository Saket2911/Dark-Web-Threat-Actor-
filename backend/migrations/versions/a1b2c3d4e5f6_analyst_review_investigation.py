"""add investigation_id to analyst reviews

Revision ID: a1b2c3d4e5f6
Revises: 69255c01a2e1
Create Date: 2026-11-19 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "69255c01a2e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {c["name"] for c in inspector.get_columns("analyst_reviews")}
    if "investigation_id" not in columns:
        op.add_column(
            "analyst_reviews",
            sa.Column("investigation_id", sa.Integer(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {c["name"] for c in inspector.get_columns("analyst_reviews")}
    if "investigation_id" in columns:
        op.drop_column("analyst_reviews", "investigation_id")
