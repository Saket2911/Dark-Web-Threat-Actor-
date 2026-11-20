"""collection job relationship counts

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-11-19 22:20:00.000000

Genuine MITRE ATT&CK imports write far more relationships than entities. The
previous schema only counted imported entities, so a run that created tens of
thousands of documented relationships but no new entities was reported as
``completed_empty``. This migration adds a dedicated persisted counter.

Existing rows keep their original values; the new column is nullable so no
historical fact is rewritten by the migration. The application writes 0 for new
jobs.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d3e4f5a6b7c8"
down_revision: Union[str, Sequence[str], None] = "c2d3e4f5a6b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "collection_jobs" not in set(inspector.get_table_names()):
        return
    columns = {column["name"] for column in inspector.get_columns("collection_jobs")}
    if "relationships_created" in columns:
        return
    with op.batch_alter_table("collection_jobs") as batch:
        batch.add_column(sa.Column("relationships_created", sa.Integer(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "collection_jobs" not in set(inspector.get_table_names()):
        return
    columns = {column["name"] for column in inspector.get_columns("collection_jobs")}
    if "relationships_created" not in columns:
        return
    with op.batch_alter_table("collection_jobs") as batch:
        batch.drop_column("relationships_created")
