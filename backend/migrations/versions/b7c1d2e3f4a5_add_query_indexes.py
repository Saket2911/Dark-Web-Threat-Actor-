"""add query indexes for graph, timeline and analysis lookups

Revision ID: b7c1d2e3f4a5
Revises: a1b2c3d4e5f6
Create Date: 2026-11-19 20:05:00.000000

Indexes are created from the SQLAlchemy metadata so the migration stays in
sync with the model definitions. Existing indexes are skipped, which makes the
migration safe to re-run against a database that was partly created by
``Base.metadata.create_all``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.database.session import Base
import app.models.entities  # noqa: F401  - registers all tables


revision: str = "b7c1d2e3f4a5"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        existing_indexes = {
            index["name"] for index in inspector.get_indexes(table.name)
        }
        for index in table.indexes:
            if index.name in existing_indexes:
                continue
            try:
                index.create(bind, checkfirst=True)
            except Exception:
                # A missing column (older schema) should not abort the whole
                # migration; the column-level migrations run first anyway.
                continue


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        existing_indexes = {
            index["name"] for index in inspector.get_indexes(table.name)
        }
        for index in table.indexes:
            if index.name in existing_indexes:
                try:
                    index.drop(bind, checkfirst=True)
                except Exception:
                    continue
