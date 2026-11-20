"""real intelligence provenance: import job statistics, source health, aliases

Revision ID: c2d3e4f5a6b7
Revises: b7c1d2e3f4a5
Create Date: 2026-11-19 23:10:00.000000

Adds the columns needed to report honest import statistics per collection job
and to keep source health for the genuine external feeds. Every added column is
nullable or has a default, so existing data (including synthetic demonstration
rows) is preserved untouched.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c2d3e4f5a6b7"
down_revision: Union[str, Sequence[str], None] = "b7c1d2e3f4a5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


NEW_COLUMNS = {
    "collection_jobs": [
        ("source_key", sa.String(length=100), {}),
        ("source_url", sa.String(length=500), {}),
        ("records_fetched", sa.Integer(), {}),
        ("records_validated", sa.Integer(), {}),
        ("records_updated", sa.Integer(), {}),
        ("records_skipped", sa.Integer(), {}),
        ("records_rejected", sa.Integer(), {}),
        ("errors", sa.Text(), {}),
        ("error_count", sa.Integer(), {}),
        ("details", sa.JSON(), {}),
    ],
    "evidence": [
        ("import_job_id", sa.Integer(), {}),
        ("source_modified_at", sa.DateTime(), {}),
    ],
    "intelligence_sources": [
        ("last_success_at", sa.DateTime(), {}),
        ("last_error", sa.Text(), {}),
        ("last_error_at", sa.DateTime(), {}),
        ("last_etag", sa.String(length=255), {}),
        ("last_object_count", sa.Integer(), {}),
    ],
    "actors": [
        ("aliases", sa.JSON(), {}),
    ],
}

NEW_INDEXES = [
    ("ix_evidence_import_job_id", "evidence", ["import_job_id"]),
    ("ix_collection_jobs_source_key", "collection_jobs", ["source_key"]),
]


def _columns(inspector, table: str) -> set:
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    for table, columns in NEW_COLUMNS.items():
        if table not in tables:
            continue
        existing = _columns(inspector, table)
        with op.batch_alter_table(table) as batch:
            for name, column_type, kwargs in columns:
                if name in existing:
                    continue
                batch.add_column(sa.Column(name, column_type, nullable=True, **kwargs))

    inspector = sa.inspect(bind)
    for index_name, table, columns in NEW_INDEXES:
        if table not in tables:
            continue
        existing_indexes = {index["name"] for index in inspector.get_indexes(table)}
        if index_name in existing_indexes:
            continue
        op.create_index(index_name, table, columns)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    for index_name, table, _columns_ in NEW_INDEXES:
        if table not in tables:
            continue
        existing_indexes = {index["name"] for index in inspector.get_indexes(table)}
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name=table)

    for table, columns in NEW_COLUMNS.items():
        if table not in tables:
            continue
        existing = _columns(inspector, table)
        with op.batch_alter_table(table) as batch:
            for name, _type, _kwargs in columns:
                if name in existing:
                    batch.drop_column(name)
