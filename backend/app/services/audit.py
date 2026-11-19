"""Audit logging helper.

Audit trails are best-effort: a failure to write an audit record must never
break the analyst action that produced it.
"""

from sqlalchemy.orm import Session

from app.models.entities import AuditLog


def audit(db: Session, user: str, action: str, details: str = "") -> None:
    try:
        db.add(AuditLog(user=user, action=action, details=details))
        db.commit()
    except Exception:  # pragma: no cover - logging must not fail the request
        db.rollback()


def recent_activity(db: Session, limit: int = 20):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .all()
    )
