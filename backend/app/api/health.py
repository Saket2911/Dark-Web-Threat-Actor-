from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import get_settings
from app.database.session import engine

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health():
    settings = get_settings()
    database_ok = True
    error = None
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - diagnostic only
        database_ok = False
        error = str(exc)
    return {
        "status": "ok" if database_ok else "degraded",
        "version": settings.app_version,
        "database": "ok" if database_ok else "error",
        "error": error,
    }
