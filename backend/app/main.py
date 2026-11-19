import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    actors,
    analysis,
    auth,
    dashboard,
    graph,
    health,
    infra,
    ingestion,
    investigations,
    reports,
    settings as settings_api,
    timeline,
)
from app.core.config import get_settings
from app.database.session import Base, engine

logger = logging.getLogger("app")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

settings = get_settings()

# create_all only adds missing tables; column changes are handled by Alembic.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Defensive threat-actor intelligence and de-anonymisation decision-support platform. "
        "Similarity scores are analytical evidence, never proof of identity."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

for router in [
    auth.router,
    dashboard.router,
    actors.router,
    ingestion.router,
    graph.router,
    analysis.router,
    infra.router,
    investigations.router,
    timeline.router,
    reports.router,
    settings_api.router,
    health.router,
]:
    app.include_router(router, prefix="/api")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):  # pragma: no cover
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "path": request.url.path,
        },
    )


@app.on_event("startup")
def log_configuration():
    logger.info("Database: %s", settings.database_path or settings.sqlalchemy_url)
    logger.info("CORS origins: %s", settings.cors_origin_list)
    if settings.secret_key in ("change-me", "") or settings.secret_key.startswith("change-me"):
        logger.warning(
            "SECRET_KEY is still a placeholder. Set a long random SECRET_KEY in the "
            "environment before exposing this service."
        )
    try:
        from alembic.config import Config
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
        from app.core.config import BACKEND_DIR

        with engine.connect() as connection:
            current = MigrationContext.configure(connection).get_current_revision()
        script = ScriptDirectory.from_config(Config(str(BACKEND_DIR / "alembic.ini")))
        head = script.get_current_head()
        if current != head:
            logger.warning(
                "Database revision %s does not match Alembic head %s. Run "
                "'alembic upgrade head' from backend/.",
                current,
                head,
            )
    except Exception as exc:  # pragma: no cover - informational only
        logger.debug("Migration check skipped: %s", exc)


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "api": "/api",
    }
