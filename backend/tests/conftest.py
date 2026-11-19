"""Shared test fixtures.

A throw-away SQLite database and model directory are created before the
application is imported, so tests never touch the real project database.
"""

import os
import tempfile
from pathlib import Path

_TMP_ROOT = Path(tempfile.mkdtemp(prefix="cn_project_tests_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP_ROOT / 'test.db').as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"
os.environ["CORS_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173"
os.environ["MODEL_DIR"] = str(_TMP_ROOT / "models")
os.environ["ABUSE_CH_AUTH_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.database.session import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models.entities import User  # noqa: E402


@pytest.fixture(scope="session")
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        users = [
            ("admin", "AdminPass123", "admin"),
            ("analyst", "AnalystPass123", "analyst"),
        ]
        for username, password, role in users:
            if not db.query(User).filter(User.username == username).first():
                db.add(
                    User(
                        username=username,
                        hashed_password=hash_password(password),
                        role=role,
                    )
                )
        db.commit()
    finally:
        db.close()
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin_headers(client):
    return _login(client, "admin", "AdminPass123")


@pytest.fixture(scope="session")
def analyst_headers(client):
    return _login(client, "analyst", "AnalystPass123")


@pytest.fixture
def make_actor(client, admin_headers):
    """Create an actor and return its JSON payload."""
    counter = {"value": 0}

    def _make(handle: str, category: str = "Test", **extra):
        counter["value"] += 1
        payload = {"primary_handle": handle, "threat_category": category, **extra}
        response = client.post("/api/actors", json=payload, headers=admin_headers)
        assert response.status_code == 201, response.text
        return response.json()

    return _make


@pytest.fixture
def make_pair(client, admin_headers, make_actor):
    """Create two actors that share a PGP fingerprint and return (a, b)."""
    from uuid import uuid4

    suffix = uuid4().hex[:6]
    fingerprint = "FINGERPRINT" + uuid4().hex.upper()
    a = make_actor(f"pair_a_{suffix}")
    b = make_actor(f"pair_b_{suffix}")
    for actor in (a, b):
        response = client.post(
            f"/api/actors/{actor['id']}/identifiers",
            json={"id_type": "pgp", "value": fingerprint, "source": "test"},
            headers=admin_headers,
        )
        assert response.status_code == 201, response.text
    return a, b, fingerprint
