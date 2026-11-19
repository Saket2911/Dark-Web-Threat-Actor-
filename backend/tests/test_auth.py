"""Authentication, token handling and role-based access control."""

from datetime import timedelta

from app.core.security import create_access_token, decode_token


def test_health_is_public(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] in ("ok", "degraded")


def test_login_success_and_me(client, analyst_headers):
    response = client.get("/api/auth/me", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "analyst"
    assert body["role"] == "analyst"
    assert "password" not in str(body).lower()
    assert "hashed" not in str(body).lower()


def test_login_failure_is_generic(client):
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "wrong-password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"

    unknown = client.post(
        "/api/auth/login", json={"username": "does-not-exist", "password": "wrong"}
    )
    assert unknown.status_code == 401
    assert unknown.json()["detail"] == response.json()["detail"]


def test_protected_endpoint_requires_token(client):
    assert client.get("/api/actors").status_code == 401
    bad = client.get("/api/actors", headers={"Authorization": "Bearer not-a-token"})
    assert bad.status_code == 401


def test_expired_token_rejected(client):
    expired = create_access_token("analyst", expires_delta=timedelta(minutes=-5))
    response = client.get("/api/actors", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_token_decodes_with_expected_claims():
    token = create_access_token("analyst", extra={"role": "analyst"})
    payload = decode_token(token)
    assert payload["sub"] == "analyst"
    assert payload["role"] == "analyst"
    assert "exp" in payload and "iat" in payload


def test_registration_requires_admin(client, analyst_headers, admin_headers):
    payload = {"username": "newuser1", "password": "StrongPass123", "role": "analyst"}
    forbidden = client.post("/api/auth/register", json=payload, headers=analyst_headers)
    assert forbidden.status_code == 403

    created = client.post("/api/auth/register", json=payload, headers=admin_headers)
    assert created.status_code == 201, created.text
    assert created.json()["username"] == "newuser1"

    duplicate = client.post("/api/auth/register", json=payload, headers=admin_headers)
    assert duplicate.status_code == 409


def test_registration_validation(client, admin_headers):
    weak = client.post(
        "/api/auth/register",
        json={"username": "weakuser", "password": "admin123", "role": "analyst"},
        headers=admin_headers,
    )
    assert weak.status_code == 422

    bad_role = client.post(
        "/api/auth/register",
        json={"username": "roler", "password": "StrongPass123", "role": "superuser"},
        headers=admin_headers,
    )
    assert bad_role.status_code == 422


def test_user_list_admin_only(client, admin_headers, analyst_headers):
    assert client.get("/api/auth/users", headers=analyst_headers).status_code == 403
    response = client.get("/api/auth/users", headers=admin_headers)
    assert response.status_code == 200
    assert all("hashed_password" not in user for user in response.json())


def test_logout_endpoint(client, analyst_headers):
    response = client.post("/api/auth/logout", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_cors_rejects_unknown_origin(client):
    allowed = client.options(
        "/api/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    rejected = client.options(
        "/api/auth/login",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert rejected.status_code == 400
