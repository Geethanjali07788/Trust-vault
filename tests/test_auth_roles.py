import json
import pytest

def test_register_viewer_success(client):
    """Test standard public registration with 'viewer' role."""
    response = client.post("/auth/register", json={
        "username": "viewer_jane",
        "email": "jane@example.com",
        "password": "SecurePassword123!",
        "role": "viewer"
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["user"]["username"] == "viewer_jane"
    assert data["user"]["role"] == "viewer"
    assert "password" not in data["user"]


def test_register_owner_success(client):
    """Test registration with 'owner' role."""
    response = client.post("/auth/register", json={
        "username": "owner_bob",
        "email": "bob@example.com",
        "password": "SecurePassword123!",
        "role": "owner"
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["user"]["username"] == "owner_bob"
    assert data["user"]["role"] == "owner"


def test_register_rejects_admin_escalation(client):
    """SECURITY TEST: Public registration MUST REJECT attempts to create an admin account."""
    response = client.post("/auth/register", json={
        "username": "sneaky_admin",
        "email": "sneaky@example.com",
        "password": "SecurePassword123!",
        "role": "admin"
    })
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "Invalid role" in data["error"] or "admin" in data["error"].lower()


def test_register_duplicate_username(client):
    """Verify duplicate username registration is rejected with 409 Conflict."""
    payload = {
        "username": "duplicate_user",
        "email": "user1@example.com",
        "password": "SecurePassword123!",
        "role": "viewer"
    }
    res1 = client.post("/auth/register", json=payload)
    assert res1.status_code == 201

    payload["email"] = "user2@example.com"
    res2 = client.post("/auth/register", json=payload)
    assert res2.status_code == 409


def test_register_invalid_inputs(client):
    """Verify short passwords and malformed emails are rejected."""
    # Short password (< 8 chars)
    res1 = client.post("/auth/register", json={
        "username": "valid_user",
        "email": "valid@example.com",
        "password": "short",
        "role": "viewer"
    })
    assert res1.status_code == 400

    # Invalid email
    res2 = client.post("/auth/register", json={
        "username": "valid_user",
        "email": "not-an-email",
        "password": "ValidPassword123!",
        "role": "viewer"
    })
    assert res2.status_code == 400


def test_login_success(client, seed_users):
    """Test successful login returns 200 and establishes session."""
    response = client.post("/auth/login", json={
        "username": "test_owner",
        "password": "OwnerSecret123!"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["user"]["username"] == "test_owner"
    assert data["user"]["role"] == "owner"

    # Verify session is established by fetching /auth/me
    me_res = client.get("/auth/me")
    assert me_res.status_code == 200
    me_data = me_res.get_json()
    assert me_data["username"] == "test_owner"
    assert me_data["role"] == "owner"


def test_login_wrong_password(client, seed_users):
    """SECURITY TEST: Wrong password must be rejected with 401 Unauthorized."""
    response = client.post("/auth/login", json={
        "username": "test_owner",
        "password": "WrongPassword999!"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.get_json()["error"]


def test_login_nonexistent_user(client):
    """Non-existent user must be rejected with 401 Unauthorized."""
    response = client.post("/auth/login", json={
        "username": "ghost_user",
        "password": "AnyPassword123!"
    })
    assert response.status_code == 401


def test_role_restriction_admin_endpoint(client, seed_users):
    """
    SECURITY TEST (RBAC):
    - Unauthenticated access returns 401.
    - Viewer access returns 403 Forbidden.
    - Owner access returns 403 Forbidden.
    - Admin access returns 200 OK.
    """
    # 1. Unauthenticated
    assert client.get("/auth/test-admin").status_code == 401

    # 2. Authenticated as Viewer -> 403 Forbidden
    client.post("/auth/login", json={"username": "test_viewer", "password": "ViewerSecret123!"})
    res_viewer = client.get("/auth/test-admin")
    assert res_viewer.status_code == 403

    # 3. Authenticated as Owner -> 403 Forbidden
    client.post("/auth/login", json={"username": "test_owner", "password": "OwnerSecret123!"})
    res_owner = client.get("/auth/test-admin")
    assert res_owner.status_code == 403

    # 4. Authenticated as Admin -> 200 OK
    client.post("/auth/login", json={"username": "test_admin", "password": "AdminSecret123!"})
    res_admin = client.get("/auth/test-admin")
    assert res_admin.status_code == 200
    assert "Welcome, Administrator" in res_admin.get_json()["message"]


def test_role_restriction_owner_endpoint(client, seed_users):
    """
    SECURITY TEST (RBAC):
    - Viewer access to owner endpoint returns 403 Forbidden.
    - Owner access returns 200 OK.
    """
    # Viewer -> 403
    client.post("/auth/login", json={"username": "test_viewer", "password": "ViewerSecret123!"})
    assert client.get("/auth/test-owner").status_code == 403

    # Owner -> 200
    client.post("/auth/login", json={"username": "test_owner", "password": "OwnerSecret123!"})
    assert client.get("/auth/test-owner").status_code == 200


def test_logout_clears_session(client, seed_users):
    """SECURITY TEST: Logging out must completely invalidate the session."""
    # Login
    client.post("/auth/login", json={"username": "test_viewer", "password": "ViewerSecret123!"})
    assert client.get("/auth/me").status_code == 200

    # Logout
    logout_res = client.post("/auth/logout")
    assert logout_res.status_code == 200

    # Attempting to access protected resource after logout must fail with 401
    assert client.get("/auth/me").status_code == 401
