import pytest
from app.services.audit import log_audit_event, get_audit_logs
from app.services.db import get_db

def _login(client, username, password):
    """Helper to log in a user and set session cookies."""
    return client.post("/auth/login", json={"username": username, "password": password})


def test_admin_endpoints_reject_unauthenticated(client):
    """SECURITY TEST: Unauthenticated requests to /admin/* must return 401."""
    assert client.get("/admin/stats").status_code == 401
    assert client.get("/admin/audit-logs").status_code == 401
    assert client.get("/admin/users").status_code == 401
    assert client.post("/admin/verify-audit-chain").status_code == 401


def test_admin_endpoints_reject_viewer_and_owner(client, app, seed_users):
    """
    SECURITY TEST (RBAC):
    Viewer and Owner must be blocked with 403 Forbidden on all admin endpoints,
    and a DENIED_ACCESS audit log must be recorded.
    """
    # 1. Viewer access attempt
    _login(client, "test_viewer", "ViewerSecret123!")
    res_viewer = client.get("/admin/stats")
    assert res_viewer.status_code == 403

    with app.app_context():
        logs = get_audit_logs(event_type="DENIED_ACCESS")
        assert len(logs) >= 1
        assert logs[0]["username"] == "test_viewer"

    # 2. Owner access attempt
    _login(client, "test_owner", "OwnerSecret123!")
    res_owner = client.get("/admin/audit-logs")
    assert res_owner.status_code == 403


def test_admin_stats_authorized(client, seed_users):
    """Admin accesses /admin/stats; assert accurate counts and metrics structure."""
    _login(client, "test_admin", "AdminSecret123!")
    res = client.get("/admin/stats")
    assert res.status_code == 200

    data = res.get_json()
    assert "users" in data
    assert "documents" in data
    assert "security" in data
    assert data["users"]["total"] >= 3
    assert data["users"]["admin"] >= 1
    assert data["users"]["owner"] >= 1
    assert data["users"]["viewer"] >= 1


def test_admin_audit_logs_pagination(client, app, seed_users):
    """Verify paginated retrieval of audit logs."""
    _login(client, "test_admin", "AdminSecret123!")

    # Seed 12 audit events
    with app.app_context():
        admin_id = seed_users["admin"]["id"]
        for i in range(12):
            log_audit_event("TEST_EVENT", user_id=admin_id, username="test_admin", details=f"Log event #{i}")

    # Request page 1 with per_page=5
    res1 = client.get("/admin/audit-logs?page=1&per_page=5")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert len(data1["logs"]) == 5
    assert data1["pagination"]["page"] == 1
    assert data1["pagination"]["per_page"] == 5
    assert data1["pagination"]["total_records"] >= 12
    assert data1["pagination"]["total_pages"] >= 3

    # Request page 2
    res2 = client.get("/admin/audit-logs?page=2&per_page=5")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert len(data2["logs"]) == 5
    # Verify different records
    assert data1["logs"][0]["id"] != data2["logs"][0]["id"]


def test_admin_audit_logs_filtering(client, app, seed_users):
    """Verify audit logs filtering by event_type."""
    _login(client, "test_admin", "AdminSecret123!")

    with app.app_context():
        admin_id = seed_users["admin"]["id"]
        log_audit_event("SPECIFIC_ALERT", user_id=admin_id, username="test_admin", details="High alert")
        log_audit_event("REGULAR_ACTION", user_id=admin_id, username="test_admin", details="Routine")

    res = client.get("/admin/audit-logs?event_type=SPECIFIC_ALERT")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["logs"]) >= 1
    for log in data["logs"]:
        assert log["event_type"] == "SPECIFIC_ALERT"


def test_admin_verify_audit_chain_authorized(client, app, seed_users):
    """Admin triggers audit chain verification; assert success on clean chain."""
    _login(client, "test_admin", "AdminSecret123!")

    with app.app_context():
        log_audit_event("INIT_EVENT_1", seed_users["admin"]["id"], "test_admin", details="Genesis block test")
        log_audit_event("INIT_EVENT_2", seed_users["admin"]["id"], "test_admin", details="Second block test")

    res = client.post("/admin/verify-audit-chain")
    assert res.status_code == 200

    data = res.get_json()
    assert data["is_valid"] is True
    assert "verified intact" in data["message"] or "chain is valid" in data["message"]


def test_admin_verify_audit_chain_detects_tampering(client, app, seed_users):
    """
    SECURITY TEST:
    If a database record is modified, the admin verification endpoint
    MUST return is_valid=False and identify the compromised record.
    """
    _login(client, "test_admin", "AdminSecret123!")

    with app.app_context():
        # Ensure we have at least 2 logs
        log_audit_event("SAFE_EVENT_1", seed_users["admin"]["id"], "test_admin", details="Clean")
        log_audit_event("SAFE_EVENT_2", seed_users["admin"]["id"], "test_admin", details="Clean")

        # Attack: Modify row 2 directly in SQLite
        conn = get_db()
        conn.execute("UPDATE audit_logs SET details = 'HACKED_DATA' WHERE id = 2")
        conn.commit()

    # Trigger admin verification
    res = client.post("/admin/verify-audit-chain")
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_valid"] is False
    assert data["compromised_id"] == 2
    assert "Tampering detected at log ID 2" in data["message"]


def test_admin_verify_audit_chain_csrf_enforcement(app, seed_users):
    """
    SECURITY TEST:
    When CSRF is enabled, POST /admin/verify-audit-chain without CSRF token
    MUST be rejected with 403 Forbidden.
    """
    app.config["WTF_CSRF_ENABLED"] = True
    csrf_client = app.test_client()

    _login(csrf_client, "test_admin", "AdminSecret123!")

    # 1. Without token -> 403 Forbidden
    res_no_token = csrf_client.post("/admin/verify-audit-chain")
    assert res_no_token.status_code == 403

    # 2. Get valid CSRF token
    token_res = csrf_client.get("/auth/csrf-token")
    valid_token = token_res.get_json()["csrf_token"]

    # 3. With token -> 200 OK
    res_valid = csrf_client.post(
        "/admin/verify-audit-chain",
        headers={"X-CSRF-Token": valid_token}
    )
    assert res_valid.status_code == 200

    app.config["WTF_CSRF_ENABLED"] = False


def test_admin_list_users_omits_password_hash(client, seed_users):
    """
    SECURITY TEST:
    /admin/users must return registered users but NEVER expose password_hash!
    """
    _login(client, "test_admin", "AdminSecret123!")
    res = client.get("/admin/users")
    assert res.status_code == 200

    data = res.get_json()
    assert data["count"] >= 3
    for u in data["users"]:
        assert "password_hash" not in u
        assert "password" not in u
        assert "username" in u
        assert "role" in u
