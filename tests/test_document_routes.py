import io
import json
import pytest
from app.services.audit import get_audit_logs, verify_audit_chain
from config import TestConfig
from app import create_app
from app.services.db import init_db
from app.models.user import create_user

def _login(client, username, password):
    """Helper to log in a user and establish session cookies."""
    return client.post("/auth/login", json={"username": username, "password": password})

def _upload_test_pdf(client, title="Financial Strategy", filename="report.pdf"):
    """Helper to upload a valid test PDF file."""
    data = {
        "title": title,
        "description": "Quarterly financial document",
        "category": "Finance",
        "file": (io.BytesIO(b"%PDF-1.4 test document content bytes"), filename)
    }
    return client.post("/documents/upload", data=data, content_type="multipart/form-data")


# ------------------ 1. Upload & Download Tests ------------------

def test_document_upload_success(client, app, seed_users):
    """Verify owner can upload a valid document and audit log records DOC_UPLOAD."""
    _login(client, "test_owner", "OwnerSecret123!")
    res = _upload_test_pdf(client, "Executive Brief", "brief.pdf")
    assert res.status_code == 201

    data = res.get_json()
    doc_id = data["document"]["id"]
    assert doc_id > 0
    assert data["document"]["original_filename"] == "brief.pdf"

    # Verify audit event
    with app.app_context():
        logs = get_audit_logs(event_type="DOC_UPLOAD", doc_id=doc_id)
        assert len(logs) == 1
        assert logs[0]["username"] == "test_owner"


def test_document_upload_invalid_file(client, app, seed_users):
    """SECURITY TEST: Executable upload must be rejected and logged as DENIED_ACCESS."""
    _login(client, "test_owner", "OwnerSecret123!")
    bad_data = {
        "title": "Malware",
        "file": (io.BytesIO(b"MZ\x90\x00executable content"), "malware.exe")
    }
    res = client.post("/documents/upload", data=bad_data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "File validation failed" in res.get_json()["error"]

    with app.app_context():
        logs = get_audit_logs(event_type="DENIED_ACCESS")
        assert len(logs) >= 1
        assert "upload_validation_failed" in logs[0]["details"]


def test_document_download_owner(client, app, seed_users):
    """Owner downloads their document; assert proper headers and audit logging."""
    _login(client, "test_owner", "OwnerSecret123!")
    upload_res = _upload_test_pdf(client, "Tax Records", "tax.pdf")
    doc_id = upload_res.get_json()["document"]["id"]

    download_res = client.get(f"/documents/{doc_id}/download")
    assert download_res.status_code == 200
    assert download_res.data == b"%PDF-1.4 test document content bytes"
    assert download_res.headers["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in download_res.headers["Cache-Control"]

    # Verify audit event
    with app.app_context():
        logs = get_audit_logs(event_type="DOC_DOWNLOAD", doc_id=doc_id)
        assert len(logs) == 1


# ------------------ 2. Negative Authorization (IDOR) Tests ------------------

def test_document_download_unauthorized_idor(client, app, seed_users):
    """
    SECURITY TEST (IDOR Prevention):
    Viewer attempts to download Owner's document without permission.
    MUST return 403 Forbidden and log DENIED_ACCESS.
    """
    # 1. Owner uploads private doc
    _login(client, "test_owner", "OwnerSecret123!")
    upload_res = _upload_test_pdf(client, "Secret Strategy", "secret.pdf")
    doc_id = upload_res.get_json()["document"]["id"]

    # 2. Viewer logs in and attempts IDOR
    _login(client, "test_viewer", "ViewerSecret123!")
    attack_res = client.get(f"/documents/{doc_id}/download")
    assert attack_res.status_code == 403

    # Verify DENIED_ACCESS audit log
    with app.app_context():
        logs = get_audit_logs(event_type="DENIED_ACCESS", doc_id=doc_id)
        assert len(logs) >= 1
        assert logs[0]["username"] == "test_viewer"
        assert "Access denied" in logs[0]["details"]


def test_denied_access_logging_with_nonexistent_doc_id(client, app, seed_users):
    """
    SECURITY TEST:
    Attacker probing arbitrary document ID (e.g. 99999) must be blocked
    and logged without crashing SQLite foreign keys.
    """
    _login(client, "test_viewer", "ViewerSecret123!")
    res = client.get("/documents/99999/download")
    assert res.status_code in (403, 404)

    with app.app_context():
        logs = get_audit_logs(event_type="DENIED_ACCESS")
        assert len(logs) >= 1


# ------------------ 3. Grant & Instant Revocation Tests ------------------

def test_permission_grant_and_immediate_revocation(client, seed_users):
    """
    SECURITY TEST:
    1. Owner grants 'read' to Viewer.
    2. Viewer downloads successfully.
    3. Owner revokes permission.
    4. Viewer is IMMEDIATELY blocked on next download attempt.
    """
    _login(client, "test_owner", "OwnerSecret123!")
    upload_res = _upload_test_pdf(client, "Shared Blueprints", "blueprints.pdf")
    doc_id = upload_res.get_json()["document"]["id"]

    # Step 1: Grant read
    grant_res = client.post(f"/documents/{doc_id}/permissions", json={
        "username": "test_viewer",
        "permission_level": "read"
    })
    assert grant_res.status_code == 200

    # Step 2: Viewer downloads
    _login(client, "test_viewer", "ViewerSecret123!")
    view_res = client.get(f"/documents/{doc_id}/download")
    assert view_res.status_code == 200

    # Step 3: Owner revokes
    _login(client, "test_owner", "OwnerSecret123!")
    revoke_res = client.delete(f"/documents/{doc_id}/permissions/{seed_users['viewer']['id']}")
    assert revoke_res.status_code == 200

    # Step 4: Viewer immediately denied
    _login(client, "test_viewer", "ViewerSecret123!")
    blocked_res = client.get(f"/documents/{doc_id}/download")
    assert blocked_res.status_code == 403


def test_non_owner_cannot_grant_permissions(client, seed_users):
    """SECURITY TEST: Non-owner cannot grant permissions to other users."""
    _login(client, "test_owner", "OwnerSecret123!")
    upload_res = _upload_test_pdf(client, "Private Vault Doc", "private.pdf")
    doc_id = upload_res.get_json()["document"]["id"]

    # Viewer attempts to grant permission to admin
    _login(client, "test_viewer", "ViewerSecret123!")
    res = client.post(f"/documents/{doc_id}/permissions", json={
        "username": "test_admin",
        "permission_level": "read"
    })
    assert res.status_code == 403


# ------------------ 4. Edit Permissions & Soft Delete ------------------

def test_document_edit_permissions(client, seed_users):
    """Read-only user cannot edit; edit-permitted user can update metadata."""
    _login(client, "test_owner", "OwnerSecret123!")
    upload_res = _upload_test_pdf(client, "Project Specs", "specs.pdf")
    doc_id = upload_res.get_json()["document"]["id"]

    # Grant read-only
    client.post(f"/documents/{doc_id}/permissions", json={
        "username": "test_viewer",
        "permission_level": "read"
    })

    # Viewer tries to edit -> 403 Forbidden
    _login(client, "test_viewer", "ViewerSecret123!")
    edit_fail = client.post(f"/documents/{doc_id}/edit", json={"title": "Hacked Title"})
    assert edit_fail.status_code == 403

    # Upgrade viewer to 'edit'
    _login(client, "test_owner", "OwnerSecret123!")
    client.post(f"/documents/{doc_id}/permissions", json={
        "username": "test_viewer",
        "permission_level": "edit"
    })

    # Viewer edits now -> 200 OK
    _login(client, "test_viewer", "ViewerSecret123!")
    edit_success = client.post(f"/documents/{doc_id}/edit", json={"title": "Updated Specs V2"})
    assert edit_success.status_code == 200


def test_soft_delete_and_inaccessibility(client, seed_users):
    """Soft deleted document is completely inaccessible afterward."""
    _login(client, "test_owner", "OwnerSecret123!")
    upload_res = _upload_test_pdf(client, "Old Record", "old.pdf")
    doc_id = upload_res.get_json()["document"]["id"]

    # Delete
    del_res = client.post(f"/documents/{doc_id}/delete")
    assert del_res.status_code == 200

    # Cannot download or view after deletion
    assert client.get(f"/documents/{doc_id}/download").status_code == 404
    assert client.get(f"/documents/{doc_id}").status_code == 404


# ------------------ 5. Permission Scoped Search ------------------

def test_permission_scoped_search(client, seed_users):
    """
    Search must strictly filter results based on user permissions.
    Viewer must NEVER see unshared documents in search.
    """
    _login(client, "test_owner", "OwnerSecret123!")
    _upload_test_pdf(client, "Confidential Financials Q3", "confidential.pdf")

    # Viewer searches -> 0 results
    _login(client, "test_viewer", "ViewerSecret123!")
    search_res = client.get("/documents/search?q=Financials")
    assert search_res.status_code == 200
    assert search_res.get_json()["count"] == 0


# ------------------ 6. CSRF Protection Tests ------------------

def test_csrf_rejection_and_acceptance(app, seed_users):
    """
    SECURITY TEST:
    When CSRF protection is active:
    - Missing CSRF token is rejected with 403 Forbidden.
    - Invalid CSRF token is rejected with 403 Forbidden.
    - Valid CSRF token is accepted.
    """
    # Create isolated client with CSRF enabled
    app.config["WTF_CSRF_ENABLED"] = True
    csrf_client = app.test_client()

    _login(csrf_client, "test_owner", "OwnerSecret123!")

    # 1. State-changing request without CSRF token -> REJECTED (403)
    res_no_csrf = csrf_client.post("/documents/1/edit", json={"title": "No CSRF"})
    assert res_no_csrf.status_code == 403
    assert "CSRF" in res_no_csrf.get_json()["error"]

    # 2. State-changing request with bogus CSRF token -> REJECTED (403)
    res_bad_csrf = csrf_client.post(
        "/documents/1/edit",
        json={"title": "Bad CSRF"},
        headers={"X-CSRF-Token": "invalid_bogus_token_12345"}
    )
    assert res_bad_csrf.status_code == 403

    # 3. Retrieve valid CSRF token from session
    token_res = csrf_client.get("/auth/csrf-token")
    assert token_res.status_code == 200
    valid_token = token_res.get_json()["csrf_token"]

    # 4. State-changing request with valid token -> Accepted (passes CSRF guard)
    upload_res = csrf_client.post(
        "/documents/upload",
        data={
            "title": "CSRF Safe Doc",
            "file": (io.BytesIO(b"%PDF-1.4 safe content"), "safe.pdf")
        },
        headers={"X-CSRF-Token": valid_token},
        content_type="multipart/form-data"
    )
    assert upload_res.status_code == 201

    # Reset config back
    app.config["WTF_CSRF_ENABLED"] = False
