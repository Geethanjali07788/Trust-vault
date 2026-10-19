import io
import pytest

def _login(client, username, password):
    """Helper to log in and set session cookies."""
    return client.post("/auth/login", json={"username": username, "password": password})


def test_root_redirect_unauthenticated(client):
    """GET / redirects unauthenticated visitors to /auth/login."""
    res = client.get("/")
    assert res.status_code == 302
    assert "/auth/login" in res.headers["Location"]


def test_login_page_renders(client):
    """GET /auth/login returns 200 and renders HTML login/register forms."""
    res = client.get("/auth/login")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Welcome to TrustVault" in html
    assert "Sign In" in html
    assert "Create Account" in html
    assert "Demo Credentials" in html
    assert "csrf-token" in html


def test_documents_index_renders_for_owner(client, seed_users):
    """GET /documents/ with Accept: text/html renders document vault table."""
    _login(client, "test_owner", "OwnerSecret123!")

    res = client.get("/documents/", headers={"Accept": "text/html"})
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Document Vault" in html
    assert "Upload Document" in html
    assert "test_owner" in html


def test_document_details_page_renders(client, seed_users):
    """GET /documents/<id> renders document details and ACL management for owner."""
    _login(client, "test_owner", "OwnerSecret123!")

    # Upload sample doc
    upload_res = client.post("/documents/upload", data={
        "title": "Strategy Plan 2026",
        "category": "Engineering",
        "file": (io.BytesIO(b"%PDF-1.4 sample PDF bytes"), "strategy.pdf")
    }, content_type="multipart/form-data")
    doc_id = upload_res.get_json()["document"]["id"]

    # View details HTML
    res = client.get(f"/documents/{doc_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Strategy Plan 2026" in html
    assert "Access Control List (ACL)" in html
    assert "Download File" in html
    assert "Grant Document Access" in html


def test_admin_dashboard_renders_for_admin(client, seed_users):
    """GET /admin/dashboard renders full oversight metrics and audit verifier for admin."""
    _login(client, "test_admin", "AdminSecret123!")

    res = client.get("/admin/dashboard")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Administrator Oversight Console" in html
    assert "Tamper-Evident Audit Trail" in html
    assert "Verify Hash Chain Integrity Now" in html
    assert "Total Users" in html
    assert "Registered User Directory" in html


def test_admin_dashboard_rejects_viewer(client, seed_users):
    """SECURITY TEST: Non-admin viewer cannot render /admin/dashboard."""
    _login(client, "test_viewer", "ViewerSecret123!")
    res = client.get("/admin/dashboard")
    assert res.status_code == 403
