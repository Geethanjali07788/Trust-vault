import pytest
from pathlib import Path
from app.services.file_validator import validate_file, sanitize_filename
from app.services.vault import save_to_vault, get_vault_file_path, is_safe_path
from app.models.document import (
    create_document,
    get_document_by_id,
    check_document_permission,
    grant_document_permission,
    revoke_document_permission,
    get_accessible_documents
)

# ----------------- 1. File Validator Tests -----------------

def test_valid_pdf_file():
    """Verify a legitimate PDF file with %PDF- header is accepted."""
    valid_pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    is_valid, error, mime = validate_file(valid_pdf_content, "quarterly_report.pdf")
    assert is_valid is True
    assert error is None
    assert mime == "application/pdf"


def test_valid_png_file():
    """Verify a legitimate PNG image with standard magic header is accepted."""
    valid_png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    is_valid, error, mime = validate_file(valid_png_content, "chart.png")
    assert is_valid is True
    assert error is None
    assert mime == "image/png"


def test_valid_text_file():
    """Verify clean UTF-8 plain text file is accepted."""
    valid_txt_content = b"This is a secure audit note for TrustVault."
    is_valid, error, mime = validate_file(valid_txt_content, "notes.txt")
    assert is_valid is True
    assert error is None
    assert mime == "text/plain"


def test_invalid_file_extension():
    """SECURITY TEST: Dangerous extensions like .exe, .sh, .py must be rejected."""
    content = b"echo 'hello'"
    for bad_name in ["script.py", "malware.exe", "exploit.sh", "backdoor.php"]:
        is_valid, error, _ = validate_file(content, bad_name)
        assert is_valid is False
        assert "not permitted" in error


def test_oversized_file_rejected():
    """SECURITY TEST: File exceeding 15MB limit must be rejected."""
    # 15MB + 1 byte
    oversized_bytes = b"0" * (15 * 1024 * 1024 + 1)
    is_valid, error, _ = validate_file(oversized_bytes, "large_file.txt")
    assert is_valid is False
    assert "exceeds maximum allowed limit" in error


def test_mismatched_signature_executable_disguised_as_pdf():
    """
    SECURITY TEST: An executable (MZ header) renamed to .pdf MUST be caught and rejected!
    """
    fake_pdf_content = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50
    is_valid, error, _ = validate_file(fake_pdf_content, "fake_invoice.pdf")
    assert is_valid is False
    assert "executable" in error.lower() or "signature mismatch" in error.lower()


def test_mismatched_signature_fake_png():
    """SECURITY TEST: Random text renamed to .png must fail signature inspection."""
    fake_png_content = b"Hello world, I am just plain text pretending to be PNG"
    is_valid, error, _ = validate_file(fake_png_content, "fake_image.png")
    assert is_valid is False
    assert "signature mismatch" in error.lower()


def test_text_file_with_null_bytes_rejected():
    """SECURITY TEST: Disguised binary data inside a .txt file must be rejected."""
    null_byte_content = b"Safe text start\x00\x01\x02binary_junk"
    is_valid, error, _ = validate_file(null_byte_content, "disguised.txt")
    assert is_valid is False
    assert "null bytes" in error.lower()


# ----------------- 2. Path Traversal & Vault Storage Tests -----------------

def test_sanitize_filename_prevents_path_traversal():
    """SECURITY TEST: Directory traversal sequences must be stripped from filenames."""
    dirty_names = [
        ("../../etc/passwd", "etc_passwd"),
        ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
        ("../../../secret.pdf", "secret.pdf"),
        ("normal_document.pdf", "normal_document.pdf"),
    ]
    for dirty, expected in dirty_names:
        cleaned = sanitize_filename(dirty)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert ".." not in cleaned


def test_vault_storage_uses_uuid_and_stays_in_vault(app):
    """
    SECURITY TEST:
    Uploaded files must be saved with a random UUID hex filename in the private vault directory.
    """
    with app.app_context():
        content = b"%PDF-1.4 test document content"
        storage_name, file_size = save_to_vault(content)

        # Storage name must be 32 hex chars + .dat
        assert storage_name.endswith(".dat")
        assert len(storage_name) == 36  # 32 hex chars + 4 for '.dat'

        # Must reside safely inside vault directory
        file_path = get_vault_file_path(storage_name)
        assert file_path.exists()
        assert file_path.read_bytes() == content

        # Path traversal checks
        vault_dir = file_path.parent
        assert is_safe_path(vault_dir, file_path) is True
        assert is_safe_path(vault_dir, Path("C:/windows/system32/calc.exe")) is False


# ----------------- 3. Document Authorization & Access Control Tests -----------------

def test_unauthorized_user_cannot_access_document(app, seed_users):
    """
    SECURITY TEST (Negative Authorization):
    User B cannot access or edit User A's document without permission.
    """
    with app.app_context():
        owner_id = seed_users["owner"]["id"]
        viewer_id = seed_users["viewer"]["id"]

        # Owner creates document
        doc_id = create_document(
            title="Owner Confidential Strategy",
            description="Private financial strategy",
            category="Finance",
            storage_name="0123456789abcdef0123456789abcdef.dat",
            original_filename="strategy.pdf",
            file_size=2048,
            mime_type="application/pdf",
            owner_id=owner_id
        )

        # 1. Viewer attempts to read -> MUST BE DENIED
        can_read, tier, reason = check_document_permission(doc_id, viewer_id, "viewer", required_level="read")
        assert can_read is False
        assert "Access denied" in reason

        # 2. Viewer attempts to edit -> MUST BE DENIED
        can_edit, tier, reason = check_document_permission(doc_id, viewer_id, "viewer", required_level="edit")
        assert can_edit is False

        # 3. Owner checks permission -> GRANTED
        can_owner, tier, _ = check_document_permission(doc_id, owner_id, "owner", required_level="read")
        assert can_owner is True
        assert tier == "owner"


def test_permission_grant_and_instant_revocation(app, seed_users):
    """
    SECURITY TEST:
    1. Owner grants 'read' -> Viewer can read, cannot edit.
    2. Owner grants 'edit' -> Viewer can edit.
    3. Owner revokes permission -> Viewer immediately denied on next check!
    """
    with app.app_context():
        owner_id = seed_users["owner"]["id"]
        viewer_id = seed_users["viewer"]["id"]

        doc_id = create_document(
            title="Shared Project Specs",
            description="Collaborative specs",
            category="Engineering",
            storage_name="abcdef0123456789abcdef0123456789.dat",
            original_filename="specs.pdf",
            file_size=4096,
            mime_type="application/pdf",
            owner_id=owner_id
        )

        # Step 1: Owner grants 'read' permission to viewer
        grant_document_permission(doc_id, viewer_id, "read", granted_by_user_id=owner_id)

        can_read, tier, _ = check_document_permission(doc_id, viewer_id, "viewer", required_level="read")
        assert can_read is True
        assert tier == "read"

        # Read-only user cannot edit!
        can_edit, _, reason = check_document_permission(doc_id, viewer_id, "viewer", required_level="edit")
        assert can_edit is False
        assert "Edit permission required" in reason

        # Step 2: Owner upgrades permission to 'edit'
        grant_document_permission(doc_id, viewer_id, "edit", granted_by_user_id=owner_id)
        can_edit_now, tier, _ = check_document_permission(doc_id, viewer_id, "viewer", required_level="edit")
        assert can_edit_now is True
        assert tier == "edit"

        # Step 3: Owner revokes permission
        revoked = revoke_document_permission(doc_id, viewer_id)
        assert revoked is True

        # IMMEDIATE REVOCATION TEST: Next check MUST fail!
        can_read_after_revoke, _, _ = check_document_permission(doc_id, viewer_id, "viewer", required_level="read")
        assert can_read_after_revoke is False


def test_accessible_documents_scoping(app, seed_users):
    """
    SECURITY TEST:
    get_accessible_documents must only return documents owned or explicitly granted.
    It must NEVER leak another user's unshared document.
    """
    with app.app_context():
        owner_id = seed_users["owner"]["id"]
        viewer_id = seed_users["viewer"]["id"]
        admin_id = seed_users["admin"]["id"]

        # Document 1: Private to owner
        doc1_id = create_document("Doc 1 (Private)", "", "General", "11111111111111111111111111111111.dat", "doc1.pdf", 100, "application/pdf", owner_id)
        # Document 2: Shared with viewer
        doc2_id = create_document("Doc 2 (Shared)", "", "General", "22222222222222222222222222222222.dat", "doc2.pdf", 200, "application/pdf", owner_id)
        grant_document_permission(doc2_id, viewer_id, "read", owner_id)

        # Viewer accesses their list
        viewer_docs = get_accessible_documents(viewer_id, "viewer")
        viewer_doc_ids = [d["id"] for d in viewer_docs]

        # Viewer MUST see doc2, MUST NOT see doc1!
        assert doc2_id in viewer_doc_ids
        assert doc1_id not in viewer_doc_ids

        # Admin accesses list -> Admin sees both doc1 and doc2
        admin_docs = get_accessible_documents(admin_id, "admin")
        admin_doc_ids = [d["id"] for d in admin_docs]
        assert doc1_id in admin_doc_ids
        assert doc2_id in admin_doc_ids
