import pytest
from app.services.audit import (
    log_audit_event,
    verify_audit_chain,
    get_audit_logs,
    compute_log_hash,
    GENESIS_HASH
)
from app.models.document import create_document
from app.services.db import get_db

def _create_sample_doc(owner_id):
    """Helper to create a sample document in the test database."""
    return create_document(
        title="Audit Test Document",
        description="Used for audit trail testing",
        category="General",
        storage_name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat",
        original_filename="sample.pdf",
        file_size=1024,
        mime_type="application/pdf",
        owner_id=owner_id
    )

def test_audit_event_creation(app, seed_users):
    """
    Verify that audit events are recorded with proper metadata,
    Genesis linkage, and SHA-256 current_hash.
    """
    with app.app_context():
        owner = seed_users["owner"]
        doc_id = _create_sample_doc(owner["id"])

        # Log first event (Upload)
        event1 = log_audit_event(
            event_type="DOC_UPLOAD",
            user_id=owner["id"],
            username=owner["username"],
            doc_id=doc_id,
            details={"filename": "financials.pdf", "size": 1024},
            ip_address="10.0.0.1",
            user_agent="TrustVaultClient/1.0"
        )

        assert event1["id"] == 1
        assert event1["event_type"] == "DOC_UPLOAD"
        assert event1["prev_hash"] == GENESIS_HASH
        assert len(event1["current_hash"]) == 64

        # Log second event (Download)
        event2 = log_audit_event(
            event_type="DOC_DOWNLOAD",
            user_id=owner["id"],
            username=owner["username"],
            doc_id=doc_id,
            details={"action": "stream_download"},
            ip_address="10.0.0.1"
        )

        assert event2["id"] == 2
        # Crucial chain link: event2.prev_hash MUST match event1.current_hash
        assert event2["prev_hash"] == event1["current_hash"]


def test_audit_chain_validity(app, seed_users):
    """Verify that an untampered sequence of audit events passes verification."""
    with app.app_context():
        owner = seed_users["owner"]
        viewer = seed_users["viewer"]
        doc_id = _create_sample_doc(owner["id"])

        # Log a realistic lifecycle of events
        log_audit_event("DOC_UPLOAD", owner["id"], owner["username"], doc_id, "Quarterly report uploaded")
        log_audit_event("PERM_GRANT", owner["id"], owner["username"], doc_id, {"target_user": viewer["username"], "level": "read"})
        log_audit_event("DOC_DOWNLOAD", viewer["id"], viewer["username"], doc_id, "Downloaded by viewer")
        log_audit_event("PERM_REVOKE", owner["id"], owner["username"], doc_id, {"target_user": viewer["username"]})
        log_audit_event("DENIED_ACCESS", viewer["id"], viewer["username"], doc_id, "Attempted download after revocation")

        is_valid, message, compromised_id = verify_audit_chain()
        assert is_valid is True
        assert compromised_id is None
        assert "verified intact" in message


def test_tamper_detection_modified_content(app, seed_users):
    """
    SECURITY TEST:
    If an attacker modifies a record's details or metadata directly in the database,
    verify_audit_chain() MUST detect it and identify the exact compromised record!
    """
    with app.app_context():
        owner = seed_users["owner"]
        viewer = seed_users["viewer"]
        doc_id = _create_sample_doc(owner["id"])

        log_audit_event("DOC_UPLOAD", owner["id"], owner["username"], doc_id, "Legitimate upload")
        log_audit_event("DOC_DOWNLOAD", viewer["id"], viewer["username"], doc_id, "Downloaded by viewer")
        log_audit_event("DOC_EDIT", owner["id"], owner["username"], doc_id, "Title updated")

        # Attack: Attacker tampers with row 2 directly in SQLite to conceal an activity
        conn = get_db()
        conn.execute("UPDATE audit_logs SET details = 'Innocent harmless view' WHERE id = 2")
        conn.commit()

        # Chain verification MUST fail
        is_valid, message, compromised_id = verify_audit_chain()
        assert is_valid is False
        assert compromised_id == 2
        assert "Tampering detected at log ID 2" in message


def test_tamper_detection_deleted_row(app, seed_users):
    """
    SECURITY TEST:
    If an attacker deletes an audit log row from the database,
    the hash chain is broken, and verify_audit_chain() MUST catch it.
    """
    with app.app_context():
        owner = seed_users["owner"]
        doc_id = _create_sample_doc(owner["id"])

        log_audit_event("DOC_UPLOAD", owner["id"], owner["username"], doc_id, "Event 1")
        log_audit_event("DOC_DOWNLOAD", owner["id"], owner["username"], doc_id, "Event 2")
        log_audit_event("DOC_DELETE", owner["id"], owner["username"], doc_id, "Event 3")

        # Attack: Attacker deletes row 2
        conn = get_db()
        conn.execute("DELETE FROM audit_logs WHERE id = 2")
        conn.commit()

        # Verification must fail at row 3 because row 3's prev_hash points to deleted row 2
        is_valid, message, compromised_id = verify_audit_chain()
        assert is_valid is False
        assert compromised_id == 3
        assert "Broken chain link" in message


def test_denied_access_logging_with_unregistered_doc_id(app, seed_users):
    """
    SECURITY TEST (Requirement 6):
    Denied access attempts on non-existent or probed document IDs (e.g. IDOR probe 99)
    must NOT crash the database and must safely record probe metadata.
    """
    with app.app_context():
        viewer = seed_users["viewer"]

        denied_entry = log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=viewer["id"],
            username=viewer["username"],
            doc_id=99,  # Document 99 does NOT exist in DB (simulating attacker IDOR probe)
            details={"reason": "IDOR attempt on non-existent document", "probe_doc_id": 99},
            ip_address="192.168.1.150",
            user_agent="curl/7.68.0"
        )

        assert denied_entry["event_type"] == "DENIED_ACCESS"
        assert denied_entry["ip_address"] == "192.168.1.150"
        assert denied_entry["user_id"] == viewer["id"]

        logs = get_audit_logs(event_type="DENIED_ACCESS")
        assert len(logs) == 1
        assert logs[0]["user_id"] == viewer["id"]
        # The probe doc id is preserved in details
        assert "probe_doc_id" in logs[0]["details"]

        # Chain verification must still be 100% valid
        is_valid, _, _ = verify_audit_chain()
        assert is_valid is True


def test_canonical_serialization_consistency():
    """
    Verify that dictionary key insertion order does NOT alter the computed hash.
    Deterministic canonical sorting ensures reproducible hashes.
    """
    dict1 = {"action": "download", "ip": "1.2.3.4", "status": "success"}
    dict2 = {"status": "success", "action": "download", "ip": "1.2.3.4"}

    hash1 = compute_log_hash("0"*64, "2026-10-19T12:00:00Z", "DOC_VIEW", 1, "alice", "1.1.1.1", "Agent", 10, dict1)
    hash2 = compute_log_hash("0"*64, "2026-10-19T12:00:00Z", "DOC_VIEW", 1, "alice", "1.1.1.1", "Agent", 10, dict2)

    assert hash1 == hash2
