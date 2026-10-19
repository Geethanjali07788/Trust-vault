import sqlite3
import pytest
from app.services.db import get_db, init_db

def test_database_initialization():
    """Verify that all 4 required tables and indexes are created properly."""
    conn = init_db(db_path=":memory:")
    cursor = conn.cursor()
    
    # Query SQLite master table for all created tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cursor.fetchall()}
    
    assert "users" in tables
    assert "documents" in tables
    assert "document_permissions" in tables
    assert "audit_logs" in tables
    conn.close()


def test_foreign_key_enforcement():
    """Verify that foreign keys prevent orphaned documents without an existing user."""
    conn = init_db(db_path=":memory:")
    cursor = conn.cursor()
    
    # Attempting to insert a document with owner_id = 999 (non-existent user) must fail!
    with pytest.raises(sqlite3.IntegrityError):
        cursor.execute(
            """
            INSERT INTO documents (title, storage_name, original_filename, file_size, mime_type, owner_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("Test Doc", "uuid-1234", "test.pdf", 1024, "application/pdf", 999)
        )
        conn.commit()
    conn.close()


def test_user_role_check_constraint():
    """Verify that the database rejects invalid roles not in ('admin', 'owner', 'viewer')."""
    conn = init_db(db_path=":memory:")
    cursor = conn.cursor()
    
    # Inserting valid roles works
    cursor.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
        ("alice", "alice@example.com", "hash123", "owner")
    )
    conn.commit()
    
    # Inserting invalid role must fail check constraint
    with pytest.raises(sqlite3.IntegrityError):
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("hacker", "hacker@example.com", "hash123", "superadmin")
        )
        conn.commit()
    conn.close()


def test_unique_document_permission():
    """Verify that a user cannot have duplicate conflicting permission rows for the same document."""
    conn = init_db(db_path=":memory:")
    cursor = conn.cursor()
    
    # Create 2 users
    cursor.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                   ("owner1", "owner1@example.com", "hash", "owner"))
    cursor.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                   ("viewer1", "viewer1@example.com", "hash", "viewer"))
    
    # Create document
    cursor.execute("""
        INSERT INTO documents (title, storage_name, original_filename, file_size, mime_type, owner_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("Financial Report", "uuid-fin", "report.pdf", 2048, "application/pdf", 1))
    
    # Grant 'read' permission
    cursor.execute("""
        INSERT INTO document_permissions (doc_id, user_id, permission_level, granted_by)
        VALUES (?, ?, ?, ?)
    """, (1, 2, "read", 1))
    conn.commit()
    
    # Attempting to insert another permission row for the same (doc_id, user_id) must fail UNIQUE constraint
    with pytest.raises(sqlite3.IntegrityError):
        cursor.execute("""
            INSERT INTO document_permissions (doc_id, user_id, permission_level, granted_by)
            VALUES (?, ?, ?, ?)
        """, (1, 2, "edit", 1))
        conn.commit()
    conn.close()
