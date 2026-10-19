import sqlite3
from app.services.db import get_db

VALID_PERMISSIONS = {"read", "edit"}

def create_document(title, description, category, storage_name, original_filename, file_size, mime_type, owner_id):
    """
    Inserts a newly vaulted document into the database.
    """
    title = (title or "").strip()
    if not title:
        raise ValueError("Document title is required.")
    if len(title) > 150:
        raise ValueError("Document title cannot exceed 150 characters.")

    category = (category or "General").strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO documents (
            title, description, category, storage_name,
            original_filename, file_size, mime_type, owner_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (title, description, category, storage_name, original_filename, file_size, mime_type, owner_id)
    )
    conn.commit()
    return cursor.lastrowid


def get_document_by_id(doc_id, include_deleted=False):
    """
    Retrieves a single document joined with owner username.
    """
    conn = get_db()
    cursor = conn.cursor()
    query = """
        SELECT d.*, u.username as owner_username, u.email as owner_email
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE d.id = ?
    """
    if not include_deleted:
        query += " AND d.is_deleted = 0"

    cursor.execute(query, (doc_id,))
    return cursor.fetchone()


def get_user_documents(owner_id):
    """
    Retrieves all non-deleted documents owned by a specific user.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT d.*, u.username as owner_username
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE d.owner_id = ? AND d.is_deleted = 0
        ORDER BY d.created_at DESC
        """,
        (owner_id,)
    )
    return cursor.fetchall()


def get_accessible_documents(user_id, user_role):
    """
    Retrieves all documents a user has permission to see.
    - Admin: all non-deleted documents in the system.
    - Owner/Viewer: documents owned by the user + documents explicitly shared with the user.
    """
    conn = get_db()
    cursor = conn.cursor()

    if user_role == "admin":
        cursor.execute(
            """
            SELECT d.*, u.username as owner_username, 'admin' as user_access_level
            FROM documents d
            JOIN users u ON d.owner_id = u.id
            WHERE d.is_deleted = 0
            ORDER BY d.created_at DESC
            """
        )
        return cursor.fetchall()

    # User's own documents + documents granted via document_permissions
    cursor.execute(
        """
        SELECT DISTINCT d.*, u.username as owner_username,
            CASE 
                WHEN d.owner_id = ? THEN 'owner'
                ELSE dp.permission_level
            END as user_access_level
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_permissions dp ON d.id = dp.doc_id AND dp.user_id = ?
        WHERE d.is_deleted = 0 AND (d.owner_id = ? OR dp.user_id = ?)
        ORDER BY d.created_at DESC
        """,
        (user_id, user_id, user_id, user_id)
    )
    return cursor.fetchall()


def check_document_permission(doc_id, user_id, user_role, required_level="read"):
    """
    Dynamic server-side authorization check for document operations.
    
    Security Controls:
    - Never caches permissions in client tokens.
    - Checks database dynamically on every access.
    - Enforces hierarchy: Owner has full control; Edit includes Read; Read is read-only.
    
    Returns:
        tuple: (has_permission: bool, access_tier: str or None, reason: str)
    """
    doc = get_document_by_id(doc_id)
    if not doc:
        return False, None, "Document not found or has been deleted."

    # 1. System Administrator Access
    if user_role == "admin":
        return True, "admin", "System administrator access granted."

    # 2. Document Owner Access (Owner has full rights)
    if doc["owner_id"] == user_id:
        return True, "owner", "Document owner full access granted."

    # 3. Check Granular Permissions (document_permissions table)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT permission_level FROM document_permissions WHERE doc_id = ? AND user_id = ?",
        (doc_id, user_id)
    )
    perm_row = cursor.fetchone()

    if not perm_row:
        return False, None, "Access denied: You have not been granted access to this document."

    granted_level = perm_row["permission_level"]

    if required_level == "read":
        # Both 'read' and 'edit' permissions can read/download
        if granted_level in ("read", "edit"):
            return True, granted_level, f"Granted '{granted_level}' access."
    elif required_level == "edit":
        # Only 'edit' permission can edit
        if granted_level == "edit":
            return True, "edit", "Granted 'edit' access."
        else:
            return False, granted_level, "Access denied: Edit permission required, but you only have read permission."
    elif required_level == "owner":
        # Only the actual owner or admin can perform owner actions (grant/revoke/delete)
        return False, granted_level, "Access denied: Only the document owner can perform this action."

    return False, None, "Access denied: Insufficient permissions."


def grant_document_permission(doc_id, target_user_id, permission_level, granted_by_user_id):
    """
    Grants or updates a named user's permission for a document.
    """
    if permission_level not in VALID_PERMISSIONS:
        raise ValueError(f"Invalid permission level '{permission_level}'. Must be 'read' or 'edit'.")

    doc = get_document_by_id(doc_id)
    if not doc:
        raise ValueError("Document not found.")

    if doc["owner_id"] == target_user_id:
        raise ValueError("Cannot grant permission to the document owner (owner already has full access).")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO document_permissions (doc_id, user_id, permission_level, granted_by)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(doc_id, user_id) DO UPDATE SET
            permission_level = excluded.permission_level,
            granted_by = excluded.granted_by,
            granted_at = CURRENT_TIMESTAMP
        """,
        (doc_id, target_user_id, permission_level, granted_by_user_id)
    )
    conn.commit()


def revoke_document_permission(doc_id, target_user_id):
    """
    Instantly revokes a user's permission for a document.
    Takes effect immediately on the user's next request.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM document_permissions WHERE doc_id = ? AND user_id = ?",
        (doc_id, target_user_id)
    )
    conn.commit()
    return cursor.rowcount > 0


def get_document_permissions(doc_id):
    """
    Returns all users who have been granted access to this document.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT dp.*, u.username, u.email, granter.username as granted_by_username
        FROM document_permissions dp
        JOIN users u ON dp.user_id = u.id
        JOIN users granter ON dp.granted_by = granter.id
        WHERE dp.doc_id = ?
        ORDER BY dp.granted_at DESC
        """,
        (doc_id,)
    )
    return cursor.fetchall()


def update_document_metadata(doc_id, title, description, category):
    """Updates non-destructive metadata of a document."""
    title = (title or "").strip()
    if not title:
        raise ValueError("Document title cannot be empty.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE documents
        SET title = ?, description = ?, category = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND is_deleted = 0
        """,
        (title, description, category, doc_id)
    )
    conn.commit()
    return cursor.rowcount > 0


def soft_delete_document(doc_id):
    """
    Marks a document as deleted without immediately wiping audit or metadata history.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE documents SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (doc_id,)
    )
    conn.commit()
    return cursor.rowcount > 0


def search_documents(user_id, user_role, query=None, owner_username=None, category=None, date_from=None, date_to=None):
    """
    Searches documents with multi-field filtering, strictly scoped to permitted documents.
    
    Security Controls:
    - Never leaks documents the user is not authorized to see.
    - Admins see all non-deleted documents in the system index.
    - Owners/Viewers see ONLY their own documents or documents explicitly granted via document_permissions.
    - Parameterized SQL prevents SQL injection across all filter criteria.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT DISTINCT d.*, u.username as owner_username,
            CASE 
                WHEN d.owner_id = ? THEN 'owner'
                ELSE dp.permission_level
            END as user_access_level
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_permissions dp ON d.id = dp.doc_id AND dp.user_id = ?
        WHERE d.is_deleted = 0
    """
    params = [user_id, user_id]

    if user_role != "admin":
        sql += " AND (d.owner_id = ? OR dp.user_id = ?)"
        params.extend([user_id, user_id])

    if query and query.strip():
        sql += " AND (d.title LIKE ? OR d.description LIKE ? OR d.original_filename LIKE ?)"
        q_param = f"%{query.strip()}%"
        params.extend([q_param, q_param, q_param])

    if owner_username and owner_username.strip():
        sql += " AND u.username LIKE ?"
        params.append(f"%{owner_username.strip()}%")

    if category and category.strip():
        sql += " AND d.category = ?"
        params.append(category.strip())

    if date_from and date_from.strip():
        sql += " AND d.created_at >= ?"
        params.append(date_from.strip())

    if date_to and date_to.strip():
        # Append end-of-day timestamp if just date string was passed
        date_to_val = date_to.strip()
        if len(date_to_val) == 10:
            date_to_val += " 23:59:59"
        sql += " AND d.created_at <= ?"
        params.append(date_to_val)

    sql += " ORDER BY d.created_at DESC"

    cursor.execute(sql, tuple(params))
    return cursor.fetchall()

