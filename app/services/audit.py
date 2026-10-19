import json
import hashlib
from datetime import datetime, timezone
from flask import has_request_context, request
from app.services.db import get_db

# Genesis hash for the initial block in the tamper-evident chain (64 hexadecimal zeros)
GENESIS_HASH = "0" * 64

def canonicalize_details(details):
    """
    Converts event details into a deterministic canonical string.
    Ensures that identical data always produces the exact same string representation.
    """
    if details is None:
        return ""
    if isinstance(details, dict):
        return json.dumps(details, sort_keys=True, separators=(",", ":"))
    return str(details).strip()


def compute_log_hash(prev_hash, timestamp, event_type, user_id, username, ip_address, user_agent, doc_id, details):
    """
    Computes a cryptographic SHA-256 hash across all fields in the audit record.
    
    Security Controls:
    - Deterministic canonical serialization prevents hash inconsistencies.
    - All fields (including previous hash and explicit ISO-8601 UTC timestamp) are hashed.
    """
    canonical_payload = {
        "prev_hash": str(prev_hash),
        "timestamp": str(timestamp),
        "event_type": str(event_type),
        "user_id": user_id,
        "username": str(username or ""),
        "ip_address": str(ip_address or ""),
        "user_agent": str(user_agent or ""),
        "doc_id": doc_id,
        "details": canonicalize_details(details)
    }

    # Deterministic JSON bytes: keys sorted alphabetically, compact separators
    raw_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw_bytes).hexdigest()


def get_latest_audit_hash(conn=None):
    """
    Retrieves the current_hash of the most recently inserted audit log.
    If no records exist, returns the predefined GENESIS_HASH.
    """
    if conn is None:
        conn = get_db()

    cursor = conn.cursor()
    cursor.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()

    if row and row["current_hash"]:
        return row["current_hash"]
    return GENESIS_HASH


def log_audit_event(event_type, user_id=None, username=None, doc_id=None, details=None, ip_address=None, user_agent=None, conn=None):
    """
    Appends a new event to the cryptographic audit trail.
    
    Security Controls:
    - Auto-extracts client IP and User-Agent in web request contexts.
    - Resolves authenticated user identity if not explicitly passed.
    - Chains onto the previous hash to produce an unbroken cryptographic sequence.
    - Explicit UTC ISO-8601 timestamp (YYYY-MM-DDTHH:MM:SSZ) guarantees identical strings.
    """
    if conn is None:
        conn = get_db()

    # If within a Flask request context, automatically populate request metadata
    if has_request_context():
        if user_id is None:
            from app.services.auth import get_current_user
            current_user = get_current_user()
            if current_user:
                user_id = current_user["id"]
                username = current_user["username"]

        if ip_address is None:
            # Check forwarded header first in case behind reverse proxy
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                ip_address = forwarded.split(",")[0].strip()
            else:
                ip_address = request.remote_addr or "127.0.0.1"

        if user_agent is None:
            user_agent = request.headers.get("User-Agent", "")[:255]

    cursor = conn.cursor()

    # Validate foreign key references so attacker probes with invalid/fake IDs do not cause foreign key errors
    actual_doc_id = doc_id
    if doc_id is not None:
        cursor.execute("SELECT id FROM documents WHERE id = ?", (doc_id,))
        if not cursor.fetchone():
            actual_doc_id = None
            if isinstance(details, dict):
                details["probe_doc_id"] = doc_id
            elif details:
                details = f"{details} [probe_doc_id={doc_id}]"
            else:
                details = f"probe_doc_id={doc_id}"

    actual_user_id = user_id
    if user_id is not None:
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            actual_user_id = None
            if isinstance(details, dict):
                details["probe_user_id"] = user_id
            elif details:
                details = f"{details} [probe_user_id={user_id}]"
            else:
                details = f"probe_user_id={user_id}"

    # Explicit UTC timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Serialize details canonically for database storage and hashing
    canonical_details_str = canonicalize_details(details)

    # Fetch previous hash
    prev_hash = get_latest_audit_hash(conn)

    # Compute new hash
    current_hash = compute_log_hash(
        prev_hash=prev_hash,
        timestamp=timestamp,
        event_type=event_type,
        user_id=actual_user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        doc_id=actual_doc_id,
        details=canonical_details_str
    )

    cursor.execute(
        """
        INSERT INTO audit_logs (
            timestamp, event_type, user_id, username,
            ip_address, user_agent, doc_id, details,
            prev_hash, current_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp, event_type, actual_user_id, username,
            ip_address, user_agent, actual_doc_id, canonical_details_str,
            prev_hash, current_hash
        )
    )
    conn.commit()
    log_id = cursor.lastrowid

    return {
        "id": log_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "user_id": actual_user_id,
        "username": username,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "doc_id": actual_doc_id,
        "details": canonical_details_str,
        "prev_hash": prev_hash,
        "current_hash": current_hash
    }


def verify_audit_chain(conn=None):
    """
    Mathematical Verification of Audit Trail Integrity.
    
    Traverses all audit logs in sequential order:
    1. Confirms the genesis record starts with GENESIS_HASH.
    2. Recalculates the SHA-256 hash of each row to detect content modification.
    3. Confirms that each row's prev_hash matches the previous row's current_hash to detect deletion or reordering.
    
    Returns:
        tuple: (is_valid: bool, message: str, compromised_id: int or None)
    """
    if conn is None:
        conn = get_db()

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
    rows = cursor.fetchall()

    if not rows:
        return True, "Audit log is empty; chain is valid.", None

    expected_prev_hash = GENESIS_HASH

    for row in rows:
        row_id = row["id"]

        # Check 1: Chain linkage (detects deletion or insertion)
        if row["prev_hash"] != expected_prev_hash:
            return (
                False,
                f"Broken chain link at log ID {row_id}: Expected prev_hash '{expected_prev_hash}', "
                f"but found '{row['prev_hash']}'. Record deletion, insertion, or reordering detected.",
                row_id
            )

        # Check 2: Content hash recalculation (detects modification of record data)
        recalculated_hash = compute_log_hash(
            prev_hash=row["prev_hash"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            user_id=row["user_id"],
            username=row["username"],
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
            doc_id=row["doc_id"],
            details=row["details"]
        )

        if row["current_hash"] != recalculated_hash:
            return (
                False,
                f"Tampering detected at log ID {row_id}: Stored hash '{row['current_hash']}' "
                f"does not match recalculated hash '{recalculated_hash}'. Content was modified.",
                row_id
            )

        expected_prev_hash = row["current_hash"]

    return True, f"All {len(rows)} audit log records verified intact with valid cryptographic chaining.", None


def get_audit_logs(limit=100, offset=0, event_type=None, user_id=None, doc_id=None, conn=None):
    """
    Retrieves audit logs with optional filtering for administrative oversight.
    """
    if conn is None:
        conn = get_db()

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if user_id is not None:
        query += " AND user_id = ?"
        params.append(user_id)
    if doc_id is not None:
        query += " AND doc_id = ?"
        params.append(doc_id)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor = conn.cursor()
    cursor.execute(query, tuple(params))
    return cursor.fetchall()


def get_audit_logs_paginated(page=1, per_page=20, event_type=None, username=None, doc_id=None, conn=None):
    """
    Paginated audit log query for admin dashboard with total counts and safe pagination bounds.
    """
    import math
    if conn is None:
        conn = get_db()

    # Sanitize pagination parameters
    try:
        page = max(1, int(page))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = min(100, max(1, int(per_page)))
    except (ValueError, TypeError):
        per_page = 20

    base_where = " WHERE 1=1"
    params = []

    if event_type and event_type.strip():
        base_where += " AND event_type = ?"
        params.append(event_type.strip())

    if username and username.strip():
        base_where += " AND username LIKE ?"
        params.append(f"%{username.strip()}%")

    if doc_id is not None:
        try:
            doc_id_val = int(doc_id)
            base_where += " AND doc_id = ?"
            params.append(doc_id_val)
        except (ValueError, TypeError):
            pass

    cursor = conn.cursor()

    # 1. Total count query
    count_sql = "SELECT COUNT(*) FROM audit_logs" + base_where
    cursor.execute(count_sql, tuple(params))
    total_records = cursor.fetchone()[0]

    total_pages = max(1, math.ceil(total_records / per_page))
    offset = (page - 1) * per_page

    # 2. Paginated rows query
    data_sql = "SELECT * FROM audit_logs" + base_where + " ORDER BY id DESC LIMIT ? OFFSET ?"
    data_params = list(params) + [per_page, offset]
    cursor.execute(data_sql, tuple(data_params))
    rows = cursor.fetchall()

    return {
        "logs": [dict(r) for r in rows],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_records": total_records,
            "total_pages": total_pages
        }
    }

