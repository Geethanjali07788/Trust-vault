from flask import Blueprint, request, jsonify, render_template
from app.services.auth import login_required, role_required, get_current_user
from app.services.csrf import csrf_protect
from app.services.db import get_db
from app.services.audit import (
    verify_audit_chain,
    get_audit_logs_paginated,
    log_audit_event
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/dashboard", methods=["GET"])
@login_required
@role_required("admin")
def dashboard_view():
    """
    Renders the responsive enterprise admin oversight dashboard.
    """
    conn = get_db()
    cursor = conn.cursor()

    # User breakdown
    cursor.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
    role_counts = {row["role"]: row["count"] for row in cursor.fetchall()}
    total_users = sum(role_counts.values())

    # Document stats
    cursor.execute("SELECT COUNT(*) FROM documents WHERE is_deleted = 0")
    total_docs = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(file_size), 0) FROM documents WHERE is_deleted = 0")
    total_storage_bytes = cursor.fetchone()[0]

    # Audit stats
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_audit_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'DENIED_ACCESS'")
    denied_access_attempts = cursor.fetchone()[0]

    stats = {
        "users": {
            "total": total_users,
            "admin": role_counts.get("admin", 0),
            "owner": role_counts.get("owner", 0),
            "viewer": role_counts.get("viewer", 0)
        },
        "documents": {
            "total_active": total_docs,
            "total_storage_bytes": total_storage_bytes,
            "total_storage_mb": round(total_storage_bytes / (1024 * 1024), 2)
        },
        "security": {
            "total_audit_events": total_audit_events,
            "denied_access_attempts": denied_access_attempts
        }
    }

    # Paginated audit logs
    page = request.args.get("page", 1)
    per_page = request.args.get("per_page", 15)
    event_type = request.args.get("event_type")
    username = request.args.get("username")
    doc_id = request.args.get("doc_id")

    audit_data = get_audit_logs_paginated(page, per_page, event_type, username, doc_id, conn)

    # Users list
    cursor.execute("SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id ASC")
    users = [dict(r) for r in cursor.fetchall()]

    return render_template("admin/dashboard.html", stats=stats, audit_data=audit_data, users=users)

@admin_bp.route("/stats", methods=["GET"])
@login_required
@role_required("admin")
def get_system_stats():
    """
    Administrator Overview Metrics.
    Returns real-time counts of users, active documents, vault storage consumption,
    and security alerts (e.g., denied access attempt counter).
    """
    conn = get_db()
    cursor = conn.cursor()

    # 1. User Statistics
    cursor.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
    role_counts = {row["role"]: row["count"] for row in cursor.fetchall()}
    total_users = sum(role_counts.values())

    # 2. Document Statistics
    cursor.execute("SELECT COUNT(*) FROM documents WHERE is_deleted = 0")
    total_docs = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(file_size), 0) FROM documents WHERE is_deleted = 0")
    total_storage_bytes = cursor.fetchone()[0]

    # 3. Security & Audit Metrics
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_audit_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'DENIED_ACCESS'")
    denied_access_attempts = cursor.fetchone()[0]

    # 4. Recent Security Activity Stream
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5")
    recent_activity = [dict(r) for r in cursor.fetchall()]

    return jsonify({
        "users": {
            "total": total_users,
            "admin": role_counts.get("admin", 0),
            "owner": role_counts.get("owner", 0),
            "viewer": role_counts.get("viewer", 0)
        },
        "documents": {
            "total_active": total_docs,
            "total_storage_bytes": total_storage_bytes,
            "total_storage_mb": round(total_storage_bytes / (1024 * 1024), 2)
        },
        "security": {
            "total_audit_events": total_audit_events,
            "denied_access_attempts": denied_access_attempts
        },
        "recent_activity": recent_activity
    }), 200


@admin_bp.route("/audit-logs", methods=["GET"])
@login_required
@role_required("admin")
def list_audit_logs():
    """
    Paginated, Filterable Audit Trail Inspector.
    Supports filtering by event_type, username, and doc_id.
    """
    page = request.args.get("page", 1)
    per_page = request.args.get("per_page", 20)
    event_type = request.args.get("event_type")
    username = request.args.get("username")
    doc_id = request.args.get("doc_id")

    paginated_data = get_audit_logs_paginated(
        page=page,
        per_page=per_page,
        event_type=event_type,
        username=username,
        doc_id=doc_id
    )

    return jsonify(paginated_data), 200


@admin_bp.route("/verify-audit-chain", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def trigger_audit_chain_verification():
    """
    On-Demand Cryptographic Hash Chain Verifier.
    Recalculates all SHA-256 hashes and verifies chain links from Genesis forward.
    """
    user = get_current_user()
    is_valid, message, compromised_id = verify_audit_chain()

    # Log the verification run in the audit trail itself
    log_audit_event(
        event_type="AUDIT_VERIFIED",
        user_id=user["id"],
        username=user["username"],
        details={"result": "valid" if is_valid else "compromised", "compromised_id": compromised_id}
    )

    return jsonify({
        "is_valid": is_valid,
        "message": message,
        "compromised_id": compromised_id
    }), 200


@admin_bp.route("/users", methods=["GET"])
@login_required
@role_required("admin")
def list_users():
    """
    Lists registered users and their roles for administrative oversight.
    SECURITY CONTROL: Password hashes are strictly excluded from output.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, email, role, is_active, created_at
        FROM users
        ORDER BY id ASC
        """
    )
    users = [dict(row) for row in cursor.fetchall()]
    return jsonify({
        "count": len(users),
        "users": users
    }), 200
