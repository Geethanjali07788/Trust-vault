import os
from flask import Blueprint, request, jsonify, send_file, make_response, render_template
from app.services.auth import login_required, get_current_user
from app.services.csrf import csrf_protect
from app.services.file_validator import validate_file, sanitize_filename
from app.services.vault import save_to_vault, get_vault_file_path
from app.models.document import (
    create_document,
    get_document_by_id,
    get_accessible_documents,
    check_document_permission,
    grant_document_permission,
    revoke_document_permission,
    get_document_permissions,
    update_document_metadata,
    soft_delete_document,
    search_documents
)
from app.models.user import get_user_by_username, get_user_by_id
from app.services.audit import log_audit_event

doc_bp = Blueprint("documents", __name__, url_prefix="/documents")

@doc_bp.route("/", methods=["GET"])
@login_required
def list_documents():
    """Lists all documents the authenticated user is authorized to access."""
    user = get_current_user()
    docs = get_accessible_documents(user["id"], user["role"])

    # If browser GET requesting HTML, render index.html
    if request.accept_mimetypes.accept_html and not request.is_json and request.args.get("format") != "json":
        return render_template("documents/index.html", documents=docs)

    return jsonify({
        "count": len(docs),
        "documents": [dict(d) for d in docs]
    }), 200


@doc_bp.route("/upload", methods=["POST"])
@login_required
@csrf_protect
def upload_document():
    """
    Secure Document Upload Endpoint.
    
    Security Controls:
    - Pre-validation of file extension, 15MB size, dangerous signatures, and magic bytes.
    - Saves strictly to isolated vault with a random UUID hex filename.
    - Path traversal prevention.
    - Cryptographic audit logging (DOC_UPLOAD).
    """
    user = get_current_user()

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded in 'file' field."}), 400

    file_obj = request.files["file"]
    if not file_obj or not file_obj.filename:
        return jsonify({"error": "Empty filename provided."}), 400

    original_filename = sanitize_filename(file_obj.filename)

    # Validate file content, signature, and size
    is_valid, error_msg, mime_type = validate_file(file_obj, original_filename)
    if not is_valid:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            details={"action": "upload_validation_failed", "filename": original_filename, "error": error_msg}
        )
        return jsonify({"error": f"File validation failed: {error_msg}"}), 400

    title = (request.form.get("title") or original_filename.rsplit(".", 1)[0]).strip()
    description = (request.form.get("description") or "").strip()
    category = (request.form.get("category") or "General").strip()

    try:
        # Save to private vault under UUID4 filename
        storage_name, file_size = save_to_vault(file_obj)

        doc_id = create_document(
            title=title,
            description=description,
            category=category,
            storage_name=storage_name,
            original_filename=original_filename,
            file_size=file_size,
            mime_type=mime_type,
            owner_id=user["id"]
        )

        log_audit_event(
            event_type="DOC_UPLOAD",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={
                "title": title,
                "original_filename": original_filename,
                "file_size": file_size,
                "mime_type": mime_type,
                "category": category
            }
        )

        return jsonify({
            "message": "Document uploaded successfully.",
            "document": {
                "id": doc_id,
                "title": title,
                "original_filename": original_filename,
                "file_size": file_size,
                "category": category,
                "mime_type": mime_type,
                "owner_id": user["id"]
            }
        }), 201

    except Exception as e:
        return jsonify({"error": f"Failed to upload document: {str(e)}"}), 500


@doc_bp.route("/<int:doc_id>", methods=["GET"])
@login_required
def get_document_details(doc_id):
    """
    Retrieves document metadata if the user has at least 'read' permission.
    Owners and Admins also receive the list of current permissions.
    """
    user = get_current_user()
    doc = get_document_by_id(doc_id)
    if not doc:
        return jsonify({"error": "Document not found or has been deleted."}), 404

    has_perm, access_tier, reason = check_document_permission(doc_id, user["id"], user["role"], required_level="read")

    if not has_perm:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "view_document_details", "reason": reason}
        )
        return jsonify({"error": reason}), 403

    log_audit_event(
        event_type="DOC_VIEW",
        user_id=user["id"],
        username=user["username"],
        doc_id=doc_id,
        details={"action": "view_metadata"}
    )

    perms = get_document_permissions(doc_id) if access_tier in ("owner", "admin") else []

    # If browser GET requesting HTML, render details.html
    if request.accept_mimetypes.accept_html and not request.is_json and request.args.get("format") != "json":
        return render_template("documents/details.html", doc=doc, permissions=perms, access_tier=access_tier)

    doc_data = dict(doc)
    doc_data["user_access_level"] = access_tier

    # If owner or admin, include the permission table
    if access_tier in ("owner", "admin"):
        doc_data["permissions"] = [dict(p) for p in perms]

    return jsonify({"document": doc_data}), 200


@doc_bp.route("/<int:doc_id>/download", methods=["GET"])
@login_required
def download_document(doc_id):
    """
    Secure File Streaming Controller.
    
    Security Controls:
    - Checks document existence first (returns 404 if deleted or nonexistent).
    - Enforces dynamic server-side authorization check (read or edit).
    - If unpermitted, logs DENIED_ACCESS with IP/User and returns 403 Forbidden.
    - Files are read from private vault and streamed with 'X-Content-Type-Options: nosniff'
      and 'Cache-Control: no-store' headers.
    """
    user = get_current_user()
    doc = get_document_by_id(doc_id)
    if not doc:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "download_file", "reason": "Document not found or has been deleted"}
        )
        return jsonify({"error": "Document not found or has been deleted."}), 404

    has_perm, access_tier, reason = check_document_permission(doc_id, user["id"], user["role"], required_level="read")

    if not has_perm:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "download_file", "reason": reason}
        )
        return jsonify({"error": reason}), 403

    try:
        file_path = get_vault_file_path(doc["storage_name"])
    except (ValueError, PermissionError, FileNotFoundError):
        return jsonify({"error": "The vaulted file could not be located on disk."}), 404

    log_audit_event(
        event_type="DOC_DOWNLOAD",
        user_id=user["id"],
        username=user["username"],
        doc_id=doc_id,
        details={"filename": doc["original_filename"], "access_tier": access_tier}
    )

    response = make_response(send_file(
        file_path,
        as_attachment=True,
        download_name=doc["original_filename"],
        mimetype=doc["mime_type"]
    ))

    # Security Headers for binary downloads
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    return response


@doc_bp.route("/<int:doc_id>/edit", methods=["POST"])
@login_required
@csrf_protect
def edit_document(doc_id):
    """
    Updates document metadata. Requires 'edit' or 'owner' permission.
    """
    user = get_current_user()
    has_perm, access_tier, reason = check_document_permission(doc_id, user["id"], user["role"], required_level="edit")

    if not has_perm:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "edit_document", "reason": reason}
        )
        return jsonify({"error": reason}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    category = (data.get("category") or "General").strip()

    if not title:
        return jsonify({"error": "Document title cannot be empty."}), 400

    update_document_metadata(doc_id, title, description, category)

    log_audit_event(
        event_type="DOC_EDIT",
        user_id=user["id"],
        username=user["username"],
        doc_id=doc_id,
        details={"title": title, "category": category, "edited_by": user["username"]}
    )

    return jsonify({"message": "Document updated successfully."}), 200


@doc_bp.route("/<int:doc_id>/delete", methods=["POST"])
@login_required
@csrf_protect
def delete_document(doc_id):
    """
    Soft-deletes a document. Only the document owner or system admin can delete.
    After deletion, the document cannot be accessed through any endpoint.
    """
    user = get_current_user()
    doc = get_document_by_id(doc_id)

    if not doc:
        return jsonify({"error": "Document not found or already deleted."}), 404

    # Enforce Owner or Admin check
    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "delete_document", "reason": "Non-owner attempt to delete"}
        )
        return jsonify({"error": "Forbidden: Only the document owner or administrator can delete this document."}), 403

    soft_delete_document(doc_id)

    log_audit_event(
        event_type="DOC_DELETE",
        user_id=user["id"],
        username=user["username"],
        doc_id=doc_id,
        details={"title": doc["title"], "original_filename": doc["original_filename"]}
    )

    return jsonify({"message": "Document deleted successfully."}), 200


@doc_bp.route("/<int:doc_id>/permissions", methods=["POST"])
@login_required
@csrf_protect
def grant_permission(doc_id):
    """
    Grants or updates 'read' or 'edit' permissions for a named user.
    Only the document owner or system administrator can manage permissions.
    """
    user = get_current_user()
    doc = get_document_by_id(doc_id)

    if not doc:
        return jsonify({"error": "Document not found."}), 404

    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "grant_permission", "reason": "Non-owner attempt to manage permissions"}
        )
        return jsonify({"error": "Forbidden: Only the document owner can grant permissions."}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    target_username = (data.get("username") or "").strip()
    target_user_id = data.get("user_id")
    permission_level = (data.get("permission_level") or "read").strip().lower()

    if permission_level not in ("read", "edit"):
        return jsonify({"error": "Invalid permission level. Must be 'read' or 'edit'."}), 400

    target_user = None
    if target_username:
        target_user = get_user_by_username(target_username)
    elif target_user_id:
        target_user = get_user_by_id(target_user_id)

    if not target_user:
        return jsonify({"error": f"Target user '{target_username or target_user_id}' not found."}), 404

    if target_user["id"] == doc["owner_id"]:
        return jsonify({"error": "Cannot grant permissions to the document owner (owner already has full rights)."}), 400

    try:
        grant_document_permission(doc_id, target_user["id"], permission_level, user["id"])

        log_audit_event(
            event_type="PERM_GRANT",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={
                "target_user_id": target_user["id"],
                "target_username": target_user["username"],
                "permission_level": permission_level
            }
        )

        return jsonify({
            "message": f"Successfully granted '{permission_level}' permission to {target_user['username']}."
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@doc_bp.route("/<int:doc_id>/permissions/revoke", methods=["POST"])
@doc_bp.route("/<int:doc_id>/permissions/<int:target_user_id>", methods=["DELETE"])
@login_required
@csrf_protect
def revoke_permission(doc_id, target_user_id=None):
    """
    Immediately revokes a named user's permission for a document.
    Only the document owner or system administrator can revoke permissions.
    Revocation takes effect on the immediate next request.
    """
    user = get_current_user()
    doc = get_document_by_id(doc_id)

    if not doc:
        return jsonify({"error": "Document not found."}), 404

    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        log_audit_event(
            event_type="DENIED_ACCESS",
            user_id=user["id"],
            username=user["username"],
            doc_id=doc_id,
            details={"action": "revoke_permission", "reason": "Non-owner attempt to revoke permissions"}
        )
        return jsonify({"error": "Forbidden: Only the document owner can revoke permissions."}), 403

    if target_user_id is None:
        data = request.get_json(silent=True) or request.form.to_dict()
        target_username = (data.get("username") or "").strip()
        target_user_id = data.get("user_id")
        if target_username and not target_user_id:
            target_user = get_user_by_username(target_username)
            if target_user:
                target_user_id = target_user["id"]

    if not target_user_id:
        return jsonify({"error": "Target user ID or username is required."}), 400

    revoked = revoke_document_permission(doc_id, target_user_id)
    if not revoked:
        return jsonify({"error": "No existing permission found for this user."}), 404

    log_audit_event(
        event_type="PERM_REVOKE",
        user_id=user["id"],
        username=user["username"],
        doc_id=doc_id,
        details={"target_user_id": target_user_id}
    )

    return jsonify({"message": "Permission revoked successfully. Access terminates immediately."}), 200


@doc_bp.route("/search", methods=["GET"])
@login_required
def search():
    """
    Permission-Scoped Search Endpoint.
    Filters by title/name, owner, category, and creation date.
    Never returns unpermitted documents.
    """
    user = get_current_user()
    q = request.args.get("q")
    owner = request.args.get("owner")
    category = request.args.get("category")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

    results = search_documents(
        user_id=user["id"],
        user_role=user["role"],
        query=q,
        owner_username=owner,
        category=category,
        date_from=date_from,
        date_to=date_to
    )

    return jsonify({
        "count": len(results),
        "results": [dict(r) for r in results]
    }), 200
