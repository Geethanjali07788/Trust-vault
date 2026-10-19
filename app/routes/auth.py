import sqlite3
from flask import Blueprint, request, jsonify, session
from app.models.user import (
    create_user,
    get_user_by_username,
    get_user_by_email,
    verify_password,
    validate_registration_input
)
from app.services.auth import (
    login_user,
    logout_user,
    get_current_user,
    login_required,
    role_required
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Public User Registration Endpoint.
    
    Security Controls:
    - Input validation on username, email, and password length.
    - REJECTS attempts to register with role='admin'.
    - Checks for existing usernames and emails to prevent collisions.
    """
    data = request.get_json(silent=True) or request.form.to_dict()

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "viewer").strip().lower()

    # Validate input format and role permissions
    is_valid, error_msg = validate_registration_input(username, email, password, role)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    # Check for existing username or email
    if get_user_by_username(username):
        return jsonify({"error": "Username is already taken."}), 409

    if get_user_by_email(email):
        return jsonify({"error": "Email is already registered."}), 409

    try:
        user_id = create_user(username, email, password, role=role, allow_admin=False)
        return jsonify({
            "message": "User registered successfully.",
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "role": role
            }
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "An account with that username or email already exists."}), 409


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    User Login Endpoint.
    
    Security Controls:
    - Verifies PBKDF2:SHA256 password hash in constant time.
    - Generic error messages to prevent username enumeration.
    - Prevents session fixation attacks by clearing the session before logging in.
    """
    data = request.get_json(silent=True) or request.form.to_dict()

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = get_user_by_username(username)
    if not user or not user["is_active"]:
        # Constant-time comparison dummy check could also be added, generic message returned
        return jsonify({"error": "Invalid username or password."}), 401

    if not verify_password(user["password_hash"], password):
        return jsonify({"error": "Invalid username or password."}), 401

    login_user(user)

    return jsonify({
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }), 200


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Destroys the current user's session."""
    logout_user()
    return jsonify({"message": "Logged out successfully."}), 200


@auth_bp.route("/me", methods=["GET"])
@login_required
def get_profile():
    """
    Returns the authenticated user's profile.
    The role returned is loaded fresh from the server database, never the client cookie.
    """
    user = get_current_user()
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"]
    }), 200


# Verification / Test Endpoints for Role-Based Access Control
@auth_bp.route("/test-admin", methods=["GET"])
@role_required("admin")
def test_admin_only():
    """Protected endpoint: only 'admin' can access."""
    return jsonify({"message": "Welcome, Administrator."}), 200


@auth_bp.route("/test-owner", methods=["GET"])
@role_required("owner", "admin")
def test_owner_only():
    """Protected endpoint: only 'owner' or 'admin' can access."""
    return jsonify({"message": "Welcome, Document Owner."}), 200


@auth_bp.route("/test-viewer", methods=["GET"])
@role_required("viewer", "owner", "admin")
def test_viewer_only():
    """Protected endpoint: 'viewer', 'owner', or 'admin' can access."""
    return jsonify({"message": "Welcome, Viewer."}), 200
