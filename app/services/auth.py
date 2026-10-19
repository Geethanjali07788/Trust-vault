from functools import wraps
from flask import session, g, request, jsonify, redirect, url_for
from app.models.user import get_user_by_id

def login_user(user):
    """
    Establishes an authenticated session for the given user.
    
    Security Controls:
    - Session Fixation Protection: session.clear() wipes out any prior unauthenticated session ID.
    - Stores minimal identity in session; the trusted role is always retrieved fresh from the database.
    """
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    g.current_user = user


def logout_user():
    """Completely destroys the authenticated session."""
    session.clear()
    g.current_user = None


def get_current_user():
    """
    Resolves the authenticated user from the database.
    
    Security Controls:
    - NEVER trusts a role or user object sent by the browser.
    - Queries the database using the signed session['user_id'].
    - Verifies that the user account is still active (is_active == 1).
    - If account was disabled or deleted, instantly invalidates the session.
    """
    if hasattr(g, "current_user") and g.current_user is not None:
        return g.current_user

    user_id = session.get("user_id")
    if not user_id:
        g.current_user = None
        return None

    user = get_user_by_id(user_id)
    if not user or not user["is_active"]:
        # Account was deleted or deactivated mid-session; revoke immediately
        session.clear()
        g.current_user = None
        return None

    g.current_user = user
    return g.current_user


def login_required(f):
    """Decorator requiring a valid authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required. Please log in."}), 401
            return jsonify({"error": "Authentication required. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    """
    Decorator enforcing Role-Based Access Control (RBAC).
    
    Security Controls:
    - First ensures the user is authenticated.
    - Evaluates the user's role loaded directly from the database record.
    - Rejects unauthorized roles with HTTP 403 Forbidden.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if user is None:
                return jsonify({"error": "Authentication required."}), 401

            if user["role"] not in allowed_roles:
                from app.services.audit import log_audit_event
                log_audit_event(
                    event_type="DENIED_ACCESS",
                    user_id=user["id"],
                    username=user["username"],
                    details={
                        "action": "role_access_blocked",
                        "path": request.path,
                        "user_role": user["role"],
                        "required_roles": list(allowed_roles)
                    }
                )
                return jsonify({
                    "error": "Forbidden: You do not have the required role to access this resource.",
                    "user_role": user["role"],
                    "required_roles": list(allowed_roles)
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
