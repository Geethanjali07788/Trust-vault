import hmac
import secrets
from functools import wraps
from flask import session, request, jsonify, current_app

def generate_csrf_token():
    """
    Generates or retrieves a secure random 32-byte hexadecimal CSRF token for the session.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(token_to_check):
    """
    Validates a submitted CSRF token using constant-time comparison to prevent timing attacks.
    Respects app.config['WTF_CSRF_ENABLED'] setting.
    """
    if not current_app.config.get("WTF_CSRF_ENABLED", True):
        # Explicitly disabled in isolated test mode
        return True

    expected_token = session.get("csrf_token")
    if not expected_token or not token_to_check:
        return False

    return hmac.compare_digest(str(expected_token), str(token_to_check))


def csrf_protect(f):
    """
    Decorator enforcing CSRF token validation on state-changing HTTP requests (POST, PUT, DELETE, PATCH).
    Token can be supplied in:
    1. Header: 'X-CSRF-Token' or 'X-CSRFToken'
    2. Form data: 'csrf_token'
    3. JSON body: 'csrf_token'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_app.config.get("WTF_CSRF_ENABLED", True):
            return f(*args, **kwargs)

        if request.method in {"POST", "PUT", "DELETE", "PATCH"}:
            token = (
                request.headers.get("X-CSRF-Token")
                or request.headers.get("X-CSRFToken")
                or (request.form.get("csrf_token") if request.form else None)
            )

            if not token and request.is_json:
                json_data = request.get_json(silent=True) or {}
                token = json_data.get("csrf_token")

            if not token or not validate_csrf_token(token):
                from app.services.audit import log_audit_event
                log_audit_event(
                    event_type="DENIED_ACCESS",
                    details={"reason": "CSRF validation failed: token missing or invalid", "method": request.method, "path": request.path}
                )
                return jsonify({"error": "CSRF validation failed: Invalid or missing CSRF token."}), 403

        return f(*args, **kwargs)
    return decorated_function
