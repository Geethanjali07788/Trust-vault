import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from app.services.db import get_db

# Allowed roles for public self-registration (admin is strictly excluded!)
PUBLIC_REGISTER_ROLES = {"viewer", "owner"}
ALL_ROLES = {"admin", "owner", "viewer"}

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

def validate_registration_input(username, email, password, role):
    """
    Validates user input during registration.
    Returns (True, None) if valid, or (False, error_message) if invalid.
    """
    if not username or len(username.strip()) < 3 or len(username.strip()) > 30:
        return False, "Username must be between 3 and 30 characters."

    if not re.match(r"^[a-zA-Z0-9_]+$", username.strip()):
        return False, "Username may only contain letters, numbers, and underscores."

    if not email or not EMAIL_REGEX.match(email.strip()):
        return False, "A valid email address is required."

    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."

    # SECURITY REQUIREMENT: Never allow public registration to claim the 'admin' role!
    if role not in PUBLIC_REGISTER_ROLES:
        return False, f"Invalid role requested. Public accounts can only be {sorted(list(PUBLIC_REGISTER_ROLES))}."

    return True, None


def create_user(username, email, password, role="viewer", is_active=1, allow_admin=False):
    """
    Safely creates a new user with a hashed password.
    
    Security Controls:
    - Never stores plaintext passwords; hashes with PBKDF2:SHA256.
    - Unless allow_admin=True (internal seed/CLI), 'admin' role is rejected.
    """
    username = username.strip()
    email = email.strip().lower()

    if not allow_admin and role not in PUBLIC_REGISTER_ROLES:
        raise ValueError("Cannot create an admin account through public registration.")

    if role not in ALL_ROLES:
        raise ValueError(f"Role '{role}' is not a valid system role.")

    # Secure salted hash generation using PBKDF2 with SHA-256
    password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO users (username, email, password_hash, role, is_active)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, email, password_hash, role, is_active)
    )
    conn.commit()
    return cursor.lastrowid


def get_user_by_id(user_id):
    """Retrieves a single user record by ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def get_user_by_username(username):
    """Retrieves a single user record by username (case-insensitive)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),))
    return cursor.fetchone()


def get_user_by_email(email):
    """Retrieves a single user record by email (case-insensitive)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip(),))
    return cursor.fetchone()


def verify_password(stored_hash, candidate_password):
    """
    Secure constant-time verification of candidate password against stored hash.
    Protects against timing attacks.
    """
    if not stored_hash or not candidate_password:
        return False
    return check_password_hash(stored_hash, candidate_password)
