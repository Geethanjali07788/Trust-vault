import os
from pathlib import Path
from datetime import timedelta

# Base Directory: C:\Users\Dell\Desktop\TrustVault
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base Configuration for TrustVault"""
    # Secret Key for session signing and CSRF tokens
    # In production, this should be set via environment variable
    SECRET_KEY = os.environ.get("TRUSTVAULT_SECRET_KEY", "trustvault-dev-insecure-key-change-in-prod-xyz123")
    
    # Database Settings
    DATABASE_PATH = os.environ.get("TRUSTVAULT_DB_PATH", str(BASE_DIR / "trustvault.db"))
    
    # Secure Vault Storage (Stored outside web root)
    STORAGE_DIR = os.environ.get("TRUSTVAULT_STORAGE_DIR", str(BASE_DIR / "storage" / "vault"))
    
    # Upload Constraints (Requirement 8)
    # 15 Megabytes maximum upload size
    MAX_CONTENT_LENGTH = 15 * 1024 * 1024
    
    # Allowed file extensions for document vault
    ALLOWED_EXTENSIONS = {
        "pdf", "docx", "xlsx", "txt", "png", "jpg", "jpeg", "csv"
    }
    
    # Session Security (Requirement 1, 5)
    SESSION_COOKIE_HTTPONLY = True          # Prevent client-side JS from stealing session cookie (XSS protection)
    SESSION_COOKIE_SAMESITE = "Lax"         # Protect against Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SECURE = False           # Set to True when running under HTTPS / TLS
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2) # Sessions expire after 2 hours of inactivity


class TestConfig(Config):
    """Configuration used exclusively for automated tests"""
    TESTING = True
    DATABASE_PATH = ":memory:"              # Ultra-fast isolated in-memory database for tests
    STORAGE_DIR = str(BASE_DIR / "tests" / "test_vault")
    SECRET_KEY = "test-secret-key-123"
    WTF_CSRF_ENABLED = False
