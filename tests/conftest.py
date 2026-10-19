import os
import tempfile
import pytest
from app import create_app
from config import TestConfig
from app.services.db import init_db
from app.models.user import create_user

@pytest.fixture
def app():
    """Create and configure a new Flask app instance for each test."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    storage_tmp_dir = tempfile.mkdtemp(prefix="tv_test_vault_")
    
    class RuntimeTestConfig(TestConfig):
        DATABASE_PATH = db_path
        STORAGE_DIR = storage_tmp_dir

    app = create_app(RuntimeTestConfig)

    with app.app_context():
        init_db(db_path=db_path)

    yield app

    # Cleanup temporary SQLite database and storage directory after test
    os.close(db_fd)
    if os.path.exists(db_path):
        os.remove(db_path)
    import shutil
    if os.path.exists(storage_tmp_dir):
        shutil.rmtree(storage_tmp_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    """Test HTTP client for sending requests to the application."""
    return app.test_client()


@pytest.fixture
def seed_users(app):
    """Seeds standard test users: 1 admin, 1 document owner, 1 viewer."""
    with app.app_context():
        admin_id = create_user("test_admin", "admin@trustvault.test", "AdminSecret123!", role="admin", allow_admin=True)
        owner_id = create_user("test_owner", "owner@trustvault.test", "OwnerSecret123!", role="owner")
        viewer_id = create_user("test_viewer", "viewer@trustvault.test", "ViewerSecret123!", role="viewer")
        return {
            "admin": {"id": admin_id, "username": "test_admin", "password": "AdminSecret123!", "role": "admin"},
            "owner": {"id": owner_id, "username": "test_owner", "password": "OwnerSecret123!", "role": "owner"},
            "viewer": {"id": viewer_id, "username": "test_viewer", "password": "ViewerSecret123!", "role": "viewer"}
        }
