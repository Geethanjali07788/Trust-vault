import os
import uuid
import re
from pathlib import Path
from flask import current_app
from config import Config

def get_vault_directory():
    """
    Retrieves and ensures existence of the private vault storage directory.
    This directory is strictly outside web-accessible roots.
    """
    if current_app:
        vault_dir = Path(current_app.config.get("STORAGE_DIR", Config.STORAGE_DIR)).resolve()
    else:
        vault_dir = Path(Config.STORAGE_DIR).resolve()

    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_dir


def is_safe_path(base_dir, target_path):
    """
    Cryptographic/Path integrity check.
    Proves that target_path resides strictly within base_dir, preventing Path Traversal.
    """
    base_dir = Path(base_dir).resolve()
    target_path = Path(target_path).resolve()
    try:
        # relative_to raises ValueError if target_path does not start with base_dir
        target_path.relative_to(base_dir)
        return True
    except ValueError:
        return False


def save_to_vault(file_storage_or_bytes):
    """
    Saves a file stream or bytes into the private vault under a randomized UUID filename.
    
    Security Controls:
    - Never uses user-supplied filenames on disk.
    - Saves as `<uuid4>.dat` in the private vault directory.
    - Verifies path safety before writing.
    
    Returns:
        tuple: (storage_name: str, file_size: int)
    """
    vault_dir = get_vault_directory()
    storage_name = f"{uuid.uuid4().hex}.dat"
    target_path = vault_dir / storage_name

    if not is_safe_path(vault_dir, target_path):
        raise ValueError("Security violation: Path traversal detected in vault destination.")

    if isinstance(file_storage_or_bytes, bytes):
        with open(target_path, "wb") as f:
            f.write(file_storage_or_bytes)
        file_size = len(file_storage_or_bytes)
    else:
        # Flask FileStorage object
        file_storage_or_bytes.save(str(target_path))
        file_size = target_path.stat().st_size

    return storage_name, file_size


def get_vault_file_path(storage_name):
    r"""
    Retrieves the absolute path to a vaulted file.
    
    Security Controls:
    - Rejects any storage_name containing directory separators ('/' or '\\').
    - Strictly matches the expected UUID hex format (`[a-f0-9]{32}\.dat`).
    - Verifies path safety.
    """
    if not storage_name or not re.match(r"^[a-f0-9]{32}\.dat$", storage_name):
        raise ValueError("Invalid storage filename format.")

    vault_dir = get_vault_directory()
    file_path = (vault_dir / storage_name).resolve()

    if not is_safe_path(vault_dir, file_path):
        raise PermissionError("Path traversal attempt detected.")

    if not file_path.exists():
        raise FileNotFoundError(f"Vaulted file '{storage_name}' does not exist on disk.")

    return file_path


def delete_from_vault(storage_name):
    """Safely deletes a vaulted file from disk."""
    try:
        file_path = get_vault_file_path(storage_name)
        if file_path.exists():
            file_path.unlink()
            return True
    except (ValueError, PermissionError, FileNotFoundError):
        pass
    return False
