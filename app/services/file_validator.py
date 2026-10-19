import os
import re
from pathlib import Path
from werkzeug.utils import secure_filename
from config import Config

# Maximum file size: 15 Megabytes (Requirement 8)
MAX_FILE_SIZE = Config.MAX_CONTENT_LENGTH

# Allowed extensions mapped to standard MIME types
ALLOWED_EXTENSIONS = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "txt": "text/plain",
    "csv": "text/csv",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}

# Known Magic Byte signatures for verification
MAGIC_SIGNATURES = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    # DOCX and XLSX are OpenXML packages (ZIP archives) starting with PK\x03\x04
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
}

# Dangerous headers that should NEVER be accepted under any circumstances
DANGEROUS_SIGNATURES = [
    (b"MZ", "Windows/DOS executable (PE/EXE/DLL)"),
    (b"\x7fELF", "Linux executable binary (ELF)"),
    (b"\xca\xfe\xba\xbe", "Java bytecode class"),
    (b"#!", "Shell script shebang"),
    (b"<?php", "PHP script"),
    (b"<script", "Client-side HTML script tag"),
]


def sanitize_filename(filename):
    """
    Sanitizes user-provided filename to prevent Path Traversal attacks.
    Strips directory separators, relative path markers ('..'), null bytes,
    and returns a clean, safe basename.
    """
    if not filename:
        return "unnamed_document"

    # Remove any directory pathing (both forward and backward slashes)
    basename = os.path.basename(filename.replace("\\", "/"))

    # Remove null bytes which can terminate strings in C-based systems
    basename = basename.replace("\x00", "")

    # Apply Werkzeug's secure_filename
    cleaned = secure_filename(basename)

    # If secure_filename stripped everything (e.g. non-ASCII or dot-only), fallback safely
    if not cleaned or cleaned.startswith("."):
        cleaned = "document_" + re.sub(r"[^\w\.-]", "_", basename)

    return cleaned[:100]  # Limit filename length


def validate_file(file_storage_or_bytes, filename):
    """
    Comprehensive multi-layer file security validation.
    
    Checks:
    1. Extension allowlist.
    2. File size limit (15 MB).
    3. Dangerous executable signatures blocklist.
    4. Magic byte signature match for claimed extension.
    5. Plain text sanitization (no binary control bytes for .txt and .csv).
    
    Returns:
        (is_valid: bool, error_message: str or None, mime_type: str or None)
    """
    if not filename:
        return False, "No filename provided.", None

    safe_name = sanitize_filename(filename)
    if "." not in safe_name:
        return False, "File must have a valid extension.", None

    ext = safe_name.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '.{ext}' is not permitted. Allowed: {sorted(list(ALLOWED_EXTENSIONS.keys()))}", None

    expected_mime = ALLOWED_EXTENSIONS[ext]

    # Read header bytes and calculate length
    if isinstance(file_storage_or_bytes, bytes):
        content = file_storage_or_bytes
        file_size = len(content)
        header = content[:32]
    else:
        # Flask FileStorage object
        file_stream = file_storage_or_bytes.stream
        file_stream.seek(0, os.SEEK_END)
        file_size = file_stream.tell()
        file_stream.seek(0)
        header = file_stream.read(32)
        file_stream.seek(0)

    # Check 1: File size limit (15MB)
    if file_size <= 0:
        return False, "Uploaded file is empty (0 bytes).", None

    if file_size > MAX_FILE_SIZE:
        return False, f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit of 15 MB.", None

    # Check 2: Reject dangerous executable/script signatures
    for dangerous_sig, desc in DANGEROUS_SIGNATURES:
        if header.startswith(dangerous_sig) or (dangerous_sig.lower() in header.lower() and len(dangerous_sig) > 4):
            return False, f"Security Violation: File contains dangerous executable or script signature ({desc}).", None

    # Check 3: Magic signature verification for binary documents
    if ext in MAGIC_SIGNATURES:
        valid_sigs = MAGIC_SIGNATURES[ext]
        matches = any(header.startswith(sig) for sig in valid_sigs)
        if not matches:
            return False, f"File signature mismatch: File claims to be '.{ext}' but binary header does not match expected signature.", None

    # Check 4: Text-based validation (.txt, .csv)
    if ext in {"txt", "csv"}:
        # Ensure file does not contain null bytes (often used to disguise binaries)
        sample = content[:1024] if isinstance(file_storage_or_bytes, bytes) else header
        if b"\x00" in sample:
            return False, "Text file contains illegal binary null bytes.", None

    return True, None, expected_mime
