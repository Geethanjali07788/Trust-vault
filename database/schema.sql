-- TrustVault Database Schema
-- SQLite3 with strict relational integrity, check constraints, and indexed lookups

PRAGMA foreign_keys = ON;

-- 1. Users Table (Requirement 1: 3 Roles - admin, owner, viewer)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'owner', 'viewer')) DEFAULT 'viewer',
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Documents Table (Requirement 2 & 8: Safe metadata & UUID storage mapping)
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT NOT NULL DEFAULT 'General',
    storage_name TEXT UNIQUE NOT NULL,      -- Random UUID filename on disk (e.g. 8f6b...dat)
    original_filename TEXT NOT NULL,        -- Original sanitized filename for user display
    file_size INTEGER NOT NULL CHECK(file_size >= 0),
    mime_type TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK(is_deleted IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Document Permissions Table (Requirement 3 & 4: Per-document read/edit ACL)
CREATE TABLE IF NOT EXISTS document_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    permission_level TEXT NOT NULL CHECK(permission_level IN ('read', 'edit')),
    granted_by INTEGER NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (doc_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id),
    UNIQUE(doc_id, user_id)                 -- One active permission tier per user per document
);

-- 4. Audit Logs Table (Requirement 6: Tamper-evident cryptographic hash chain)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,               -- e.g. DOC_UPLOAD, DOC_DOWNLOAD, PERM_GRANT, DENIED_ACCESS
    user_id INTEGER,                        -- Nullable if unauthenticated visitor
    username TEXT,                          -- Cached username at time of event
    ip_address TEXT,
    user_agent TEXT,
    doc_id INTEGER,                         -- Document affected (if applicable)
    details TEXT,                           -- JSON or structured descriptive text
    prev_hash TEXT NOT NULL,                -- SHA-256 hash of previous audit record (Genesis = 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000')
    current_hash TEXT NOT NULL,             -- SHA-256(prev_hash + id + timestamp + event_type + user_id + doc_id + details)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (doc_id) REFERENCES documents(id) ON DELETE SET NULL
);

-- Performance & Query Optimization Indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents(created_at);
CREATE INDEX IF NOT EXISTS idx_doc_perms_lookup ON document_permissions(doc_id, user_id);
CREATE INDEX IF NOT EXISTS idx_doc_perms_user ON document_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_logs(doc_id);
