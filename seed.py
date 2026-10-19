"""
TrustVault Database Seeder
Populates safe, non-sensitive demo accounts and sample vaulted documents for demonstration.

Usage:
    .\\venv\\Scripts\\python.exe seed.py
"""
import os
from pathlib import Path
from config import Config
from app import create_app
from app.services.db import init_db, get_db
from app.models.user import create_user, get_user_by_username
from app.models.document import create_document, grant_document_permission
from app.services.vault import save_to_vault
from app.services.audit import log_audit_event, verify_audit_chain

def run_seed():
    app = create_app(Config)
    with app.app_context():
        print("[+] Initializing TrustVault SQLite Schema...")
        init_db()

        conn = get_db()
        cursor = conn.cursor()

        print("[+] Checking and seeding default accounts...")
        # 1. Administrator Account
        admin = get_user_by_username("admin")
        if not admin:
            admin_id = create_user(
                username="admin",
                email="admin@trustvault.local",
                password="AdminSecret123!",
                role="admin",
                allow_admin=True
            )
            print(f"    - Created Administrator account: admin (ID: {admin_id})")
        else:
            admin_id = admin["id"]
            print(f"    - Administrator account already exists (ID: {admin_id})")

        # 2. Document Owner Account
        owner = get_user_by_username("owner")
        if not owner:
            owner_id = create_user(
                username="owner",
                email="owner@trustvault.local",
                password="OwnerSecret123!",
                role="owner"
            )
            print(f"    - Created Document Owner account: owner (ID: {owner_id})")
        else:
            owner_id = owner["id"]
            print(f"    - Document Owner account already exists (ID: {owner_id})")

        # 3. Document Viewer Account
        viewer = get_user_by_username("viewer")
        if not viewer:
            viewer_id = create_user(
                username="viewer",
                email="viewer@trustvault.local",
                password="ViewerSecret123!",
                role="viewer"
            )
            print(f"    - Created Document Viewer account: viewer (ID: {viewer_id})")
        else:
            viewer_id = viewer["id"]
            print(f"    - Document Viewer account already exists (ID: {viewer_id})")

        # 4. Seed Sample Vault Documents (if none exist)
        cursor.execute("SELECT COUNT(*) FROM documents WHERE is_deleted = 0")
        doc_count = cursor.fetchone()[0]

        if doc_count == 0:
            print("[+] Seeding sample documents into private vault storage...")
            # Sample PDF
            pdf_bytes = b"%PDF-1.4\n% TrustVault Sample Confidential Audit Document\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
            pdf_storage, pdf_size = save_to_vault(pdf_bytes)
            doc1_id = create_document(
                title="Q3 FY26 Financial Audit Strategy",
                description="Confidential quarterly financial audit plan and balance review.",
                category="Finance",
                storage_name=pdf_storage,
                original_filename="Q3_Financial_Audit.pdf",
                file_size=pdf_size,
                mime_type="application/pdf",
                owner_id=owner_id
            )
            log_audit_event(
                event_type="DOC_UPLOAD",
                user_id=owner_id,
                username="owner",
                doc_id=doc1_id,
                details={"filename": "Q3_Financial_Audit.pdf", "category": "Finance", "size": pdf_size}
            )
            print(f"    - Seeded Private Document: 'Q3_Financial_Audit.pdf' (ID: {doc1_id})")

            # Sample TXT (Shared with viewer)
            txt_bytes = b"TrustVault Corporate Security Guidelines\n1. Enforce least privilege.\n2. Verify audit chain regularly.\n3. Passwords must be hashed with PBKDF2."
            txt_storage, txt_size = save_to_vault(txt_bytes)
            doc2_id = create_document(
                title="Corporate Security Policy 2026",
                description="Baseline company security policies and compliance guidelines.",
                category="Engineering",
                storage_name=txt_storage,
                original_filename="Security_Policy_2026.txt",
                file_size=txt_size,
                mime_type="text/plain",
                owner_id=owner_id
            )
            log_audit_event(
                event_type="DOC_UPLOAD",
                user_id=owner_id,
                username="owner",
                doc_id=doc2_id,
                details={"filename": "Security_Policy_2026.txt", "category": "Engineering", "size": txt_size}
            )
            print(f"    - Seeded Shared Document: 'Security_Policy_2026.txt' (ID: {doc2_id})")

            # Grant Read Permission to Viewer for Document 2
            grant_document_permission(doc2_id, viewer_id, "read", granted_by_user_id=owner_id)
            log_audit_event(
                event_type="PERM_GRANT",
                user_id=owner_id,
                username="owner",
                doc_id=doc2_id,
                details={"target_user": "viewer", "target_user_id": viewer_id, "permission_level": "read"}
            )
            print(f"    - Granted 'read' permission on Document {doc2_id} to 'viewer'")

        # 5. Verify cryptographic hash chain on seeded data
        print("[+] Verifying cryptographic audit chain integrity...")
        is_valid, msg, comp_id = verify_audit_chain()
        if is_valid:
            print(f"    - Audit Chain Status: OK ({msg})")
        else:
            print(f"    - Audit Chain Status: COMPROMISED at row {comp_id}!")

        print("\n=======================================================")
        print("  Database Seeding Completed Successfully!")
        print("  Demo Accounts:")
        print("    1. Admin:  Username 'admin'  | Password 'AdminSecret123!'")
        print("    2. Owner:  Username 'owner'  | Password 'OwnerSecret123!'")
        print("    3. Viewer: Username 'viewer' | Password 'ViewerSecret123!'")
        print("=======================================================\n")

if __name__ == "__main__":
    run_seed()
