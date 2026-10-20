## 1. Unauthorized Document Access

**Threat:** A user may try to access another user's private documents without permission.

**Mitigation:** Verify authentication and document-level permissions on every relevant server request. Test access using multiple user accounts and confirm that unauthorized reads and downloads are denied.

## 2. Privilege Escalation

**Threat:** A viewer may try to access admin-only features or change their role without authorization.

**Mitigation:** Load roles from trusted server-side records. Never trust role values supplied by the browser. Enforce role checks on protected server endpoints.

## 3. Permission Revocation Failure

**Threat:** A user may continue accessing a document after their permission has been revoked.

**Mitigation:** Check current permissions on every document request. Test access again after revocation and confirm that previously available links cannot bypass authorization.

## 4. Malicious File Uploads

**Threat:** An attacker may upload an executable or a file disguised as an allowed document.

**Mitigation:** Enforce file-size limits and an extension allowlist. Validate file content or signatures where applicable, generate safe storage names, and store uploaded files outside the public web directory. File validation cannot guarantee that every file is harmless.

## 5. Path Traversal

**Threat:** A crafted filename or path may attempt to access files outside the document vault.

**Mitigation:** Generate server-controlled storage names. Never trust client-provided file paths. Resolve file locations safely and verify that file operations remain within the intended storage directory.

## 6. Audit Log Tampering

**Threat:** Someone may attempt to modify, reorder, or delete security event records.

**Mitigation:** Use a hash chain to detect changes to audit records and restrict database access. A hash chain alone cannot prevent a privileged attacker from rewriting the entire chain and recalculating its hashes. Independent verification or protected external storage can provide stronger tamper evidence.

## 7. Session Attacks

**Threat:** An attacker may attempt to misuse a stolen or improperly managed session.

**Mitigation:** Configure appropriate session security settings, clear the session on logout, protect the application with HTTPS in production, and review session expiration and cookie settings.

## 8. Cross-Site Request Forgery (CSRF)

**Threat:** A malicious website may attempt to trigger actions using a logged-in user's browser.

**Mitigation:** Apply CSRF protection to state-changing requests and test that requests with missing or invalid CSRF tokens are rejected.

## 9. Accepted Risks and Limitations

- File extension and signature checks cannot guarantee that every uploaded file is harmless.
- Local SQLite and file storage depend on the security and availability of the host machine.
- A hash chain provides tamper evidence but does not by itself prevent a privileged attacker from rewriting the complete chain.
- Production security depends on correct deployment, HTTPS, secret management, access restrictions, and server configuration.
- Security controls must be verified against the actual implementation and test results before deployment.

## 10. Verification Plan

- Test unauthorized document reads and downloads.
- Test unauthorized document edits and deletions.
- Test admin-only endpoints using non-admin accounts.
- Test permission revocation and verify that access is denied afterward.
- Test file upload validation, file-size restrictions, and path traversal protections.
- Test audit logging for both allowed and denied actions.
- Test audit-chain verification after modifying or deleting an audit record.
- Test CSRF protection on state-changing requests.
- Review session and cookie settings before production deployment.

## 11. Security Status

This document describes potential threats, mitigations, and planned verification steps. Listing a mitigation does not prove that it is implemented or fully effective. Implementation and test evidence should be reviewed before claiming that a security requirement has been satisfied.
