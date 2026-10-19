## 1. Unauthorized Document Access

**Threat:** A user may try to access another user's private documents.

**Mitigation:** Verify authentication and document-level permissions on every server request. Test access using multiple user accounts.

## 2. Privilege Escalation

**Threat:** A viewer may try to access admin-only features or change their role.

**Mitigation:** Load roles from trusted server-side records. Do not trust roles supplied by the browser.

## 3. Permission Revocation Failure

**Threat:** A user may continue accessing a document after their permission is revoked.

**Mitigation:** Check current permissions on every document request. Test previously issued links after revocation.

## 4. Malicious File Uploads

**Threat:** An attacker may upload an executable or a file disguised as an allowed document.

**Mitigation:** Enforce file-size and extension allowlists, inspect file signatures where applicable, and store uploads outside the public web directory.

## 5. Path Traversal

**Threat:** A crafted filename may attempt to access files outside the document vault.

**Mitigation:** Generate random storage names and never trust client-provided file paths.

## 6. Audit Log Tampering

**Threat:** Someone may attempt to modify or remove security event records.

**Mitigation:** Use a hash chain for audit records and restrict database access. A hash chain alone cannot prevent a privileged attacker from rewriting the entire chain; independent verification or external protected storage may be needed.

## 7. Session Attacks

**Threat:** An attacker may attempt to misuse a stolen or improperly managed session.

**Mitigation:** Use secure session settings, clear sessions on logout, and require HTTPS in production.

## 8. Cross-Site Request Forgery

**Threat:** A malicious site may attempt to trigger actions using a logged-in user's browser.

**Mitigation:** Use CSRF protection for state-changing requests and test it.

## 9. Accepted Risks and Limitations

- File extension and signature checks cannot guarantee that every uploaded file is harmless.
- A local SQLite database and local file storage depend on the security of the host machine.
- Audit hash chains require protected keys or independent verification to provide stronger tamper evidence.
- Security controls listed above must be verified against the actual implementation before deployment.

## 10. Verification Plan

- Test unauthorized document reads and downloads.
- Test unauthorized edits and deletions.
- Test admin-only endpoints with non-admin accounts.
- Test permission revocation against previously issued links.
- Test upload validation and path traversal.
- Test audit records for allowed and denied actions.
