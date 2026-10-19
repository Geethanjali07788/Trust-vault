## Purpose

This document describes the API endpoints provided by TrustVault.

## Authentication

Protected endpoints must require a valid authenticated session. The server must verify the user's current role and document-level permissions.

## Authentication Endpoints

- POST /auth/register — Register an account. Public registration must not allow users to create admin accounts.
- POST /auth/login — Authenticate a user.
- POST /auth/logout — End the current session.
- GET /auth/me — Return the current authenticated user's profile.

## Role Test Endpoints

- GET /auth/test-admin — Admin role required.
- GET /auth/test-owner — Owner role required.
- GET /auth/test-viewer — Viewer role required.

## Document Endpoints

Document endpoint paths, HTTP methods, request fields, and response codes must be documented after checking the actual route implementation.

Each document operation must verify the current user's permission on the server. Unauthorized requests must not expose document contents or file paths.

## Audit Logging

Document operations, permission changes, and denied access attempts must be logged as required by the challenge.

## Error Responses

- 401 Unauthorized — Authentication is missing or invalid.
- 403 Forbidden — The user is authenticated but lacks permission.
- 404 Not Found — The requested resource does not exist or is intentionally concealed.

## Verification Note

This is an initial documentation draft. Confirm every endpoint, role requirement, and response against the actual application routes and tests before submission.
