## Project Overview

TrustVault is a secure document-sharing application built with Python and Flask. It is designed to manage documents, control access, and maintain an audit trail of important activities.

## Features

- User authentication and role-based access control.
- Document upload and management.
- Document-level permissions.
- Secure file validation and storage.
- Activity audit logging.
- Automated tests.

Note: Verify each feature against the actual implementation before claiming it is complete.

## Technology Stack

- Python
- Flask
- SQLite
- HTML, CSS, JavaScript
- Pytest

## Setup Instructions

1. Install Python.
2. Create and activate a virtual environment.
3. Install dependencies:

   `python -m pip install -r requirements.txt`

4. Initialize the database using the project's documented setup process.
5. Start the application using the verified run command.

## Running Tests

Activate the virtual environment and run:

`python -m pytest -v`

## Security

TrustVault is intended to enforce authorization on the server, store files outside public web directories, and record security-relevant events. These controls must be verified through code review and security tests before deployment.

## Deployment

Deployment instructions and the live URL will be added after deployment has been completed and verified.

## Demo

A five-minute demonstration video will be prepared after the application has been tested.

## Project Status

This README is an initial draft. Update it to reflect only features, test results, and deployment details that have actually been verified.
