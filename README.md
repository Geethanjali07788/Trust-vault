## Project Overview

TrustVault is a secure document-sharing web application built using Python and Flask. It is designed to help users manage documents, control access to sensitive files, and maintain an audit trail of important activities.

The main goal of TrustVault is to provide a centralized platform for document management with authentication, access control, file validation, and activity logging.

## Features

- **User Authentication:** Provides user login and authentication functionality.
- **Role-Based Access Control:** Controls access to application features based on user roles.
- **Document Upload and Management:** Allows users to upload and manage documents.
- **Document-Level Permissions:** Supports access restrictions for individual documents.
- **File Validation:** Validates uploaded files according to the implemented validation rules.
- **Secure File Storage:** Stores uploaded documents using the application's configured storage mechanism.
- **Activity Audit Logging:** Records important activities to support accountability and auditing.
- **Automated Testing:** Includes automated tests using Pytest to check application behavior.

_Note: The availability and effectiveness of each feature depend on the current implementation and verified test results._

## Technology Stack

- **Programming Language:** Python
- **Web Framework:** Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript
- **Testing Framework:** Pytest
- **Version Control:** Git and GitHub
- **Deployment Platform:** Render

## Project Architecture

TrustVault follows a web application architecture consisting of the following components:

1. **Frontend:** HTML, CSS, and JavaScript provide the user interface.
2. **Backend:** Flask handles application routes, requests, authentication, and business logic.
3. **Database:** SQLite stores application data according to the database schema.
4. **Document Management:** Handles document uploads, storage, and permission checks.
5. **Audit Logging:** Records supported application activities.
6. **Testing:** Pytest is used to execute automated tests.

## Project Setup and Installation

### Prerequisites

- Python installed on your system
- Git
- A code editor such as Visual Studio Code

### Step 1: Clone the Repository

Replace the placeholder below with your actual public repository URL when sharing this README.

```bash
git clone https://github.com/Geethanjali07788/Trust-vault.git
cd Trust-vault
```

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 3: Activate the Virtual Environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux or macOS:**

```bash
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### Step 5: Configure the Application

Configure the environment variables and application settings required by the project.

Use a secure secret key and keep passwords, secret keys, and other sensitive configuration values out of the Git repository.

Initialize the database using the project's actual database initialization procedure.

### Step 6: Run the Application

Use the verified startup command for the project. For example, if the application exposes a Flask object named `app` in `run.py`, the command may be:

```bash
flask --app run:app run
```

Follow the application's actual configuration and startup instructions if they differ from this example.

## Running Automated Tests

Activate the virtual environment and run:

```bash
python -m pytest -v
```

The project test suite has been reported to pass 60 tests in the local development environment.

Test results should be verified against the current code before submission. Passing automated tests does not, by itself, guarantee that every security requirement is satisfied.

## Security Considerations

TrustVault is designed with document security and access control in mind.

Security-related areas include:

- Authentication and session management
- Role-based authorization
- Document-level permission checks
- Uploaded-file validation
- Protection against unauthorized document access
- Audit logging of important activities
- Automated tests for security-sensitive behavior

Security should be verified by testing both authorized and unauthorized access scenarios. In particular, users should not be able to access documents or perform actions beyond their assigned permissions.

See `THREATS.md` for the project's threat analysis and security testing documentation.

## AI-Assisted Development

AI tools were used as development assistance during the project. Their suggestions were reviewed and adapted as needed.

The file `PROMPTS.md` documents the actual prompts used during development, the generated suggestions, issues identified, corrective actions, and relevant Git commit references.

AI-generated code and suggestions should be reviewed, tested, and understood before being included in the application.

## Deployment

**Live Application:**[Open TrustVault](https://trustvault-app-qwoi.onrender.com)

The deployed application should be checked in a private or incognito browser window to confirm that it is accessible without a developer's existing login session.

Some free hosting services may temporarily suspend inactive applications, so initial loading may take additional time.

## Demo

A project demonstration should cover:

1. Introduction to TrustVault
2. User authentication
3. Document upload and management
4. Document access permissions
5. Audit logging
6. Automated testing and security considerations

**Demo Video:** https://drive.google.com/file/d/1u9vkBatKsagt4tmMTPr70ESoP6DEXKdD/view?usp=sharing

Only demonstrate features that are implemented and working in the deployed application.

## Limitations

- Application behavior depends on the current implementation and deployment configuration.
- Security depends on the correct implementation of authentication, authorization, file validation, and storage controls.
- The deployed database and uploaded-file persistence depend on the hosting environment's storage configuration.
- Automated tests cover only the scenarios included in the test suite.

## Future Enhancements

- Multi-factor authentication
- More detailed audit reports
- Improved document search and filtering
- Additional security testing
- Enhanced monitoring and error reporting

These are potential future improvements and should not be interpreted as currently implemented features.

## Conclusion

TrustVault demonstrates the development of a document-sharing application using Python, Flask, and SQLite, with a focus on document management, access control, file validation, and audit logging.

The project aims to provide a foundation for secure document handling while emphasizing testing, clear documentation, and responsible security practices.
