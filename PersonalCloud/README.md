# Secure Personal Cloud Storage System

This project is a secure personal cloud storage system developed as part of a Master's in Cybersecurity. It allows users to create "buckets" (logical storage units), upload and download files, and manage them securely. The application is containerized using Docker and emphasizes security with encryption and authentication.

## Features
- **Personal Cloud Storage**: Upload, download, and manage files similar to Google Drive.
- **Buckets**: Organize files into user-defined buckets (e.g., "photos", "documents").
- **Containerization**: Deployed using Docker for portability and isolation.
- **Security**:
  - **Data at Rest**: Files are encrypted with AES-256.
  - **Data in Transit**: HTTPS enforced (self-signed in development).
  - **Authentication**: User login with hashed passwords.
  - **Container Security**: Runs as a non-root user with minimal privileges.

## Tech Stack
- **Language**: Python 3.9+
- **Framework**: Flask
- **Database**: SQLite (via SQLAlchemy)
- **Encryption**: `cryptography` library
- **Container**: Docker
- **Dependencies**: Listed in `requirements.txt`

