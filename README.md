# Vulnerability Scanner

Professional web vulnerability scanner with a Flask backend, a React dashboard, and a SQLite data store. The project is designed for controlled testing of authorized targets and focuses on a practical workflow for reconnaissance, content discovery, and injection testing.

## Overview

This application provides a compact end-to-end scanning flow:

1. A target URL is submitted through the web interface.
2. The backend validates authorization and starts an asynchronous scan.
3. The scanner runs passive reconnaissance, content discovery, and active injection checks.
4. Findings are stored in SQLite and visualized in the dashboard.

The codebase is split into three main layers:

- `backend/` for the Flask API and scanning engine.
- `database/` for the SQLite schema and local persistence.
- `frontend/` for the React + Vite interface and reporting views.

## Key Features

- Passive HTTP security header analysis.
- Directory and hidden content discovery using wordlist-based fuzzing.
- Reflected XSS and SQL injection checks against forms and parameters.
- Session-aware scanning support for authenticated targets via cookies.
- SQLite-backed scan history, target tracking, and vulnerability storage.
- Dashboard views for scan summaries, recent activity, and severity breakdowns.

## Architecture

The scanner is orchestrated by the Flask API in `backend/API.py`.

- `backend/core/common.py` handles URL normalization, session creation, and database helpers.
- `backend/core/recon.py` performs passive recon on security headers.
- `backend/core/fuzzer.py` discovers hidden paths and sensitive endpoints.
- `backend/core/payloads.py` tests injection vectors for XSS and SQLi.
- `frontend/src/App.jsx` renders the scan dashboard and communicates with the API.

## Requirements

- Python 3.10 or newer.
- Node.js 18 or newer.
- npm.

## Setup

### Backend

1. Open a terminal in the repository root.
2. Create and activate a Python virtual environment.
3. Install the backend dependencies used by the project.
4. Start the Flask API.

Example:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install flask flask-cors requests urllib3
python API.py
```

### Frontend

1. Open a second terminal in `frontend/`.
2. Install the Node dependencies.
3. Start the Vite development server.

Example:

```bash
cd frontend
npm install
npm run dev
```

By default, the frontend expects the backend to be available at `http://127.0.0.1:5000`.

## Usage

1. Start the backend API.
2. Start the frontend application.
3. Open the dashboard in your browser.
4. Enter an authorized target URL.
5. Confirm that you are authorized to test the target.
6. Optionally provide a cookie header or security level for authenticated environments.
7. Launch the scan and monitor results from the dashboard.

## Supported Test Targets

The project is especially useful for lab and training environments such as:

- DVWA
- OWASP Juice Shop
- Other intentionally vulnerable applications

Example lab commands and test URLs are documented in `documentation.txt`.

## API Endpoints

- `GET /api/scans` - list scan history.
- `GET /api/stats` - summarize vulnerabilities by severity.
- `POST /api/scan` - start a new asynchronous scan.
- `GET /api/last-scan` - fetch the latest scan and its findings.
- `GET /api/scan/<id>` - fetch details for a specific scan.

## Safety Notice

This tool is intended only for systems you own or are explicitly authorized to test. The API enforces an authorization confirmation step before starting a scan, but responsibility for legal and ethical use remains with the operator.

## Repository Structure

```text
backend/
  API.py
  core/
database/
frontend/
documentation.txt
Projet_Scanner_Vulnerabilites.txt
```

## Contributing

Contributions should preserve the current architecture and keep scans deterministic, auditable, and safe for authorized environments. If you add new checks, document the expected target type, severity model, and any special prerequisites.

## License

No license file is currently provided. Add one before redistributing or publishing the project broadly.