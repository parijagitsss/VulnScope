# VulnScope — Phase 1

A local-only Flask and SQLite security assessment training application.

## Windows PowerShell setup

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python .\app\app.py
```

Open http://127.0.0.1:5000. Demo accounts: `admin` / `admin123` and `analyst` / `analyst123`.

Run tests: `python -m pytest -q`.

## Features

- Login and logout with password hashing
- SQLite demo users
- Session-protected dashboard
- Own-profile viewing and updating
- Comments with auto-escaped templates
- CSRF tokens on POST forms

## Safety

This project is for local, authorized testing only. Keep Flask bound to `127.0.0.1`. Demo credentials are not suitable for production. Phase 1 intentionally uses safe patterns; vulnerability exercises are planned for separate isolated lab endpoints in Phase 2.
