# VulnScope — Web Application VAPT & Security Assessment

**Status:** Under development · **Environment:** Local security lab · **Language:** Python

VulnScope is a hands-on web application security project built to practice **vulnerability assessment and penetration testing (VAPT)**. It includes a Flask web application, deliberately vulnerable lab routes, safer implementations for comparison, and Python scripts that check expected security behavior.

> [!WARNING]
> **Educational lab only.** This project contains intentionally vulnerable code. Run it only on `127.0.0.1` or in an isolated, authorized lab. Do **not** deploy it to a public server or test systems without permission. Use synthetic accounts and data.

## Current features

- Flask application with login and authenticated dashboard.
- SQLite-backed application data.
- **SQL injection lab** with an intentionally vulnerable user-search endpoint (`/lab/sqli`).
- **SQL injection remediation** using parameterized queries (`/lab/sqli-safe`).
- Python script (`scanner/test_sqli.py`) that sends a test payload to the local lab and inspects the response.
- JSON findings file for documenting security observations.

## Security testing progress

| Area | Status | Notes |
| --- | --- | --- |
| SQL injection (CWE-89) | Implemented and manually reproduced | Local lab returned three dummy records when given a tautology payload |
| Secure SQL query comparison | Implemented and tested | Parameterized query returns no records for the same input |
| XSS | Planned | Vulnerable vs. escaped output |
| CSRF | Planned | Request authenticity and anti-CSRF controls |
| IDOR / access control | Planned | Object-level authorization checks |
| Authentication assessment | Planned | Session and authentication test cases |
| Burp Suite, OWASP ZAP, Nmap evidence | Planned / in progress | Integrate only after tests are performed |
| Report generation | Planned | Summarized findings, evidence, impact and remediation |

The severity and impact of findings will be assessed as the project evolves; demo findings are not claims about external applications.

## Technology stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript, Jinja templates
- **Automated checks:** Python `requests`
- **Planned security tools:** Burp Suite, OWASP ZAP, Nmap
- **Version control:** Git and GitHub

## Run locally on Windows

Requires Python and Git.

```powershell
git clone https://github.com/parijagitsss/VulnScope.git
cd VulnScope
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If your `requirements.txt` does not yet include `Flask` and `requests`, install them with `python -m pip install flask requests` and update the requirements file before publishing a release.

Set a **local-only session secret** for this PowerShell terminal, then start Flask:

```powershell
$env:VULNSCOPE_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python .\app\app.py
```

Open <http://127.0.0.1:5000> in your browser. Keep the server bound to localhost.

## Test the SQL injection lab

With Flask running in one terminal, open a second terminal in the project folder and run:

```powershell
.\venv\Scripts\Activate.ps1
python .\scanner\test_sqli.py
```

The local lab compares:

- **Vulnerable route:** `/lab/sqli?username=admin`
- **Safer route:** `/lab/sqli-safe?username=admin`

In the intentionally vulnerable route, a tautology input can change SQL query logic and return all three **dummy** user records. The parameterized route treats the same input as data, returning no matches. This comparison shows *why parameterized queries matter*.

## Sample finding

**VS-001 — SQL injection (CWE-89)**

- **Location:** `/lab/sqli`
- **Cause:** Untrusted input concatenated into an SQL statement
- **Observed impact:** Three dummy users returned instead of a single username match
- **Remediation:** Use parameterized queries
- **Verification:** Re-test the same input against `/lab/sqli-safe`

This is an intentionally introduced training finding, not a real-world vulnerability disclosure.

## Next milestones

1. Add a contained XSS lab and its escaped-output comparison.
2. Add CSRF, IDOR and authentication-security exercises.
3. Collect authorized local evidence with Burp Suite, OWASP ZAP and Nmap.
4. Improve automated checks and generate a structured HTML/PDF assessment report.
5. Add sanitized screenshots of the dashboard, tests and findings.

## Responsible use

Do not upload `.env` files, databases, private credentials, real user data or unredacted session tokens to GitHub. The demonstration code is intentionally insecure; **never use it in production**.
