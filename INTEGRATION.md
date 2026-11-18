# VulnScope CSRF Lab — Windows add-on

This add-on provides a **styled CSRF training page**, a vulnerable demo endpoint,
a token-protected demo endpoint, and a Python verification script.

**Lab safety:** run only on `127.0.0.1`. It intentionally accepts a tokenless POST
at `/lab/csrf`. Do not deploy the lab on a public server. No real accounts or
database records are changed.

## 1. Back up and copy files

Your existing project root is `D:\VulnScope`. Make a backup of your existing
`app\csrf_lab.py` if you already created it. Copy the files in this add-on into
the matching folders of your project:

- `app\csrf_lab.py` — replaces the earlier unstyled lab module
- `app\templates\csrf_lab.html` — new HTML template
- `app\static\csrf_lab.css` — new CSS theme
- `scanner\test_csrf.py` — automated HTTP test
- `reports\VS-003-example.json` — example finding; **do not replace** `findings.json`

**Do not replace `app\app.py`, your login templates, SQLi files, or XSS files.**

## 2. Keep the Blueprint registration in `app\app.py`

You should already have these lines **after** creating the Flask app:

```python
from csrf_lab import csrf_lab
app.register_blueprint(csrf_lab)
```

Do not add them twice.

## 3. Keep the earlier global CSRF validation exception

Your `app\app.py` already has a global CSRF validator. To let the training lab
validate independently, it needs this **localhost-only exception** at the
start of that validator function, while keeping the remainder of the global
validator unchanged:

```python
if request.endpoint in {"csrf_lab.vulnerable", "csrf_lab.safe"} and request.remote_addr in {"127.0.0.1", "::1"}:
    return None
```

Do not disable global protection for other application routes. The protected
lab itself returns **HTTP 403** if its CSRF token is missing or invalid.

## 4. Run on Windows (PowerShell)

```powershell
cd D:\VulnScope
.\venv\Scripts\Activate.ps1
$env:VULNSCOPE_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python .\app\app.py
```

Open `http://127.0.0.1:5000/lab/csrf/start`, then try both versions via the
tabs. Keep the Flask terminal open.

## 5. Run the automated test in a second terminal

```powershell
cd D:\VulnScope
.\venv\Scripts\Activate.ps1
python -m pip install requests
python .\scanner\test_csrf.py
```

Expected output:

```text
PASS: Vulnerable demo accepted a tokenless POST.
PASS: Protected demo rejected the tokenless POST (HTTP 403).
PASS: Protected demo accepted a valid CSRF token.
SUCCESS: VulnScope CSRF lab checks passed.
```

The test checks the behavior of tokenless and token-validated HTTP requests. A
complete browser-based, cross-origin CSRF demonstration also depends on browser
cookie behavior (e.g., SameSite) and other defenses, which this lab does not
attempt to bypass.

## 6. Report and publish

After verifying the lab, copy the object from `reports\VS-003-example.json`
into your existing `reports\findings.json` array (add a comma between entries)
and change its status to `Verified in local lab`.

Review your Git diff for secrets and local data before pushing to your **public**
repository. Then:

```powershell
git add app/app.py app/csrf_lab.py app/templates/csrf_lab.html app/static/csrf_lab.css scanner/test_csrf.py reports/findings.json
git diff --cached --check
git commit -m "Add styled CSRF lab and token validation tests"
git push origin main
```

Do not commit the example report unless you want to retain it as an extra file.

# VulnScope — IDOR Lab Add-on (Windows)

## What this adds

An isolated **IDOR / broken object-level authorization** training lab with two fictional profiles: Alice (user ID 1) and Bob (user ID 2). The intentionally vulnerable route `/lab/idor` retrieves any dummy profile by ID without ownership checks. `/lab/idor-safe` performs server-side authorization and returns HTTP 403 for Bob when the active demo session belongs to Alice.

**Local training only**. Never expose the deliberately vulnerable routes on a public server. This lab uses synthetic data, not your real VulnScope database.

## 1. Copy files into your existing project

Unzip the add-on, then copy the contents into `D:\VulnScope`, preserving this structure:

```text
D:\VulnScope\
  app\
    app.py                 <- keep your working file
    idor_lab.py            <- new
    templates\idor_lab.html <- new
    static\idor_lab.css   <- new
  scanner\test_idor.py    <- new/replace after backup
  reports\VS-004-example.json <- reference only
```

If you already created `scanner/test_idor.py`, back it up before replacing. **Do not replace** `app/app.py`, `reports/findings.json`, `README.md`, or your existing SQLi/XSS/CSRF labs. The ZIP deliberately does not contain those files.

## 2. Register the Flask Blueprint

Open your existing `app/app.py`. Find where you construct the app (something like `app = Flask(__name__)`). After the app is created and before it starts serving requests, add exactly once:

```python
from idor_lab import idor_lab
app.register_blueprint(idor_lab)
```

Keep your existing SQLi, XSS, CSRF, authentication, and global CSRF code. Because the IDOR lab uses **GET requests only**, it doesn't require a global CSRF-validation exception.

## 3. Run on Windows PowerShell

With the existing server stopped (Ctrl+C):

```powershell
cd D:\VulnScope
.\venv\Scripts\Activate.ps1
$env:VULNSCOPE_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python .\app\app.py
```

If your project uses a different `venv` location, activate the one you've been using. If you already configured your secret in the **same** terminal, you need not generate it again.

Open `http://127.0.0.1:5000/lab/idor/start` to set up an isolated demo session as Alice.

### Manual comparison

1. `http://127.0.0.1:5000/lab/idor?user_id=1` — returns Alice's dummy profile (200).
2. `http://127.0.0.1:5000/lab/idor?user_id=2` — returns Bob's dummy profile (200): deliberately vulnerable.
3. `http://127.0.0.1:5000/lab/idor-safe?user_id=2` — access denied (403): fixed version.
4. `http://127.0.0.1:5000/lab/idor-safe?user_id=1` — Alice's own profile (200): allowed.

**Why IDOR?** A record identifier is not authorization. Only server-side checks should determine who can read a record.

## 4. Automated test

Keep Flask running in one terminal. In a second terminal:

```powershell
cd D:\VulnScope
.\venv\Scripts\Activate.ps1
python -m pip install requests
python .\scanner\test_idor.py
```

Expected output:

```text
PASS: Alice can access her own profile on the protected endpoint (200).
PASS: Vulnerable endpoint exposes Bob's synthetic profile (200).
PASS: Protected endpoint blocks access to Bob's profile (403).
IDOR demonstration and remediation checks complete.
```

A failed test may indicate a missing Blueprint registration, a missing file, an app-level redirect/login guard, or a server that is not running; copy the traceback to troubleshoot.

## 5. Document VS-004

After confirming the behavior, open `reports/VS-004-example.json`, copy its object into the `findings` array in your existing `reports/findings.json`, and update `status` to `Verified in local lab`. Include a comma after the preceding entry. Do not overwrite the rest of the JSON.

Validate it with:

```powershell
python -m json.tool .\reports\findings.json > $null
```

Severity is illustrative; do not present this demo score as a formal CVSS assessment.

## 6. Commit to GitHub (after testing)

```powershell
cd D:\VulnScope
git add app/app.py app/idor_lab.py app/templates/idor_lab.html app/static/idor_lab.css scanner/test_idor.py reports/findings.json INTEGRATION_IDOR.md reports/VS-004-example.json
git diff --cached --check
git diff --cached --stat
git commit -m "Add styled IDOR vulnerability lab and authorization tests"
git push origin main
```

Do not stage your `venv`, `.env`, secret keys, local SQLite database, or captured session cookies. Review `git diff --cached` if in doubt.

## Troubleshooting

- **404**: Ensure you registered `idor_lab` and restarted Flask.
- **500**: Check for missing `idor_lab.html` or `idor_lab.css` files; read the terminal traceback.
- **302**: First-time visitors redirect to `/lab/idor/start` to initialize the demo session.
- **403** for Bob on `/lab/idor-safe`: this is the **expected secure behavior**.
- **Tests can't connect**: Flask must be running at `http://127.0.0.1:5000` in a different terminal.
