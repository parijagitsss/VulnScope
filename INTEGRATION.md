# VS-005 Authentication Controls Lab — Windows Integration

This **training-only** lab compares unlimited incorrect login attempts with a simple account/IP rate limiter. It **never authenticates real accounts** and does not use the main VulnScope user database. Keep Flask on `127.0.0.1`; do not deploy the vulnerable Blueprint.

## Install

1. Back up your existing project at `D:\VulnScope`.
2. Copy `app/auth_lab.py`, `app/templates/auth_lab.html`, `app/static/auth_lab.css`, `app/static/auth_lab.js`, `scanner/test_auth.py`, and `reports/VS-005-example.json` into the corresponding folders.
3. In `app/app.py`, **after** `app = Flask(__name__)` and before the app runs, register the Blueprint **once**:

   ```python
   from auth_lab import auth_lab
   app.register_blueprint(auth_lab)
   ```

4. Your existing global CSRF validator will reject these demo POST routes unless you add their endpoint names to its localhost-only educational bypass. In the **existing CSRF guard** where you already exempt `csrf_lab.vulnerable` and `csrf_lab.safe`, add these three **exact** endpoint names:

   ```python
   "auth_lab.vulnerable_attempt",
   "auth_lab.safe_attempt",
   "auth_lab.reset",
   ```

   **Do not** remove CSRF checks for real login, comments, profile, or other routes. The demo's 401/429 responses are not proof of CSRF resistance. Never deploy with these exceptions.

5. In PowerShell, from `D:\VulnScope`:

   ```powershell
   .\venv\Scripts\Activate.ps1
   $env:VULNSCOPE_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
   python .\app\app.py
   ```

6. Open `http://127.0.0.1:5000/lab/auth/start`. Click the left button **four times**: each returns 401. Click the right button **four times**: the fourth returns 429. Use **Reset lab counters** to repeat.

7. In a **second** PowerShell terminal:

   ```powershell
   cd D:\VulnScope
   .\venv\Scripts\Activate.ps1
   python -m pip install requests
   python .\scanner\test_auth.py
   ```

   Expected: two `PASS:` lines. The reset endpoint restores the lab after tests.

8. After tests pass, add `reports/VS-005-example.json` as a new object **inside** the `findings` array in your existing `reports/findings.json`. Mark verified only after observing the results. Do not overwrite earlier findings.

9. Publish only the new lab files and the changes you reviewed:

   ```powershell
   git add app/app.py app/auth_lab.py app/templates/auth_lab.html app/static/auth_lab.css app/static/auth_lab.js scanner/test_auth.py reports/VS-005-example.json
   git add reports/findings.json  # only if you updated the report
   git diff --cached --check
   git diff --cached --stat
   git commit -m "Add authentication rate-limiting lab and automated tests"
   git push origin main
   ```

## What it demonstrates—and what it doesn't

- Vulnerable endpoint: HTTP 401 for every invalid attempt; there is no throttling or lockout.
- Protected endpoint: first 3 failures return HTTP 401; the fourth returns HTTP 429 for ~120 seconds, using in-memory counters keyed by source IP + synthetic username.
- Production auth also requires account privacy, durable/distributed throttling, correct session handling, CSRF protections where relevant, MFA, and monitoring. This demo is not a production authentication implementation.
- The stylesheet/JavaScript are scoped to this lab. All other VulnScope files and routes remain intact.
