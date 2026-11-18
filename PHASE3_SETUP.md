# VulnScope Phase 3 — Automated Local VAPT & HTML Dashboard

This is an **add-on** for the five VulnScope labs you built in Phases 1–2. It runs a fixed set of HTTP requests against **only** your local training app, verifies the observable unsafe-vs-protected comparisons, and writes a styled HTML dashboard plus machine-readable JSON.

## Files included

```text
scanner/
  run_assessment.py          # 5 automated lab checks
  report_builder.py          # HTML and JSON generator, HTML escaping
  assets/assessment.css      # Dark dashboard styling (embedded in output)
tests/
  test_phase3_report.py      # Offline unit tests
PHASE3_SETUP.md
```

**No `app.py` edits are needed.** Don't overwrite your existing `reports/findings.json`, `reports/assessment.html` or any existing `scanner/test_*.py`.

## Windows setup

1. Back up the current `D:\VulnScope` folder. Extract the ZIP, then copy the `scanner` and `tests` folders into `D:\VulnScope` (merge folders, do not replace the entire folders). Copy this setup document into the project root.
2. Open terminal 1 (Flask):

   ```powershell
   cd D:\VulnScope
   .\venv\Scripts\Activate.ps1
   $env:VULNSCOPE_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
   python .\app\app.py
   ```

3. Open terminal 2 (scanner):

   ```powershell
   cd D:\VulnScope
   .\venv\Scripts\Activate.ps1
   python -m pip install requests
   python .\scanner\run_assessment.py
   ```

4. Output files will appear at:

   - `reports/vulnscope_assessment.html` — dark-mode security assessment dashboard; double-click to open in browser
   - `reports/vulnscope_assessment.json` — structured results for follow-on reporting

5. Offline unit tests (optional):

   ```powershell
   python -m unittest discover -s tests -p "test_phase3_report.py"
   ```

The script returns exit code 0 when all five comparisons are verified and exit code 1 if any need review. If Flask is offline, it exits with code 2 before writing a misleading new report.

## What each check actually tests

| Check | Training-only behavior compared |
|---|---|
| VS-001 SQLi | 1 normal user vs. 3 synthetic users from tautology vs. 0 with parameterized SQL |
| VS-002 XSS | Unescaped vs. escaped script markup in response HTML; **does not execute JavaScript** |
| VS-003 CSRF | Tokenless POST updates a dummy session profile on unsafe endpoint but protected endpoint responds 403 |
| VS-004 IDOR | Alice can read Bob's fictional profile on unsafe endpoint; secure endpoint responds 403 |
| VS-005 Authentication | Four incorrect dummy passwords: [401,401,401,401] vs. [401,401,401,429] |

The CSRF check changes **synthetic session-only** data. The authentication check uses exactly four failed attempts against the hard-coded training endpoint and resets its demo counters after finishing.

`needs_review` is **not proof of security**. It means a check could not demonstrate the expected comparison. Read its evidence notes, verify all Blueprints are registered and the dedicated localhost training exceptions are configured, and rerun the scanner.

## Important limitations

- The scanner **refuses non-loopback URLs** and sends requests to five hard-coded VulnScope labs only. No external targets, open-ended crawling, password spraying, or port scanning.
- Ratings are **illustrative**, not calculated CVSS. A verified local lab finding does not establish risk to a production website.
- The HTML report **escapes observations** to avoid introducing report-viewer XSS.
- This is a static report, not a running dashboard server. It does **not** replace Burp Suite, OWASP ZAP, or Nmap; those tools can be integrated later in an authorized local workflow.
- Never run these intentionally vulnerable Flask Blueprints on a public host.

## Commit to GitHub

Review the new files and reports before publishing; they should not contain credentials, tokens, `.db`, or virtual environments.

```powershell
git add scanner/run_assessment.py scanner/report_builder.py scanner/assets/assessment.css tests/test_phase3_report.py PHASE3_SETUP.md
git add reports/vulnscope_assessment.html reports/vulnscope_assessment.json
git diff --cached --stat
git diff --cached --check
git commit -m "Add automated local VAPT checks and HTML assessment dashboard"
git push origin main
```

Keep `reports/findings.json` and `reports/assessment.html` unchanged unless you intentionally update them separately.
