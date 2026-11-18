# VulnScope

### Automated Web Application VAPT & Security Assessment — Local Training Lab

**Python · Flask · SQLite · HTML/CSS/JavaScript · Burp Suite · OWASP ZAP · Nmap**

VulnScope is a hands-on web application security project that combines an intentionally vulnerable Flask application with **repeatable security checks**, **secure-versus-vulnerable comparisons**, and **evidence-led reporting**. I developed the application and tested its local training endpoints using Python automation and security tools on Kali Linux.

> [!WARNING]
> **Educational use only.** The app intentionally contains vulnerabilities. Run it exclusively on `127.0.0.1` or an isolated, authorized lab. Do not expose it to the internet or use it to test systems without permission. All demonstration accounts and records are synthetic.

## Project highlights

- Built a Flask application with SQLite-backed demo accounts, login, dashboard, and training routes.
- Implemented **five intentionally vulnerable labs** alongside more secure implementations for comparison.
- Created Python checks for the expected unsafe-versus-protected behavior of each lab.
- Used **Burp Suite Repeater** to inspect and verify SQL injection requests manually.
- Used **Nmap** to identify the local HTTP service (`127.0.0.1:5000`, Werkzeug).
- Used **OWASP ZAP** for passive HTTP security review; imported alerts are treated as *unverified* until reviewed.
- Generated HTML and JSON assessment outputs with documented findings, impact, and remediation.

## Vulnerability labs

| Finding | Category | Deliberately vulnerable behavior | Protected comparison |
| --- | --- | --- | --- |
| VS-001 | SQL Injection · CWE-89 | Tautology input returns all three fictional user records | Parameterized query treats the input as data |
| VS-002 | Reflected XSS · CWE-79 | Untrusted markup is reflected without proper escaping | Output is HTML-escaped |
| VS-003 | CSRF · CWE-352 | Dummy profile accepts an update without validating a CSRF token | Session-bound token required |
| VS-004 | IDOR · CWE-639 | Fictional user Alice can view Bob's profile by changing an ID | Server-side ownership check denies access |
| VS-005 | Missing Login Rate Limiting · CWE-307 | Demo login allows repeated invalid attempts | Demo login rate-limits attempts with HTTP 429 |

**Scope:** These results refer to deliberately vulnerable **local lab endpoints**, not vulnerabilities discovered in a third-party or production site. Severity labels in the reports are illustrative unless separately scored. A report's “verified” label reflects the status recorded in the project's findings file; the report generator itself does not independently confirm exploitability.

## How the project works

```text
VulnScope Flask application (localhost:5000)
    ├── Login, dashboard & synthetic accounts
    ├── Intentionally vulnerable lab endpoints
    └── Protected comparison endpoints
                     │
                     ▼
       Python verification scripts
       ├── SQLi / XSS / CSRF
       ├── IDOR / Authentication
       └── Results (HTML + JSON)
                     │
                     ▼
         Supporting manual evidence
       ├── Burp Suite: HTTP requests
       ├── Nmap: local service discovery
       └── ZAP: passive alerts for review
                     │
                     ▼
           Final VAPT HTML report
```

## Technology stack

| Area | Tools |
| --- | --- |
| Application | Python, Flask, Jinja, SQLite |
| UI | HTML, CSS, JavaScript |
| Automated checks | Python, `requests` |
| Manual web testing | Burp Suite Community Edition |
| Passive web scanning | OWASP ZAP |
| Service discovery | Nmap |
| Reports | HTML, JSON, Python report generators |
| Development | VS Code on Windows, Kali Linux in VirtualBox, Git/GitHub |

## Run locally (Windows)

**Prerequisites:** Python, Git, PowerShell.

```powershell
git clone https://github.com/parijagitsss/VulnScope.git
cd VulnScope
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If the requirements file does not include `requests`, install it in the same environment with `python -m pip install requests`.

Generate a temporary local session secret and run Flask:

```powershell
$env:VULNSCOPE_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python .\app\app.py
```

Open **http://127.0.0.1:5000**. Keep Flask bound to loopback; do not run this intentionally vulnerable app on a public network interface.

## Run automated lab checks

With Flask running, open a **second** PowerShell terminal in the project root and activate the environment:

```powershell
.\venv\Scripts\Activate.ps1
python .\scanner\run_assessment.py
```

The local assessment runs the five known VulnScope lab comparisons and writes:

- [`reports/vulnscope_assessment.html`](reports/vulnscope_assessment.html) — automated comparison dashboard
- [`reports/vulnscope_assessment.json`](reports/vulnscope_assessment.json) — machine-readable assessment results

These scripts test **fixed, local training endpoints**; this is not an unrestricted internet vulnerability scanner. The XSS HTTP test checks reflected/escaped markup; browser JavaScript execution was checked separately. A `needs_review` result is inconclusive, not proof of security.

## Generate the final VAPT report

The final report combines recorded lab findings and optional, previously collected tool evidence. It **does not perform a new scan**.

```powershell
python .\tools\build_final_report.py
start .\reports\final_vapt_report.html
```

- **[Final VAPT report — HTML file](reports/final_vapt_report.html)** (download and open in a browser to view the styled report)
- **[Final report summary — JSON](reports/final_vapt_summary.json)**
- **[Recorded findings](reports/findings.json)**

Nmap XML and ZAP JSON can optionally be imported from `reports/tool_evidence/` after inspection. An open Nmap port is **not** automatically a security flaw, and passive ZAP alerts are **candidate findings**, not validated vulnerabilities.

## Testing workflow (Kali Linux)

For manual verification, the repository can be cloned into Kali and Flask run there, keeping the target at `127.0.0.1`. Windows localhost and Kali VM localhost are different hosts, so the application and the testing tools were run together inside Kali for this part of the project.

- **Nmap:** identified the local Flask HTTP service on TCP port 5000.
- **Burp Suite:** captured local HTTP traffic and compared normal, injected, and parameterized SQL requests in Repeater.
- **OWASP ZAP:** browsed the application through the proxy and reviewed passive alerts, which are not automatically added as confirmed vulnerabilities.

## Project layout

```text
VulnScope/
├── app/                # Flask app, database, HTML templates and CSS
├── scanner/            # Lab tests and automated assessment/report code
├── tools/              # Final report generator
├── tests/              # Report and application tests
├── reports/            # Findings and sanitized HTML/JSON outputs
├── requirements.txt
└── README.md
```

## Security and limitations

- **Never deploy this project publicly.** It intentionally includes SQL injection, XSS, CSRF, IDOR and authentication weaknesses.
- Use synthetic accounts and local-only test data; keep Flask bound to `127.0.0.1`.
- Do not commit `.env`, virtual environments, SQLite databases, secret keys, browser cookies, CSRF tokens, or raw proxy captures that contain session data.
- Review and sanitize Nmap, Burp, and ZAP exports before publishing any evidence.
- Lab severities are illustrative rather than independently calculated CVSS scores.
- This project demonstrates VAPT methodology and controlled verification; it is **not** a production-ready security scanner or certification of another system's security.

## Portfolio

**Repository:** https://github.com/parijagitsss/VulnScope

The project demonstrates Python web development, security test design, HTTP request analysis, authorization checks, remediation comparison, and reproducible technical reporting.
