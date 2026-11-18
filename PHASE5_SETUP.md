# VulnScope Phase 5 — Evidence-led report (Windows + Kali)

## Goal

Combine your existing five lab findings, Nmap service evidence, and optional ZAP passive alerts in a professional HTML report. This is an *offline formatter*, not a new scanner. It will not invent findings or change your existing JSON.

## Step 1 — Copy this add-on into the existing Windows project

Extract the ZIP. Copy its `tools/` and `tests/test_final_report.py` files into `D:\VulnScope` (merge folders, do not delete existing files), plus `reports/tool_evidence/README.md`.

Do **not** overwrite `reports/findings.json`, `reports/vulnscope_assessment.json`, `app/app.py`, or your scanner code.

## Step 2 — Save Nmap evidence from Kali

With Flask running inside Kali:

```bash
mkdir -p ~/VulnScope-evidence
nmap -sV -p 5000 -oX ~/VulnScope-evidence/nmap-localhost.xml 127.0.0.1
```

Keep it on Kali until you have a transfer method. To move files from your Kali VM to Windows without extra apps, use a VirtualBox shared folder if your Guest Additions and share permissions are set up, or use any established file-transfer method you trust. Copy the resulting XML to `D:\VulnScope\reports\tool_evidence\nmap-localhost.xml`.

## Step 3 — Export ZAP alerts (optional)

Use ZAP's **Report → Generate Report** and choose a JSON-format report if available, restricting the scope to `http://127.0.0.1:5000`. Save the report as `zap-alerts.json` and copy it to `D:\VulnScope\reports\tool_evidence\zap-alerts.json`. If only HTML export is available, keep that HTML in the evidence folder; the report will still build, but will not automatically display alert rows.

**Before transferring or publishing tool exports, inspect them for HTTP request headers, cookies, session IDs, CSRF tokens and other sensitive information.** Do not publish raw ZAP/Burp data by default.

## Step 4 — Build your report (Windows, no new downloads)

```powershell
cd D:\VulnScope
python .\tools\build_final_report.py
start .\reports\final_vapt_report.html
```

Reads `reports/findings.json`, optional `reports/tool_evidence/nmap-localhost.xml`, optional `reports/tool_evidence/zap-alerts.json`. Outputs `reports/final_vapt_report.html` and `reports/final_vapt_summary.json`. It does not overwrite earlier Phase 3 reports.

To run the standalone unit tests:

```powershell
python -m unittest discover -s .\tests -p 'test_final_report.py'
```

## Step 5 — Commit only sanitized artifacts

```powershell
git status
git add tools/build_final_report.py tests/test_final_report.py PHASE5_SETUP.md reports/tool_evidence/README.md
# Stage these only after reviewing for sensitive data:
git add reports/final_vapt_report.html reports/final_vapt_summary.json
git diff --cached --stat
git diff --cached --check
git commit -m "Add final evidence-led VAPT report generator"
git push origin main
```

Note: `reports/tool_evidence/` may contain sensitive raw exports. Commit curated/sanitized evidence only if you have reviewed it explicitly. Nmap's detection of an open port is not automatically a vulnerability; ZAP passive alerts require verification.
