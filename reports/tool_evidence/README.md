# Local tool evidence (optional)

Place sanitized tool exports here if you want them included in the report.

- `nmap-localhost.xml` — Nmap's XML export (localhost port 5000 only).
- `zap-alerts.json` — a ZAP traditional JSON report or a curated `{"alerts": [...]}` JSON file (optional). ZAP HTML reports may also be saved here but the generator does not parse HTML.
- `burp/` — screenshots of manual Burp Suite Repeater requests and responses (remove cookies, tokens and personal information).

Do not commit raw reports containing session cookies, secrets, personal data, or identifiers other than synthetic lab data.

The report generator never runs a scan or sends network requests.
