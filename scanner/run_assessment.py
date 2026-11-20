# Authorized LOCALHOST-only security assessment of the ONE employee portal.

# No alternate secure routes and no external targets. Creates limited dummy test
# comments/profile changes and restores the display name afterward. It never
# runs automatically; run when you want to assess and document findings.
from __future__ import annotations

import html
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:5000'
OUT = ROOT/'reports'


def token_for(page):
    match = re.search(r'name="_csrf_token"\s+value="([^"]+)"', page)
    if not match:
        raise RuntimeError('Could not find login or form CSRF token')
    return html.unescape(match.group(1))


def login(sess, username='alice', password='Welcome123!'):
    page = sess.get(BASE+'/login', timeout=6)
    page.raise_for_status()
    resp = sess.post(BASE+'/login', data={
        '_csrf_token': token_for(page.text), 'username':username, 'password':password
    },timeout=6,allow_redirects=False)
    if resp.status_code != 302:
        raise RuntimeError(f'Could not sign in as {username}: HTTP {resp.status_code}')


def check(key, title, cwe, note, action):
    try:
        vulnerable, evidence = action()
        return {'id':key,'title':title,'cwe':cwe,
                'result':'reproduced' if vulnerable else 'not_reproduced',
                'evidence':evidence,'remediation':note}
    except Exception as err:
        return {'id':key,'title':title,'cwe':cwe,'result':'test_error',
                'evidence':f'{type(err).__name__}: {str(err)[:180]}',
                'remediation':note}


def main():
    if urlparse(BASE).hostname != '127.0.0.1':
        raise SystemExit('Refusing to scan anything except 127.0.0.1')
    s = requests.Session()
    login(s)
    session_timeout = dict(timeout=6, allow_redirects=False)
    findings = []

    def sqli():
        response = s.get(BASE+'/employees', params={'username':"' OR '1'='1"},timeout=6)
        response.raise_for_status()
        found = 'serviceaudit@example.test' in response.text
        return found, ('Restricted fictional directory record appeared in search results.'
                       if found else 'Restricted fictional record was not returned.')
    findings.append(check('VS-001','Employee directory SQL injection','CWE-89',
                          'Use a parameterized SQL query and preserve directory visibility.',sqli))

    def idor():
        response=s.get(BASE+'/tickets/1044',**session_timeout)
        found=response.status_code==200 and 'Production deployment review notes' in response.text
        return found, ('Alice received Bob’s private fictional ticket (HTTP 200).'
                       if found else f'Alice did not get Bob’s private ticket (HTTP {response.status_code}).')
    findings.append(check('VS-004','Ticket ownership bypass (IDOR)','CWE-639',
                          'Check ticket ownership on every request.',idor))

    def xss():
        page=s.get(BASE+'/tickets/1041',timeout=6)
        page.raise_for_status()
        marker='vulnscope-audit-'+secrets.token_hex(3)
        payload=f'<em>{marker}</em>'
        submitted=s.post(BASE+'/tickets/1041/comments',data={'body':payload,
                          '_csrf_token':token_for(page.text)},**session_timeout)
        if submitted.status_code != 302:
            raise RuntimeError(f'Comment submission HTTP {submitted.status_code}')
        page=s.get(BASE+'/tickets/1041',timeout=6)
        found=payload in page.text
        return found, ('Unescaped HTML from submitted comment appears in ticket page; '
                       'verify JavaScript execution manually.' if found else
                       'Submitted markup was escaped before display.')
    findings.append(check('VS-002','Stored HTML injection / potential XSS','CWE-79',
                          'Remove the unsafe Jinja |safe filter for untrusted comments.',xss))

    def csrf():
        page=s.get(BASE+'/settings',timeout=6)
        page.raise_for_status()
        old=re.search(r'id="name"\s+name="display_name"\s+maxlength="60"\s+value="([^"]*)"',page.text)
        original=html.unescape(old.group(1)) if old else 'Alice Carter'
        new='CSRF Audit '+secrets.token_hex(2)
        response=s.post(BASE+'/settings',data={'display_name':new},**session_timeout)
        changed=new in s.get(BASE+'/settings',timeout=6).text
        # Restore original name regardless of whether a CSRF token was required.
        current=s.get(BASE+'/settings',timeout=6)
        s.post(BASE+'/settings',data={'display_name':original,
                 '_csrf_token':token_for(current.text)},**session_timeout)
        return response.status_code==302 and changed, (
            'Tokenless profile update was accepted (same-site session).' if changed and response.status_code==302
            else f'Tokenless profile update rejected (HTTP {response.status_code}).')
    findings.append(check('VS-003','Missing anti-CSRF protection on settings','CWE-352',
                          'Require a CSRF token for sensitive form submissions; evaluate SameSite too.',csrf))

    def auth():
        other=requests.Session()
        page=other.get(BASE+'/login',timeout=6)
        page.raise_for_status()
        token=token_for(page.text)
        username='auditunknown'+secrets.token_hex(3)
        codes=[]
        for i in range(4):
            resp=other.post(BASE+'/login',data={'username':username,'password':'not-the-password',
                           '_csrf_token':token},**session_timeout)
            codes.append(resp.status_code)
        return codes==[401,401,401,401], f'Four consecutive failed login HTTP codes: {codes}.'
    findings.append(check('VS-005','Missing login attempt throttling','CWE-307',
                          'Throttle repeated login failures; consider per-account and per-IP controls.',auth))

    OUT.mkdir(exist_ok=True)
    report={'title':'VulnScope — local security assessment','target':BASE,
            'timestamp_utc':datetime.now(timezone.utc).isoformat(),
            'scope':'One intentionally vulnerable fictional website on localhost; no external targets',
            'notes':'HTTP/HTML tests do not prove browser-based JavaScript execution; manually verify XSS. '
                    'Tokenless requests alone do not demonstrate a cross-site browser exploit.',
            'findings':findings}
    (OUT/'assessment.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    cards=[]
    for f in findings:
        result=f['result']
        cards.append('<article class="finding">'
                     f'<div class="meta"><span>{html.escape(f["id"])} · {html.escape(f["cwe"])}</span><span class="status {result}">{result.replace("_", " ").upper()}</span></div>'
                     f'<h2>{html.escape(f["title"])}</h2><p>{html.escape(f["evidence"])}</p>'
                     f'<p class="fix"><b>Remediation:</b> {html.escape(f["remediation"])}</p></article>')
    report_html='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>VulnScope Assessment</title><style>
    body{background:#0b1423;color:#e5edf7;font:16px/1.55 system-ui,Segoe UI,Arial;margin:0;padding:30px}
    main{max-width:900px;margin:auto}header{padding:28px 0;border-bottom:1px solid #33445c}
    h1{font-size:32px;margin:0}h2{font-size:20px;margin:8px 0}.muted{color:#a9bdd3}
    .finding{background:#16243a;padding:24px;border:1px solid #2e425c;border-radius:14px;margin:18px 0}
    .meta{display:flex;justify-content:space-between;font-size:12px;color:#b5ccdf;gap:15px}
    .status{font-weight:800;letter-spacing:.08em}.reproduced{color:#ff9e9e}.not_reproduced{color:#70e6c6}.test_error{color:#ffd98b}
    .fix{color:#b9cce0;margin-top:20px}footer{font-size:13px;color:#9eb4cd;padding:20px 0}
    </style></head><body><main><header><div class="muted">LOCAL SECURITY ASSESSMENT</div><h1>VulnScope · VAPT Report</h1><p class="muted">One site. Five checks. Findings before and after remediation.</p></header><p class="muted">'''+html.escape(report['timestamp_utc'])+' · '+html.escape(BASE)+'''</p>'''+''.join(cards)+'''<footer>All records are fictional. Findings document a controlled localhost exercise. Review manually before making real-world security claims.</footer></main></body></html>'''
    (OUT/'assessment.html').write_text(report_html,encoding='utf-8')
    print('\nVulnScope local assessment — same website URLs before/after fixes')
    for f in findings:
        print(f'  {f["id"]}: {f["result"]} — {f["title"]}')
    print('Saved reports/assessment.json and reports/assessment.html')
    print('Reminder: a missing XSS alert in Python is not browser verification.')


if __name__ == '__main__':
    main()
