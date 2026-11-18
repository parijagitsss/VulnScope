#!/usr/bin/env python3
"""Build a local, evidence-led HTML VAPT report with Python's standard library.

Reads existing findings.json without modifying it. Generates report HTML and JSON.
Use only on your own VulnScope training lab. No network requests are made.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from urllib.parse import quote
import xml.etree.ElementTree as ET


def read_json(path: Path):
    if not path.is_file():
        return None
    with path.open(encoding='utf-8') as file:
        return json.load(file)


def read_findings(path: Path):
    obj = read_json(path)
    if obj is None:
        return []
    data = obj.get('findings', []) if isinstance(obj, dict) else obj
    if not isinstance(data, list):
        raise ValueError('reports/findings.json must contain a findings array')
    return [item for item in data if isinstance(item, dict)]


def nmap_services(path: Path):
    if not path.is_file():
        return []
    root = ET.parse(path).getroot()
    items = []
    for host in root.findall('host'):
        addr = host.find('address')
        host_addr = addr.get('addr', '') if addr is not None else ''
        for port in host.findall('./ports/port'):
            state = port.find('state')
            service = port.find('service')
            items.append({
                'host': host_addr,
                'port': port.get('portid', ''),
                'protocol': port.get('protocol', ''),
                'state': state.get('state', '') if state is not None else '',
                'service': service.get('name', '') if service is not None else '',
                'product': service.get('product', '') if service is not None else '',
                'version': service.get('version', '') if service is not None else '',
            })
    return items


def zap_alerts(path: Path):
    """Accept ZAP traditional JSON exports or a manually curated alerts array."""
    obj = read_json(path)
    if obj is None:
        return []
    if isinstance(obj, dict) and 'site' in obj:
        sites = obj.get('site', [])
        if isinstance(sites, dict):
            sites = [sites]
        alerts = []
        for site in sites:
            if isinstance(site, dict) and isinstance(site.get('alerts'), list):
                alerts.extend(site['alerts'])
    elif isinstance(obj, dict):
        alerts = obj.get('alerts', [])
    elif isinstance(obj, list):
        alerts = obj
    else:
        alerts = []
    if not isinstance(alerts, list):
        return []
    out = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        out.append({
            'name': str(alert.get('name') or alert.get('alert') or 'Unnamed ZAP alert'),
            'risk': str(alert.get('risk') or alert.get('riskdesc') or 'Not specified'),
            'confidence': str(alert.get('confidence') or 'Not specified'),
            'status': 'Unverified automated alert',
        })
    return out


def e(value):
    return escape(str(value if value is not None else ''), quote=True)


def status_tag(value):
    s = str(value or 'Not verified')
    low = s.lower()
    kind = 'good' if any(x in low for x in ['verified', 'reproduced']) and not any(x in low for x in ['unverified', 'not verified']) else 'warn'
    return f'<span class="pill {kind}">{e(s)}</span>'


def severity_tag(value):
    s = str(value or 'Unrated')
    low = s.lower()
    kind = 'high' if 'critical' in low or 'high' in low else 'medium' if 'medium' in low else 'neutral'
    return f'<span class="pill {kind}">{e(s)}</span>'


def table_rows(items, columns):
    if not items:
        return '<tr><td colspan="%d" class="muted">No evidence imported yet.</td></tr>' % len(columns)
    return '\n'.join('<tr>' + ''.join(f'<td>{e(item.get(k, ""))}</td>' for k in columns) + '</tr>' for item in items)


def build_html(findings, services, alerts, created_at):
    verified = [x for x in findings if 'verified' in str(x.get('status', '')).lower() and 'unverified' not in str(x.get('status', '')).lower()]
    cards = []
    for f in findings:
        title = f.get('title', 'Untitled finding')
        endpoint = f.get('endpoint', f.get('affected_endpoint', 'Not recorded'))
        fields = [
            ('Endpoint', endpoint),
            ('Category', f.get('category', 'Not recorded')),
            ('Description', f.get('description', 'Not recorded')),
            ('Observed impact', f.get('impact', 'Not recorded')),
            ('Remediation', f.get('remediation', 'Not recorded')),
            ('Secure comparison', f.get('secure_endpoint', 'Not recorded')),
        ]
        details = ''.join(f'<dt>{e(k)}</dt><dd>{e(v)}</dd>' for k, v in fields)
        cards.append(f'''<article class="finding">
          <div class="finding-head"><div><small>{e(f.get('id',''))}</small><h3>{e(title)}</h3></div><div>{severity_tag(f.get('severity'))} {status_tag(f.get('status'))}</div></div>
          <dl>{details}</dl></article>''')
    finding_html = '\n'.join(cards) if cards else '<p class="muted">No findings.json entries found. Add only confirmed observations.</p>'
    css = r'''
    :root{color-scheme:dark;font-family:Inter,Segoe UI,Arial,sans-serif;background:#0b1220;color:#edf6ff}
    *{box-sizing:border-box}body{margin:0;background:linear-gradient(160deg,#0b1220,#101c2c 55%,#0d1624);line-height:1.6}
    main{max-width:1080px;margin:auto;padding:44px 24px 80px}
    .eyebrow{letter-spacing:.17em;text-transform:uppercase;color:#69e7cc;font-weight:700;font-size:.78rem}
    h1{font-size:clamp(2rem,4.4vw,3.2rem);line-height:1.13;max-width:730px;margin:14px 0}
    h2{font-size:1.4rem;margin:34px 0 16px}h3{font-size:1.13rem;margin:3px 0 0}
    .lede{color:#b1c2d3;max-width:820px}.muted{color:#9fb0c4}
    .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:32px 0}
    .metric,.panel,.finding{background:#142238;border:1px solid #31445b;border-radius:15px;padding:21px}
    .metric b{display:block;font-size:2rem;color:#70ead1}.metric span{font-size:.86rem;color:#b6c4d5}
    .panel{margin:14px 0}.finding{margin:14px 0}.finding-head{display:flex;gap:12px;align-items:start;justify-content:space-between;flex-wrap:wrap}
    .finding-head small{color:#76e5d0}dl{display:grid;grid-template-columns:minmax(125px,170px) 1fr;gap:10px;margin:20px 0 0}
    dt{color:#97a9bf;font-size:.9rem}dd{margin:0;overflow-wrap:anywhere}
    .pill{display:inline-block;border:1px solid #4b657c;border-radius:25px;padding:3px 9px;color:#cce2ed;font-size:.74rem;white-space:nowrap;margin:2px}
    .pill.good{border-color:#2e7d6c;color:#78edc8}.pill.warn,.pill.medium{border-color:#9e7b39;color:#f5ca73}.pill.high{border-color:#a6506d;color:#ff9ab8}
    .scroll{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;border-bottom:1px solid #2e4056}th{color:#75e1cb;font-size:.83rem}td{font-size:.9rem}
    code{padding:2px 5px;background:#0c1726;border-radius:3px;color:#81e3d2}footer{font-size:.81rem;color:#92a7bf;margin-top:40px}
    @media print{:root{color-scheme:light;background:#fff;color:#151e2d}body{background:white;color:#151e2d}.metric,.panel,.finding{background:#fff;border-color:#ccc;break-inside:avoid}.muted,.lede,dt,.metric span{color:#344}}
    '''
    return f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnScope — Final VAPT Assessment</title><style>{css}</style></head><body><main>
    <div class="eyebrow">VulnScope · Local security training environment</div>
    <h1>Web Application Vulnerability Assessment &amp; Penetration Testing</h1>
    <p class="lede">Assessment date: {e(created_at)}. Scope: the deliberately vulnerable VulnScope application running on <code>127.0.0.1:5000</code>. This report consolidates existing project findings and optional tool exports without performing a new scan.</p>
    <section class="metrics"><div class="metric"><b>{len(findings)}</b><span>Recorded lab findings</span></div><div class="metric"><b>{len(verified)}</b><span>Marked verified in source JSON</span></div><div class="metric"><b>{len(services)}</b><span>Nmap ports reported</span></div><div class="metric"><b>{len(alerts)}</b><span>ZAP alerts (unverified)</span></div></section>
    <section class="panel"><h2>Scope &amp; methodology</h2><p>This educational assessment combines controlled local SQLi, XSS, CSRF, IDOR, and authentication lab tests; optional Nmap service discovery; Burp Suite manual HTTP verification; and ZAP passive-alert review.</p><p><b>Interpretation:</b> A finding marked verified reflects the status recorded in <code>reports/findings.json</code>, not independent confirmation by this report generator. Nmap open ports indicate exposure, not necessarily vulnerabilities. ZAP alerts remain candidate findings pending validation. Severity labels are illustrative unless independently scored.</p></section>
    <h2>Application vulnerability findings</h2>{finding_html}
    <section class="panel"><h2>Nmap service discovery</h2><div class="scroll"><table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>{table_rows(services,['host','port','protocol','state','service','product','version'])}</tbody></table></div></section>
    <section class="panel"><h2>ZAP passive alerts — unverified</h2><p class="muted">These automated alert labels do not establish exploitability or confirm a vulnerability. Review each in ZAP before adding it to the verified findings.</p><div class="scroll"><table><thead><tr><th>Alert</th><th>Risk</th><th>Confidence</th><th>Interpretation</th></tr></thead><tbody>{table_rows(alerts,['name','risk','confidence','status'])}</tbody></table></div></section>
    <section class="panel"><h2>Evidence &amp; limitations</h2><p>Keep Burp Repeater screenshots and sanitized original tool exports in <code>reports/tool_evidence/</code>. Review all evidence for session cookies, tokens and personal information before publishing. The report excludes full HTTP traces, user secrets, and automatic claims of exploitability. No external hosts are scanned by this script.</p></section>
    <footer>Generated by VulnScope • Re-run after changing findings or evidence • For isolated training only</footer></main></body></html>'''


def main(argv=None):
    p = argparse.ArgumentParser(description='Build VulnScope final report (offline only)')
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1], help='Project root folder')
    args = p.parse_args(argv)
    root = args.root.resolve()
    reports = root / 'reports'
    evidence = reports / 'tool_evidence'
    reports.mkdir(parents=True, exist_ok=True)

    findings = read_findings(reports / 'findings.json')
    services = nmap_services(evidence / 'nmap-localhost.xml')
    alerts = zap_alerts(evidence / 'zap-alerts.json')
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    summary = {
        'generated_at_utc': now,
        'scope': '127.0.0.1:5000 only; local VulnScope lab',
        'counts': {
            'recorded_findings': len(findings),
            'source_marked_verified': sum('verified' in str(f.get('status','')).lower() and 'unverified' not in str(f.get('status','')).lower() for f in findings),
            'nmap_reported_ports': len(services),
            'zap_unverified_alerts': len(alerts),
        },
        'nmap_services': services,
        'zap_unverified_alerts': alerts,
        'finding_ids': [str(f.get('id', '')) for f in findings],
        'notes': 'This report generator does not independently validate the source findings or ZAP alerts.'
    }
    output_html = reports / 'final_vapt_report.html'
    output_json = reports / 'final_vapt_summary.json'
    output_html.write_text(build_html(findings, services, alerts, now), encoding='utf-8')
    output_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Report created:', output_html)
    print('Summary created:', output_json)
    print(f"Recorded findings: {len(findings)} | Nmap port entries: {len(services)} | ZAP alerts (unverified): {len(alerts)}")
    if not (evidence / 'nmap-localhost.xml').exists():
        print('Optional Nmap XML not imported yet.')
    if not (evidence / 'zap-alerts.json').exists():
        print('Optional ZAP JSON not imported yet (HTML reports can still be stored separately).')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
