"""Create safe, readable HTML and JSON assessment outputs."""
from __future__ import annotations

import html
import json
from pathlib import Path


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_report(data: dict, css: str) -> str:
    checks = data["results"]
    verified = sum(item["status"] == "verified" for item in checks)
    needs_review = len(checks) - verified
    high_count = sum(item["status"] == "verified" and item["severity"].startswith("High") for item in checks)
    cards = []
    for item in checks:
        is_verified = item["status"] == "verified"
        status_label = "Verified in local lab" if is_verified else "Needs review"
        status_class = "verified" if is_verified else "review"
        evidence = "".join(f"<li>{esc(line)}</li>" for line in item["observations"])
        limitation = f'<p class="limit"><strong>Scope note:</strong> {esc(item["limitations"])}</p>' if item.get("limitations") else ""
        cards.append(f'''
        <article class="finding">
          <div class="finding-top">
            <div class="finding-id">{esc(item['id'])} <span class="separator">/</span> {esc(item['category'])}</div>
            <span class="status {status_class}">{status_label}</span>
          </div>
          <div class="finding-title-row"><h3>{esc(item['title'])}</h3><span class="severity">{esc(item['severity'])}</span></div>
          <p class="description">{esc(item['interpretation'])}</p>
          <div class="endpoints"><span>Vulnerable: <code>{esc(item['vulnerable_endpoint'])}</code></span><span>Protected: <code>{esc(item['secure_endpoint'])}</code></span></div>
          <details><summary>Evidence &amp; remediation <span aria-hidden="true">+</span></summary>
            <div class="detail-body"><h4>Observed HTTP behavior</h4><ul>{evidence}</ul>
              <h4>Remediation</h4><p>{esc(item['remediation'])}</p>{limitation}
            </div>
          </details>
        </article>''')
    cards_html = "\n".join(cards)
    escaped_css = css.replace("</style", "<\\/style")
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>VulnScope | Local Security Assessment</title>
<style>{escaped_css}</style>
</head>
<body>
<div class="page">
  <header class="nav"><div class="logo"><span class="shield">◇</span> Vuln<span class="mint">Scope</span></div><span class="local">● LOCAL TRAINING LAB</span></header>
  <main>
    <div class="eyebrow">AUTOMATED SECURITY ASSESSMENT · PHASE 3</div>
    <section class="hero"><div><h1>Vulnerability assessment<br><span>at a glance.</span></h1>
      <p>Evidence-led checks of five intentionally insecure web application labs, each compared against a protected endpoint.</p></div>
      <div class="hero-symbol" aria-hidden="true">VS<span> / 03</span></div></section>
    <section class="metrics" aria-label="Assessment summary">
      <div class="metric"><span>LAB CHECKS</span><strong>{len(checks):02d}</strong><small>Explicit local endpoints</small></div>
      <div class="metric"><span>VERIFIED</span><strong class="mint">{verified:02d}</strong><small>Expected unsafe / safe behavior</small></div>
      <div class="metric"><span>NEEDS REVIEW</span><strong class="amber">{needs_review:02d}</strong><small>Incomplete comparison</small></div>
      <div class="metric"><span>HIGH (DEMO)</span><strong>{high_count:02d}</strong><small>Illustrative rating only</small></div>
    </section>
    <section class="scope"><div><span class="label">SCOPE</span><strong>{esc(data['scope'])}</strong></div>
      <div><span class="label">GENERATED AT (UTC)</span><strong>{esc(data['generated_at_utc'])}</strong></div></section>
    <section class="findings-section"><div class="section-head"><div><div class="eyebrow">TEST RESULTS</div><h2>Security findings</h2></div><div class="count">{len(checks)} checks</div></div>
      <div class="findings">{cards_html}</div></section>
    <section class="boundary"><span class="boundary-icon">!</span><div><h3>Educational lab evidence only</h3>
      <p>{esc(data['disclaimer'])} Generated observations are not evidence of vulnerabilities in external websites or production services. Do not publish session cookies or real user data.</p></div></section>
  </main>
  <footer>VulnScope · Automated VAPT learning project <span>Python · Flask · requests · Secure coding comparison</span></footer>
</div>
</body></html>'''


def write_report(data: dict, output_dir: Path, css_path: Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / "vulnscope_assessment.html"
    json_path = output_dir / "vulnscope_assessment.json"
    css = Path(css_path).read_text(encoding="utf-8")
    html_path.write_text(render_report(data, css), encoding="utf-8")
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return html_path, json_path
