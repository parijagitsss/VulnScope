"""VulnScope Phase 3: lab-only automated assessment.

Supported target: loopback address only. This scanner checks only the five
hard-coded synthetic VulnScope labs; it is not a general-purpose web scanner.

Run while Flask is listening locally:
    python scanner/run_assessment.py
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from report_builder import write_report

BASE = "http://127.0.0.1:5000"
TIMEOUT = 6
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
REPORTS = PROJECT_ROOT / "reports"
XSS_PAYLOAD = '<script>alert("VulnScope XSS test")</script>'
SQL_PAYLOAD = "' OR '1'='1"

DEFINITIONS = [
    ("VS-001", "SQL Injection", "CWE-89", "High", "/lab/sqli", "/lab/sqli-safe",
     "Use parameterized SQL queries for every untrusted value."),
    ("VS-002", "Reflected XSS", "CWE-79", "Medium", "/lab/xss", "/lab/xss-safe",
     "Use context-appropriate output encoding; do not mark untrusted input safe."),
    ("VS-003", "Cross-Site Request Forgery", "CWE-352", "Medium", "/lab/csrf", "/lab/csrf-safe",
     "Validate per-session CSRF tokens on state-changing requests."),
    ("VS-004", "Insecure Direct Object Reference", "CWE-639", "High", "/lab/idor", "/lab/idor-safe",
     "Enforce server-side object-level authorization on every request."),
    ("VS-005", "Missing Login Rate Limiting", "CWE-307", "Medium", "/lab/auth/vulnerable/attempt", "/lab/auth/safe/attempt",
     "Apply sensible per-account and per-IP throttling with monitoring."),
]


def validate_base_url(value: str) -> str:
    """Reject remote targets, credentials, and path/query injection."""
    parts = urlsplit(value)
    if (parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "::1"}
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or parts.path not in {"", "/"}):
        raise ValueError("Only http://127.0.0.1:<port> (or [::1]) is supported")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    if port is None or not (1 <= port <= 65535):
        raise ValueError("Specify a local port, e.g. 5000")
    return value.rstrip("/")


def new_client() -> requests.Session:
    client = requests.Session()
    client.trust_env = False  # Never route localhost lab traffic through a proxy.
    return client


def result(meta, passed: bool, observations: list[str], detail: str, limitation: str = "") -> dict:
    ident, title, category, severity, vulnerable, secure, fix = meta
    return {
        "id": ident,
        "title": title,
        "category": category,
        "severity": severity + " (illustrative)",
        "status": "verified" if passed else "needs_review",
        "vulnerable_endpoint": vulnerable,
        "secure_endpoint": secure,
        "observations": observations,
        "interpretation": detail,
        "remediation": fix,
        "limitations": limitation,
    }


def request(client, method, base, path, **kwargs):
    return client.request(method, base + path, timeout=TIMEOUT,
                          allow_redirects=False, **kwargs)


def check_sqli(base, meta):
    with new_client() as client:
        baseline = request(client, "GET", base, "/lab/sqli", params={"username": "admin"})
        vulnerable = request(client, "GET", base, "/lab/sqli", params={"username": SQL_PAYLOAD})
        secure = request(client, "GET", base, "/lab/sqli-safe", params={"username": SQL_PAYLOAD})
        counts = []
        for response in (baseline, vulnerable, secure):
            try:
                counts.append(len(response.json()["results"]) if response.status_code == 200 else None)
            except (ValueError, KeyError, TypeError):
                counts.append(None)
        passed = (counts == [1, 3, 0])
        return result(meta, passed, [
            f"Ordinary username: HTTP {baseline.status_code}, results={counts[0]}",
            f"Injection (dummy records only): HTTP {vulnerable.status_code}, results={counts[1]}",
            f"Parameterized endpoint: HTTP {secure.status_code}, results={counts[2]}",
        ], "Synthetic user search allows a tautology in the unsafe query; the parameterized query treats it as data." if passed else "Expected 1 / 3 / 0 record comparison was not observed.")


def check_xss(base, meta):
    with new_client() as client:
        vulnerable = request(client, "GET", base, "/lab/xss", params={"comment": XSS_PAYLOAD})
        secure = request(client, "GET", base, "/lab/xss-safe", params={"comment": XSS_PAYLOAD})
        raw = vulnerable.status_code == 200 and XSS_PAYLOAD in vulnerable.text
        escaped = secure.status_code == 200 and XSS_PAYLOAD not in secure.text and "&lt;script&gt;" in secure.text
        return result(meta, raw and escaped, [
            f"Unsafe page: HTTP {vulnerable.status_code}, raw markup reflected={raw}",
            f"Escaping page: HTTP {secure.status_code}, markup escaped={escaped}",
        ], "Unsafe HTML reflection and corresponding output escaping were compared." if raw and escaped else "Expected raw/escaped HTML comparison was not observed.",
        "HTTP checks do not execute JavaScript. Verify alert behavior separately in a real browser.")


def check_csrf(base, meta):
    with new_client() as client:
        start = request(client, "GET", base, "/lab/csrf/start")
        # These are synthetic session-backed names, not actual user profile changes.
        weak = request(client, "POST", base, "/lab/csrf", data={"display_name": "AuditDemoChanged"})
        weak_view = request(client, "GET", base, "/lab/csrf")
        safe = request(client, "POST", base, "/lab/csrf-safe", data={"display_name": "AuditDemoBlocked"})
        safe_view = request(client, "GET", base, "/lab/csrf-safe")
        weak_ok = weak.status_code in {200, 302, 303} and "AuditDemoChanged" in weak_view.text
        safe_ok = safe.status_code == 403 and "AuditDemoBlocked" not in safe_view.text
        passed = start.status_code in {200, 302, 303} and weak_ok and safe_ok
        return result(meta, passed, [
            f"Session initialization: HTTP {start.status_code}",
            f"Tokenless dummy update, unsafe endpoint: HTTP {weak.status_code}, changed={weak_ok}",
            f"Tokenless dummy update, protected endpoint: HTTP {safe.status_code}, rejected={safe_ok}",
        ], "Tokenless synthetic profile update succeeds only in the unsafe endpoint." if passed else "Expected tokenless accept/reject comparison was not observed.",
        "This tests a missing CSRF token, not a real cross-origin browser exploit. Browser cookie SameSite behavior is out of scope.")


def check_idor(base, meta):
    with new_client() as client:
        start = request(client, "GET", base, "/lab/idor/start")
        own = request(client, "GET", base, "/lab/idor-safe", params={"user_id": "1"})
        weak = request(client, "GET", base, "/lab/idor", params={"user_id": "2"})
        safe = request(client, "GET", base, "/lab/idor-safe", params={"user_id": "2"})
        own_ok = own.status_code == 200 and 'data-profile-id="1"' in own.text
        weak_ok = weak.status_code == 200 and 'data-profile-id="2"' in weak.text
        safe_ok = safe.status_code == 403
        passed = start.status_code in {200, 302, 303} and own_ok and weak_ok and safe_ok
        return result(meta, passed, [
            f"Own synthetic profile: HTTP {own.status_code}, accessible={own_ok}",
            f"Another synthetic profile (unsafe): HTTP {weak.status_code}, exposed={weak_ok}",
            f"Another synthetic profile (protected): HTTP {safe.status_code}, denied={safe_ok}",
        ], "Demo user Alice can see Bob's synthetic profile only through the unsafe endpoint." if passed else "Expected access-control comparison was not observed.")


def check_auth(base, meta):
    with new_client() as client:
        started = request(client, "GET", base, "/lab/auth/start")
        init = request(client, "POST", base, "/lab/auth/reset")
        weak_codes = []
        safe_codes = []
        try:
            if init.status_code == 200:
                for _ in range(4):
                    r = request(client, "POST", base, "/lab/auth/vulnerable/attempt",
                                data={"password": "invalid-demo-password"})
                    weak_codes.append(r.status_code)
                for _ in range(4):
                    r = request(client, "POST", base, "/lab/auth/safe/attempt",
                                data={"password": "invalid-demo-password"})
                    safe_codes.append(r.status_code)
        finally:
            try:
                request(client, "POST", base, "/lab/auth/reset")
            except requests.RequestException:
                pass
        passed = (started.status_code in {200, 302, 303} and init.status_code == 200
                  and weak_codes == [401]*4 and safe_codes == [401, 401, 401, 429])
        return result(meta, passed, [
            f"Demo session: HTTP {started.status_code}; counter reset: HTTP {init.status_code}",
            f"No-limit 4 synthetic failures: {weak_codes}",
            f"Rate-limited 4 synthetic failures: {safe_codes}",
        ], "The fourth failed demo login is rate-limited only in the protected endpoint." if passed else "Expected 401 / 429 comparison was not observed. Re-check your localhost CSRF exception or lab counters.",
        "Demonstrates a basic in-memory limit on a fictional account, not a production-scale account-security assessment.")


CHECKS = [check_sqli, check_xss, check_csrf, check_idor, check_auth]


def run(base: str) -> dict:
    base = validate_base_url(base)
    results = []
    for meta, checker in zip(DEFINITIONS, CHECKS):
        try:
            print(f"[RUN] {meta[0]} — {meta[1]}", flush=True)
            entry = checker(base, meta)
        except (requests.RequestException, ValueError, KeyError, TypeError, AssertionError) as exc:
            entry = result(meta, False, [f"Check could not complete: {type(exc).__name__}"],
                           "Insufficient evidence; verify the local lab is running and registered.")
        print(f"      {entry['status']}", flush=True)
        results.append(entry)
    return {
        "project": "VulnScope",
        "assessment_type": "Automated verification of five local, deliberately vulnerable lab modules",
        "scope": base,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": "Training-only local lab. Severity ratings are illustrative, not calculated CVSS scores. Not a comprehensive penetration test.",
        "verified_count": sum(item["status"] == "verified" for item in results),
        "checks_run": len(results),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope Phase 3 local lab report generator")
    parser.add_argument("--base-url", default=BASE, help="Loopback URL only (default: http://127.0.0.1:5000)")
    args = parser.parse_args()
    try:
        base = validate_base_url(args.base_url)
    except ValueError as exc:
        parser.error(str(exc))

    # Do not create a misleading 'completed assessment' when Flask is offline.
    with new_client() as client:
        try:
            preflight = request(client, "GET", base, "/")
        except requests.RequestException:
            print("ERROR: VulnScope is not reachable. Start Flask in a separate terminal first.")
            return 2
        if preflight.status_code >= 500:
            print(f"ERROR: Server returned HTTP {preflight.status_code} on preflight.")
            return 2

    assessment = run(base)
    paths = write_report(assessment, REPORTS, HERE / "assets" / "assessment.css")
    print("\nAssessment complete:")
    print(f"  Verified: {assessment['verified_count']} / {assessment['checks_run']}")
    print(f"  HTML: {paths[0]}")
    print(f"  JSON: {paths[1]}")
    print("  Reports are evidence of local demo behavior, not a real-world penetration test.")
    return 0 if assessment["verified_count"] == assessment["checks_run"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
