"""Run while the VulnScope Flask server is listening on 127.0.0.1:5000.

Only tests the local demonstration profile, never a real account.
"""

import re

import requests

BASE_URL = "http://127.0.0.1:5000"


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with requests.Session() as client:
        start = client.get(f"{BASE_URL}/lab/csrf/start", timeout=5)
        check(start.status_code == 200, "Failed to start CSRF lab")

        # The deliberately vulnerable endpoint accepts a tokenless form POST.
        vulnerable = client.post(
            f"{BASE_URL}/lab/csrf",
            data={"display_name": "CSRF Demo Changed"},
            allow_redirects=True,
            timeout=5,
        )
        check(vulnerable.status_code == 200, "Vulnerable POST did not complete")
        check("CSRF Demo Changed" in vulnerable.text, "Vulnerable name did not change")
        print("PASS: Vulnerable demo accepted a tokenless POST.")

        # The protected endpoint MUST refuse the identical tokenless update.
        rejected = client.post(
            f"{BASE_URL}/lab/csrf-safe",
            data={"display_name": "Unauthorized Change"},
            allow_redirects=False,
            timeout=5,
        )
        check(rejected.status_code == 403, f"Expected 403, got {rejected.status_code}")
        safe_page = client.get(f"{BASE_URL}/lab/csrf-safe", timeout=5)
        check("Unauthorized Change" not in safe_page.text, "Rejected update changed the name")
        print("PASS: Protected demo rejected the tokenless POST (HTTP 403).")

        # The normal protected form has a valid token and MUST still work.
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', safe_page.text)
        check(match is not None, "Protected form lacks a hidden CSRF token")
        valid = client.post(
            f"{BASE_URL}/lab/csrf-safe",
            data={"display_name": "Authorized Change", "csrf_token": match.group(1)},
            allow_redirects=True,
            timeout=5,
        )
        check(valid.status_code == 200, "Protected form submission failed")
        check("Authorized Change" in valid.text, "Protected name did not change")
        print("PASS: Protected demo accepted a valid CSRF token.")

    print("SUCCESS: VulnScope CSRF lab checks passed.")


if __name__ == "__main__":
    main()
