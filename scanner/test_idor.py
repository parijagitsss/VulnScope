"""Automated IDOR lab check. Run while local Flask server is running.

Usage: python scanner/test_idor.py
Requires: requests (python -m pip install requests)
"""

import requests

BASE_URL = "http://127.0.0.1:5000"
TIMEOUT = 5


def run_test():
    with requests.Session() as client:
        # Start lab session as Alice (demo ID 1) and retain its cookie.
        start = client.get(f"{BASE_URL}/lab/idor/start", timeout=TIMEOUT)
        start.raise_for_status()

        own = client.get(
            f"{BASE_URL}/lab/idor-safe",
            params={"user_id": 1}, timeout=TIMEOUT
        )
        assert own.status_code == 200, f"Own protected record: {own.status_code}"
        assert 'data-profile-id="1"' in own.text

        vulnerable = client.get(
            f"{BASE_URL}/lab/idor",
            params={"user_id": 2}, timeout=TIMEOUT
        )
        assert vulnerable.status_code == 200, f"Vulnerable Bob record: {vulnerable.status_code}"
        assert 'data-profile-id="2"' in vulnerable.text
        assert "bob@example.test" in vulnerable.text

        protected = client.get(
            f"{BASE_URL}/lab/idor-safe",
            params={"user_id": 2}, timeout=TIMEOUT,
            allow_redirects=False
        )
        assert protected.status_code == 403, f"Protected Bob record: {protected.status_code}"

        print("PASS: Alice can access her own profile on the protected endpoint (200).")
        print("PASS: Vulnerable endpoint exposes Bob's synthetic profile (200).")
        print("PASS: Protected endpoint blocks access to Bob's profile (403).")
        print("IDOR demonstration and remediation checks complete.")


if __name__ == "__main__":
    run_test()
