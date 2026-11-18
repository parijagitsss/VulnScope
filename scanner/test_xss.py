"""Check reflected XSS HTML output. Browser execution must be verified manually."""

import requests

BASE_URL = "http://127.0.0.1:5000"
PAYLOAD = '<script>alert("VulnScope XSS test")</script>'


def main():
    vulnerable = requests.get(
        f"{BASE_URL}/lab/xss", params={"comment": PAYLOAD}, timeout=5
    )
    secure = requests.get(
        f"{BASE_URL}/lab/xss-safe", params={"comment": PAYLOAD}, timeout=5
    )
    vulnerable.raise_for_status()
    secure.raise_for_status()

    # requests does not execute JavaScript. It checks the HTTP response HTML.
    assert PAYLOAD in vulnerable.text, "Vulnerable response did not contain raw script"
    assert PAYLOAD not in secure.text, "Secure response still contains raw script"
    assert "&lt;script&gt;" in secure.text, "Expected escaped script tag"

    print("PASS: Vulnerable endpoint reflects unescaped HTML.")
    print("PASS: Secure endpoint escapes the same input.")
    print("Next: verify browser alert in vulnerable page, but not safe page.")


if __name__ == "__main__":
    main()
