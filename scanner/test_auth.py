"""Run while VulnScope is running at http://127.0.0.1:5000."""
import requests

BASE = "http://127.0.0.1:5000"

def main():
    session = requests.Session()
    start = session.get(BASE + "/lab/auth/start", timeout=5)
    start.raise_for_status()

    reset = session.post(BASE + "/lab/auth/reset", timeout=5)
    reset.raise_for_status()

    weak_codes = [session.post(BASE + "/lab/auth/vulnerable/attempt",
                 data={"password": "invalid-demo-password"}, timeout=5).status_code
                  for _ in range(4)]
    assert weak_codes == [401, 401, 401, 401], weak_codes
    print("PASS: Vulnerable lab allows repeated failed attempts (4 x 401)")

    safe_codes = [session.post(BASE + "/lab/auth/safe/attempt",
                 data={"password": "invalid-demo-password"}, timeout=5).status_code
                  for _ in range(4)]
    assert safe_codes == [401, 401, 401, 429], safe_codes
    print("PASS: Protected lab blocks a fourth attempt (401, 401, 401, 429)")

    session.post(BASE + "/lab/auth/reset", timeout=5).raise_for_status()
    print("VS-005 demonstration successful; lab counters reset")

if __name__ == "__main__":
    main()
