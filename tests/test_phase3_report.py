"""Small offline unit tests. Run: python -m unittest discover -s tests -p 'test_phase3_report.py'"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))
from report_builder import render_report
from run_assessment import validate_base_url


class Phase3Tests(unittest.TestCase):
    def test_loopback_url_accepted(self):
        self.assertEqual(validate_base_url("http://127.0.0.1:5000"), "http://127.0.0.1:5000")

    def test_external_and_untrusted_urls_rejected(self):
        for value in ("https://example.com", "http://192.168.1.1:5000", "http://127.0.0.1:5000/other", "http://127.0.0.1:5000?next=evil"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_base_url(value)

    def test_report_escapes_untrusted_evidence(self):
        data = {
            "scope": "http://127.0.0.1:5000", "generated_at_utc": "2026-11-18T00:00:00+00:00",
            "disclaimer": "Training only", "results": [{
                "id": "VS-001", "title": "test", "category": "CWE-89", "severity": "High (illustrative)",
                "status": "needs_review", "vulnerable_endpoint": "/bad", "secure_endpoint": "/safe",
                "observations": ["<script>alert('oops')</script>"], "interpretation": "test", "remediation": "Use params", "limitations": "",
            }]
        }
        page = render_report(data, "body{color:white}")
        self.assertIn("&lt;script&gt;alert", page)
        self.assertNotIn("<script>alert('oops')</script>", page)
        self.assertIn("Needs review", page)


if __name__ == "__main__":
    unittest.main()
