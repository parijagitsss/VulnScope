"""Smoke tests for normal employee workflows. Run: python -m unittest discover -s tests"""
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import database


class WebsiteSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='vulnscope_website_test_')
        cls.patcher = patch.object(database, 'DB_PATH', Path(cls.temp.name) / 'site.db')
        cls.patcher.start()
        database.initialize()
        from app import app
        cls.app = app
        cls.app.config['TESTING'] = True

    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        cls.temp.cleanup()

    def setUp(self):
        self.client = self.app.test_client()

    def login(self):
        with self.client.session_transaction() as session:
            session['_portal_csrf'] = 'test-token'
        response = self.client.post('/login', data={
            '_csrf_token': 'test-token', 'username': 'alice', 'password': 'Welcome123!'
        })
        self.assertEqual(response.status_code, 302)

    def test_login_dashboard(self):
        self.login()
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Good to see you', response.data)

    def test_people_directory_starts_without_results(self):
        self.login()
        response = self.client.get('/employees')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.count(b'data-employee-row'), 0)
        response = self.client.get('/employees?username=alice')
        self.assertEqual(response.data.count(b'data-employee-row'), 1)

    def test_single_ticket_route_and_settings(self):
        self.login()
        self.assertEqual(self.client.get('/tickets/1041').status_code, 200)
        self.assertEqual(self.client.get('/settings').status_code, 200)

    def test_no_parallel_secure_routes(self):
        self.login()
        for route in ['/employees/secure', '/settings/secure',
                      '/tickets/secure/1041', '/login-protected', '/lab/sqli']:
            self.assertEqual(self.client.get(route).status_code, 404, route)


if __name__ == '__main__':
    unittest.main()
