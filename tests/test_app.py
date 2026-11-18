import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from app import app

def test_login_page():
    app.config['TESTING'] = True
    with app.test_client() as client:
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Welcome to VulnScope' in response.data

def test_dashboard_requires_login():
    app.config['TESTING'] = True
    with app.test_client() as client:
        response = client.get('/dashboard')
        assert response.status_code == 302
        assert '/login' in response.location
