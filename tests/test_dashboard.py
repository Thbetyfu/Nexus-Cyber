"""
Unit tests untuk web dashboard (Phase 6)
Run: pytest tests/test_dashboard.py -v
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ===================================
# FIXTURES
# ===================================

@pytest.fixture
def app():
    """Create test Flask app"""
    from web_gateway import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    flask_app.config['SESSION_COOKIE_SECURE'] = False
    return flask_app


@pytest.fixture
def client(app):
    """Flask test client"""
    with app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Authenticated test client"""
    client.post('/login', data={
        'username': 'admin',
        'password': os.getenv('ADMIN_PASSWORD', 'default_password')
    })
    return client


# ===================================
# HELPERS
# ===================================

def make_mock_cursor(rows=None, row=None):
    """Create a mock DB cursor"""
    mock_cursor = MagicMock()
    if row is not None:
        mock_cursor.fetchone.return_value = row
    if rows is not None:
        mock_cursor.fetchall.return_value = rows
    return mock_cursor


def make_mock_conn(cursor):
    """Create a mock DB connection"""
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = cursor
    mock_conn.cursor.return_value.__enter__ = lambda s: s
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    return mock_conn


# ===================================
# TEST: AUTHENTICATION
# ===================================

class TestAuthentication:
    """Test login/logout flows"""

    def test_root_redirects_to_login(self, client):
        """/ should redirect unauthenticated users to /login"""
        res = client.get('/', follow_redirects=False)
        assert res.status_code == 302
        assert 'login' in res.location

    def test_admin_redirects_to_login(self, client):
        """Unauthenticated /admin access → redirect"""
        res = client.get('/admin', follow_redirects=False)
        assert res.status_code == 302
        assert 'login' in res.location

    def test_login_page_loads(self, client):
        """GET /login should return 200"""
        res = client.get('/login')
        assert res.status_code == 200
        assert b'Nexus-Cyber' in res.data

    def test_login_with_invalid_credentials(self, client):
        """Wrong password → 200 + error message"""
        res = client.post('/login', data={
            'username': 'admin',
            'password': 'wrong_password_xyz'
        })
        assert res.status_code == 200
        assert b'Invalid credentials' in res.data

    def test_login_with_valid_credentials(self, client):
        """Valid credentials → redirect to dashboard"""
        res = client.post('/login', data={
            'username': 'admin',
            'password': os.getenv('ADMIN_PASSWORD', 'default_password')
        }, follow_redirects=False)
        assert res.status_code == 302
        assert 'admin' in res.location

    def test_logout_clears_session(self, auth_client):
        """After logout, /admin must redirect again"""
        auth_client.get('/logout')
        res = auth_client.get('/admin')
        assert res.status_code == 302


# ===================================
# TEST: DASHBOARD PAGES
# ===================================

class TestDashboardPages:
    """Test dashboard HTML routes"""

    def test_dashboard_loads(self, auth_client):
        """Authenticated /admin → 200"""
        res = auth_client.get('/admin')
        assert res.status_code == 200
        assert b'Nexus-Cyber' in res.data

    @patch('web_gateway.get_db')
    def test_incidents_page_loads(self, mock_get_db, auth_client):
        """Authenticated /admin/incidents → 200"""
        mock_db = mock_get_db.return_value
        mock_cursor = make_mock_cursor(
            rows=[],
            row={'count': 0}
        )
        mock_conn = make_mock_conn(mock_cursor)
        mock_db.pool.get_connection.return_value = mock_conn

        res = auth_client.get('/admin/incidents')
        assert res.status_code == 200

    @patch('web_gateway.get_db')
    def test_blocked_ips_page_loads(self, mock_get_db, auth_client):
        """Authenticated /admin/blocked-ips → 200"""
        mock_db = mock_get_db.return_value
        mock_cursor = make_mock_cursor(rows=[])
        mock_conn = make_mock_conn(mock_cursor)
        mock_db.pool.get_connection.return_value = mock_conn

        res = auth_client.get('/admin/blocked-ips')
        assert res.status_code == 200

    @patch('web_gateway.get_db')
    def test_incident_detail_page_loads(self, mock_get_db, auth_client):
        """Incident detail page → 200"""
        mock_db = mock_get_db.return_value
        mock_cursor = make_mock_cursor(row={
            'id': 1,
            'incident_type': 'SQL_INJECTION',
            'severity': 'CRITICAL',
            'source_ip': '10.0.0.1',
            'created_at': '2026-03-04',
            'summary': 'Test',
            'forensic_data': None
        })
        mock_conn = make_mock_conn(mock_cursor)
        mock_db.pool.get_connection.return_value = mock_conn

        res = auth_client.get('/admin/incident/1')
        assert res.status_code == 200


# ===================================
# TEST: API ENDPOINTS
# ===================================

class TestAPI:
    """Test API REST endpoints"""

    def test_api_stats_requires_auth(self, client):
        """Unauthenticated /api/stats → redirect"""
        res = client.get('/api/stats', follow_redirects=False)
        assert res.status_code == 302

    @patch('web_gateway.get_db')
    def test_api_stats_returns_json(self, mock_get_db, auth_client):
        """Authenticated /api/stats → valid JSON"""
        mock_db = mock_get_db.return_value
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            {'total_queries': 100, 'safe_queries': 70, 'dangerous_queries': 20, 'critical_queries': 10},
            {'total_incidents': 5, 'critical_incidents': 2, 'high_incidents': 3},
            {'count': 3}
        ]
        mock_cursor.fetchall.return_value = []
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.pool.get_connection.return_value = mock_conn

        res = auth_client.get('/api/stats')
        assert res.status_code == 200

        data = res.get_json()
        assert 'query_stats' in data
        assert 'incident_stats' in data
        assert 'blocked_ips_count' in data
        assert 'timestamp' in data

    def test_api_recent_threats_requires_auth(self, client):
        """Unauthenticated /api/recent-threats → redirect"""
        res = client.get('/api/recent-threats', follow_redirects=False)
        assert res.status_code == 302

    @patch('web_gateway.get_db')
    def test_api_recent_threats_returns_list(self, mock_get_db, auth_client):
        """Authenticated /api/recent-threats → list"""
        mock_db = mock_get_db.return_value
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.pool.get_connection.return_value = mock_conn

        res = auth_client.get('/api/recent-threats?limit=5')
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, list)


# ===================================
# TEST: IP MANAGEMENT
# ===================================

class TestIPManagement:
    """Test IP blocking/unblocking"""

    def test_unblock_invalid_ip_format(self, auth_client):
        """POST /api/unblock-ip/invalid-ip → 400"""
        res = auth_client.post('/api/unblock-ip/not-an-ip')
        assert res.status_code == 400
        data = res.get_json()
        assert 'error' in data

    @patch('web_gateway.get_db')
    def test_unblock_valid_ip(self, mock_get_db, auth_client):
        """POST /api/unblock-ip/valid-ip → 200"""
        mock_db = mock_get_db.return_value
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.pool.get_connection.return_value = mock_conn

        res = auth_client.post('/api/unblock-ip/192.168.1.100')
        assert res.status_code == 200
        data = res.get_json()
        assert data.get('success') is True


# ===================================
# TEST: SYSTEM RESET
# ===================================

class TestSystemReset:
    """Test system reset endpoint"""

    def test_reset_wrong_password(self, auth_client):
        """Reset with wrong password → 401"""
        res = auth_client.post('/api/reset-system',
                               json={'password': 'wrong_password'},
                               content_type='application/json')
        assert res.status_code == 401

    @patch('web_gateway.get_db')
    def test_reset_correct_password(self, mock_get_db, auth_client):
        """Reset with correct password → 200"""
        mock_db = mock_get_db.return_value
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.pool.get_connection.return_value = mock_conn

        admin_pass = os.getenv('ADMIN_PASSWORD', 'default_password')
        res = auth_client.post('/api/reset-system',
                               json={'password': admin_pass},
                               content_type='application/json')
        assert res.status_code == 200
        data = res.get_json()
        assert data.get('success') is True


# ===================================
# TEST: ERROR HANDLING
# ===================================

class TestErrorHandling:
    """Test error pages"""

    def test_404_page(self, client):
        """Non-existent route → 404"""
        res = client.get('/nonexistent-route-xyz')
        assert res.status_code == 404
        assert b'404' in res.data


# ===================================
# INTEGRATION TEST
# ===================================

class TestDashboardIntegration:
    """Full end-to-end flow test"""

    @patch('web_gateway.get_db')
    def test_full_authenticated_flow(self, mock_get_db, client):
        """
        1. Visit /login
        2. POST valid creds
        3. GET /admin (dashboard)
        4. GET /api/stats
        5. GET /logout
        6. Confirm /admin is locked again
        """
        mock_db = mock_get_db.return_value
        # Mock DB
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            {'total_queries': 50, 'safe_queries': 40, 'dangerous_queries': 8, 'critical_queries': 2},
            {'total_incidents': 2, 'critical_incidents': 1, 'high_incidents': 1},
            {'count': 1}
        ]
        mock_cursor.fetchall.return_value = []
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.pool.get_connection.return_value = mock_conn

        # 1. Login page loads
        res = client.get('/login')
        assert res.status_code == 200

        # 2. Login
        res = client.post('/login', data={
            'username': 'admin',
            'password': os.getenv('ADMIN_PASSWORD', 'default_password')
        }, follow_redirects=True)
        assert res.status_code == 200

        # 3. Dashboard loads
        res = client.get('/admin')
        assert res.status_code == 200

        # 4. API works
        res = client.get('/api/stats')
        assert res.status_code == 200
        assert 'query_stats' in res.get_json()

        # 5. Logout
        client.get('/logout')

        # 6. Dashboard locked
        res = client.get('/admin', follow_redirects=False)
        assert res.status_code == 302
