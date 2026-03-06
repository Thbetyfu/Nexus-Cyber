#!/usr/bin/env python3
"""
Nexus-Cyber Data-Vault Gateway - Web Administration Panel
- Real-time query monitoring
- Incident history & forensics
- IP blocking/unblocking
- System statistics
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, disconnect
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
import os
import json
import logging
from datetime import datetime, timedelta
from config import get_config
from security.input_validator import InputValidator
from security.rate_limiter import RateLimiter, BruteForceDetector
from security.logger import app_logger as logger, security_logger, audit_logger, log_audit_event
import time
import threading

# Add current directory to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

config = get_config()

# ===========================
# FLASK APP SETUP
# ===========================

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = config.SESSION_SECURE_COOKIE
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_HTTPONLY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ===========================
# RATE LIMITING & BRUTE FORCE
# ===========================
rate_limiter = RateLimiter(max_requests=config.RATE_LIMIT_QUERIES_PER_MINUTE, time_window=60)
brute_force_detector = BruteForceDetector(max_failures=5, lockout_duration=900)

# ===========================
# DATABASE CONNECTION
# ===========================

from database.db_config import DatabaseManager

_db_instance = None

def get_db():
    """Lazy singleton for the database manager"""
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager()
    return _db_instance

# Alias used throughout the module — resolved lazily
class _LazyDB:
    """Proxy that instantiates DatabaseManager on first attribute access"""
    def __getattr__(self, name):
        return getattr(get_db(), name)

db = _LazyDB()

# ===========================
# AUTHENTICATION
# ===========================

ADMIN_PASSWORD = config.ADMIN_PASSWORD
ADMIN_USERNAME = config.ADMIN_USERNAME

def login_required(f):
    """Decorator for authenticated routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def socketio_login_required(f):
    """Decorator for authenticated WebSocket events"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            disconnect()
            return False
        return f(*args, **kwargs)
    return decorated_function

# ===========================
# ROUTES - AUTHENTICATION
# ===========================

@app.route('/')
def index():
    """Redirect to login if not authenticated"""
    if 'authenticated' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login"""
    if request.method == 'POST':
        client_ip = request.remote_addr
        
        # Check rate limiting
        if config.RATE_LIMIT_ENABLED:
            allowed, info = rate_limiter.is_allowed(client_ip)
            if not allowed:
                security_logger.warning(f"Rate limit exceeded for {client_ip}")
                return render_template('login.html', error='Too many attempts. Please try later.'), 429
        
        # Check brute force lock
        if brute_force_detector.is_locked(client_ip):
            security_logger.warning(f"IP {client_ip} is locked out")
            return render_template('login.html', error='Account temporarily locked. Try again later.'), 403

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate input formatting
        if not InputValidator.validate_username(username):
            security_logger.warning(f"Invalid username format attempted: {username} from {client_ip}")
            brute_force_detector.record_failure(client_ip)
            return render_template('login.html', error='Invalid username format')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            brute_force_detector.record_success(client_ip)
            session['authenticated'] = True
            session.permanent = True
            log_audit_event('LOGIN', username, 'Admin Panel', 'SUCCESS')
            return redirect(url_for('dashboard'))
        else:
            brute_force_detector.record_failure(client_ip)
            log_audit_event('LOGIN', username, 'Admin Panel', 'FAILED')
            security_logger.warning(f"Failed login attempt: {username} from {client_ip}")
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Admin logout"""
    username = session.get('username', 'admin')
    session.clear()
    log_audit_event('LOGOUT', username, 'Admin Panel', 'SUCCESS')
    return redirect(url_for('login'))

# ===========================
# ROUTES - DASHBOARD
# ===========================

@app.route('/admin')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/admin/incidents')
@login_required
def incidents():
    """Incidents history page"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    try:
        connection = db.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Get total count
        cursor.execute("SELECT COUNT(*) as count FROM incidents")
        total = cursor.fetchone()['count']
        
        # Get paginated results
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM incidents
            ORDER BY detected_at DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        
        incidents_data = cursor.fetchall()
        cursor.close()
        connection.close()
        
        return render_template('incidents.html', 
                             incidents=incidents_data,
                             page=page,
                             per_page=per_page,
                             total=total)
    
    except Exception as e:
        logger.error(f"Error fetching incidents: {e}")
        return render_template('incidents.html', error=str(e))

@app.route('/admin/incident/<incident_id>')
@login_required
def incident_detail(incident_id):
    """Incident detail view"""
    try:
        connection = db.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM incidents WHERE id=%s", (incident_id,))
        incident = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if incident and incident.get('forensic_data'):
            try:
                incident['forensic_data_json'] = json.loads(incident['forensic_data'])
            except:
                incident['forensic_data_json'] = incident['forensic_data']
        
        return render_template('incident_detail.html', incident=incident)
    
    except Exception as e:
        logger.error(f"Error fetching incident: {e}")
        return render_template('incident_detail.html', error=str(e))

@app.route('/admin/blocked-ips')
@login_required
def blocked_ips():
    """View blocked IPs"""
    try:
        connection = db.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM blocked_ips
            ORDER BY blocked_at DESC
            LIMIT 100
        """)
        
        ips = cursor.fetchall()
        cursor.close()
        connection.close()
        
        return render_template('blocked_ips.html', ips=ips)
    
    except Exception as e:
        logger.error(f"Error fetching blocked IPs: {e}")
        return render_template('blocked_ips.html', error=str(e))

# ===========================
# API ROUTES - REST
# ===========================

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    """System statistics"""
    try:
        connection = db.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Query statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_queries,
                SUM(CASE WHEN risk_level='SAFE' THEN 1 ELSE 0 END) as safe_queries,
                SUM(CASE WHEN risk_level='DANGEROUS' THEN 1 ELSE 0 END) as dangerous_queries,
                SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) as critical_queries
            FROM query_audit_log
        """)
        query_stats = cursor.fetchone()
        
        # Incident statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_incidents,
                SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_incidents,
                SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_incidents
            FROM incidents
        """)
        incident_stats = cursor.fetchone()
        
        # Blocked IPs
        cursor.execute("SELECT COUNT(*) as count FROM blocked_ips")
        blocked_ips_count = cursor.fetchone()['count']
        
        # Threats per hour (last 24h)
        cursor.execute("""
            SELECT 
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:00') as hour,
                COUNT(*) as threat_count
            FROM query_audit_log
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            AND risk_level IN ('DANGEROUS', 'CRITICAL')
            GROUP BY hour
            ORDER BY hour DESC
        """)
        threats_by_hour = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'query_stats': query_stats,
            'incident_stats': incident_stats,
            'blocked_ips_count': blocked_ips_count,
            'threats_by_hour': threats_by_hour,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-threats', methods=['GET'])
@login_required
def api_recent_threats():
    """Get recent threats"""
    limit = request.args.get('limit', 20, type=int)
    
    try:
        connection = db.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM incidents
            WHERE severity IN ('CRITICAL', 'HIGH')
            ORDER BY detected_at DESC
            LIMIT %s
        """, (limit,))
        
        threats = cursor.fetchall()
        cursor.close()
        connection.close()
        
        return jsonify(threats)
    
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-ip/<ip>', methods=['POST'])
@login_required
def api_unblock_ip(ip):
    """Unblock an IP"""
    try:
        # Validate IP format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address'}), 400
        
        # Remove from database
        connection = db.pool.get_connection()
        cursor = connection.cursor()
        
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address=%s", (ip,))
        connection.commit()
        cursor.close()
        connection.close()
        
        # Note: Removing from iptables would require sudo permissions
        
        logger.info(f"IP unblocked: {ip}")
        return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reset-system', methods=['POST'])
@login_required
def api_reset_system():
    """System reset (clear logs, incidents, etc)"""
    try:
        # Confirm password
        data = request.get_json() or {}
        password = data.get('password', '')
        if password != ADMIN_PASSWORD:
            return jsonify({'error': 'Invalid password'}), 401
        
        connection = db.pool.get_connection()
        cursor = connection.cursor()
        
        # Clear logs
        cursor.execute("DELETE FROM query_audit_log")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM blocked_ips")
        
        connection.commit()
        cursor.close()
        connection.close()
        
        logger.warning("System reset performed")
        return jsonify({'success': True, 'message': 'System reset complete'})
    
    except Exception as e:
        logger.error(f"Error resetting system: {e}")
        return jsonify({'error': str(e)}), 500

# ===========================
# WEBSOCKET EVENTS - LIVE STREAM
# ===========================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'data': 'Connected to Nexus-Cyber monitoring'})

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe_queries')
@socketio_login_required
def handle_subscribe_queries():
    """Subscribe to live query stream"""
    
    def emit_queries():
        """Emit recent queries continuously"""
        # Note: In a real production app, we would use a message queue (Redis/RabbitMQ)
        # to push new entries here instead of polling the DB.
        # But for this phase, polling is acceptable for local dev.
        last_id = 0
        while True:
            try:
                connection = db.pool.get_connection()
                cursor = connection.cursor(dictionary=True)
                
                # Get recent queries since last check
                cursor.execute("""
                    SELECT 
                        id, timestamp, source_ip, risk_level, 
                        action_taken, confidence_score
                    FROM query_audit_log
                    WHERE id > %s
                    ORDER BY id ASC
                    LIMIT 50
                """, (last_id,))
                
                queries = cursor.fetchall()
                if queries:
                    last_id = queries[-1]['id']
                    # Emit to client
                    for q in queries:
                        q['timestamp'] = q['timestamp'].isoformat() if q['timestamp'] else None
                        socketio.emit('query_detected', q)
                
                cursor.close()
                connection.close()
                time.sleep(2)
            
            except Exception as e:
                logger.error(f"Error in query stream: {e}")
                time.sleep(5)
    
    # Start background thread
    thread = threading.Thread(target=emit_queries, daemon=True)
    thread.start()

@socketio.on('subscribe_incidents')
@socketio_login_required
def handle_subscribe_incidents():
    """Subscribe to incident stream"""
    
    def emit_incidents():
        """Emit recent incidents continuously"""
        last_id = 0
        while True:
            try:
                connection = db.pool.get_connection()
                cursor = connection.cursor(dictionary=True)
                
                # Get incidents since last id
                cursor.execute("""
                    SELECT * FROM incidents
                    WHERE id > %s
                    ORDER BY id ASC
                """, (last_id,))
                
                incidents_list = cursor.fetchall()
                if incidents_list:
                    last_id = incidents_list[-1]['id']
                    # Emit to client
                    for incident in incidents_list:
                        incident['detected_at'] = incident['detected_at'].isoformat() if incident['detected_at'] else None
                        socketio.emit('incident_detected', incident)
                
                cursor.close()
                connection.close()
                time.sleep(3)
            
            except Exception as e:
                logger.error(f"Error in incident stream: {e}")
                time.sleep(5)
    
    thread = threading.Thread(target=emit_incidents, daemon=True)
    thread.start()

# ===========================
# ERROR HANDLERS
# ===========================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template('500.html'), 500

# ===========================
# MAIN
# ===========================

if __name__ == '__main__':
    logger.info("🚀 Nexus-Cyber Web Gateway starting...")
    
    # Run Flask with SocketIO
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
        use_reloader=False,
        allow_unsafe_werkzeug=True
    )
