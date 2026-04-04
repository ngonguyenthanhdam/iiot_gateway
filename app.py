"""
Secure IIoT Gateway Dashboard - Flask Backend
Handles session management, routing, and API endpoints with real database integration.
Default: User Mode (is_admin = False) until admin login.
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

app = Flask(__name__)

# Security configuration
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production-12345')

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Templates folder configuration
base_dir = os.path.dirname(os.path.abspath(__file__))
app.template_folder = os.path.join(base_dir, 'templates')

# Database configuration
DB_PATH = os.path.join(base_dir, 'db', 'factory_data.db')

# Node ID mapping
NODE_ID_MAPPING = {
    'ESP32_SEC_01': 'node_01',
    'ESP8266_SEC_02': 'node_02',
    'ESP8266_SEC_03': 'node_03'
}

# Admin credentials (in production, store hashed in database)
ADMIN_PASSWORD_HASH = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())


def get_db_connection() -> sqlite3.Connection:
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize database with FULL schema + safe migration for existing DB"""
    with get_db_connection() as conn:
        # 1. Devices table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id     TEXT    NOT NULL UNIQUE,
                sensor_type TEXT,
                location    TEXT,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 2. Sensor logs table - FULL schema
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sensor_logs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id     INTEGER NOT NULL,
                temp          REAL,
                humi          REAL,
                gas           INTEGER,
                light_level   INTEGER,
                buzzer_active INTEGER,
                is_muted      INTEGER,
                status        TEXT,
                msg_id        INTEGER,
                timestamp     INTEGER,
                received_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            )
        ''')

        # 3. Thresholds table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS thresholds (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id       TEXT NOT NULL UNIQUE,
                gas_threshold INTEGER NOT NULL DEFAULT 100,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 4. System events table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   INTEGER,
                severity    TEXT,
                description TEXT
            )
        ''')

        # ==================== MIGRATION: Add missing columns safely ====================
        # Add columns that may be missing from old database
        columns_to_add = [
            ('sensor_logs', 'light_level',   'INTEGER'),
            ('sensor_logs', 'buzzer_active', 'INTEGER'),
            ('sensor_logs', 'is_muted',      'INTEGER'),
            ('sensor_logs', 'gas',           'INTEGER'),
            ('sensor_logs', 'received_at',   'DATETIME'),
            ('sensor_logs', 'captured_at',   'DATETIME')
        ]

        for table, col, col_type in columns_to_add:
            # Check if column already exists
            cursor = conn.execute(f"PRAGMA table_info({table})")
            existing_cols = [row[1] for row in cursor.fetchall()]
            if col not in existing_cols:
                print(f"🔄 Adding missing column: {table}.{col}")
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {col} {col_type}')

        # Insert default devices
        default_devices = [
            ('ESP32_SEC_01', 'ENV_MONITOR', 'Factory Floor - Sector 01'),
            ('ESP8266_SEC_02', 'DHT11+MQ2', 'Factory Floor - Sector 02'),
            ('ESP8266_SEC_03', 'DHT11+MQ2', 'Factory Floor - Sector 03')
        ]
        for node_id, sensor_type, location in default_devices:
            conn.execute('''
                INSERT OR IGNORE INTO devices (node_id, sensor_type, location)
                VALUES (?, ?, ?)
            ''', (node_id, sensor_type, location))

        # Default thresholds
        for node_id in ['node_02', 'node_03']:
            conn.execute('''
                INSERT OR IGNORE INTO thresholds (node_id, gas_threshold)
                VALUES (?, 100)
            ''', (node_id,))

        conn.commit()
        print("✅ Database initialized successfully with migration!")


def get_threshold(node_id: str) -> int:
    """Get gas threshold for a node"""
    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT gas_threshold FROM thresholds WHERE node_id = ?',
            (node_id,)
        ).fetchone()
        return row['gas_threshold'] if row else 100


def update_threshold(node_id: str, threshold: int):
    """Update gas threshold for a node"""
    with get_db_connection() as conn:
        conn.execute('''
            UPDATE thresholds
            SET gas_threshold = ?, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ?
        ''', (threshold, node_id))
        conn.commit()


def get_latest_sensor_data() -> Dict[str, Any]:
    """Get latest sensor data for all nodes - robust version with logging"""
    try:
        with get_db_connection() as conn:
            node_data = {
                'node_01': {},
                'node_02': {},
                'node_03': {},
            }

            # Get latest sensor row for each device_id using gateway receive time
            # Device timestamp is useful for packet metadata, but may not always be monotonic.
            # Use received_at to ensure the newest packet received by the gateway is selected.
            rows = conn.execute('''
                SELECT d.node_id AS mqtt_node,
                       sl.temp,
                       sl.humi,
                       sl.gas,
                       sl.light_level,
                       sl.buzzer_active,
                       sl.is_muted,
                       sl.status,
                       sl.msg_id,
                       sl.timestamp,
                       sl.received_at
                FROM sensor_logs sl
                JOIN devices d ON sl.device_id = d.id
                JOIN (
                    SELECT device_id, MAX(received_at) AS max_received
                    FROM sensor_logs
                    GROUP BY device_id
                ) latest ON sl.device_id = latest.device_id AND sl.received_at = latest.max_received
            ''').fetchall()

            print(f"[DEBUG] get_latest_sensor_data: Fetched {len(rows)} rows from DB")
            for row in rows:
                mqtt_node = row['mqtt_node']
                ui_node = NODE_ID_MAPPING.get(mqtt_node)

                if not ui_node:
                    # Fallback mapping based on known identifiers
                    if mqtt_node.startswith('ESP32'):
                        ui_node = 'node_01'
                    elif mqtt_node.endswith('_02'):
                        ui_node = 'node_02'
                    elif mqtt_node.endswith('_03'):
                        ui_node = 'node_03'

                if not ui_node:
                    print(f"[WARNING] Unmapped MQTT node_id in DB: {mqtt_node}")
                    continue

                node_data[ui_node] = {
                    'temperature': row['temp'],
                    'humidity': row['humi'],
                    'gas': row['gas'],
                    'light_level': row['light_level'],
                    'buzzer_active': bool(row['buzzer_active']) if row['buzzer_active'] is not None else False,
                    'is_muted': bool(row['is_muted']) if row['is_muted'] is not None else False,
                    'status': row['status'],
                    'msg_id': row['msg_id'],
                    'timestamp': row['timestamp']
                }
                print(f"[DEBUG] Mapped {mqtt_node} to {ui_node}: temp={row['temp']}, gas={row['gas']}")

            # Add thresholds
            node_data['thresholds'] = {
                'node_02_gas_threshold': get_threshold('node_02'),
                'node_03_gas_threshold': get_threshold('node_03')
            }

            print(f"[DEBUG] Returning node_data with keys: {list(node_data.keys())}")
            return node_data

    except Exception as e:
        print(f"❌ ERROR in get_latest_sensor_data: {e}")
        return {
            'node_01': {},
            'node_02': {},
            'node_03': {},
            'thresholds': {
                'node_02_gas_threshold': 100,
                'node_03_gas_threshold': 100
            }
        }


@app.before_request
def before_request():
    """Set session to permanent before each request"""
    session.permanent = True


# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    """Redirect root to dashboard"""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """
    Main dashboard route - renders dashboard as Jinja2 template.
    Default: is_admin = False (User mode)
    """
    is_admin = session.get('is_admin', False)
    return render_template('index.html', is_admin=is_admin)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """
    Admin login route with rate limiting and bcrypt password validation.
    """
    error = None

    if request.method == 'POST':
        password = request.form.get('password', '')

        # Validate password using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH):
            session['is_admin'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid password'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Clear session and redirect to dashboard (User mode)"""
    session.clear()
    return redirect(url_for('dashboard'))


# ==================== API ENDPOINTS ====================
@limiter.exempt
@app.route('/api/node_data')
def node_data():
    """
    Fetch current sensor data for all three nodes from database.
    Returns: node_01, node_02, node_03 data + thresholds
    """
    try:
        return jsonify(get_latest_sensor_data())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@limiter.exempt
@app.route('/api/events')
def events():
    """
    Fetch security and system events log from database.
    Returns: list of event objects with timestamp and description
    """
    try:
        with get_db_connection() as conn:
            events_data = conn.execute('''
                SELECT timestamp, severity, description
                FROM system_events
                ORDER BY timestamp DESC
                LIMIT 50
            ''').fetchall()

            events_list = []
            for event in events_data:
                events_list.append({
                    'timestamp': datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S'),
                    'description': event['description'],
                    'type': event['severity'].lower()
                })

            # If no events in DB, return some default ones
            if not events_list:
                events_list = [
                    {
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'description': 'System started and dashboard initialized',
                        'type': 'startup'
                    }
                ]

            return jsonify(events_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/update_threshold', methods=['POST'])
def update_threshold_api():
    """
    Update gas threshold for a node (Admin only).
    Requires: is_admin = True
    Request body: { node_id, threshold_type, value }
    """
    # Check admin authorization
    if not session.get('is_admin', False):
        return jsonify({'error': 'Unauthorized - Admin access required'}), 403

    try:
        data = request.get_json()
        node_id = data.get('node_id')
        threshold_type = data.get('threshold_type')
        value = data.get('value')

        # Validate input
        if not node_id or not threshold_type or value is None:
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            value = int(value)
            if value < 0 or value > 10000:
                return jsonify({'error': 'Threshold must be between 0 and 10000'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid threshold value'}), 400

        # Validate node and threshold type
        if node_id not in ['node_02', 'node_03'] or threshold_type != 'gas':
            return jsonify({'error': 'Unknown node or threshold type'}), 400

        # Update in database
        update_threshold(node_id, value)

        return jsonify({
            'status': 'success',
            'message': f'Threshold for {node_id} updated to {value} ppm'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation', methods=['POST'])
def simulation():
    """
    Trigger simulation events (Admin only).
    Simulates: replay attacks, node disconnections, sensor errors.
    Requires: is_admin = True
    Request body: { type, state }
    """
    # Check admin authorization
    if not session.get('is_admin', False):
        return jsonify({'error': 'Unauthorized - Admin access required'}), 403

    try:
        data = request.get_json()
        sim_type = data.get('type')
        sim_state = data.get('state')

        if not sim_type or not sim_state:
            return jsonify({'error': 'Missing type or state'}), 400

        # Map simulation types
        simulation_map = {
            'replay_attack': ['start', 'stop'],
            'disconnection': ['trigger', 'restore'],
            'sensor_error': ['inject', 'clear']
        }

        if sim_type not in simulation_map or sim_state not in simulation_map[sim_type]:
            return jsonify({'error': f'Invalid simulation type or state'}), 400

        # Log simulation (in production, trigger actual backend events)
        print(f"[SIMULATION] {sim_type.upper()}: {sim_state}")

        return jsonify({
            'status': 'success',
            'message': f'Simulation {sim_type} {sim_state} triggered'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/chat', methods=['POST'])
def chat():
    """
    AI Q&A endpoint (Gemini Pro integration).
    Request body: { question }
    Returns: { answer }
    """
    try:
        data = request.get_json()
        question = data.get('question', '')

        if not question:
            return jsonify({'error': 'No question provided'}), 400

        # Mock response (replace with actual Gemini API call in production)
        mock_responses = {
            'threshold': 'Gas thresholds can be adjusted in the Node tabs. Safe levels are typically 0-100 ppm.',
            'sensor': 'The system monitors three sensor nodes: Node_01 (ESP32) with temp/humidity/light, and Node_02/Node_03 (ESP8266) with temp/humidity/gas sensors.',
            'security': 'The dashboard includes RBAC controls, simulation modes for testing security, and real-time event logging.',
            'temperature': 'Normal operating temperature range is 15-30°C. Current readings are within safe parameters.',
            'gas': 'Gas concentration is measured in parts per million (ppm). Alert threshold can be customized per node.',
            'default': f'You asked: "{question}" - In production, this would be answered by Gemini Pro. Features: node monitoring, threshold management, security simulation, event logging.'
        }

        # Simple keyword matching for demo
        question_lower = question.lower()
        answer = mock_responses['default']

        for keyword, response in mock_responses.items():
            if keyword in question_lower:
                answer = response
                break

        return jsonify({'answer': answer})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    # Initialize database
    init_database()

    print("=" * 60)
    print("Secure IIoT Gateway Dashboard - Flask Server")
    print("=" * 60)
    print("\n📊 Dashboard: http://localhost:5000/dashboard")
    print("🔐 Admin Login: http://localhost:5000/login")
    print("   Default password: admin123")
    print("\n⚙️  Default mode: USER (read-only)")
    print("🔓 Admin mode: Available after login\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
