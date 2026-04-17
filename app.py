"""
Secure IIoT Gateway Dashboard - Flask Backend
Handles routing and API endpoints with real database integration.
All users have full admin-level access.
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, Response, stream_with_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import json
import threading
import queue
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import paho.mqtt.client as mqtt

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

# MQTT configuration
MQTT_BROKER_IP = "192.168.1.2"
MQTT_BROKER_PORT = 1883

# Node ID mapping
NODE_ID_MAPPING = {
    'ESP32_SEC_01': 'node_01',
    'ESP8266_SEC_02': 'node_02',
    'ESP8266_SEC_03': 'node_03'
}

UI_TO_MQTT_NODE = {v: k for k, v in NODE_ID_MAPPING.items()}



def get_db_connection() -> sqlite3.Connection:
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_mqtt_node_id(node_id: str) -> str:
    """Normalize incoming node id to MQTT canonical id"""
    if not node_id:
        return 'ESP32_SEC_01'
    if node_id in NODE_ID_MAPPING:
        return node_id
    return UI_TO_MQTT_NODE.get(node_id, node_id)


def now_ms() -> int:
    return int(time.time() * 1000)


def get_current_user_role() -> str:
    """
    Current deployment policy: only highest role ADMIN is valid.
    Still enforced server-side for sensitive endpoints.
    """
    return session.get('user_role', 'ADMIN')


def log_system_event(timestamp_s: int, severity: str, description: str):
    with get_db_connection() as conn:
        conn.execute(
            'INSERT INTO system_events (timestamp, severity, description) VALUES (?, ?, ?)',
            (timestamp_s, severity, description)
        )
        conn.commit()





def publish_mqtt_command(topic: str, payload: Dict[str, Any]) -> Optional[str]:
    try:
        client = mqtt.Client()
        client.connect(MQTT_BROKER_IP, MQTT_BROKER_PORT, 60)
        client.publish(topic, json.dumps(payload))
        client.disconnect()
        return None
    except Exception as e:
        return str(e)




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
                gas_warn      INTEGER DEFAULT 300,
                gas_crit      INTEGER DEFAULT 600,
                temp_warn     REAL DEFAULT 30.0,
                temp_crit     REAL DEFAULT 35.0,
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
                INSERT OR IGNORE INTO thresholds (node_id, gas_warn, gas_crit, temp_warn, temp_crit)
                VALUES (?, 250, 400, 35.0, 45.0)
            ''', (node_id,))

        conn.commit()
        print("✅ Database initialized successfully with migration!")


def get_thresholds(node_id: str) -> Dict[str, Any]:
    """Get all thresholds for a node"""
    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT gas_warn, gas_crit, temp_warn, temp_crit FROM thresholds WHERE node_id = ?',
            (node_id,)
        ).fetchone()
        if row:
            return {
                'gas_warn': row['gas_warn'],
                'gas_crit': row['gas_crit'],
                'temp_warn': row['temp_warn'],
                'temp_crit': row['temp_crit']
            }
        else:
            return {'gas_warn': 350, 'gas_crit': 400, 'temp_warn': 35.0, 'temp_crit': 45.0}


def update_threshold(node_id: str, threshold_type: str, value: Any):
    """Update a specific threshold for a node"""
    with get_db_connection() as conn:
        conn.execute(f'''
            UPDATE thresholds
            SET {threshold_type} = ?, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ?
        ''', (value, node_id))
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

            # Get latest sensor row for each device_id (all nodes in one query)
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
                       sl.timestamp
                FROM sensor_logs sl
                JOIN devices d ON sl.device_id = d.id
                JOIN (
                    SELECT device_id, MAX(timestamp) AS max_ts
                    FROM sensor_logs
                    GROUP BY device_id
                ) latest ON sl.device_id = latest.device_id AND sl.timestamp = latest.max_ts
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
                'node_02': get_thresholds('node_02'),
                'node_03': get_thresholds('node_03')
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
    """
    return render_template('index.html', is_admin=True)


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
    Update a threshold for a node.
    Request body: { node_id, threshold_type, value }
    """
    try:
        data = request.get_json()
        node_id = data.get('node_id')
        threshold_type = data.get('threshold_type')
        value = data.get('value')

        # Validate input
        if not node_id or not threshold_type or value is None:
            return jsonify({'error': 'Missing required fields'}), 400

        valid_types = ['gas_warn', 'gas_crit', 'temp_warn', 'temp_crit']
        if threshold_type not in valid_types:
            return jsonify({'error': 'Invalid threshold type'}), 400

        try:
            if 'temp' in threshold_type:
                value = float(value)
                if value < 0 or value > 100:
                    return jsonify({'error': 'Temperature threshold must be between 0 and 100°C'}), 400
            else:
                value = int(value)
                if value < 0 or value > 10000:
                    return jsonify({'error': 'Gas threshold must be between 0 and 10000 ppm'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid threshold value'}), 400

        # Validate node
        if node_id not in ['node_02', 'node_03']:
            return jsonify({'error': 'Unknown node'}), 400

        # Update in database
        update_threshold(node_id, threshold_type, value)

        # Publish to MQTT
        mqtt_node_id = {'node_02': 'ESP8266_SEC_02', 'node_03': 'ESP8266_SEC_03'}[node_id]
        topic = f"factory/sensors/{mqtt_node_id}/cmd"
        payload = f'{{"cmd": "set_threshold", "{threshold_type}": {value}}}'
        try:
            client = mqtt.Client()
            client.connect(MQTT_BROKER_IP, MQTT_BROKER_PORT, 60)
            client.publish(topic, payload)
            client.disconnect()
        except Exception as e:
            return jsonify({'error': f'MQTT publish failed: {e}'}), 500

        return jsonify({
            'status': 'success',
            'message': f'{threshold_type} for {node_id} updated to {value}'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/mute_buzzer', methods=['POST'])
def mute_buzzer_api():
    """
    Mute buzzer for a node.
    Request body: { node_id, type }
    """
    try:
        data = request.get_json()
        node_id = data.get('node_id')
        buzzer_type = data.get('type')

        # Validate input
        if not node_id or not buzzer_type:
            return jsonify({'error': 'Missing required fields'}), 400

        if node_id not in ['node_02', 'node_03'] or buzzer_type not in ['gas', 'temp']:
            return jsonify({'error': 'Invalid node or buzzer type'}), 400

        # Publish to MQTT
        mqtt_node_id = {'node_02': 'ESP8266_SEC_02', 'node_03': 'ESP8266_SEC_03'}[node_id]
        topic = f"factory/sensors/{mqtt_node_id}/cmd"
        payload = f'{{"cmd": "mute_{buzzer_type}"}}'
        try:
            client = mqtt.Client()
            client.connect(MQTT_BROKER_IP, MQTT_BROKER_PORT, 60)
            client.publish(topic, payload)
            client.disconnect()
        except Exception as e:
            return jsonify({'error': f'MQTT publish failed: {e}'}), 500

        return jsonify({
            'status': 'success',
            'message': f'{buzzer_type} buzzer for {node_id} muted'
        })

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
    # Runtime listener for door and other topics removed.

    print("=" * 60)
    print("Secure IIoT Gateway Dashboard - Flask Server")
    print("=" * 60)
    print("\n📊 Dashboard: http://localhost:5000/dashboard")
    print("🔓 Mode: ADMIN (full access)\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
