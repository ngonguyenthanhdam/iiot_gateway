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
DEFAULT_NODE_FOR_DOOR = 'ESP32_SEC_01'
DOOR_ALERT_TOPIC = "factory/sensors/ESP32_SEC_01/door/alert"
DOOR_STATE_TOPIC = "factory/sensors/ESP32_SEC_01/door/state"
DOOR_CMD_TOPIC = "factory/sensors/ESP32_SEC_01/door/cmd"

sse_subscribers: List[queue.Queue] = []
sse_lock = threading.Lock()
mqtt_runtime_client: Optional[mqtt.Client] = None



def get_db_connection() -> sqlite3.Connection:
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_mqtt_node_id(node_id: str) -> str:
    """Normalize incoming node id to MQTT canonical id"""
    if not node_id:
        return DEFAULT_NODE_FOR_DOOR
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


def log_door_event(
    node_id: str,
    event_type: str,
    description: str,
    event_code: Optional[str] = None,
    severity: Optional[str] = 'INFO',
    actor_role: Optional[str] = None,
    actor_id: Optional[str] = None,
    timestamp_ms: Optional[int] = None,
    raw_payload: Optional[str] = None
):
    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO door_events (
                node_id, event_type, event_code, severity, description,
                actor_role, actor_id, timestamp_ms, gateway_received_ts, raw_payload
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        ''', (
            node_id, event_type, event_code, severity, description,
            actor_role, actor_id, timestamp_ms, raw_payload
        ))
        conn.commit()


def publish_sse_event(event: Dict[str, Any]):
    with sse_lock:
        dead = []
        for q in sse_subscribers:
            try:
                q.put_nowait(event)
            except Exception:
                dead.append(q)
        for q in dead:
            if q in sse_subscribers:
                sse_subscribers.remove(q)


def require_admin_or_403(action_name: str, node_id: str) -> Optional[Any]:
    role = get_current_user_role()
    if role != 'ADMIN':
        desc = f"Unauthorized {action_name} attempt on {node_id} with role={role}"
        log_system_event(int(time.time()), 'WARNING', desc)
        log_door_event(
            node_id=node_id,
            event_type='AUTH',
            event_code='UNAUTHORIZED_ATTEMPT',
            severity='WARNING',
            description=desc,
            actor_role=role
        )
        return jsonify({'error': 'Forbidden: ADMIN role required'}), 403
    return None


def publish_mqtt_command(topic: str, payload: Dict[str, Any]) -> Optional[str]:
    try:
        client = mqtt.Client()
        client.connect(MQTT_BROKER_IP, MQTT_BROKER_PORT, 60)
        client.publish(topic, json.dumps(payload))
        client.disconnect()
        return None
    except Exception as e:
        return str(e)


def publish_rfid_sync(node_id: str, reason: str):
    mqtt_node = normalize_mqtt_node_id(node_id)
    with get_db_connection() as conn:
        cards = conn.execute('''
            SELECT card_uid
            FROM registered_rfid_cards
            WHERE is_active = 1
            ORDER BY card_uid
        ''').fetchall()

    active_cards = [row['card_uid'] for row in cards]
    payload = {
        'cmd': 'rfid_sync',
        'source': 'gateway',
        'reason': reason,
        'effect_latency_target_seconds': 60,
        'issued_at_ms': now_ms(),
        'active_cards': active_cards
    }

    err = publish_mqtt_command(f"factory/sensors/{mqtt_node}/door/cmd", payload)
    if err is None:
        with get_db_connection() as conn:
            conn.execute('''
                UPDATE registered_rfid_cards
                SET last_synced_at = CURRENT_TIMESTAMP
                WHERE is_active = 1
            ''')
            conn.commit()


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

        # 5. Door events table (separate from sensor_logs)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS door_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id             TEXT NOT NULL,
                event_type          TEXT NOT NULL,
                event_code          TEXT,
                severity            TEXT,
                description         TEXT NOT NULL,
                actor_role          TEXT,
                actor_id            TEXT,
                timestamp_ms        INTEGER,
                gateway_received_ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                raw_payload         TEXT
            )
        ''')

        # 6. Registered RFID cards lifecycle table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS registered_rfid_cards (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                card_uid         TEXT NOT NULL UNIQUE,
                card_label       TEXT,
                owner_name       TEXT,
                is_active        INTEGER NOT NULL DEFAULT 1,
                created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked_at       DATETIME,
                revoked_reason   TEXT,
                last_synced_at   DATETIME
            )
        ''')

        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_door_events_node_gateway_ts
            ON door_events (node_id, gateway_received_ts DESC)
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_door_events_severity_gateway_ts
            ON door_events (severity, gateway_received_ts DESC)
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_registered_rfid_cards_active
            ON registered_rfid_cards (is_active, updated_at DESC)
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


@app.route('/api/simulation', methods=['POST'])
def simulation():
    """
    Trigger simulation events.
    Simulates: replay attacks, node disconnections, sensor errors.
    Request body: { type, state }
    """
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


@app.route('/api/node/<node_id>/door/toggle', methods=['POST'])
def door_toggle(node_id: str):
    auth_error = require_admin_or_403('door_toggle', node_id)
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    action = data.get('action', 'toggle')
    actor_id = data.get('actor_id')

    mqtt_node = normalize_mqtt_node_id(node_id)
    payload = {
        'cmd': 'door_toggle',
        'action': action,
        'issued_by': 'ADMIN',
        'issued_at_ms': now_ms()
    }

    err = publish_mqtt_command(f"factory/sensors/{mqtt_node}/door/cmd", payload)
    if err:
        return jsonify({'error': f'MQTT publish failed: {err}'}), 500

    log_door_event(
        node_id=mqtt_node,
        event_type='COMMAND',
        event_code='TOGGLE_REQUEST',
        severity='INFO',
        description=f"Door toggle requested ({action})",
        actor_role='ADMIN',
        actor_id=actor_id,
        timestamp_ms=payload['issued_at_ms'],
        raw_payload=json.dumps(payload)
    )

    return jsonify({
        'status': 'success',
        'message': 'Door toggle command published',
        'node_id': mqtt_node
    })


@app.route('/api/node/<node_id>/door/clear_fault', methods=['POST'])
def clear_fault(node_id: str):
    auth_error = require_admin_or_403('door_clear_fault', node_id)
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    actor_id = data.get('actor_id')

    mqtt_node = normalize_mqtt_node_id(node_id)
    payload = {
        'cmd': 'clear_fault',
        'target': 'Node_01',
        'issued_by': 'ADMIN',
        'issued_at_ms': now_ms()
    }

    err = publish_mqtt_command(f"factory/sensors/{mqtt_node}/door/cmd", payload)
    if err:
        return jsonify({'error': f'MQTT publish failed: {err}'}), 500

    log_door_event(
        node_id=mqtt_node,
        event_type='FAULT_CLEAR',
        event_code='CLEAR_FAULT_REQUEST',
        severity='INFO',
        description='Admin issued clear fault command',
        actor_role='ADMIN',
        actor_id=actor_id,
        timestamp_ms=payload['issued_at_ms'],
        raw_payload=json.dumps(payload)
    )

    return jsonify({
        'status': 'success',
        'message': 'Fault clear command published',
        'node_id': mqtt_node
    })


@app.route('/api/node/<node_id>/door/status', methods=['GET'])
def door_status(node_id: str):
    mqtt_node = normalize_mqtt_node_id(node_id)

    with get_db_connection() as conn:
        latest = conn.execute('''
            SELECT event_type, event_code, severity, description, timestamp_ms, gateway_received_ts, raw_payload
            FROM door_events
            WHERE node_id = ?
            ORDER BY gateway_received_ts DESC, id DESC
            LIMIT 1
        ''', (mqtt_node,)).fetchone()

        last_uid_row = conn.execute('''
            SELECT description
            FROM door_events
            WHERE node_id = ?
              AND event_type IN ('RFID', 'ALERT', 'DOOR_STATE')
              AND description LIKE '%UID%'
            ORDER BY gateway_received_ts DESC, id DESC
            LIMIT 1
        ''', (mqtt_node,)).fetchone()

    if latest:
        event_code = (latest['event_code'] or '').upper()
        severity = (latest['severity'] or 'INFO').upper()
        desc = latest['description'] or ''
        door_state = 'UNKNOWN'
        fault_state = False
        alarm_active = False

        if event_code in ('LOCKED', 'CLOSED'):
            door_state = 'LOCKED'
        elif event_code in ('UNLOCKED', 'OPEN'):
            door_state = 'UNLOCKED'
        elif event_code in ('FAULT', 'SERVO_FAULT', 'REED_FAULT', 'RFID_DISCONNECTED', 'PHYSICAL_FAULT'):
            door_state = 'FAULT'
            fault_state = True

        if severity == 'CRITICAL' or 'FAULT' in event_code or 'MISMATCH' in event_code:
            fault_state = True
            if door_state == 'UNKNOWN':
                door_state = 'FAULT'

        if 'INVALID RFID' in desc.upper() or 'BUZZER' in desc.upper() or fault_state:
            alarm_active = True

        door_phase = 'UNKNOWN'
        if latest['raw_payload']:
            try:
                raw_data = json.loads(latest['raw_payload'])
                door_phase = raw_data.get('door_phase', raw_data.get('phase', 'UNKNOWN'))
            except Exception:
                pass

        status_payload = {
            'node_id': mqtt_node,
            'door_state': door_state,
            'door_phase': door_phase,
            'fault_state': fault_state,
            'alarm_active': alarm_active,
            'last_trigger': latest['event_code'] or latest['event_type'] or 'UNKNOWN',
            'last_uid': last_uid_row['description'] if last_uid_row else None,
            'last_update_ms': latest['timestamp_ms'],
            'gateway_received_ts': latest['gateway_received_ts']
        }
    else:
        status_payload = {
            'node_id': mqtt_node,
            'door_state': 'UNKNOWN',
            'door_phase': 'UNKNOWN',
            'fault_state': False,
            'alarm_active': False,
            'last_trigger': None,
            'last_uid': None,
            'last_update_ms': None,
            'gateway_received_ts': None
        }

    return jsonify(status_payload)


@app.route('/api/node/<node_id>/door/history', methods=['GET'])
def door_history(node_id: str):
    mqtt_node = normalize_mqtt_node_id(node_id)
    limit_raw = request.args.get('limit', '100')
    try:
        limit = max(1, min(500, int(limit_raw)))
    except ValueError:
        return jsonify({'error': 'Invalid limit'}), 400

    with get_db_connection() as conn:
        rows = conn.execute('''
            SELECT id, node_id, event_type, event_code, severity, description,
                   actor_role, actor_id, timestamp_ms, gateway_received_ts, raw_payload
            FROM door_events
            WHERE node_id = ?
            ORDER BY gateway_received_ts DESC, id DESC
            LIMIT ?
        ''', (mqtt_node, limit)).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route('/api/door/alerts/stream', methods=['GET'])
@limiter.exempt
def door_alert_stream():
    def generate():
        q: queue.Queue = queue.Queue(maxsize=200)
        with sse_lock:
            sse_subscribers.append(q)

        yield "event: ready\ndata: {\"status\":\"connected\"}\n\n"
        try:
            while True:
                event = q.get()
                payload = json.dumps(event, ensure_ascii=False)
                yield f"event: door_alert\ndata: {payload}\n\n"
        finally:
            with sse_lock:
                if q in sse_subscribers:
                    sse_subscribers.remove(q)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@app.route('/api/rfid/register', methods=['POST'])
def rfid_register():
    auth_error = require_admin_or_403('rfid_register', DEFAULT_NODE_FOR_DOOR)
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    card_uid = (data.get('card_uid') or '').strip()
    card_label = data.get('card_label')
    owner_name = data.get('owner_name')
    actor_id = data.get('actor_id')

    if not card_uid:
        return jsonify({'error': 'card_uid is required'}), 400

    with get_db_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM registered_rfid_cards WHERE card_uid = ?',
            (card_uid,)
        ).fetchone()

        if existing:
            conn.execute('''
                UPDATE registered_rfid_cards
                SET card_label = ?, owner_name = ?, is_active = 1,
                    updated_at = CURRENT_TIMESTAMP,
                    revoked_at = NULL, revoked_reason = NULL
                WHERE card_uid = ?
            ''', (card_label, owner_name, card_uid))
        else:
            conn.execute('''
                INSERT INTO registered_rfid_cards
                (card_uid, card_label, owner_name, is_active, updated_at)
                VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            ''', (card_uid, card_label, owner_name))
        conn.commit()

    log_door_event(
        node_id=DEFAULT_NODE_FOR_DOOR,
        event_type='RFID',
        event_code='CARD_REGISTERED',
        severity='INFO',
        description=f'RFID card registered/activated: {card_uid}',
        actor_role='ADMIN',
        actor_id=actor_id,
        timestamp_ms=now_ms(),
        raw_payload=json.dumps(data)
    )

    publish_rfid_sync(DEFAULT_NODE_FOR_DOOR, reason='register')

    return jsonify({
        'status': 'success',
        'message': 'RFID card registered and sync command propagated',
        'effect_latency_target_seconds': 60
    })


@app.route('/api/rfid/revoke', methods=['POST'])
def rfid_revoke():
    auth_error = require_admin_or_403('rfid_revoke', DEFAULT_NODE_FOR_DOOR)
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    card_uid = (data.get('card_uid') or '').strip()
    reason = data.get('reason', 'revoked by admin')
    actor_id = data.get('actor_id')

    if not card_uid:
        return jsonify({'error': 'card_uid is required'}), 400

    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT id FROM registered_rfid_cards WHERE card_uid = ?',
            (card_uid,)
        ).fetchone()
        if not row:
            return jsonify({'error': 'RFID card not found'}), 404

        conn.execute('''
            UPDATE registered_rfid_cards
            SET is_active = 0,
                updated_at = CURRENT_TIMESTAMP,
                revoked_at = CURRENT_TIMESTAMP,
                revoked_reason = ?
            WHERE card_uid = ?
        ''', (reason, card_uid))
        conn.commit()

    log_door_event(
        node_id=DEFAULT_NODE_FOR_DOOR,
        event_type='RFID',
        event_code='CARD_REVOKED',
        severity='WARNING',
        description=f'RFID card revoked immediately: {card_uid}',
        actor_role='ADMIN',
        actor_id=actor_id,
        timestamp_ms=now_ms(),
        raw_payload=json.dumps(data)
    )

    publish_rfid_sync(DEFAULT_NODE_FOR_DOOR, reason='revoke')

    return jsonify({
        'status': 'success',
        'message': 'RFID card revoked and sync command propagated',
        'effect_latency_target_seconds': 60
    })


@app.route('/api/rfid/cards', methods=['GET'])
def rfid_cards():
    with get_db_connection() as conn:
        rows = conn.execute('''
            SELECT id, card_uid, card_label, owner_name, is_active,
                   created_at, updated_at, revoked_at, revoked_reason, last_synced_at
            FROM registered_rfid_cards
            ORDER BY updated_at DESC, id DESC
        ''').fetchall()

    return jsonify([dict(r) for r in rows])


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


def on_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Door MQTT runtime subscriber connected")
        client.subscribe(DOOR_ALERT_TOPIC, qos=1)
        client.subscribe(DOOR_STATE_TOPIC, qos=1)
    else:
        print(f"❌ Door MQTT runtime subscriber failed with rc={rc}")


def on_mqtt_message(client, userdata, msg):
    topic = msg.topic
    payload_raw = msg.payload.decode('utf-8', errors='ignore')
    try:
        payload = json.loads(payload_raw)
    except Exception:
        payload = {'raw': payload_raw}

    timestamp_ms = payload.get('timestamp_ms')
    if not isinstance(timestamp_ms, int):
        timestamp_ms = None

    event_code = payload.get('code') or payload.get('state') or payload.get('event')
    severity = (payload.get('severity') or 'INFO').upper()

    if topic == DOOR_ALERT_TOPIC:
        description = payload.get('description') or f"Door alert: {event_code or 'UNKNOWN'}"
        log_door_event(
            node_id=DEFAULT_NODE_FOR_DOOR,
            event_type='ALERT',
            event_code=event_code,
            severity=severity,
            description=description,
            actor_role='SYSTEM',
            timestamp_ms=timestamp_ms,
            raw_payload=payload_raw
        )

        if severity == 'CRITICAL':
            publish_sse_event({
                'node_id': DEFAULT_NODE_FOR_DOOR,
                'severity': 'CRITICAL',
                'event_type': 'ALERT',
                'event_code': event_code,
                'description': description,
                'timestamp_ms': timestamp_ms,
                'gateway_received_ts': datetime.utcnow().isoformat() + 'Z',
                'topic': topic
            })

    elif topic == DOOR_STATE_TOPIC:
        state = payload.get('state') or event_code or 'UNKNOWN'
        description = payload.get('description') or f"Door state update: {state}"
        log_door_event(
            node_id=DEFAULT_NODE_FOR_DOOR,
            event_type='DOOR_STATE',
            event_code=state,
            severity='INFO',
            description=description,
            actor_role='SYSTEM',
            timestamp_ms=timestamp_ms,
            raw_payload=payload_raw
        )


def start_mqtt_runtime_listener():
    global mqtt_runtime_client
    if mqtt_runtime_client is not None:
        return

    client = mqtt.Client(client_id='iiot_gateway_door_runtime')
    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    try:
        client.connect(MQTT_BROKER_IP, MQTT_BROKER_PORT, 60)
        client.loop_start()
        mqtt_runtime_client = client
        print("✅ Door MQTT runtime listener started")
    except Exception as e:
        print(f"❌ Could not start door MQTT runtime listener: {e}")


# ==================== MAIN ====================

if __name__ == '__main__':
    # Initialize database
    init_database()
    start_mqtt_runtime_listener()

    print("=" * 60)
    print("Secure IIoT Gateway Dashboard - Flask Server")
    print("=" * 60)
    print("\n📊 Dashboard: http://localhost:5000/dashboard")
    print("🔓 Mode: ADMIN (full access)\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
