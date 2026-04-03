# Secure IIoT Gateway Framework

<div align="center">

![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%204-red.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)

**A High-Performance, Security-Focused Industrial IoT Gateway with Real-time Monitoring and AI-Powered Analytics**

[Features](#features) • [Architecture](#system-architecture) • [Installation](#installation--setup) • [Configuration](#configuration) • [Technologies](#technologies)

</div>

---

## 📋 Project Overview

The **Secure IIoT Gateway Framework** is an enterprise-grade Industrial IoT deployment platform designed to collect, process, and monitor sensor data from distributed edge devices (ESP32, ESP8266) with comprehensive security mechanisms and intelligent analytics. Built for Raspberry Pi 4 environments, this framework bridges the gap between edge devices and cloud infrastructure with a focus on data integrity, system security, and real-time insights.

### Core Value Proposition

- **Real-Time Data Collection**: High-performance MQTT client for seamless integration with IoT sensor networks
- **Enterprise Security**: Built-in replay attack detection, timestamp regression validation, and comprehensive audit trails
- **Integrated Monitoring**: Native SNMP agent support with system watchdog ensuring 24/7 operational reliability
- **AI-Powered Insights**: Gemini Pro integration for intelligent log analysis and anomaly detection
- **Web Dashboard**: Responsive, real-time monitoring interface with role-based access control and attack simulation capabilities

---

## ✨ Key Features

### 🔧 High-Performance C++ Gateway System

| Component | Purpose |
|-----------|---------|
| **MqttClient** | Asynchronous MQTT broker communication with QoS support |
| **DataProcessor** | Real-time sensor data validation and transformation |
| **DatabaseManager** | Efficient SQLite operations with connection pooling |
| **SnmpAgent** | SNMP v2/v3 monitoring and alerting |
| **Watchdog** | Health monitoring and automatic service recovery |

### 🔐 Advanced Security Mechanisms

- **Replay Attack Detection**: Cryptographic nonce validation and sequence tracking
- **Timestamp Regression Prevention**: Multi-layer temporal integrity checks
- **RBAC (Role-Based Access Control)**: User authentication and granular permission management
- **Secure Configuration**: Encrypted sensitive data in `gateway_config.json`
- **Audit Logging**: Comprehensive access and operation logs for compliance

### 📊 Web Dashboard & Visualization

Built with **Flask** and **Bootstrap 5**, featuring:

| Tab | Functionality |
|-----|---------------|
| **Node 01/02/03** | Real-time sensor data visualization with Chart.js graphs |
| **Error Simulation** | Test gateway resilience with controlled fault injection |
| **Attack Simulation** | Security testing framework for replay and timestamp attacks |
| **AI Insights** | Gemini Pro chatbot for interactive log and data analysis |
| **Settings** | Configuration management and user profile administration |

### 🤖 AI-Powered Analysis

- **Gemini Pro Integration**: Natural language processing for log anomaly detection
- **Intelligent Insights**: Automatic pattern recognition in sensor data
- **Contextual Assistance**: Interactive chatbot for operational guidance

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     EDGE DEVICES (WiFi)                         │
│            ESP32 / ESP8266 Sensor Nodes (x3)                    │
└────────────────────────────┬────────────────────────────────────┘
                             │ MQTT (Publish)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RASPBERRY PI 4 (8GB RAM)                     │
│                   Secure IIoT Gateway Framework                 │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           C++ Backend (High-Performance Core)            │   │
│  │                                                          │   │
│  │  ┌────────────────┐  ┌─────────────────────────────┐     │   │
│  │  │  MqttClient    │  │      DataProcessor          │     │   │
│  │  │  - Subscribe   │  │  - Validation               │     │   │
│  │  │  - QoS Mgmt    │  │  - Transformation           │     │   │
│  │  │  - Async Ops   │  │  - Security Checks          │     │   │
│  │  └────────────────┘  └─────────────────────────────┘     │   │
│  │                              │                           │   │
│  │  ┌────────────────┐  ┌───────▼──────────────────────┐    │   │
│  │  │   Watchdog     │  │  DatabaseManager (SQLite)    │    │   │
│  │  │  - Health      │  │  - Insert/Query Ops          │    │   │
│  │  │    Monitoring  │  │  - Connection Pooling        │    │   │
│  │  │  - Auto        │  │  - Transaction Management    │    │   │
│  │  │    Recovery    │  └─────────┬────────────────────┘    │   │
│  │  └────────────────┘            │                         │   │
│  │                                 │                        │   │
│  │  ┌────────────────────────────────────────────────┐      │   │
│  │  │            SnmpAgent Monitoring                │      │   │
│  │  │  - System Metrics Export                       │      │   │
│  │  │  - OID Registration                            │      │   │
│  │  └────────────────────────────────────────────────┘      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │     SQLite Database (Local Persistent Storage)           │   │
│  │  - Sensor readings, timestamps, metadata                 │   │
│  │  - User credentials, audit logs                          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │        Python Web Application (Flask + Bootstrap)        │   │
│  │                                                          │   │
│  │  ┌──────────────────────────────────────────────────┐    │   │
│  │  │             Web Dashboard (UI Layer)             │    │   │
│  │  │  • Real-time Chart.js Visualizations             │    │   │
│  │  │  • Node Status Monitoring (3x Tabs)              │    │   │
│  │  │  • Error & Attack Simulation                     │    │   │
│  │  │  • AI Chatbot Integration                        │    │   │
│  │  │  • RBAC Authentication                           │    │   │
│  │  └──────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │      Gemini Pro AI APIs (Cloud Integration)              │   │
│  │  - Log analysis and anomaly detection                    │   │
│  │  - Interactive insights and recommendations              │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow Pipeline

```
Sensor Node → MQTT Publish
          ↓
    MqttClient (Subscribe & Parse)
          ↓
    DataProcessor (Validate & Transform)
          ├─→ Security Checks (Replay Detection, Timestamp Validation)
          ├─→ DatabaseManager (Store in SQLite)
          └─→ Real-time Dashboard Updates (WebSocket/AJAX)
          
System Metrics ←→ SnmpAgent (Network Monitoring)
Gate Health    ←→ Watchdog (Auto-Recovery)
Logs           ←→ Gemini Pro (AI Analysis)
```

---

## 🚀 Installation & Setup

### Prerequisites

- **Hardware**: Raspberry Pi 4 (8GB RAM recommended)
- **OS**: Raspberry Pi OS (or compatible Linux distribution)
- **Network**: WiFi/Ethernet connectivity and MQTT broker access
- **Tools**: Git, CMake 3.10+, Python 3.11+

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/iiot_gateway.git
cd iiot_gateway
```

### Step 2: Automated Setup (Recommended)

Execute the automated setup script:

```bash
chmod +x scripts/setup_pi.sh
./scripts/setup_pi.sh
```

This script will:
- Install system dependencies (CMake, Python packages, Mosquitto client)
- Configure MQTT broker connectivity
- Initialize SQLite database
- Set up environment variables

### Step 3: Manual Build (if needed)

```bash
# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake ..

# Compile C++ components
make -j$(nproc)

# Return to root
cd ..
```

### Step 4: Launch Gateway

```bash
# Start the gateway service
./scripts/start_gateway.sh
```

Or manually run:

```bash
# Terminal 1: Start C++ backend
./build/iiot_gateway

# Terminal 2: Start Flask web application
python app.py
```

### Verification

Access the dashboard at: **http://localhost:5000**

Expected output:
```
✓ C++ Gateway initialized
✓ MQTT client connected to broker:1883
✓ Database initialized: SQLite ready
✓ Flask application running on 0.0.0.0:5000
✓ Watchdog monitoring started
✓ SNMP agent listening on 0.0.0.0:161
```

---

## 📊 Web Dashboard & Simulation

### Dashboard Interface

#### 🔌 **Node Monitoring Tabs (01, 02, 03)**

Real-time visualization of sensor data from three connected IoT nodes:

| Metric | Display | Update Frequency |
|--------|---------|-----------------|
| Temperature | Line graph | 5 seconds |
| Humidity | Gauge chart | 5 seconds |
| Pressure | Area chart | 5 seconds |
| Signal Strength | Indicator | Continuous |
| Status | Color-coded badge | Real-time |

#### ⚠️ **Error Simulation Tab**

Test gateway resilience with controlled fault injection:

```
Available Scenarios:
├── Network Disconnection: Simulate MQTT broker unavailability
├── Sensor Malfunction: Generate invalid sensor readings
├── Database Failure: Trigger SQLite connection failure
├── Memory Leak Simulation: Monitor system resource degradation
└── Watchdog Recovery: Test automatic service restart
```

#### 🔓 **Attack Simulation Tab**

Comprehensive security testing framework:

| Attack Type | Description | Detection Method |
|------------|-------------|-----------------|
| **Replay Attack** | Retransmit captured messages | Nonce validation + Sequence tracking |
| **Timestamp Regression** | Send past-dated packets | Temporal integrity checks |
| **Credential Brute Force** | Multiple login attempts | Rate limiting + Account lockout |
| **Unauthorized Access** | Invalid permission elevation | RBAC enforcement |
| **Data Tampering** | Modify sensor payloads | Cryptographic checksums |

#### 🤖 **AI Insights Tab**

Interactive Gemini Pro chatbot for:
- Log file analysis and anomaly detection
- Sensor data pattern recognition
- Operational recommendations
- Security incident investigation

Example queries:
```
"Analyze the last 100 sensor readings for anomalies"
"What caused the spike in CPU usage at 14:32?"
"Show me all security-related log entries from today"
"Predict potential sensor failures based on trends"
```

#### ⚙️ **Settings Tab**

User administration and system configuration:
- User profile management
- Role and permission assignment
- Gateway configuration editing
- Database backup/restore
- Log export and archival

---

## ⚙️ Configuration

### gateway_config.json

Configure all gateway parameters in `config/gateway_config.json`:

```json
{
  "mqtt": {
    "broker": "localhost",
    "port": 1883,
    "client_id": "iiot_gateway_01",
    "qos": 1,
    "keep_alive": 60,
    "topics": [
      "sensor/node01/+",
      "sensor/node02/+",
      "sensor/node03/+"
    ]
  },
  "database": {
    "path": "db/gateway_data.db",
    "pool_size": 5,
    "backup_interval_hours": 24
  },
  "web": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false,
    "session_timeout": 3600
  },
  "snmp": {
    "enabled": true,
    "port": 161,
    "community": "public",
    "version": "2c"
  },
  "watchdog": {
    "enabled": true,
    "check_interval_seconds": 30,
    "auto_restart": true
  },
  "security": {
    "replay_detection": true,
    "timestamp_validation": true,
    "enable_rbac": true,
    "password_hash_algorithm": "bcrypt",
    "session_encryption": true
  },
  "gemini": {
    "api_key": "${GEMINI_API_KEY}",
    "model": "gemini-pro",
    "timeout_seconds": 30
  },
  "logging": {
    "level": "INFO",
    "max_file_size_mb": 100,
    "retention_days": 30,
    "output_path": "logs/"
  }
}
```

### Environment Variables

```bash
# Required
export MQTT_BROKER="your-mqtt-broker-ip"
export GEMINI_API_KEY="your-gemini-api-key"

# Optional (with defaults)
export GATEWAY_PORT=5000
export DATABASE_PATH="db/gateway_data.db"
export LOG_LEVEL="INFO"
```

### Configuration Best Practices

- ✅ Use environment variables for sensitive credentials
- ✅ Validate configuration on startup
- ✅ Enable timestamp validation in production
- ✅ Set appropriate QoS levels (1 or 2 for critical data)
- ✅ Configure regular database backups
- ✅ Use strong session encryption keys

---

## 🛠️ Technologies & Dependencies

### Core Components

| Technology | Version | Purpose |
|-----------|---------|---------|
| **C++** | 20 | Backend gateway core, MQTT/SNMP clients |
| **Python** | 3.11+ | Flask web application, AI integration |
| **CMake** | 3.10+ | Build system and compilation |
| **SQLite** | 3.x | Local data persistence |

### C++ Libraries

```
├── Paho MQTT C++ (MQTT communication)
├── SQLite3 C/C++ API (Database operations)
├── SNMP++ (SNMP monitoring)
├── Boost (Utilities and threading)
├── OpenSSL (Cryptography and TLS)
└── JSON for Modern C++ (Configuration parsing)
```

### Python Packages

```
Flask==2.3.0              # Web framework
Flask-Login==0.6.2        # User authentication
Flask-SQLAlchemy==3.0.0   # ORM for database
Werkzeug==2.3.0           # Security utilities
google-generativeai==0.3.0 # Gemini Pro API
paho-mqtt==1.6.1          # MQTT client library
pysnmp==4.4.12            # SNMP operations
Chart.js==4.0.0           # Frontend charting
Bootstrap==5.3.0          # UI framework
```

### System Dependencies

```bash
# Debian/Ubuntu
sudo apt-get install cmake g++ python3-dev libssl-dev libsqlite3-dev

# MQTT
sudo apt-get install mosquitto mosquitto-clients

# SNMP
sudo apt-get install snmp snmp-mibs-downloader
```

---

## 📁 Project Structure

```
iiot_gateway/
│
├── 📄 README.md                        # This file
├── 📄 CMakeLists.txt                   # C++ build configuration
├── 📄 app.py                            # Flask web application entry point
├── 📄 test_typedef.cpp                  # Unit tests
│
├── 🗂️ src/                              # C++ source code
│   ├── main.cpp                          # Gateway main entry point
│   ├── MqttClient.cpp                    # MQTT communication
│   ├── DataProcessor.cpp                 # Data validation & transformation
│   ├── DatabaseManager.cpp               # SQLite operations
│   ├── SnmpAgent.cpp                     # SNMP monitoring
│   └── Watchdog.cpp                      # Health monitoring & recovery
│
├── 🗂️ include/                          # C++ header files
│   ├── MqttClient.h
│   ├── DataProcessor.h
│   ├── DatabaseManager.h
│   ├── SnmpAgent.h
│   ├── Watchdog.h
│   └── models/
│       └── SensorData.h                  # Data structure definitions
│
├── 🗂️ config/                           # Configuration files
│   └── gateway_config.json               # Main configuration
│
├── 🗂️ db/                               # Database storage
│   └── (SQLite database files)
│
├── 🗂️ logs/                             # Application logs
│   └── (Log files with timestamps)
│
├── 🗂️ build/                            # Compiled binaries
│   └── (CMake build output)
│
├── 🗂️ templates/                        # Flask HTML templates
│   ├── index.html                        # Main dashboard
│   └── login.html                        # Authentication page
│
└── 🗂️ scripts/                          # Setup and deployment
    ├── setup_pi.sh                       # Automated setup script
    └── start_gateway.sh                  # Service launch script
```

---

## 🔒 Security Considerations

### Authentication & Authorization

- **Login Required**: All dashboard access requires username/password authentication
- **Session Management**: 1-hour session timeout with automatic re-authentication
- **RBAC Levels**: 
  - `admin`: Full system access
  - `operator`: Monitor and simulate (read-only on critical settings)
  - `viewer`: Dashboard viewing only

### Data Protection

- ✓ **Replay Attack Detection**: Nonce-based verification with sequence tracking
- ✓ **Timestamp Integrity**: Regression detection with configurable time windows
- ✓ **Encrypted Connections**: TLS 1.2+ for MQTT and web communications
- ✓ **Credential Security**: Bcrypt password hashing with salt
- ✓ **Audit Logging**: Complete audit trail for all user actions

### Network Hardening

- Use VPN or private network for MQTT broker
- Enable firewall rules limiting dashboard access
- Run gateway with minimal system privileges
- Regularly update all dependencies

---

## 📈 Performance Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| **MQTT Throughput** | 1000+ msg/sec | Depends on broker and network |
| **Data Processing Latency** | <50ms | End-to-end from MQTT to database |
| **Dashboard Update Frequency** | 5 seconds | Real-time data visualization |
| **Memory Usage** | <500MB | Stable under typical loads |
| **CPU Utilization** | <30% | Optimized C++ implementation |
| **Database Query Time** | <10ms | Indexed queries on typical datasets |

### Optimization Tips

```bash
# Run with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Monitor performance
top -p $(pgrep -f ./build/iiot_gateway)

# Database maintenance
sqlite3 db/gateway_data.db "VACUUM;"
```

---

## 🐛 Troubleshooting

### Common Issues

**Gateway fails to start**
```bash
# Check for port conflicts
netstat -tulpn | grep :5000
netstat -tulpn | grep :1883

# Verify MQTT broker is running
mosquitto -v
```

**Dashboard not accessible**
```bash
# Check Flask service status
ps aux | grep app.py

# Verify port 5000 is open
curl http://localhost:5000
```

**Database errors**
```bash
# Check database integrity
sqlite3 db/gateway_data.db "PRAGMA integrity_check;"

# Restore from backup if corrupted
cp db/gateway_data.db.backup db/gateway_data.db
```

**SNMP agent not responding**
```bash
# Verify SNMP service
snmpwalk -v 2c -c public localhost

# Check firewall rules
sudo ufw allow 161/udp
```

### Debug Mode

Enable verbose logging:

```json
{
  "logging": {
    "level": "DEBUG",
    "output_path": "logs/"
  }
}
```

Then monitor logs:
```bash
tail -f logs/gateway.log
```

---

## 📚 Documentation & Resources

### API Endpoints

- Dashboard: `GET http://gateway:5000/`
- Node Data: `GET http://gateway:5000/api/nodes/<node_id>/data`
- Simulate Attack: `POST http://gateway:5000/api/simulate/attack`
- AI Chat: `POST http://gateway:5000/api/ai/chat`

### MQTT Topics

```
sensor/node01/temperature    → Temperature readings
sensor/node01/humidity       → Humidity readings
sensor/node01/pressure       → Pressure readings
gateway/status               → Gateway health status
gateway/alerts/critical      → Critical alerts
```

### SNMP OIDs

```
1.3.6.1.2.1.1.3.0          → System uptime
1.3.6.1.2.1.25.3.2.1.5.1   → CPU load average
1.3.6.1.2.1.25.2.3.1.6.1   → Memory usage
```

---

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
ctest

# Code formatting
clang-format -i src/*.cpp include/*.h
```

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👥 Support & Contact

- **Issues**: Create an issue on GitHub
- **Email**: support@iiotgateway.dev
- **Documentation**: Check the `/docs` folder for detailed guides
- **Community**: Join our discussion forum

---

## 🙏 Acknowledgments

Built with ❤️ for the industrial IoT community. Special thanks to:
- Raspberry Pi Foundation
- Eclipse Mosquitto Team
- Google Gemini API
- Open-source communities

---

**Last Updated**: April 2, 2026

