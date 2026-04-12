// =============================================================================
// DatabaseManager.cpp — SQLite Persistence Layer Implementation
// Industrial IoT Gateway Security Platform
// Standard : C++17
// =============================================================================

#include "DatabaseManager.h"

// C++ standard library
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>   // put_time

using namespace std;
using namespace chrono;
namespace IndustrialGateway {

// =============================================================================
// Internal helpers (file-scope, not exposed in the header)
// =============================================================================

namespace {

/// Returns current UTC time as a compact log prefix: [2024-05-14 08:30:01]
string nowStr() {
    auto now   = system_clock::now();
    time_t t = system_clock::to_time_t(now);
    tm tm_buf{};
    gmtime_r(&t, &tm_buf);   // thread-safe (POSIX)
    ostringstream oss;
    oss << "[" << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " UTC]";
    return oss.str();
}

} // anonymous namespace

// =============================================================================
// Construction & Destruction (RAII)
// =============================================================================

// -----------------------------------------------------------------------------
// Constructor
//
// Opens (or creates) the SQLite database at dbPath, enables WAL journaling for
// better concurrent read performance, and initialises the schema.
//
// WAL mode is important because:
//   • The watchdog thread may be reading while DataProcessor is writing.
//   • WAL allows one writer + multiple concurrent readers without blocking.
//
// Throws runtime_error if the file cannot be opened.
// -----------------------------------------------------------------------------
DatabaseManager::DatabaseManager(const string& dbPath)
    : m_db(nullptr)
    , m_dbPath(dbPath)
{
    lock_guard<mutex> lock(m_mutex);

    // SQLITE_OPEN_CREATE  : create the file if it does not exist
    // SQLITE_OPEN_READWRITE: we need both read and write access
    // SQLITE_OPEN_FULLMUTEX: ask SQLite itself to be thread-safe as well
    int rc = sqlite3_open_v2(
        dbPath.c_str(),
        &m_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr  // use default VFS
    );

    if (rc != SQLITE_OK) {
        // sqlite3_errmsg() is valid even when m_db is nullptr after a failed open
        string errMsg = m_db ? sqlite3_errmsg(m_db) : "unknown error";
        if (m_db) {
            sqlite3_close(m_db);
            m_db = nullptr;
        }
        throw runtime_error(
            "[DatabaseManager] Cannot open database '" + dbPath +
            "': " + errMsg +
            " (rc=" + to_string(rc) + ")"
        );
    }

    cout << nowStr()
              << " [DB] Opened database: " << dbPath << "\n";

    // Enable WAL journal mode — must be done before any transactions
    // We call sqlite3_exec directly here (m_mutex already held, can't use execSQL)
    char* errMsg = nullptr;
    rc = sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << nowStr()
                  << " [DB] WARNING: Could not set WAL mode: "
                  << (errMsg ? errMsg : "unknown") << "\n";
        sqlite3_free(errMsg);
        // Non-fatal — fall back to DELETE journal mode
    }

    // Enforce foreign key constraints (SQLite disables them by default)
    rc = sqlite3_exec(m_db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << nowStr()
                  << " [DB] WARNING: Could not enable foreign keys: "
                  << (errMsg ? errMsg : "unknown") << "\n";
        sqlite3_free(errMsg);
    }

    // Build the schema — throws on DDL failure
    initSchema();

    cout << nowStr() << " [DB] Schema initialised successfully.\n";
}

// -----------------------------------------------------------------------------
// Destructor — RAII guarantee
// -----------------------------------------------------------------------------
DatabaseManager::~DatabaseManager() {
    lock_guard<mutex> lock(m_mutex);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
        cout << nowStr() << " [DB] Connection closed: " << m_dbPath << "\n";
    }
}

// -----------------------------------------------------------------------------
// Move constructor
// -----------------------------------------------------------------------------
DatabaseManager::DatabaseManager(DatabaseManager&& other) noexcept
    : m_db(other.m_db)
    , m_dbPath(move(other.m_dbPath))
{
    other.m_db = nullptr;  // relinquish ownership
}

// -----------------------------------------------------------------------------
// Move assignment
// -----------------------------------------------------------------------------
DatabaseManager& DatabaseManager::operator=(DatabaseManager&& other) noexcept {
    if (this != &other) {
        // Close our current handle first
        if (m_db) {
            sqlite3_close(m_db);
        }
        m_db       = other.m_db;
        m_dbPath   = move(other.m_dbPath);
        other.m_db = nullptr;
    }
    return *this;
}

// =============================================================================
// Private — Schema Initialisation
// =============================================================================

// -----------------------------------------------------------------------------
// initSchema
//
// Creates the three core tables if they do not already exist.
// Runs inside the constructor with m_mutex already held.
//
// TABLE: devices
//   Whitelist of authorised ESP32 nodes.  node_id has a UNIQUE constraint so
//   that re-inserting the same device on gateway restart is idempotent.
//   The `location` field is populated with a placeholder on auto-insert and
//   can be updated manually via the SQLite CLI to record physical placement.
//
// TABLE: sensor_logs
//   Append-only time-series table.  device_id is a FK to devices.id.
//   temp and humi are REAL NULLABLE — nullopt becomes SQL NULL.
//   An index on (device_id, timestamp) accelerates the getLastMsgId() query
//   and the history API endpoint served by the FastAPI backend.
//
// TABLE: system_events
//   Immutable audit log for security incidents and fault events.
//   node_id is stored as plain TEXT (no FK) so that events from unknown
//   devices (the very thing we want to record) can still be inserted.
// -----------------------------------------------------------------------------
void DatabaseManager::initSchema() {
    // ------------------------------------------------------------------
    // Table 1: devices — authorised node whitelist
    //
    // New columns (v1.1.0):
    //   sensor_type  TEXT    — e.g. "ENV_MONITOR", "DHT11+MQ2"
    //   has_gas      INTEGER — 1 if node carries an MQ gas sensor, else 0
    //   last_msg_id  INTEGER — highest msg_id accepted from this node;
    //                          updated after every successful insertSensorLog().
    //                          Enables O(1) replay-attack detection via a
    //                          primary-key lookup instead of MAX(sensor_logs).
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id     TEXT    NOT NULL UNIQUE,
            location    TEXT    NOT NULL DEFAULT 'UNKNOWN',
            sensor_type TEXT    NOT NULL DEFAULT 'UNKNOWN',
            has_gas     INTEGER NOT NULL DEFAULT 0,   -- boolean: 0=false, 1=true
            last_msg_id INTEGER NOT NULL DEFAULT 0,   -- replay-attack high-water mark
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )SQL");

    // ------------------------------------------------------------------
    // Table 2: sensor_logs — time-series sensor readings
    //
    // New columns (v1.2.0):
    //   gas         INTEGER — raw 10-bit ADC value from ESP8266 A0 pin (0–1023).
    //   light_level INTEGER — raw 12-bit ADC value from ESP32 light sensor (0–4095).
    //   buzzer_active INTEGER — 1 if buzzer is active, 0 otherwise (ESP32 only).
    //   is_muted     INTEGER — 1 if mute button pressed, 0 otherwise (ESP32 only).
    //                  All new columns are NULLABLE for backward compatibility.
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS sensor_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   INTEGER NOT NULL,
            temp        REAL,               -- NULL when sensor not present
            humi        REAL,               -- NULL when sensor not present
            gas         INTEGER,            -- NULL when no gas sensor / preheating
            light_level INTEGER,            -- NULL when no light sensor
            buzzer_active INTEGER,          -- NULL when no buzzer control
            is_muted    INTEGER,            -- NULL when no mute button
            status      TEXT    NOT NULL,
            msg_id      INTEGER NOT NULL,
            timestamp   INTEGER NOT NULL,   -- Unix epoch seconds (from device)
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        );
    )SQL");

    // Performance index: latest msg_id lookup + history range queries
    execSQL(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_sensor_logs_device_ts
        ON sensor_logs (device_id, timestamp DESC);
    )SQL");

    // ------------------------------------------------------------------
    // Table 3: system_events — security & fault audit trail
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS system_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id     TEXT    NOT NULL,
            severity    TEXT    NOT NULL,   -- 'WARNING' | 'ERROR' | 'CRITICAL'
            description TEXT    NOT NULL,
            timestamp   INTEGER NOT NULL,   -- Unix epoch seconds
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )SQL");

    // Index for the /api/v1/events/alerts endpoint (sorted by recency)
    execSQL(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_system_events_ts
        ON system_events (timestamp DESC);
    )SQL");

    // ------------------------------------------------------------------
    // Table 4: door_events — dedicated smart-door event history
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS door_events (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id             TEXT    NOT NULL,
            event_type          TEXT    NOT NULL,   -- DOOR_STATE | ALERT | COMMAND | RFID | FAULT_CLEAR | AUTH
            event_code          TEXT,               -- LOCKED | UNLOCKED | FAULT | REED_FAULT ...
            severity            TEXT,               -- INFO | WARNING | CRITICAL
            description         TEXT    NOT NULL,
            actor_role          TEXT,               -- ADMIN | SYSTEM
            actor_id            TEXT,               -- optional user/admin identity
            timestamp_ms        INTEGER,            -- device-origin timestamp in ms
            gateway_received_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            raw_payload         TEXT
        );
    )SQL");

    execSQL(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_door_events_node_gateway_ts
        ON door_events (node_id, gateway_received_ts DESC);
    )SQL");

    execSQL(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_door_events_severity_gateway_ts
        ON door_events (severity, gateway_received_ts DESC);
    )SQL");

    // ------------------------------------------------------------------
    // Table 5: registered_rfid_cards — gateway-authoritative RFID lifecycle
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS registered_rfid_cards (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            card_uid       TEXT    NOT NULL UNIQUE,
            card_label     TEXT,
            owner_name     TEXT,
            is_active      INTEGER NOT NULL DEFAULT 1,    -- 1=active, 0=revoked
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            revoked_at     DATETIME,
            revoked_reason TEXT,
            last_synced_at DATETIME
        );
    )SQL");

    execSQL(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_registered_rfid_cards_active
        ON registered_rfid_cards (is_active, updated_at DESC);
    )SQL");

    // Migrate existing databases to add new columns (safe ALTER TABLE)
    migrateSensorLogsTable();
    migrateDevicesTable();
    migrateDoorEventsTable();
    migrateRegisteredRfidCardsTable();
}

// -----------------------------------------------------------------------------
// migrateDevicesTable
//
// Safely adds new columns to devices for backward compatibility.
// Similar to migrateSensorLogsTable() but for the devices table.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// migrateSensorLogsTable
//
// Safely adds new columns to sensor_logs for backward compatibility.
// Uses ALTER TABLE ADD COLUMN IF NOT EXISTS (SQLite 3.37.0+), but since older
// versions don't support IF NOT EXISTS for ADD COLUMN, we check column existence
// manually to avoid errors on re-run.
//
// This function is called from initSchema() after table creation.
// -----------------------------------------------------------------------------
void DatabaseManager::migrateSensorLogsTable() {
    // Check if columns already exist to avoid ALTER TABLE errors
    auto columnExists = [this](const string& colName) -> bool {
        const char* sql = "PRAGMA table_info(sensor_logs);";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;

        bool exists = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (name == colName) {
                exists = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
        return exists;
    };

    // Add light_level column if not exists
    if (!columnExists("light_level")) {
        execSQL("ALTER TABLE sensor_logs ADD COLUMN light_level INTEGER;");
    }

    // Add buzzer_active column if not exists
    if (!columnExists("buzzer_active")) {
        execSQL("ALTER TABLE sensor_logs ADD COLUMN buzzer_active INTEGER;");
    }

    // Add is_muted column if not exists
    if (!columnExists("is_muted")) {
        execSQL("ALTER TABLE sensor_logs ADD COLUMN is_muted INTEGER;");
    }
}

// -----------------------------------------------------------------------------
// migrateDevicesTable
//
// Safely adds new columns to devices for backward compatibility.
// Similar to migrateSensorLogsTable() but for the devices table.
// -----------------------------------------------------------------------------
void DatabaseManager::migrateDevicesTable() {
    // Check if columns already exist to avoid ALTER TABLE errors
    auto deviceColumnExists = [this](const string& colName) -> bool {
        const char* sql = "PRAGMA table_info(devices);";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;

        bool exists = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (name == colName) {
                exists = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
        return exists;
    };

    // Add sensor_type column if not exists
    if (!deviceColumnExists("sensor_type")) {
        execSQL("ALTER TABLE devices ADD COLUMN sensor_type TEXT NOT NULL DEFAULT 'UNKNOWN';");
    }

    // Add has_gas column if not exists
    if (!deviceColumnExists("has_gas")) {
        execSQL("ALTER TABLE devices ADD COLUMN has_gas INTEGER NOT NULL DEFAULT 0;");
    }

    // Add last_msg_id column if not exists
    if (!deviceColumnExists("last_msg_id")) {
        execSQL("ALTER TABLE devices ADD COLUMN last_msg_id INTEGER NOT NULL DEFAULT 0;");
    }
}

// -----------------------------------------------------------------------------
// migrateDoorEventsTable
//
// Safely adds optional/new columns to door_events for backward compatibility.
// -----------------------------------------------------------------------------
void DatabaseManager::migrateDoorEventsTable() {
    auto columnExists = [this](const string& colName) -> bool {
        const char* sql = "PRAGMA table_info(door_events);";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;

        bool exists = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (name == colName) {
                exists = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
        return exists;
    };

    if (!columnExists("event_code")) {
        execSQL("ALTER TABLE door_events ADD COLUMN event_code TEXT;");
    }
    if (!columnExists("actor_role")) {
        execSQL("ALTER TABLE door_events ADD COLUMN actor_role TEXT;");
    }
    if (!columnExists("actor_id")) {
        execSQL("ALTER TABLE door_events ADD COLUMN actor_id TEXT;");
    }
    if (!columnExists("timestamp_ms")) {
        execSQL("ALTER TABLE door_events ADD COLUMN timestamp_ms INTEGER;");
    }
    if (!columnExists("gateway_received_ts")) {
        execSQL("ALTER TABLE door_events ADD COLUMN gateway_received_ts DATETIME DEFAULT CURRENT_TIMESTAMP;");
    }
    if (!columnExists("raw_payload")) {
        execSQL("ALTER TABLE door_events ADD COLUMN raw_payload TEXT;");
    }
}

// -----------------------------------------------------------------------------
// migrateRegisteredRfidCardsTable
//
// Safely adds optional/new columns to registered_rfid_cards for backward
// compatibility.
// -----------------------------------------------------------------------------
void DatabaseManager::migrateRegisteredRfidCardsTable() {
    auto columnExists = [this](const string& colName) -> bool {
        const char* sql = "PRAGMA table_info(registered_rfid_cards);";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;

        bool exists = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (name == colName) {
                exists = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
        return exists;
    };

    if (!columnExists("card_label")) {
        execSQL("ALTER TABLE registered_rfid_cards ADD COLUMN card_label TEXT;");
    }
    if (!columnExists("owner_name")) {
        execSQL("ALTER TABLE registered_rfid_cards ADD COLUMN owner_name TEXT;");
    }
    if (!columnExists("updated_at")) {
        execSQL("ALTER TABLE registered_rfid_cards ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;");
    }
    if (!columnExists("revoked_at")) {
        execSQL("ALTER TABLE registered_rfid_cards ADD COLUMN revoked_at DATETIME;");
    }
    if (!columnExists("revoked_reason")) {
        execSQL("ALTER TABLE registered_rfid_cards ADD COLUMN revoked_reason TEXT;");
    }
    if (!columnExists("last_synced_at")) {
        execSQL("ALTER TABLE registered_rfid_cards ADD COLUMN last_synced_at DATETIME;");
    }
}

// =============================================================================
// Public API
// =============================================================================

// -----------------------------------------------------------------------------
// isDeviceKnown
//
// Used by DataProcessor as the anti-spoofing check BEFORE any data is
// processed.  Returns true only for pre-provisioned devices.
// -----------------------------------------------------------------------------
bool DatabaseManager::isDeviceKnown(const string& nodeId) {
    lock_guard<mutex> lock(m_mutex);

    const char* sql = "SELECT COUNT(*) FROM devices WHERE node_id = ?;";
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("isDeviceKnown(prepare)", rc);
        return false;
    }

    // Bind the node_id parameter (index 1, 1-based in SQLite)
    sqlite3_bind_text(stmt, 1, nodeId.c_str(), -1, SQLITE_TRANSIENT);

    bool known = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        known = (sqlite3_column_int(stmt, 0) > 0);
    }

    sqlite3_finalize(stmt);
    return known;
}

// -----------------------------------------------------------------------------
// ensureDeviceExists
//
// Tries to INSERT OR IGNORE the device, then queries the resulting rowid.
// Using INSERT OR IGNORE + SELECT avoids a race condition between CHECK and
// INSERT in a multi-threaded environment (the mutex prevents this anyway, but
// the single-statement approach is also safer against SQLite's own concurrency).
//
// Returns the device primary key on success, -1 on any DB error.
// -----------------------------------------------------------------------------
int64_t DatabaseManager::ensureDeviceExists(const string& nodeId) {
    lock_guard<mutex> lock(m_mutex);

    // Step 1: Insert if not present (IGNORE silently skips duplicate node_id)
    {
        const char* insertSql =
            "INSERT OR IGNORE INTO devices (node_id, location) VALUES (?, 'AUTO_REGISTERED');";
        sqlite3_stmt* stmt = nullptr;

        int rc = sqlite3_prepare_v2(m_db, insertSql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            logSqliteError("ensureDeviceExists(insert/prepare)", rc);
            return -1;
        }

        sqlite3_bind_text(stmt, 1, nodeId.c_str(), -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE && rc != SQLITE_CONSTRAINT) {
            logSqliteError("ensureDeviceExists(insert/step)", rc);
            return -1;
        }
    }

    // Step 2: Retrieve the primary key (whether just inserted or pre-existing)
    {
        const char* selectSql = "SELECT id FROM devices WHERE node_id = ?;";
        sqlite3_stmt* stmt    = nullptr;

        int rc = sqlite3_prepare_v2(m_db, selectSql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            logSqliteError("ensureDeviceExists(select/prepare)", rc);
            return -1;
        }

        sqlite3_bind_text(stmt, 1, nodeId.c_str(), -1, SQLITE_TRANSIENT);

        int64_t deviceId = -1;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            deviceId = sqlite3_column_int64(stmt, 0);
        }

        sqlite3_finalize(stmt);
        return deviceId;
    }
}

// -----------------------------------------------------------------------------
// insertSensorLog
//
// Persists one parsed SensorReading to `sensor_logs`.
// Uses a prepared statement with bound parameters — never string concatenation
// — to prevent SQL injection and handle special characters in nodeId.
//
// optional handling:
//   temperature.has_value() == false  →  sqlite3_bind_null (stored as SQL NULL)
//   temperature.has_value() == true   →  sqlite3_bind_double
// -----------------------------------------------------------------------------
bool DatabaseManager::insertSensorLog(const SensorReading& reading) {
    // First, resolve the device FK (also registers new devices automatically)
    int64_t deviceId = ensureDeviceExists(reading.nodeId);
    if (deviceId < 0) {
        cerr << nowStr()
                  << " [DB] insertSensorLog: could not resolve device_id for '"
                  << reading.nodeId << "'\n";
        return false;
    }

    lock_guard<mutex> lock(m_mutex);

    // New columns: light_level (5), buzzer_active (6), is_muted (7); status shifts to 8, etc.
    const char* sql = R"SQL(
        INSERT INTO sensor_logs
            (device_id, temp, humi, gas, light_level, buzzer_active, is_muted, status, msg_id, timestamp)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("insertSensorLog(prepare)", rc);
        return false;
    }

    // Bind positional parameters (1-based)
    sqlite3_bind_int64(stmt, 1, deviceId);

    // Temperature — NULL when sensor not present on this node type
    if (reading.temperature.has_value()) {
        sqlite3_bind_double(stmt, 2, static_cast<double>(*reading.temperature));
    } else {
        sqlite3_bind_null(stmt, 2);
    }

    // Humidity — same optional treatment
    if (reading.humidity.has_value()) {
        sqlite3_bind_double(stmt, 3, static_cast<double>(*reading.humidity));
    } else {
        sqlite3_bind_null(stmt, 3);
    }

    // Gas — NULL when no sensor fitted OR when value is -1 (preheat sentinel).
    // Storing -1 as NULL avoids false threshold alerts during sensor warm-up
    // and keeps the column semantically clean: NULL means "no data", not "0 ppm".
    if (reading.gasValue.has_value() && *reading.gasValue >= 0) {
        sqlite3_bind_int(stmt, 4, static_cast<int>(*reading.gasValue));
    } else {
        sqlite3_bind_null(stmt, 4);
    }

    // Light level — NULL when no light sensor (ESP32 only)
    if (reading.lightLevel.has_value()) {
        sqlite3_bind_int(stmt, 5, static_cast<int>(*reading.lightLevel));
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    // Buzzer active — NULL when no buzzer control (ESP32 only)
    if (reading.buzzerActive.has_value()) {
        sqlite3_bind_int(stmt, 6, *reading.buzzerActive ? 1 : 0);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    // Is muted — NULL when no mute button (ESP32 only)
    if (reading.isMuted.has_value()) {
        sqlite3_bind_int(stmt, 7, *reading.isMuted ? 1 : 0);
    } else {
        sqlite3_bind_null(stmt, 7);
    }

    // Status string (param 8)
    string statusStr = deviceStatusToString(reading.status);
    sqlite3_bind_text(stmt, 8, statusStr.c_str(), -1, SQLITE_TRANSIENT);

    // msg_id (param 9) and device timestamp (param 10)
    sqlite3_bind_int64(stmt, 9, static_cast<int64_t>(reading.msgId));
    sqlite3_bind_int64(stmt, 10, reading.timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        logSqliteError("insertSensorLog(step)", rc);
        return false;
    }

    // Keep devices.last_msg_id current so getLastMsgId() is an O(1) PK lookup
    // instead of a MAX() scan across sensor_logs.  m_mutex is already held.
    updateLastMsgId(reading.nodeId, reading.msgId);

    return true;
}

// -----------------------------------------------------------------------------
// insertSystemEvent
//
// Appends a security or fault event to `system_events`.
// This table is the forensic audit trail; records are NEVER deleted by the
// gateway (only sensor_logs are subject to purgeOldLogs).
// -----------------------------------------------------------------------------
bool DatabaseManager::insertSystemEvent(const SecurityEvent& event) {
    lock_guard<mutex> lock(m_mutex);

    const char* sql = R"SQL(
        INSERT INTO system_events
            (node_id, severity, description, timestamp)
        VALUES
            (?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("insertSystemEvent(prepare)", rc);
        return false;
    }

    sqlite3_bind_text (stmt, 1, event.nodeId.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 2, event.severity.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 3, event.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, event.timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        logSqliteError("insertSystemEvent(step)", rc);
        return false;
    }

    // Also echo to stdout for real-time visibility during development
    cout << nowStr()
              << " [SECURITY EVENT] [" << event.severity << "] "
              << event.nodeId << " — " << event.description << "\n";

    return true;
}

// -----------------------------------------------------------------------------
// getLastMsgId
//
// Reads devices.last_msg_id directly — a single primary-key lookup (O(1))
// rather than the previous MAX(sensor_logs.msg_id) JOIN which required a full
// index scan per call.  This column is kept current by updateLastMsgId() which
// is called inside every successful insertSensorLog().
//
// DataProcessor call pattern:
//   uint32_t last = db.getLastMsgId(nodeId);
//   if (incoming.msgId <= last) → replay attack → log & discard
//
// Returns 0 when no rows exist yet (first message always accepted).
// -----------------------------------------------------------------------------
uint32_t DatabaseManager::getLastMsgId(const string& nodeId) {
    lock_guard<mutex> lock(m_mutex);

    const char* sql = R"SQL(
        SELECT last_msg_id FROM devices WHERE node_id = ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("getLastMsgId(prepare)", rc);
        return 0;   // Safe fallback: treat as first message
    }

    sqlite3_bind_text(stmt, 1, nodeId.c_str(), -1, SQLITE_TRANSIENT);

    uint32_t lastId = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        lastId = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return lastId;
}

// -----------------------------------------------------------------------------
// provisionAuthorizedNodes
//
// Inserts or updates every entry from the gateway_config.json
// "authorized_nodes.nodes" array.
//
// INSERT OR IGNORE + UPDATE pattern
// ───────────────────────────────────
// A plain INSERT OR IGNORE would skip existing rows entirely, leaving location,
// sensor_type and has_gas stale after a config change.  A plain INSERT OR
// REPLACE would delete-then-reinsert, resetting last_msg_id to 0 and breaking
// replay-attack protection across gateway restarts.
//
// The correct approach is two statements per node:
//   1. INSERT OR IGNORE — adds the row if node_id is new; a no-op if it exists.
//   2. UPDATE ... WHERE node_id = ? — overwrites metadata (location, sensor_type,
//      has_gas) but deliberately omits last_msg_id so replay state is preserved.
//
// Both steps run inside a single BEGIN/COMMIT transaction for atomicity.
// If any step fails the transaction is rolled back and the method returns -1.
//
// Returns: count of nodes successfully provisioned, or -1 on fatal DB error.
// -----------------------------------------------------------------------------
int DatabaseManager::provisionAuthorizedNodes(const vector<AuthorizedNode>& nodes) {
    lock_guard<mutex> lock(m_mutex);

    if (nodes.empty()) {
        cout << nowStr() << " [DB] provisionAuthorizedNodes: node list is empty — skipped.\n";
        return 0;
    }

    // Wrap all inserts/updates in a transaction — atomic on success, fully
    // rolled back on any error.
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << nowStr() << " [DB] provisionAuthorizedNodes: BEGIN failed: "
             << (errMsg ? errMsg : "?") << "\n";
        sqlite3_free(errMsg);
        return -1;
    }

    int provisioned = 0;

    for (const auto& node : nodes) {
        // ── Step 1: Insert if not present ────────────────────────────────────
        // INSERT OR IGNORE leaves last_msg_id at its DEFAULT 0 for new rows
        // and does nothing at all for existing rows.
        const char* insertSql = R"SQL(
            INSERT OR IGNORE INTO devices
                (node_id, location, sensor_type, has_gas, last_msg_id)
            VALUES
                (?, ?, ?, ?, 0);
        )SQL";

        sqlite3_stmt* stmt = nullptr;
        rc = sqlite3_prepare_v2(m_db, insertSql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            logSqliteError("provisionAuthorizedNodes(insert/prepare)", rc);
            sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return -1;
        }

        sqlite3_bind_text(stmt, 1, node.nodeId.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, node.location.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, node.sensorType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 4, node.hasGas ? 1 : 0);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            logSqliteError("provisionAuthorizedNodes(insert/step) for " + node.nodeId, rc);
            sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return -1;
        }

        // ── Step 2: Update metadata for existing rows ─────────────────────────
        // Deliberately excludes last_msg_id — never reset replay-attack state.
        const char* updateSql = R"SQL(
            UPDATE devices
            SET    location    = ?,
                   sensor_type = ?,
                   has_gas     = ?
            WHERE  node_id     = ?;
        )SQL";

        rc = sqlite3_prepare_v2(m_db, updateSql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            logSqliteError("provisionAuthorizedNodes(update/prepare)", rc);
            sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return -1;
        }

        sqlite3_bind_text(stmt, 1, node.location.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, node.sensorType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 3, node.hasGas ? 1 : 0);
        sqlite3_bind_text(stmt, 4, node.nodeId.c_str(),     -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            logSqliteError("provisionAuthorizedNodes(update/step) for " + node.nodeId, rc);
            sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return -1;
        }

        ++provisioned;
        cout << nowStr()
             << " [DB] Provisioned node: " << node.nodeId
             << " | type=" << node.sensorType
             << " | gas=" << (node.hasGas ? "yes" : "no")
             << " | location=" << node.location << "\n";
    }

    // Commit the whole batch
    rc = sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << nowStr() << " [DB] provisionAuthorizedNodes: COMMIT failed: "
             << (errMsg ? errMsg : "?") << "\n";
        sqlite3_free(errMsg);
        sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return -1;
    }

    cout << nowStr()
         << " [DB] provisionAuthorizedNodes: " << provisioned
         << " node(s) ready.\n";
    return provisioned;
}

// -----------------------------------------------------------------------------
// updateLastMsgId  (private)
//
// Updates devices.last_msg_id to msgId for the given nodeId.
// Called inside insertSensorLog() with m_mutex already held.
// Uses MAX semantics: only updates if the new value is strictly greater than
// the stored value, protecting against out-of-order delivery in edge cases.
// -----------------------------------------------------------------------------
bool DatabaseManager::updateLastMsgId(const string& nodeId, uint32_t msgId) {
    const char* sql = R"SQL(
        UPDATE devices
        SET    last_msg_id = ?
        WHERE  node_id     = ?
          AND  last_msg_id < ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("updateLastMsgId(prepare)", rc);
        return false;
    }

    const int64_t msgId64 = static_cast<int64_t>(msgId);
    sqlite3_bind_int64(stmt, 1, msgId64);
    sqlite3_bind_text (stmt, 2, nodeId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, msgId64);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        logSqliteError("updateLastMsgId(step)", rc);
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// purgeOldLogs
//
// Removes sensor_logs rows whose `timestamp` (device epoch) is older than
// retentionDays ago.  Audit events in system_events are never purged.
//
// Returns number of deleted rows, or -1 on error.
// -----------------------------------------------------------------------------
int64_t DatabaseManager::purgeOldLogs(int retentionDays) {
    lock_guard<mutex> lock(m_mutex);

    // Compute the cutoff as a Unix epoch value
    auto now     = system_clock::now();
    auto cutoff  = now - hours(24 * retentionDays);
    int64_t cutoffEpoch = duration_cast<seconds>(
                              cutoff.time_since_epoch()).count();

    const char* sql = "DELETE FROM sensor_logs WHERE timestamp < ?;";
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("purgeOldLogs(prepare)", rc);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, cutoffEpoch);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        logSqliteError("purgeOldLogs(step)", rc);
        return -1;
    }

    int64_t deleted = sqlite3_changes(m_db);
    cout << nowStr()
              << " [DB] Purged " << deleted
              << " sensor_log rows older than " << retentionDays << " days.\n";
    return deleted;
}

// -----------------------------------------------------------------------------
// getLatestDataForAllNodes
//
// Retrieves the most recent SensorReading for every known node.
// Uses a window function (ROW_NUMBER() OVER) to get the latest row per node_id,
// then filters to only the top-ranked row per group.
//
// Alternative query without window functions (slower on large tables):
//   SELECT sl.* FROM sensor_logs sl
//   INNER JOIN (SELECT device_id, MAX(timestamp) AS max_ts
//               FROM sensor_logs GROUP BY device_id) latest
//   ON sl.device_id = latest.device_id AND sl.timestamp = latest.max_ts;
//
// Returns: vector<SensorReading> with one entry per node that has ever logged data.
// -----------------------------------------------------------------------------
std::vector<SensorReading> DatabaseManager::getLatestDataForAllNodes() {
    lock_guard<mutex> lock(m_mutex);

    const char* sql = R"SQL(
        SELECT sl.device_id, d.node_id, d.sensor_type,
               sl.temp, sl.humi, sl.gas, sl.light_level, sl.buzzer_active, sl.is_muted,
               sl.status, sl.msg_id, sl.timestamp, sl.captured_at
        FROM sensor_logs sl
        INNER JOIN devices d ON sl.device_id = d.id
        WHERE sl.id IN (
            SELECT id FROM (
                SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY timestamp DESC) AS rn
                FROM sensor_logs
            ) WHERE rn = 1
        )
        ORDER BY d.node_id;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logSqliteError("getLatestDataForAllNodes(prepare)", rc);
        return {};
    }

    std::vector<SensorReading> readings;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        SensorReading reading;

        // device_id (0) — not stored in SensorReading
        // node_id (1)
        reading.nodeId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        // sensor_type (2) — parse from string
        string sensorTypeStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        reading.sensorType = sensorTypeFromString(sensorTypeStr);

        // temp (3) — REAL, may be NULL
        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            reading.temperature = static_cast<float>(sqlite3_column_double(stmt, 3));
        }

        // humi (4) — REAL, may be NULL
        if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
            reading.humidity = static_cast<float>(sqlite3_column_double(stmt, 4));
        }

        // gas (5) — INTEGER, may be NULL
        if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
            reading.gasValue = static_cast<int32_t>(sqlite3_column_int(stmt, 5));
        }

        // light_level (6) — INTEGER, may be NULL
        if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
            reading.lightLevel = static_cast<int32_t>(sqlite3_column_int(stmt, 6));
        }

        // buzzer_active (7) — INTEGER, may be NULL
        if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
            reading.buzzerActive = (sqlite3_column_int(stmt, 7) != 0);
        }

        // is_muted (8) — INTEGER, may be NULL
        if (sqlite3_column_type(stmt, 8) != SQLITE_NULL) {
            reading.isMuted = (sqlite3_column_int(stmt, 8) != 0);
        }

        // status (9) — TEXT
        string statusStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        reading.status = deviceStatusFromString(statusStr);

        // msg_id (10) — INTEGER
        reading.msgId = static_cast<uint32_t>(sqlite3_column_int64(stmt, 10));

        // timestamp (11) — INTEGER (device epoch)
        reading.timestamp = sqlite3_column_int64(stmt, 11);

        // captured_at (12) — not stored in SensorReading (gateway timestamp)

        // receivedAt — set to 0 (not available from DB)
        reading.receivedAt = 0;

        readings.push_back(std::move(reading));
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        logSqliteError("getLatestDataForAllNodes(step)", rc);
        return {};
    }

    return readings;
}

// =============================================================================
// Private Helpers
// =============================================================================
// -----------------------------------------------------------------------------
// execSQL — executes a single DDL/DML statement that returns no rows.
// m_mutex must be held by the caller (called from constructor & initSchema).
// Throws runtime_error on failure.
// -----------------------------------------------------------------------------
void DatabaseManager::execSQL(const string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        string msg = errMsg ? errMsg : "unknown SQLite error";
        sqlite3_free(errMsg);
        throw runtime_error(
            "[DatabaseManager] Schema error on '" + m_dbPath + "': " + msg
        );
    }
}

// -----------------------------------------------------------------------------
// logSqliteError — formats and prints a non-fatal SQLite error.
// Does NOT throw; allows callers to return a safe fallback value instead.
// -----------------------------------------------------------------------------
void DatabaseManager::logSqliteError(const string& context, int rc) const {
    string detail = m_db ? sqlite3_errmsg(m_db) : "handle is null";
    cerr << nowStr()
              << " [DB ERROR] " << context
              << " — rc=" << rc
              << " msg=" << detail
              << " db=" << m_dbPath << "\n";
}

} // namespace IndustrialGateway