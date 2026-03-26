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
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS devices (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id    TEXT    NOT NULL UNIQUE,
            location   TEXT    NOT NULL DEFAULT 'UNKNOWN',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )SQL");

    // ------------------------------------------------------------------
    // Table 2: sensor_logs — time-series sensor readings
    // ------------------------------------------------------------------
    execSQL(R"SQL(
        CREATE TABLE IF NOT EXISTS sensor_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   INTEGER NOT NULL,
            temp        REAL,           -- NULL when sensor not present
            humi        REAL,           -- NULL when sensor not present
            status      TEXT NOT NULL,
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

    const char* sql = R"SQL(
        INSERT INTO sensor_logs
            (device_id, temp, humi, status, msg_id, timestamp)
        VALUES
            (?, ?, ?, ?, ?, ?);
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

    // Status string
    string statusStr = deviceStatusToString(reading.status);
    sqlite3_bind_text(stmt, 4, statusStr.c_str(), -1, SQLITE_TRANSIENT);

    // msg_id and device timestamp
    sqlite3_bind_int64(stmt, 5, static_cast<int64_t>(reading.msgId));
    sqlite3_bind_int64(stmt, 6, reading.timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        logSqliteError("insertSensorLog(step)", rc);
        return false;
    }

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
// Queries the highest msg_id ever stored for the given node.
// DataProcessor calls this after receiving a new packet:
//
//   uint32_t last = db.getLastMsgId(nodeId);
//   if (incoming.msgId <= last) {
//       // Replay attack detected — log & discard
//   }
//
// Performance: the idx_sensor_logs_device_ts index makes MAX(msg_id)
// efficient even with millions of rows.
//
// Returns 0 when no rows exist yet (first message from this device is always
// accepted regardless of its msgId value).
// -----------------------------------------------------------------------------
uint32_t DatabaseManager::getLastMsgId(const string& nodeId) {
    lock_guard<mutex> lock(m_mutex);

    // Sub-select resolves node_id → device_id inline, avoiding a second
    // round-trip for the FK lookup.
    const char* sql = R"SQL(
        SELECT COALESCE(MAX(sl.msg_id), 0)
        FROM   sensor_logs sl
        JOIN   devices     d  ON d.id = sl.device_id
        WHERE  d.node_id = ?;
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
