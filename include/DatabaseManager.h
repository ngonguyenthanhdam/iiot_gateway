// =============================================================================
// DatabaseManager.h — SQLite Persistence Layer
// Industrial IoT Gateway Security Platform
// Standard : C++17
//
// Responsibilities:
//   • RAII ownership of the sqlite3* connection handle
//   • Schema initialisation (CREATE TABLE IF NOT EXISTS) on construction
//   • ensureDeviceExists()  — anti-spoofing whitelist lookup / auto-insert
//   • insertSensorLog()     — time-series data persistence
//   • insertSystemEvent()   — security / fault audit trail
//   • getLastMsgId()        — replay-attack detection state
//
// Thread safety:
//   All public methods acquire m_mutex before touching SQLite.  The library
//   is compiled with SQLITE_THREADSAFE=1 by default on Linux, but we add our
//   own coarse mutex so callers never need to reason about serialisation.
//
// Error policy:
//   Constructor throws std::runtime_error if the DB file cannot be created or
//   opened (e.g. permission denied, no space left).  All other methods log the
//   SQLite error and return a safe fallback value — they never throw — so that
//   a transient DB error does not crash the gateway process.
// =============================================================================

#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

// C++ standard library
#include <string>
#include <mutex>
#include <stdexcept>    // std::runtime_error thrown by constructor
#include <cstdint>      // uint32_t, int64_t

// SQLite C API
#include <sqlite3.h>

// Project types
#include "models/SensorData.h"   // SensorReading, SecurityEvent

namespace IndustrialGateway {

// =============================================================================
// DatabaseManager
//
// Usage pattern (typical):
//
//   DatabaseManager db("db/factory_data.db");   // throws if can't open
//   db.ensureDeviceExists("ESP32_SEC_01");
//   db.insertSensorLog(reading);
//   uint32_t last = db.getLastMsgId("ESP32_SEC_01");
// =============================================================================
class DatabaseManager {
public:
    // -------------------------------------------------------------------------
    // Constructor — opens (or creates) the SQLite database file and runs the
    // schema initialisation.
    //
    // Parameters:
    //   dbPath — relative or absolute path to the .db file.
    //            The parent directory must already exist.
    //
    // Throws:
    //   std::runtime_error  if sqlite3_open_v2() fails (bad path, permissions,
    //                       corrupt file, etc.)
    // -------------------------------------------------------------------------
    explicit DatabaseManager(const std::string& dbPath);

    // -------------------------------------------------------------------------
    // Destructor — RAII guarantee: sqlite3_close() is always called even if an
    // exception unwinds the stack after construction.
    // -------------------------------------------------------------------------
    ~DatabaseManager();

    // Non-copyable: SQLite handles are not duplicable
    DatabaseManager(const DatabaseManager&)            = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    // Movable: allows storing in std::optional or returning from factories
    DatabaseManager(DatabaseManager&&)            noexcept;
    DatabaseManager& operator=(DatabaseManager&&) noexcept;

    // =========================================================================
    // Public API — all methods are thread-safe
    // =========================================================================

    // -------------------------------------------------------------------------
    // ensureDeviceExists
    //
    // Looks up node_id in the `devices` table.
    //   • If found  → returns the integer primary key (device_id).
    //   • If absent → inserts a new row with a placeholder location and
    //                 returns the new rowid.
    //
    // Called by DataProcessor before every insertSensorLog() so that the
    // foreign-key relationship (sensor_logs.device_id → devices.id) is always
    // satisfied.  Also serves as the anti-spoofing whitelist mechanism: the
    // caller can query whether a node_id was pre-provisioned by checking
    // whether the returned id was pre-existing (see isDeviceKnown()).
    //
    // Returns: device primary key (>0), or -1 on DB error.
    // -------------------------------------------------------------------------
    int64_t ensureDeviceExists(const std::string& nodeId);

    // -------------------------------------------------------------------------
    // isDeviceKnown
    //
    // Returns true only if node_id already exists in the `devices` table at
    // call time.  Unlike ensureDeviceExists(), this method does NOT insert a
    // new row, so DataProcessor can call it for the anti-spoofing check
    // BEFORE deciding whether to process the payload.
    //
    // Returns: true if known, false if unknown or on DB error.
    // -------------------------------------------------------------------------
    bool isDeviceKnown(const std::string& nodeId);

    // -------------------------------------------------------------------------
    // insertSensorLog
    //
    // Persists one SensorReading to the `sensor_logs` time-series table.
    // Calls ensureDeviceExists() internally to resolve the device_id FK.
    //
    // Optional fields (std::optional<float>):
    //   • temperature / humidity are stored as SQL NULL when std::nullopt.
    //
    // Returns: true on success, false on any SQLite error.
    // -------------------------------------------------------------------------
    bool insertSensorLog(const SensorReading& reading);

    // -------------------------------------------------------------------------
    // insertSystemEvent
    //
    // Appends one SecurityEvent to the `system_events` audit table.
    // This is the forensic record used for Insider Threat analysis.
    //
    // Returns: true on success, false on any SQLite error.
    // -------------------------------------------------------------------------
    bool insertSystemEvent(const SecurityEvent& event);

    // -------------------------------------------------------------------------
    // getLastMsgId
    //
    // Queries the maximum msg_id ever stored in `sensor_logs` for the given
    // node_id.  Used by DataProcessor to detect replay attacks:
    //
    //   if (incoming.msgId <= getLastMsgId(nodeId)) → replay attack
    //
    // Returns: highest known msg_id, or 0 if no records exist yet.
    // -------------------------------------------------------------------------
    uint32_t getLastMsgId(const std::string& nodeId);

    // -------------------------------------------------------------------------
    // purgeOldLogs
    //
    // Deletes sensor_logs rows older than `retentionDays` days.
    // Intended to be called periodically (e.g. once per day) to prevent the
    // SQLite file from growing unbounded on a resource-limited Pi4.
    //
    // Returns: number of rows deleted, or -1 on error.
    // -------------------------------------------------------------------------
    int64_t purgeOldLogs(int retentionDays);

private:
    // =========================================================================
    // Private helpers
    // =========================================================================

    // -------------------------------------------------------------------------
    // initSchema — runs CREATE TABLE IF NOT EXISTS for all three tables.
    // Called once from the constructor (with m_mutex already held).
    // Throws std::runtime_error if any DDL statement fails.
    // -------------------------------------------------------------------------
    void initSchema();

    // -------------------------------------------------------------------------
    // execSQL — convenience wrapper around sqlite3_exec() for DDL statements
    // that return no rows.  Throws std::runtime_error on failure.
    // -------------------------------------------------------------------------
    void execSQL(const std::string& sql);

    // -------------------------------------------------------------------------
    // logSqliteError — writes a formatted SQLite error to stderr and the
    // system debug log (does not throw).
    // -------------------------------------------------------------------------
    void logSqliteError(const std::string& context, int rc) const;

    // =========================================================================
    // Member variables
    // =========================================================================

    sqlite3*         m_db;       ///< Raw SQLite connection handle (owned, RAII)
    std::string      m_dbPath;   ///< Stored for error messages
    mutable std::mutex m_mutex;  ///< Serialises all SQLite calls across threads
};

} // namespace IndustrialGateway

#endif // DATABASE_MANAGER_H