// =============================================================================
// DataProcessor.h  —  JSON Parsing, Security Pipeline & Device Cache
// Industrial IoT Gateway Security Platform
// Standard : C++17
//
// This class is the cognitive core of the gateway.  Every raw MQTT payload
// delivered by MqttClient::on_message() passes through DataProcessor before
// anything is written to the database, logged to disk, or forwarded to SNMP.
//
// ── Responsibilities ──────────────────────────────────────────────────────────
//  1. JSON validation
//       Rejects payloads missing any of the 5 mandatory fields.
//
//  2. Type coercion  →  SensorReading struct
//       Converts raw JSON primitives into strongly-typed C++ values using the
//       helper functions in SensorData.h.
//
//  3. Anti-spoofing (LEVEL_3)
//       Checks node_id against the DatabaseManager whitelist BEFORE accepting
//       any data.  Unknown devices are event-logged and silently dropped.
//
//  4. Replay-attack detection (LEVEL_3)
//       Compares incoming msg_id against the highest persisted msg_id for that
//       node.  A non-increasing counter means the packet has been replayed.
//
//  5. Anomaly detection — temperature jump (LEVEL_3)
//       |T_new − T_old| > 20 °C  within a 5-second window.
//
//  6. Anomaly detection — humidity jump (LEVEL_2)
//       |H_new − H_old| > 40 %RH  within a 5-second window.
//
//  7. NOT_OPERATING handler (LEVEL_2)
//       Marks the device FAULTY in the cache; subsequent queries return 0xEE.
//
//  8. Recovery validation
//       After a FAULTY state, the device must send 3 consecutive valid
//       OPERATIONAL packets before the cache status reverts to OPERATIONAL.
//
//  9. Device cache update
//       Writes the validated SensorReading to the in-memory
//       unordered_map<string, SensorReading> under its own mutex.
//
// 10. Database persistence
//       Calls DatabaseManager::insertSensorLog() for accepted readings and
//       DatabaseManager::insertSystemEvent() for every security incident.
//
// ── Threading model ───────────────────────────────────────────────────────────
//  • onRawMessage() is the entry point called from the mosquitto loop thread.
//  • getCachedReading() / getAllCachedReadings() are called from:
//      – Watchdog thread (heartbeat checks)
//      – SnmpAgent thread (OID GET responses)
//      – future REST API thread (dashboard)
//
//  A single std::mutex (m_cacheMutex) serialises all access to m_deviceCache.
//  DatabaseManager has its own internal mutex — no nesting required here.
//
// ── Error policy ──────────────────────────────────────────────────────────────
//  Constructor throws std::invalid_argument if dbManager is nullptr.
//  onRawMessage() never throws; all failures are logged and the packet is
//  silently dropped so the gateway loop continues uninterrupted.
// =============================================================================

#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H

// Project headers
#include "DatabaseManager.h"         // insertSensorLog, insertSystemEvent, etc.
#include "models/SensorData.h"       // SensorReading, SecurityEvent, enums

// C++ standard library
#include <string>
#include <unordered_map>   // O(1) device cache lookup
#include <optional>        // return type for cache queries
#include <vector>          // getAllCachedReadings()
#include <mutex>           // std::mutex, std::lock_guard
#include <memory>          // std::shared_ptr (DatabaseManager injection)
#include <fstream>         // std::ofstream for security_alerts.log
#include <atomic>          // std::atomic<uint64_t> counters
#include <chrono>          // std::chrono::system_clock

// nlohmann/json — header-only JSON library
// Install: sudo apt install nlohmann-json3-dev
#include <nlohmann/json.hpp>

namespace IndustrialGateway {

// =============================================================================
// ProcessingConfig — thresholds and tuning knobs read from gateway_config.json.
// Passed to the constructor so DataProcessor is not hard-coded to any value.
// =============================================================================
struct ProcessingConfig {
    float    tempJumpThreshold   = 20.0f;  ///< °C  — triggers LEVEL_3 anomaly
    float    humiJumpThreshold   = 40.0f;  ///< %RH — triggers LEVEL_2 anomaly
    int      recoveryPacketCount = 3;      ///< consecutive OK packets to clear FAULTY
    bool     replayDetection     = true;   ///< false → disable for testing only
    std::string securityLogPath  = "logs/security_alerts.log";
    std::string debugLogPath     = "logs/system_debug.log";
};

// =============================================================================
// DataProcessor
//
// Injected dependency pattern: DatabaseManager is passed as a shared_ptr so
// that unit tests can substitute a mock, and so that the processor does not
// own the database lifetime (main.cpp owns it).
// =============================================================================
class DataProcessor {
public:

    // -------------------------------------------------------------------------
    // Constructor
    //
    // Parameters:
    //   dbManager — shared ownership of the database layer; must not be nullptr
    //   config    — processing thresholds (defaults match the spec)
    //
    // Throws:
    //   std::invalid_argument — if dbManager is nullptr
    //   std::runtime_error    — if log files cannot be opened
    // -------------------------------------------------------------------------
    explicit DataProcessor(
        std::shared_ptr<DatabaseManager> dbManager,
        ProcessingConfig                 config = {}
    );

    // Destructor — flushes and closes log file streams
    ~DataProcessor();

    // Non-copyable (owns file handles and mutable state)
    DataProcessor(const DataProcessor&)            = delete;
    DataProcessor& operator=(const DataProcessor&) = delete;

    // =========================================================================
    // Primary entry point — called by MqttClient::on_message() via callback
    // =========================================================================

    // -------------------------------------------------------------------------
    // onRawMessage
    //
    // The single method that MqttClient forwards every MQTT message to.
    // Executes the full 10-step processing pipeline described in the file
    // header.  Never throws; all errors are handled internally.
    //
    // Parameters:
    //   topic   — full MQTT topic, e.g. "factory/sensors/ESP32_SEC_01/data"
    //   payload — raw UTF-8 JSON string from the ESP32 payload
    //
    // Thread safety: safe to call from any thread; uses m_cacheMutex for
    //               all cache reads and writes.
    // -------------------------------------------------------------------------
    void onRawMessage(const std::string& topic, const std::string& payload);

    // =========================================================================
    // Device cache read interface
    // Used by: Watchdog (heartbeat), SnmpAgent (OID GET), REST API
    // =========================================================================

    // -------------------------------------------------------------------------
    // getCachedReading
    //
    // Returns a copy of the latest SensorReading for the given nodeId, or
    // std::nullopt if the device has not been seen yet in this session.
    //
    // Returns a VALUE copy (not a reference) so callers do not need to hold
    // m_cacheMutex while using the data.
    // -------------------------------------------------------------------------
    std::optional<SensorReading> getCachedReading(const std::string& nodeId) const;

    // -------------------------------------------------------------------------
    // getAllCachedReadings
    //
    // Returns a snapshot copy of the entire device cache.
    // Used by SnmpAgent to populate OID tables and by the Watchdog to iterate
    // all known nodes for heartbeat checking.
    //
    // Returns a value (full copy) so the caller can iterate without holding
    // the cache mutex.
    // -------------------------------------------------------------------------
    std::unordered_map<std::string, SensorReading> getAllCachedReadings() const;

    // -------------------------------------------------------------------------
    // updateCachedStatus
    //
    // Allows the Watchdog to externally set a device's status to OFFLINE
    // without touching the rest of the SensorReading fields.
    //
    // Thread safety: acquires m_cacheMutex internally.
    // -------------------------------------------------------------------------
    void updateCachedStatus(const std::string& nodeId, DeviceStatus newStatus);

    // =========================================================================
    // Diagnostic counters — lock-free reads for SNMP metrics
    // =========================================================================
    uint64_t getTotalAccepted()   const noexcept;  ///< packets fully processed
    uint64_t getTotalRejected()   const noexcept;  ///< packets dropped (any reason)
    uint64_t getSecurityEvents()  const noexcept;  ///< total security events logged

private:
    // =========================================================================
    // Processing pipeline — private step methods called by onRawMessage()
    //
    // Each method follows the same contract:
    //   • Returns true  → step passed, continue to next
    //   • Returns false → packet must be dropped; event already logged
    // =========================================================================

    // -------------------------------------------------------------------------
    // Step 1: parseJson
    //
    // Parses the raw UTF-8 string into a nlohmann::json object.
    // Validates that the JSON is well-formed AND contains the 5 mandatory
    // top-level fields: node_id, sensor_type, payload, status, msg_id,
    // timestamp.
    //
    // Returns false (drops packet) if:
    //   • The string is not valid JSON
    //   • Any mandatory field is missing
    //   • node_id or sensor_type are not strings
    //   • msg_id or timestamp are not numbers
    // -------------------------------------------------------------------------
    bool parseJson(const std::string& raw,
                   nlohmann::json&    out_doc) const;

    // -------------------------------------------------------------------------
    // Step 2: buildReading
    //
    // Converts a validated nlohmann::json object into a SensorReading struct.
    // Extracts temperature and humidity from the nested "payload" object
    // as std::optional<float> (nullopt if the key is absent).
    // Sets receivedAt = current wall-clock epoch (gateway-side timestamp).
    // -------------------------------------------------------------------------
    SensorReading buildReading(const nlohmann::json& doc) const;

    // -------------------------------------------------------------------------
    // checkAntiSpoofing  [LEVEL_3 / CRITICAL]
    //
    // Two-tier whitelist check:
    //
    //   Tier 1 — in-memory cache (m_knownDeviceCache):
    //     O(1) hash lookup.  If the node was seen before this session the
    //     result is already cached — no DB round-trip needed.
    //     A false entry means "permanently unauthorised this session", which
    //     prevents DB amplification from a flood of spoofed packets.
    //
    //   Tier 2 — DB fallback (DatabaseManager::isDeviceKnown):
    //     Only on first encounter per session.  Result is written into
    //     m_knownDeviceCache so it is never re-queried for the same node.
    //
    // On failure:
    //   insertSystemEvent() severity="CRITICAL" type="unauthorized_device"
    //   Returns false — packet dropped.
    // -------------------------------------------------------------------------
    bool checkAntiSpoofing(const SensorReading& reading);

    // -------------------------------------------------------------------------
    // checkReplayAttack  [LEVEL_3 / CRITICAL]
    //
    // Two-tier message-ID monotonicity check:
    //
    //   Tier 1 — in-memory map (m_lastMsgId) — hot path, O(1):
    //     incoming.msgId MUST be strictly greater than m_lastMsgId[node].
    //     On success, m_lastMsgId[node] is updated immediately (in RAM).
    //
    //   Tier 2 — DB seed (DatabaseManager::getLastMsgId):
    //     Called exactly ONCE per node per gateway session (guarded by
    //     m_msgIdSeeded).  Seeds m_lastMsgId so the check survives restarts.
    //
    // On failure:
    //   insertSystemEvent() severity="CRITICAL" type="replay_attack"
    //   Detail includes both received and expected msg_id values.
    //   Returns false — packet dropped.
    // -------------------------------------------------------------------------
    bool checkReplayAttack(const SensorReading& reading);

    // -------------------------------------------------------------------------
    // checkNotOperating  [LEVEL_2 / ERROR]
    //
    // If reading.status == NOT_OPERATING:
    //   • Cache status → FAULTY, recovery counter reset
    //   • insertSystemEvent() severity="ERROR" type="device_not_operating"
    //   • Returns false — packet dropped from normal pipeline
    // -------------------------------------------------------------------------
    bool checkNotOperating(const SensorReading& reading);

    // -------------------------------------------------------------------------
    // checkAnomalies  [LEVEL_3 CRITICAL / LEVEL_2 ERROR]
    //
    // Three independent rules, all evaluated even if earlier ones fire.
    //
    // ── Time-gate (5 seconds, gateway wall-clock) ────────────────────────────
    //   Uses receivedAt (stamped by the gateway) NOT device timestamp.
    //   If Δt > 5 s between readings, jump rules are SKIPPED — a data gap is
    //   not a jump.
    //
    // ── Rule A: Temperature jump  [CRITICAL] ─────────────────────────────────
    //   |T_new − T_old| > tempJumpThreshold (20 °C) within 5 s window
    //   insertSystemEvent() severity="CRITICAL" type="TEMP_JUMP"
    //
    // ── Rule B: Humidity jump  [ERROR] ───────────────────────────────────────
    //   |H_new − H_old| > humiJumpThreshold (40 %) within 5 s window
    //   insertSystemEvent() severity="ERROR" type="HUMI_JUMP"
    //
    // ── Rule C: Timestamp regression  [ERROR] ────────────────────────────────
    //   incoming.timestamp < previous.timestamp (device clock going backwards)
    //   insertSystemEvent() severity="ERROR" type="TIMESTAMP_REGRESSION"
    //
    // Returns void — anomalies are LOGGED but never drop the packet.
    // -------------------------------------------------------------------------
    void checkAnomalies(const SensorReading& incoming,
                        const SensorReading& previous);

    // -------------------------------------------------------------------------
    // Step 7: handleRecovery
    //
    // Called only when reading.status == OPERATIONAL and the cached status
    // is FAULTY.  Increments the per-node consecutive-OK counter.
    // When the counter reaches m_config.recoveryPacketCount, the cache status
    // is promoted back to OPERATIONAL and a recovery event is logged.
    // -------------------------------------------------------------------------
    void handleRecovery(const std::string& nodeId, DeviceStatus cachedStatus);

    // =========================================================================
    // Logging helpers — write to both SQLite system_events and the flat files
    // =========================================================================

    // -------------------------------------------------------------------------
    // logSecurityEvent
    //
    // Writes a SecurityEvent to:
    //   1. DatabaseManager::insertSystemEvent()   (SQLite audit trail)
    //   2. logs/security_alerts.log               (flat file, line-buffered)
    // -------------------------------------------------------------------------
    void logSecurityEvent(const std::string& nodeId,
                          const std::string& severity,
                          const std::string& description);

    // -------------------------------------------------------------------------
    // logDebug
    //
    // Writes a timestamped informational message to logs/system_debug.log.
    // Never writes to stderr — keeps production stdout clean.
    // -------------------------------------------------------------------------
    void logDebug(const std::string& msg) const;

    // -------------------------------------------------------------------------
    // extractNodeIdFromTopic
    //
    // Extracts the node_id segment from the MQTT topic string.
    // Topic format: factory/sensors/<node_id>/data
    //
    // Returns the extracted node_id, or empty string on parse failure.
    // Used for pre-validation log messages before the JSON is parsed.
    // -------------------------------------------------------------------------
    static std::string extractNodeIdFromTopic(const std::string& topic);

    // -------------------------------------------------------------------------
    // nowEpoch — returns current wall-clock time as Unix epoch seconds.
    // -------------------------------------------------------------------------
    static int64_t nowEpoch();

    // =========================================================================
    // Member variables
    // =========================================================================

    // Injected dependency — shared ownership, outlives DataProcessor
    std::shared_ptr<DatabaseManager> m_db;

    // Runtime configuration — set at construction, read-only thereafter
    const ProcessingConfig m_config;

    // ── Device cache ──────────────────────────────────────────────────────────
    // Stores the most recent validated SensorReading for every node_id seen.
    //
    // Key   : node_id string (e.g. "ESP32_SEC_01")
    // Value : SensorReading struct (latest validated reading)
    //
    // Access pattern:
    //   Writers : onRawMessage()       — called from mosquitto loop thread
    //   Readers : getCachedReading()   — called from Watchdog / SNMP threads
    //             getAllCachedReadings()
    //             updateCachedStatus()
    //
    // All access is serialised by m_cacheMutex.
    mutable std::mutex                                     m_cacheMutex;
    std::unordered_map<std::string, SensorReading>         m_deviceCache;

    // ── Recovery counters ─────────────────────────────────────────────────────
    // Tracks how many consecutive OPERATIONAL packets have been received
    // after a FAULTY state, per node_id.
    // Protected by m_cacheMutex (written and read always under that lock).
    std::unordered_map<std::string, int>                   m_recoveryCounters;

    // ── Security state maps — all protected by m_cacheMutex ──────────────────

    // ANTI-SPOOFING: in-memory whitelist mirror.
    //
    // Populated on first DB lookup per node_id; acts as a fast-path cache
    // so that isDeviceKnown() only hits SQLite once per unique node_id.
    // A node absent from the DB will be stored as false and never re-queried,
    // preventing DB-amplification from a flood of spoofed packets.
    //
    // Key   : node_id string
    // Value : true  = found in devices table (authorised)
    //         false = not found (unauthorised — drop all future packets too)
    std::unordered_map<std::string, bool>                  m_knownDeviceCache;

    // REPLAY ATTACK: in-memory last-seen message-id map.
    //
    // Populated from DB on first packet per node_id (via getLastMsgId()),
    // then updated in-memory on every accepted packet.
    // This makes the replay check a pure RAM comparison on the hot path;
    // the DB is only consulted once per node_id per gateway session.
    //
    // Key   : node_id string
    // Value : highest msg_id successfully accepted so far
    std::unordered_map<std::string, uint32_t>              m_lastMsgId;

    // ANOMALY DETECTION: tracks whether the in-memory lastMsgId for a node
    // has been seeded from the DB yet.  Without this flag we would re-query
    // the DB on every message for nodes that legitimately have msgId == 0.
    //
    // Key   : node_id string
    // Value : true = m_lastMsgId[nodeId] is already DB-seeded for this session
    std::unordered_map<std::string, bool>                  m_msgIdSeeded;

    // ── Log file streams ──────────────────────────────────────────────────────
    // Opened once at construction; kept open for the lifetime of the object.
    // Protected by m_logMutex (separate from cache mutex to avoid contention).
    mutable std::mutex m_logMutex;
    mutable std::ofstream m_securityLog;
    mutable std::ofstream m_debugLog;

    // ── Diagnostic counters ───────────────────────────────────────────────────
    std::atomic<uint64_t> m_totalAccepted;   ///< packets that reached DB write
    std::atomic<uint64_t> m_totalRejected;   ///< packets dropped at any step
    std::atomic<uint64_t> m_securityEvents;  ///< total security events raised
};

} // namespace IndustrialGateway

#endif // DATA_PROCESSOR_H