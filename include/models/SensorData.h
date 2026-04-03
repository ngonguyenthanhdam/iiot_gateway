#ifndef SENSOR_DATA_H
#define SENSOR_DATA_H

// ==============================================================================
// SensorData.h — Core Data Model
// Industrial IoT Gateway Security Platform
//
// Defines the canonical in-memory representation of a sensor reading produced
// by any ESP32/ESP8266 edge node.  All Gateway modules operate on these types.
//
// C++17 features used:
//   • std::optional<T>   — field may be absent for nodes without that sensor
//   • enum class         — strongly-typed, scoped enumerations
//   • namespace          — avoids global symbol pollution
//
// Change log
// ----------
// v1.1.0  Added NodeMetrics struct for per-node runtime tracking.
//         Added std::optional<int32_t> gasValue to SensorReading for gas-
//         capable ESP8266 nodes (SEC_02, SEC_03).
//         Added ENV_MONITOR_GAS SensorType for nodes carrying both DHT + MQ.
//         Updated SensorType helpers accordingly.
// ==============================================================================

#include <string>
#include <optional>   // C++17: nullable value semantics without raw pointers
#include <cstdint>    // uint32_t, int64_t

namespace IndustrialGateway {

// ------------------------------------------------------------------------------
// DeviceStatus
//
// Mirrors the "status" string in the MQTT JSON payload, plus gateway-derived
// states.  OFFLINE is never sent by a device — it is inferred by the Watchdog
// when no heartbeat arrives within the configured timeout (default: 30 s).
// ------------------------------------------------------------------------------
enum class DeviceStatus : uint8_t {
    OPERATIONAL   = 0,   ///< Device is running normally
    WARNING       = 1,   ///< Non-critical anomaly reported by device or gateway
    CRITICAL      = 2,   ///< Critical hardware/software fault on device
    NOT_OPERATING = 3,   ///< Device explicitly declared non-operational
    OFFLINE       = 4,   ///< Gateway-inferred: heartbeat timeout exceeded
    FAULTY        = 5,   ///< Gateway-locked: after NOT_OPERATING, pending recovery
    ALARM         = 6,   ///< Gas or environmental threshold crossed (ESP8266 nodes)
    UNKNOWN       = 255  ///< Fallback — status string could not be parsed
};

// ------------------------------------------------------------------------------
// SensorType
//
// Derived from the "sensor_type" string field in the MQTT payload.
// Add new types here as additional node classes are commissioned; the rest of
// the pipeline will handle them via the UNKNOWN fallback.
//
// v1.1.0: Added ENV_MONITOR_GAS for ESP8266 nodes that carry both a DHT11
// temperature/humidity sensor and an MQ-type analog gas sensor on A0.
// ------------------------------------------------------------------------------
enum class SensorType : uint8_t {
    ENV_MONITOR     = 0,   ///< Environmental: temperature + humidity only (DHT11/22)
    SECURITY        = 1,   ///< Security: motion (PIR), sound, vibration …
    ENV_MONITOR_GAS = 2,   ///< Environmental + gas: DHT11/22 + MQ sensor on A0
    UNKNOWN         = 255  ///< Unrecognised sensor_type string
};

// ------------------------------------------------------------------------------
// SensorReading
//
// Canonical, parsed representation of one MQTT message.
//
// Lifecycle:
//   1. DataProcessor parses raw JSON → fills this struct
//   2. Stored in the in-memory device cache (unordered_map<string, SensorReading>)
//   3. Persisted to SQLite via DatabaseManager::insertSensorLog()
//   4. Read by SnmpAgent for GET responses (no DB round-trip needed)
//   5. Compared with previous reading in DataProcessor for anomaly detection
//
// Design notes:
//   • temperature / humidity / gasValue / lightLevel / buzzerActive / isMuted are std::optional<T> — only nodes whose
//     hardware carries that sensor populate the field. Attempting to read an
//     unpopulated optional throws std::bad_optional_access, making absent-field
//     access a hard error rather than a silent default.
//   • gasValue is int32_t (not float): the ESP8266 ADC is 10-bit (0–1023) and
//     the value is stored raw. int32_t accommodates sentinel values such as -1
//     (sensor preheat not yet complete) without ambiguity with valid ADC readings.
//   • lightLevel is int32_t: ESP32 ADC is 12-bit (0–4095).
//   • buzzerActive and isMuted are bool: directly from ESP32 payload.
//   • msgId is uint32_t — matches the ESP SecurityUtils counter width (2^32).
//   • timestamp is int64_t — Unix epoch seconds; avoids the year-2038 issue.
// ------------------------------------------------------------------------------
struct SensorReading {
    std::string              nodeId;       ///< Unique device identifier ("ESP8266_SEC_02")
    SensorType               sensorType;  ///< Parsed sensor category
    std::optional<float>     temperature; ///< °C    — present for ENV_MONITOR* nodes
    std::optional<float>     humidity;    ///< %RH   — present for ENV_MONITOR* nodes
    std::optional<int32_t>   gasValue;    ///< ADC   — present only for ENV_MONITOR_GAS
                                          ///<          nodes (ESP8266 MQ sensor, 0–1023).
                                          ///<          -1 indicates sensor still preheating.
    std::optional<int32_t>   lightLevel;  ///< ADC   — present only for ENV_MONITOR
                                          ///<          nodes (ESP32 light sensor, 0–4095).
    std::optional<bool>      buzzerActive;///< true if buzzer is sounding — ESP32 only
    std::optional<bool>      isMuted;     ///< true if mute button pressed — ESP32 only
    DeviceStatus             status;      ///< Operational status
    uint32_t                 msgId;       ///< Monotonically increasing message counter
    int64_t                  timestamp;   ///< Unix epoch (seconds) from device payload

    // Gateway wall-clock time when the packet was received (set by DataProcessor,
    // NOT by the ESP node).  Used by the Watchdog heartbeat check and anomaly
    // detection time-gate.  A value of 0 means the struct is a placeholder
    // (device has never been seen this session).
    int64_t                  receivedAt;  ///< Gateway Unix epoch (seconds) at receipt

    // Safe default: produces an identifiable "empty" reading so that the
    // device cache can be pre-populated before the first real message arrives.
    SensorReading()
        : sensorType(SensorType::UNKNOWN)
        , temperature(std::nullopt)
        , humidity(std::nullopt)
        , gasValue(std::nullopt)
        , lightLevel(std::nullopt)
        , buzzerActive(std::nullopt)
        , isMuted(std::nullopt)
        , status(DeviceStatus::UNKNOWN)
        , msgId(0)
        , timestamp(0)
        , receivedAt(0)
    {}
};

// ------------------------------------------------------------------------------
// NodeMetrics
//
// Per-node runtime statistics maintained by the Gateway across the lifetime of
// a session.  One NodeMetrics entry exists in the device cache for every node
// that has ever sent a message — including nodes in OFFLINE or FAULTY states.
//
// Relationship to SensorReading
// ──────────────────────────────
// SensorReading  = one parsed MQTT packet    (instantiated per message)
// NodeMetrics    = running totals for a node  (mutated in place, never replaced)
//
// The distinction matters for replay-attack detection:
//   • SensorReading::msgId  is the counter value INSIDE the current packet.
//   • NodeMetrics::lastMsgId is the highest counter value the gateway has seen
//     from this node across ALL packets this session.  If an incoming
//     SensorReading::msgId <= NodeMetrics::lastMsgId, the packet is a replay
//     or was re-ordered — the DataProcessor must reject it and raise a
//     LEVEL_3 CRITICAL SecurityEvent.
//
// Gas monitoring
// ──────────────
// NodeMetrics::gasValue stores the most recent raw ADC gas reading.
// Together with the previous-reading cache in DataProcessor, it enables:
//   • Threshold comparison against gateway_config.json "gas" thresholds
//   • Spike detection (|current - previous| > gas_jump_adc → anomaly)
//   • SNMP GET response for gas level without a SQLite round-trip
//
// Fields
// ──────
// lastMsgId        Highest msg_id seen from this node.  Initialised to 0
//                  (a node that has never sent has seen no message).
//                  uint32_t matches the ESP SecurityUtils::nextMessageId()
//                  counter width.
//
// gasValue         Most recent raw ADC gas reading (int32_t, 0–1023 when valid).
//                  -1  = node has not yet sent a gas reading (preheat, or node
//                        does not have a gas sensor).
//                  std::optional is NOT used here — unlike SensorReading which
//                  models a single packet, NodeMetrics needs a sentinel-safe
//                  integer that can be stored in SQLite INTEGER columns and
//                  serialised into SNMP varbinds without unwrapping an optional.
//
// totalPackets     Count of all packets received from this node, valid or not.
//
// validPackets     Count of packets that passed all validation checks.
//                  Used by the recovery subsystem (see gateway_config.json
//                  "recovery.valid_packets_required").
//
// replayCount      Count of replay-attack detections for this node this session.
//                  A non-zero value warrants operator investigation.
//
// lastSeenAt       Gateway wall-clock time (Unix epoch seconds) of the most
//                  recent packet, used by the Watchdog for OFFLINE detection.
// ------------------------------------------------------------------------------
struct NodeMetrics {
    std::string  nodeId;          ///< Same key as SensorReading::nodeId

    // ── Replay-attack protection ──────────────────────────────────────────────
    uint32_t     lastMsgId;       ///< Highest msg_id seen from this node (ever)
    uint32_t     replayCount;     ///< Replay detections this session

    // ── Gas monitoring ────────────────────────────────────────────────────────
    int32_t      gasValue;        ///< Latest raw ADC gas reading; -1 if not available
    int32_t      prevGasValue;    ///< Previous reading — enables spike detection
                                  ///<  without an extra cache lookup in DataProcessor

    // ── Health counters ───────────────────────────────────────────────────────
    uint64_t     totalPackets;    ///< All received packets (including invalid)
    uint64_t     validPackets;    ///< Packets that passed all validation checks
    DeviceStatus currentStatus;   ///< Most recently derived DeviceStatus

    // ── Timing ───────────────────────────────────────────────────────────────
    int64_t      lastSeenAt;      ///< Gateway epoch (s) of most recent packet

    /// Default: safe zero-initialised state for a newly-registered node.
    /// lastMsgId = 0  means "no message yet seen" — the first real packet
    /// (msg_id = 1 from SecurityUtils) will always be > 0 and therefore valid.
    /// gasValue = -1  means "no gas data yet" — prevents false threshold alerts
    /// before the first reading arrives.
    NodeMetrics()
        : lastMsgId(0)
        , replayCount(0)
        , gasValue(-1)
        , prevGasValue(-1)
        , totalPackets(0)
        , validPackets(0)
        , currentStatus(DeviceStatus::UNKNOWN)
        , lastSeenAt(0)
    {}
};

// ------------------------------------------------------------------------------
// SecurityEvent
//
// Represents one entry in the `system_events` audit table.
// Created by DataProcessor and Watchdog when a security or fault condition is
// detected, then persisted via DatabaseManager::insertSystemEvent().
//
// Also written to logs/security_alerts.log as a flat-file audit trail.
//
// severity field values:
//   "WARNING"  → LEVEL_1 — near-threshold or informational
//   "ERROR"    → LEVEL_2 — device fault, humidity jump, hardware anomaly
//   "CRITICAL" → LEVEL_3 — replay attack, spoofed device, temp/gas jump, offline
// ------------------------------------------------------------------------------
struct SecurityEvent {
    std::string nodeId;       ///< Originating device (may be "UNKNOWN" for rogue nodes)
    std::string severity;     ///< "WARNING" | "ERROR" | "CRITICAL"
    std::string description;  ///< Human-readable incident description
    int64_t     timestamp;    ///< Unix epoch seconds when the event was detected

    SecurityEvent()
        : timestamp(0)
    {}
};

// ==============================================================================
// Helper Free Functions
// Kept as inline functions here to avoid a separate .cpp compilation unit for
// simple enum/string conversions.
// ==============================================================================

/// Convert DeviceStatus → human-readable string (used by DB, logs, SNMP)
inline std::string deviceStatusToString(DeviceStatus s) {
    switch (s) {
        case DeviceStatus::OPERATIONAL:   return "OPERATIONAL";
        case DeviceStatus::WARNING:       return "WARNING";
        case DeviceStatus::CRITICAL:      return "CRITICAL";
        case DeviceStatus::NOT_OPERATING: return "NOT_OPERATING";
        case DeviceStatus::OFFLINE:       return "OFFLINE";
        case DeviceStatus::FAULTY:        return "FAULTY";
        case DeviceStatus::ALARM:         return "ALARM";
        default:                          return "UNKNOWN";
    }
}

/// Parse "status" JSON string → DeviceStatus enum
inline DeviceStatus deviceStatusFromString(const std::string& s) {
    if (s == "OPERATIONAL")   return DeviceStatus::OPERATIONAL;
    if (s == "WARNING")       return DeviceStatus::WARNING;
    if (s == "CRITICAL")      return DeviceStatus::CRITICAL;
    if (s == "NOT_OPERATING") return DeviceStatus::NOT_OPERATING;
    if (s == "alarm")         return DeviceStatus::ALARM;    // from ESP8266 nodes
    if (s == "warn")          return DeviceStatus::WARNING;  // from ESP8266 nodes
    if (s == "ok")            return DeviceStatus::OPERATIONAL;
    return DeviceStatus::UNKNOWN;
}

/// Parse "sensor_type" JSON string → SensorType enum
inline SensorType sensorTypeFromString(const std::string& s) {
    if (s == "ENV_MONITOR")     return SensorType::ENV_MONITOR;
    if (s == "SECURITY")        return SensorType::SECURITY;
    if (s == "DHT11+MQ2")       return SensorType::ENV_MONITOR_GAS;
    if (s == "ENV_MONITOR_GAS") return SensorType::ENV_MONITOR_GAS;
    return SensorType::UNKNOWN;
}

/// Convert SensorType → human-readable string
inline std::string sensorTypeToString(SensorType t) {
    switch (t) {
        case SensorType::ENV_MONITOR:     return "ENV_MONITOR";
        case SensorType::SECURITY:        return "SECURITY";
        case SensorType::ENV_MONITOR_GAS: return "ENV_MONITOR_GAS";
        default:                          return "UNKNOWN";
    }
}

/// Returns true if this SensorType carries a gas sensor.
/// Use to decide whether to parse / validate the "gas" payload field.
inline bool hasGasSensor(SensorType t) {
    return t == SensorType::ENV_MONITOR_GAS;
}

/// Returns true if this SensorType carries temperature/humidity sensors.
inline bool hasEnvSensors(SensorType t) {
    return t == SensorType::ENV_MONITOR
        || t == SensorType::ENV_MONITOR_GAS;
}

} // namespace IndustrialGateway

#endif // SENSOR_DATA_H