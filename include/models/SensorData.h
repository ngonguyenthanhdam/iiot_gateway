#ifndef SENSOR_DATA_H
#define SENSOR_DATA_H

// ==============================================================================
// SensorData.h — Core Data Model
// Industrial IoT Gateway Security Platform
//
// Defines the canonical in-memory representation of a sensor reading produced
// by any ESP32/ESP8266 edge node.  All Gateway modules operate on this struct.
//
// C++17 features used:
//   • std::optional<float>  — field may be absent for non-ENV sensor types
//   • enum class            — strongly-typed, scoped enumerations
//   • namespace             — avoids global symbol pollution
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
    WARNING       = 1,   ///< Non-critical anomaly reported by device
    CRITICAL      = 2,   ///< Critical hardware/software fault on device
    NOT_OPERATING = 3,   ///< Device explicitly declared non-operational
    OFFLINE       = 4,   ///< Gateway-inferred: heartbeat timeout exceeded
    UNKNOWN       = 255  ///< Fallback — status string could not be parsed
};

// ------------------------------------------------------------------------------
// SensorType
//
// Derived from the "sensor_type" string field in the MQTT payload.
// Add new types here as additional node classes are commissioned; the rest of
// the pipeline will automatically handle them via the UNKNOWN fallback.
// ------------------------------------------------------------------------------
enum class SensorType : uint8_t {
    ENV_MONITOR = 0,   ///< Environmental: temperature + humidity (DHT11/22)
    SECURITY    = 1,   ///< Security: motion (PIR), sound, vibration …
    UNKNOWN     = 255  ///< Unrecognised sensor_type string
};

// ------------------------------------------------------------------------------
// SensorReading
//
// Canonical, parsed representation of one MQTT message.
//
// Lifecycle:
//   1. DataProcessor parses raw JSON → fills this struct
//   2. Stored in the in-memory device cache  (unordered_map<string, SensorReading>)
//   3. Persisted to SQLite via DatabaseManager::insertSensorLog()
//   4. Read by SnmpAgent for GET responses (no DB round-trip needed)
//   5. Compared with previous reading in DataProcessor for anomaly detection
//
// Design notes:
//   • temperature / humidity are std::optional<float> — non-ENV nodes (e.g.
//     PIR sensors) do not carry these fields; optionals make that explicit and
//     prevent accidental access of uninitialised floats.
//   • msgId is uint32_t — matches the ESP32 counter width (wraps at 2^32).
//   • timestamp is int64_t — Unix epoch seconds; avoids the year-2038 issue.
// ------------------------------------------------------------------------------
struct SensorReading {
    std::string           nodeId;       ///< Unique device identifier ("ESP32_SEC_01")
    SensorType            sensorType;   ///< Parsed sensor category
    std::optional<float>  temperature;  ///< °C — only for ENV_MONITOR nodes
    std::optional<float>  humidity;     ///< %RH — only for ENV_MONITOR nodes
    DeviceStatus          status;       ///< Operational status
    uint32_t              msgId;        ///< Monotonically increasing message counter
    int64_t               timestamp;    ///< Unix epoch (seconds) from device payload

    // Gateway wall-clock time when the packet was received (set by DataProcessor,
    // NOT by the ESP32).  Used by the Watchdog heartbeat check and anomaly
    // detection time-gate.  A value of 0 means the struct is a placeholder
    // (device has never been seen this session).
    int64_t               receivedAt;   ///< Gateway Unix epoch (seconds) at receipt

    // Safe default: produces an identifiable "empty" reading so that the
    // device cache can be pre-populated before the first real message arrives.
    SensorReading()
        : sensorType(SensorType::UNKNOWN)
        , temperature(std::nullopt)
        , humidity(std::nullopt)
        , status(DeviceStatus::UNKNOWN)
        , msgId(0)
        , timestamp(0)
        , receivedAt(0)
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
        default:                          return "UNKNOWN";
    }
}

/// Parse "status" JSON string → DeviceStatus enum
inline DeviceStatus deviceStatusFromString(const std::string& s) {
    if (s == "OPERATIONAL")   return DeviceStatus::OPERATIONAL;
    if (s == "WARNING")       return DeviceStatus::WARNING;
    if (s == "CRITICAL")      return DeviceStatus::CRITICAL;
    if (s == "NOT_OPERATING") return DeviceStatus::NOT_OPERATING;
    return DeviceStatus::UNKNOWN;
}

/// Parse "sensor_type" JSON string → SensorType enum
inline SensorType sensorTypeFromString(const std::string& s) {
    if (s == "ENV_MONITOR") return SensorType::ENV_MONITOR;
    if (s == "SECURITY")    return SensorType::SECURITY;
    return SensorType::UNKNOWN;
}

/// Convert SensorType → human-readable string
inline std::string sensorTypeToString(SensorType t) {
    switch (t) {
        case SensorType::ENV_MONITOR: return "ENV_MONITOR";
        case SensorType::SECURITY:    return "SECURITY";
        default:                      return "UNKNOWN";
    }
}

} // namespace IndustrialGateway

#endif // SENSOR_DATA_H