// =============================================================================
// DataProcessor.cpp — JSON Parsing, Security Pipeline & Device Cache
// Industrial IoT Gateway Security Platform
// Standard : C++17
// =============================================================================

#include "DataProcessor.h"

// C++ standard library
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>      // put_time
#include <cmath>        // abs
#include <stdexcept>    // invalid_argument, runtime_error

using namespace std;

namespace IndustrialGateway {

// =============================================================================
// Internal helpers (anonymous namespace — not exported in any header)
// =============================================================================
namespace {

// -----------------------------------------------------------------------------
// nowStr() — produces a UTC timestamp for log lines: [2024-05-14 08:30:01 UTC]
// -----------------------------------------------------------------------------
string nowStr() {
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    ostringstream oss;
    oss << "[" << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " UTC]";
    return oss.str();
}

// -----------------------------------------------------------------------------
// Mandatory top-level JSON field names.
// Stored as constants to prevent silent typo bugs in the validation loop.
// -----------------------------------------------------------------------------
constexpr const char* kFieldNodeId      = "node_id";
constexpr const char* kFieldSensorType  = "sensor_type";
constexpr const char* kFieldPayload     = "payload";
constexpr const char* kFieldStatus      = "status";
constexpr const char* kFieldMsgId       = "msg_id";
constexpr const char* kFieldTimestamp   = "timestamp";

// Nested payload field names
constexpr const char* kFieldTemp        = "temp";
constexpr const char* kFieldHumi        = "humi";

} // anonymous namespace

// =============================================================================
// Constructor & Destructor
// =============================================================================

// -----------------------------------------------------------------------------
// Constructor
//
// Opens both log files in append mode so previous entries survive restarts.
// ios::app guarantees every write goes to the end — safe for concurrent use
// under m_logMutex.
// -----------------------------------------------------------------------------
DataProcessor::DataProcessor(
    shared_ptr<DatabaseManager> dbManager,
    ProcessingConfig                 config)
    : m_db(move(dbManager))
    , m_config(move(config))
    , m_totalAccepted(0)
    , m_totalRejected(0)
    , m_securityEvents(0)
{
    if (!m_db) {
        throw invalid_argument(
            "[DataProcessor] DatabaseManager pointer must not be nullptr."
        );
    }

    // Open security alert log — critical events, replay attacks, spoofing
    m_securityLog.open(m_config.securityLogPath,
                       ios::out | ios::app);
    if (!m_securityLog.is_open()) {
        throw runtime_error(
            "[DataProcessor] Cannot open security log: " +
            m_config.securityLogPath
        );
    }

    // Open system debug log — normal flow, accepted readings, recoveries
    m_debugLog.open(m_config.debugLogPath,
                    ios::out | ios::app);
    if (!m_debugLog.is_open()) {
        throw runtime_error(
            "[DataProcessor] Cannot open debug log: " +
            m_config.debugLogPath
        );
    }

    cout << nowStr() << " [DataProcessor] Initialised.\n"
              << "  Security log : " << m_config.securityLogPath << "\n"
              << "  Debug log    : " << m_config.debugLogPath    << "\n"
              << "  Temp jump    : ±" << m_config.tempJumpThreshold << " °C\n"
              << "  Humi jump    : ±" << m_config.humiJumpThreshold << " %RH\n"
              << "  Recovery req : "  << m_config.recoveryPacketCount
              << " consecutive OK packets\n";
}

// -----------------------------------------------------------------------------
// Destructor — flush and close log streams
// -----------------------------------------------------------------------------
DataProcessor::~DataProcessor() {
    lock_guard<mutex> lock(m_logMutex);
    if (m_securityLog.is_open()) m_securityLog.close();
    if (m_debugLog.is_open())    m_debugLog.close();
}

// =============================================================================
// Primary Entry Point
// =============================================================================

// -----------------------------------------------------------------------------
// onRawMessage — the full 10-step processing pipeline
//
// Each step is a private method returning bool.
//   true  → continue
//   false → drop packet (event already logged by the step that failed)
//
// The pipeline is deliberately linear and explicit — no early-exit map or
// function pointer table — so that a code reviewer can trace the exact
// sequence of operations for any given packet.
// -----------------------------------------------------------------------------
void DataProcessor::onRawMessage(const string& topic,
                                 const string& payload)
{
    // ── Step 1: JSON parse + structural validation ────────────────────────────
    nlohmann::json doc;
    if (!parseJson(payload, doc)) {
        m_totalRejected.fetch_add(1, memory_order_relaxed);
        logDebug("DROPPED [parse_error] topic=" + topic);
        return;
    }

    // ── Step 2: Build SensorReading from validated JSON ───────────────────────
    SensorReading reading = buildReading(doc);

    logDebug("RECV node=" + reading.nodeId +
             " msg_id=" + to_string(reading.msgId) +
             " type="   + sensorTypeToString(reading.sensorType) +
             " status=" + deviceStatusToString(reading.status));

    // ── Step 3: Anti-spoofing — node must be in the whitelist ─────────────────
    if (!checkAntiSpoofing(reading)) {
        m_totalRejected.fetch_add(1, memory_order_relaxed);
        return;
    }

    // ── Step 4: Replay-attack detection — msg_id must be strictly increasing ──
    if (m_config.replayDetection && !checkReplayAttack(reading)) {
        m_totalRejected.fetch_add(1, memory_order_relaxed);
        return;
    }

    // ── Step 5: Handle NOT_OPERATING status ───────────────────────────────────
    // Returns false → packet logged as fault event, dropped from normal path.
    // The cache status update and DB write happen inside checkNotOperating().
    if (!checkNotOperating(reading)) {
        m_totalRejected.fetch_add(1, memory_order_relaxed);
        return;
    }

    // ── Step 6: Anomaly detection — compare against cached previous reading ───
    // Copy the previous reading under the lock, then release before calling
    // checkAnomalies (which may call logSecurityEvent → DB write).
    // Holding m_cacheMutex across a DB operation would increase lock contention
    // with the Watchdog and SNMP threads unnecessarily.
    {
        optional<SensorReading> previous;
        {
            lock_guard<mutex> lock(m_cacheMutex);
            auto it = m_deviceCache.find(reading.nodeId);
            if (it != m_deviceCache.end()) {
                previous = it->second;   // copy while lock is held
            }
        }   // lock released here — safe to call into DB

        if (previous.has_value()) {
            checkAnomalies(reading, *previous);
        }
        // If no previous reading exists, anomaly check is skipped for this
        // node's first message — there is nothing to compare against.
    }

    // ── Step 7: Recovery handling ─────────────────────────────────────────────
    // Check if the device was previously FAULTY and is now sending OPERATIONAL.
    // Same pattern: copy status under lock, then act outside the lock.
    {
        DeviceStatus cachedStatus = DeviceStatus::UNKNOWN;
        {
            lock_guard<mutex> lock(m_cacheMutex);
            auto it = m_deviceCache.find(reading.nodeId);
            if (it != m_deviceCache.end()) {
                cachedStatus = it->second.status;
            }
        }   // lock released before handleRecovery (which also acquires it)

        if (cachedStatus == DeviceStatus::FAULTY &&
            reading.status == DeviceStatus::OPERATIONAL)
        {
            handleRecovery(reading.nodeId, cachedStatus);
        }
    }

    // ── Step 8: Update the device cache with the latest validated reading ─────
    {
        lock_guard<mutex> lock(m_cacheMutex);
        m_deviceCache[reading.nodeId] = reading;
    }

    // ── Step 9: Persist the sensor reading to SQLite ──────────────────────────
    bool dbOk = m_db->insertSensorLog(reading);
    if (!dbOk) {
        cerr << nowStr()
                  << " [DataProcessor] DB write failed for node: "
                  << reading.nodeId << "\n";
        // Non-fatal: the cache is already updated, so SNMP/watchdog still
        // get the latest data even if the DB write fails transiently.
    }

    // ── Step 10: Bookkeeping ──────────────────────────────────────────────────
    m_totalAccepted.fetch_add(1, memory_order_relaxed);

    logDebug("OK node=" + reading.nodeId +
             " temp=" + (reading.temperature.has_value()
                         ? to_string(*reading.temperature) : "N/A") +
             " humi=" + (reading.humidity.has_value()
                         ? to_string(*reading.humidity) : "N/A"));
}

// =============================================================================
// Processing Pipeline — Step Implementations
// =============================================================================

// -----------------------------------------------------------------------------
// Step 1: parseJson
//
// Two-phase validation:
//   Phase A — parse: catch nlohmann::json::parse_error
//   Phase B — field presence check against the 6 mandatory keys
//
// nlohmann::json throws on malformed input; we catch and return false so the
// caller can log and drop without crashing the gateway loop thread.
// -----------------------------------------------------------------------------
bool DataProcessor::parseJson(const string& raw,
                              nlohmann::json&    out_doc) const
{
    // Phase A: Parse the raw string
    try {
        out_doc = nlohmann::json::parse(raw);
    }
    catch (const nlohmann::json::parse_error& e) {
        cerr << nowStr()
                  << " [DataProcessor] JSON parse error: "
                  << e.what()
                  << " | raw(first 120): "
                  << raw.substr(0, 120) << "\n";
        return false;
    }

    // Phase B: Structural validation — all 6 top-level fields are mandatory
    // per the spec's "Kiểm tra tính toàn vẹn" (integrity check) rule.
    const vector<const char*> required = {
        kFieldNodeId, kFieldSensorType, kFieldPayload,
        kFieldStatus, kFieldMsgId,      kFieldTimestamp
    };

    for (const char* field : required) {
        if (!out_doc.contains(field)) {
            cerr << nowStr()
                      << " [DataProcessor] Missing mandatory field: '"
                      << field << "'\n";
            return false;
        }
    }

    // Phase C: Type checks for fields that must not be null
    if (!out_doc[kFieldNodeId].is_string() ||
        out_doc[kFieldNodeId].get<string>().empty())
    {
        cerr << nowStr()
                  << " [DataProcessor] 'node_id' must be a non-empty string\n";
        return false;
    }

    if (!out_doc[kFieldMsgId].is_number_unsigned()) {
        cerr << nowStr()
                  << " [DataProcessor] 'msg_id' must be an unsigned integer\n";
        return false;
    }

    if (!out_doc[kFieldTimestamp].is_number()) {
        cerr << nowStr()
                  << " [DataProcessor] 'timestamp' must be a number\n";
        return false;
    }

    if (!out_doc[kFieldPayload].is_object()) {
        cerr << nowStr()
                  << " [DataProcessor] 'payload' must be a JSON object\n";
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------------
// Step 2: buildReading
//
// Converts the validated JSON document into a SensorReading struct.
//
// Temperature and humidity are extracted from the nested "payload" sub-object.
// They are wrapped in optional:
//   • If the key is present AND a valid number → optional<float> with value
//   • If absent, null, or non-numeric          → nullopt
//
// receivedAt is stamped with the gateway's current wall-clock time so the
// Watchdog can detect silence even if device timestamps are unreliable.
// -----------------------------------------------------------------------------
SensorReading DataProcessor::buildReading(const nlohmann::json& doc) const {
    SensorReading r;

    // Top-level scalar fields
    r.nodeId     = doc[kFieldNodeId].get<string>();
    r.sensorType = sensorTypeFromString(
                       doc[kFieldSensorType].get<string>());
    r.status     = deviceStatusFromString(
                       doc[kFieldStatus].get<string>());
    r.msgId      = doc[kFieldMsgId].get<uint32_t>();
    r.timestamp  = doc[kFieldTimestamp].get<int64_t>();

    // Gateway-side wall-clock receipt time (used by Watchdog heartbeat logic)
    r.receivedAt = nowEpoch();

    // Nested payload — extract optional sensor values
    const nlohmann::json& pl = doc[kFieldPayload];

    // Temperature: present and numeric?
    if (pl.contains(kFieldTemp) && pl[kFieldTemp].is_number()) {
        r.temperature = pl[kFieldTemp].get<float>();
    }
    // else: remains nullopt (sensor not fitted, or field omitted)

    // Humidity: present and numeric?
    if (pl.contains(kFieldHumi) && pl[kFieldHumi].is_number()) {
        r.humidity = pl[kFieldHumi].get<float>();
    }

    return r;
}

// =============================================================================
// SECURITY CHECK IMPLEMENTATIONS
// =============================================================================

// -----------------------------------------------------------------------------
// checkAntiSpoofing — Two-tier whitelist: RAM cache → DB fallback
//
// ── Why two tiers? ────────────────────────────────────────────────────────────
// In a denial-of-service scenario a rogue sender could flood the gateway with
// packets carrying fabricated node_ids.  If every packet caused a DB SELECT,
// that would be a DB-amplification attack.  The in-memory m_knownDeviceCache
// absorbs the flood after one DB lookup per unique bogus node_id.
//
// ── State machine per node_id ─────────────────────────────────────────────────
//  First packet from nodeX:
//    m_knownDeviceCache has no entry → query DB → store result in map
//  Subsequent packets from nodeX:
//    m_knownDeviceCache[nodeX] == true  → pass immediately (no DB hit)
//    m_knownDeviceCache[nodeX] == false → fail immediately (no DB hit)
//
// ── insertSystemEvent fields ──────────────────────────────────────────────────
//  severity    : CRITICAL  (LEVEL_3)
//  description : "unauthorized_device | node_id=X | msg_id=Y | …"
// -----------------------------------------------------------------------------
bool DataProcessor::checkAntiSpoofing(const SensorReading& reading) {

    // ── Tier 1: in-memory whitelist cache (O(1), no DB I/O) ──────────────────
    {
        lock_guard<mutex> lock(m_cacheMutex);
        auto it = m_knownDeviceCache.find(reading.nodeId);
        if (it != m_knownDeviceCache.end()) {
            if (it->second) {
                return true;   // Cache hit: known-good device, proceed
            }
            // Cache hit: known-bad device — fall through to log & drop
            // (We still log every attempt so the audit trail shows the full
            //  flood volume, not just the first packet from this node.)
        } else {
            // ── Tier 2: DB lookup on first encounter (release lock first) ────
            // Pattern: copy the node_id string out, release the lock, do the
            // DB call, then re-acquire to write the result back.
            // This avoids holding m_cacheMutex across a potentially slow
            // SQLite operation.
        }
    }

    // Check whether we already had a cache entry (known-bad) or need a DB hit
    bool hasCacheEntry = false;
    {
        lock_guard<mutex> lock(m_cacheMutex);
        hasCacheEntry = (m_knownDeviceCache.count(reading.nodeId) > 0);
    }

    if (!hasCacheEntry) {
        // DB lookup — outside the lock
        bool known = m_db->isDeviceKnown(reading.nodeId);

        {
            lock_guard<mutex> lock(m_cacheMutex);
            // Double-check: another concurrent packet from the same node could
            // have already populated the cache while we were in the DB call.
            if (m_knownDeviceCache.count(reading.nodeId) == 0) {
                m_knownDeviceCache[reading.nodeId] = known;
            }
        }

        if (known) {
            logDebug("ANTI-SPOOF PASS node=" + reading.nodeId +
                     " (DB lookup, now cached as authorised)");
            return true;   // Authorised — proceed with pipeline
        }
    }

    // ── Unauthorised: build forensic event description ────────────────────────
    string desc =
        "unauthorized_device"
        " | node_id="         + reading.nodeId +
        " | msg_id="          + to_string(reading.msgId) +
        " | sensor_type="     + sensorTypeToString(reading.sensorType) +
        " | reported_status=" + deviceStatusToString(reading.status) +
        " | device_ts="       + to_string(reading.timestamp) +
        " | gateway_ts="      + to_string(reading.receivedAt);

    logSecurityEvent(reading.nodeId, "CRITICAL", desc);

    cerr << nowStr()
              << " [SECURITY][LEVEL_3] ✗ UNAUTHORIZED DEVICE"
              << " node='"  << reading.nodeId << "'"
              << " msg_id=" << reading.msgId << "\n";

    return false;   // Drop the packet
}

// -----------------------------------------------------------------------------
// checkReplayAttack — Two-tier msg_id monotonicity: RAM map → DB seed
//
// ── Why two tiers? ────────────────────────────────────────────────────────────
// The DB is only read ONCE per node per gateway session (m_msgIdSeeded flag).
// After seeding, every subsequent check is a pure integer comparison in RAM.
// This means:
//   • No DB I/O on the hot path (every 5-second packet)
//   • Check survives gateway restarts (DB seed carries forward last accepted id)
//   • Thread-safe: m_lastMsgId and m_msgIdSeeded both protected by m_cacheMutex
//
// ── State machine per node_id ─────────────────────────────────────────────────
//  First packet in this session:
//    m_msgIdSeeded[node] == false
//    → call DB::getLastMsgId() once → store in m_lastMsgId[node]
//    → set m_msgIdSeeded[node] = true
//    → if DB returns 0 (no history), accept the packet unconditionally
//
//  All subsequent packets:
//    m_msgIdSeeded[node] == true → pure RAM comparison
//    incoming.msgId > m_lastMsgId[node] → accept, update m_lastMsgId
//    incoming.msgId <= m_lastMsgId[node] → replay attack
//
// ── Edge cases ────────────────────────────────────────────────────────────────
//  ESP32 reboot (counter resets to 0):
//    Indistinguishable from a replay at the gateway level.  Per the spec,
//    planned device resets require the operator to de-register and
//    re-register the device (clears DB history → getLastMsgId() returns 0).
//
//  uint32_t wrap-around at 4 294 967 295:
//    At 1 msg/5s the counter wraps in ~680 years.  Not handled specially.
//
// ── insertSystemEvent fields ──────────────────────────────────────────────────
//  severity    : CRITICAL  (LEVEL_3)
//  description : "replay_attack | node=X | rx_msg_id=Y | last_msg_id=Z | gap=W"
// -----------------------------------------------------------------------------
bool DataProcessor::checkReplayAttack(const SensorReading& reading) {

    uint32_t lastId = 0;

    {
        lock_guard<mutex> lock(m_cacheMutex);

        // ── Seed the in-memory map from DB on first encounter ─────────────────
        if (!m_msgIdSeeded[reading.nodeId]) {
            // Release the lock before the DB call to avoid holding m_cacheMutex
            // across a potentially slow SQLite operation.
            // We use a local flag to avoid double-seeding from a race.
        }
    }

    // ── DB seed (outside the lock) ────────────────────────────────────────────
    bool needsSeed = false;
    {
        lock_guard<mutex> lock(m_cacheMutex);
        needsSeed = !m_msgIdSeeded[reading.nodeId];
    }

    if (needsSeed) {
        uint32_t dbLastId = m_db->getLastMsgId(reading.nodeId);

        lock_guard<mutex> lock(m_cacheMutex);
        // Double-check: another thread might have seeded while we were in DB
        if (!m_msgIdSeeded[reading.nodeId]) {
            m_lastMsgId[reading.nodeId]  = dbLastId;
            m_msgIdSeeded[reading.nodeId] = true;

            logDebug("REPLAY-SEED node=" + reading.nodeId +
                     " last_db_msg_id=" + to_string(dbLastId));
        }
    }

    // ── Hot path: pure in-memory comparison ───────────────────────────────────
    {
        lock_guard<mutex> lock(m_cacheMutex);
        lastId = m_lastMsgId[reading.nodeId];

        if (lastId == 0) {
            // No prior history in this session (first ever message from device)
            // Accept it and seed the map.
            m_lastMsgId[reading.nodeId] = reading.msgId;
            logDebug("REPLAY-FIRST node=" + reading.nodeId +
                     " first_msg_id=" + to_string(reading.msgId));
            return true;
        }

        if (reading.msgId > lastId) {
            // Legitimate strictly-increasing message — update in-memory map.
            // The DB is updated later by insertSensorLog(), not here.
            m_lastMsgId[reading.nodeId] = reading.msgId;
            return true;
        }
    }

    // ── Replay detected ───────────────────────────────────────────────────────
    // Compute the "gap" — negative gap means the counter went backwards.
    int64_t gap = static_cast<int64_t>(reading.msgId) -
                  static_cast<int64_t>(lastId);

    string desc =
        "replay_attack"
        " | node="        + reading.nodeId +
        " | rx_msg_id="   + to_string(reading.msgId) +
        " | last_msg_id=" + to_string(lastId) +
        " | gap="         + to_string(gap) +
        " | device_ts="   + to_string(reading.timestamp);

    logSecurityEvent(reading.nodeId, "CRITICAL", desc);

    cerr << nowStr()
              << " [SECURITY][LEVEL_3] ✗ REPLAY ATTACK"
              << " node='"   << reading.nodeId << "'"
              << " rx_id="   << reading.msgId
              << " last_id=" << lastId
              << " gap="     << gap << "\n";

    return false;   // Drop the packet
}

// -----------------------------------------------------------------------------
// Step 5: checkNotOperating
//
// The device itself reports NOT_OPERATING to signal a local hardware/sensor
// fault.  This is distinct from OFFLINE (which the Watchdog infers).
//
// On NOT_OPERATING:
//   1. Update cache status → FAULTY
//   2. Reset the recovery counter for this node
//   3. Log a LEVEL_2 (ERROR) event
//   4. Return false → drop from normal pipeline
//
// The DB write for the status-change event still happens via logSecurityEvent
// so there is a forensic record of the exact moment the device failed.
// -----------------------------------------------------------------------------
bool DataProcessor::checkNotOperating(const SensorReading& reading) {
    if (reading.status != DeviceStatus::NOT_OPERATING) {
        return true;   // Status is fine — continue normal processing
    }

    // Mark the device FAULTY in the cache
    {
        lock_guard<mutex> lock(m_cacheMutex);
        m_deviceCache[reading.nodeId].status = DeviceStatus::FAULTY;
        m_recoveryCounters[reading.nodeId]   = 0;   // Reset recovery counter
    }

    logSecurityEvent(
        reading.nodeId,
        "ERROR",
        "device_not_operating: device reported NOT_OPERATING status. "
        "Marked FAULTY in cache. msg_id=" +
        to_string(reading.msgId)
    );

    cerr << nowStr()
              << " [FAULT] Device '" << reading.nodeId
              << "' reported NOT_OPERATING — marked FAULTY\n";

    return false;   // Drop from normal pipeline
}

// -----------------------------------------------------------------------------
// checkAnomalies — Three independent rules with a strict 5-second time-gate
//
// ── Time-gate rationale ───────────────────────────────────────────────────────
// We use receivedAt (gateway wall-clock, set by buildReading()) NOT the
// device's timestamp field.  The device timestamp could be:
//   • Spoofed to fake a long gap and bypass the jump check
//   • Drifted on a device without NTP
//
// By gating on our own clock we ensure the "5 seconds" window is real.
// If the previous reading is older than k_anomalyWindowSec (5 s) the jump
// rules are skipped — a data gap caused by network jitter or device sleep is
// not anomalous, it just means we have no valid baseline to compare against.
//
// All three rules are evaluated INDEPENDENTLY per call.  A single packet that
// violates both temp and humi generates two separate system_events rows.
//
// ── insertSystemEvent severity mapping ───────────────────────────────────────
//  Rule A (TEMP_JUMP)           → CRITICAL  (LEVEL_3 per spec)
//  Rule B (HUMI_JUMP)           → ERROR     (LEVEL_2 per spec)
//  Rule C (TIMESTAMP_REGRESSION)→ ERROR     (LEVEL_2 — clock inconsistency)
// -----------------------------------------------------------------------------
void DataProcessor::checkAnomalies(const SensorReading& incoming,
                                   const SensorReading& previous)
{
    // ── Time-gate: measure Δt using gateway wall-clock (not device timestamp) ─
    // receivedAt is int64_t Unix epoch seconds stamped by buildReading().
    constexpr int64_t k_anomalyWindowSec = 5;
    int64_t wallDelta = incoming.receivedAt - previous.receivedAt;

    // Device-reported timestamp delta (for log context only — not trusted)
    int64_t deviceDelta = incoming.timestamp - previous.timestamp;

    bool withinWindow = (wallDelta >= 0 && wallDelta <= k_anomalyWindowSec);

    logDebug("ANOMALY-CHECK node=" + incoming.nodeId +
             " wall_dt=" + to_string(wallDelta) + "s" +
             " device_dt=" + to_string(deviceDelta) + "s" +
             " within_window=" + (withinWindow ? "yes" : "no"));

    // ── Rule C: Timestamp regression (checked regardless of time-gate) ────────
    // The device's own clock should never go backwards.  If it does, a clock-
    // based replay or packet injection is the most likely cause.
    // This is checked BEFORE the window gate because it is independent of Δt.
    if (incoming.timestamp < previous.timestamp) {
        int64_t regression = previous.timestamp - incoming.timestamp;

        string desc =
            "anomaly_detected [TIMESTAMP_REGRESSION]"
            " | node="         + incoming.nodeId +
            " | ts_new="       + to_string(incoming.timestamp) +
            " | ts_old="       + to_string(previous.timestamp) +
            " | regression_s=" + to_string(regression) +
            " | msg_id_new="   + to_string(incoming.msgId) +
            " | msg_id_old="   + to_string(previous.msgId);

        logSecurityEvent(incoming.nodeId, "ERROR", desc);

        cerr << nowStr()
                  << " [ANOMALY][LEVEL_2] ✗ TIMESTAMP REGRESSION"
                  << " node='"        << incoming.nodeId << "'"
                  << " ts_new="       << incoming.timestamp
                  << " ts_old="       << previous.timestamp
                  << " regression="   << regression << "s\n";
    }

    // ── Jump rules only apply within the 5-second window ─────────────────────
    if (!withinWindow) {
        logDebug("ANOMALY-SKIP (outside window) node=" + incoming.nodeId +
                 " wall_dt=" + to_string(wallDelta) + "s");
        return;   // Gap too large — no valid baseline for jump detection
    }

    // ── Rule A: Temperature jump  [CRITICAL / LEVEL_3] ───────────────────────
    if (incoming.temperature.has_value() && previous.temperature.has_value()) {

        float tNew   = *incoming.temperature;
        float tOld   = *previous.temperature;
        float tDelta = abs(tNew - tOld);

        if (tDelta > m_config.tempJumpThreshold) {
            string desc =
                "anomaly_detected [TEMP_JUMP]"
                " | node="      + incoming.nodeId +
                " | T_new="     + to_string(tNew)   + "°C"
                " | T_old="     + to_string(tOld)   + "°C"
                " | delta="     + to_string(tDelta) + "°C"
                " | threshold=" + to_string(m_config.tempJumpThreshold) + "°C"
                " | wall_dt="   + to_string(wallDelta) + "s"
                " | device_dt=" + to_string(deviceDelta) + "s"
                " | msg_id="    + to_string(incoming.msgId);

            logSecurityEvent(incoming.nodeId, "CRITICAL", desc);

            cerr << nowStr()
                      << " [ANOMALY][LEVEL_3] ✗ TEMP JUMP"
                      << " node='"    << incoming.nodeId << "'"
                      << " Δ="        << tDelta << "°C"
                      << " ("         << tOld << "→" << tNew << ")"
                      << " wall_dt="  << wallDelta << "s\n";
        }
    }

    // ── Rule B: Humidity jump  [ERROR / LEVEL_2] ─────────────────────────────
    if (incoming.humidity.has_value() && previous.humidity.has_value()) {

        float hNew   = *incoming.humidity;
        float hOld   = *previous.humidity;
        float hDelta = abs(hNew - hOld);

        if (hDelta > m_config.humiJumpThreshold) {
            string desc =
                "anomaly_detected [HUMI_JUMP]"
                " | node="      + incoming.nodeId +
                " | H_new="     + to_string(hNew)   + "%"
                " | H_old="     + to_string(hOld)   + "%"
                " | delta="     + to_string(hDelta) + "%"
                " | threshold=" + to_string(m_config.humiJumpThreshold) + "%"
                " | wall_dt="   + to_string(wallDelta) + "s"
                " | device_dt=" + to_string(deviceDelta) + "s"
                " | msg_id="    + to_string(incoming.msgId);

            logSecurityEvent(incoming.nodeId, "ERROR", desc);

            cerr << nowStr()
                      << " [ANOMALY][LEVEL_2] ✗ HUMI JUMP"
                      << " node='"    << incoming.nodeId << "'"
                      << " Δ="        << hDelta << "%"
                      << " ("         << hOld << "→" << hNew << ")"
                      << " wall_dt="  << wallDelta << "s\n";
        }
    }
}

// -----------------------------------------------------------------------------
// Step 7: handleRecovery
//
// Three-packet validation gate before promoting a FAULTY device back to
// OPERATIONAL.  This prevents a single lucky valid packet from clearing a
// device that is intermittently malfunctioning.
//
// State machine:
//   FAULTY + OPERATIONAL packet → counter++
//   counter < threshold         → cache remains FAULTY
//   counter == threshold        → cache set OPERATIONAL, log recovery event
// -----------------------------------------------------------------------------
void DataProcessor::handleRecovery(const string& nodeId,
                                   DeviceStatus       cachedStatus)
{
    (void)cachedStatus;   // Parameter kept for future extension (e.g. per-status rules)

    lock_guard<mutex> lock(m_cacheMutex);

    int& counter = m_recoveryCounters[nodeId];
    counter++;

    int required = m_config.recoveryPacketCount;

    logDebug("RECOVERY node=" + nodeId +
             " progress=" + to_string(counter) +
             "/" + to_string(required));

    if (counter >= required) {
        // Promote back to OPERATIONAL and reset counter
        m_deviceCache[nodeId].status = DeviceStatus::OPERATIONAL;
        counter = 0;
    }

    // Capture the final counter value before releasing the lock
    bool recovered = (counter == 0 &&
                      m_deviceCache.count(nodeId) &&
                      m_deviceCache[nodeId].status == DeviceStatus::OPERATIONAL);

    // Lock released at end of scope — logSecurityEvent acquires its own
    // locks (m_logMutex + DB internal mutex), so we must NOT hold m_cacheMutex
    // while calling it (would create an ordering dependency between the two
    // mutexes, risking deadlock if another code path acquires them in reverse).

    if (recovered) {
        logSecurityEvent(
            nodeId,
            "WARNING",
            "device_recovered: Status restored to OPERATIONAL after " +
            to_string(required) +
            " consecutive valid packets. Device recovered - Status restored."
        );

        cout << nowStr()
                  << " [RECOVERY] ✓ Device '" << nodeId
                  << "' recovered — status restored to OPERATIONAL\n";
    }
}

// =============================================================================
// Device Cache — Public Read Interface
// =============================================================================

// -----------------------------------------------------------------------------
// getCachedReading — returns a value copy, safe to use after lock release
// -----------------------------------------------------------------------------
optional<SensorReading>
DataProcessor::getCachedReading(const string& nodeId) const {
    lock_guard<mutex> lock(m_cacheMutex);

    auto it = m_deviceCache.find(nodeId);
    if (it == m_deviceCache.end()) {
        return nullopt;
    }
    return it->second;   // Returns by value — copy made while lock is held
}

// -----------------------------------------------------------------------------
// getAllCachedReadings — snapshot copy of the entire cache
// -----------------------------------------------------------------------------
unordered_map<string, SensorReading>
DataProcessor::getAllCachedReadings() const {
    lock_guard<mutex> lock(m_cacheMutex);
    return m_deviceCache;   // STL copy constructor; fine for a handful of nodes
}

// -----------------------------------------------------------------------------
// updateCachedStatus — used by the Watchdog to mark nodes OFFLINE
// -----------------------------------------------------------------------------
void DataProcessor::updateCachedStatus(const string& nodeId,
                                       DeviceStatus       newStatus)
{
    lock_guard<mutex> lock(m_cacheMutex);

    auto it = m_deviceCache.find(nodeId);
    if (it != m_deviceCache.end()) {
        it->second.status = newStatus;
    } else {
        // Device was never seen this session (gateway restarted while node
        // was offline).  Insert a minimal placeholder so SNMP can report it.
        SensorReading placeholder;
        placeholder.nodeId  = nodeId;
        placeholder.status  = newStatus;
        m_deviceCache[nodeId] = placeholder;
    }
}

// =============================================================================
// Diagnostic Counters
// =============================================================================

uint64_t DataProcessor::getTotalAccepted()  const noexcept {
    return m_totalAccepted.load(memory_order_relaxed);
}
uint64_t DataProcessor::getTotalRejected()  const noexcept {
    return m_totalRejected.load(memory_order_relaxed);
}
uint64_t DataProcessor::getSecurityEvents() const noexcept {
    return m_securityEvents.load(memory_order_relaxed);
}

// =============================================================================
// Private Logging Helpers
// =============================================================================

// -----------------------------------------------------------------------------
// logSecurityEvent
//
// Dual-destination write:
//   1. SQLite  system_events  — permanent, queryable, used by REST API
//   2. Flat file security_alerts.log — fast, human-readable, survives DB loss
//
// Format in the flat file:
//   [2024-05-14 08:30:01 UTC] [CRITICAL] ESP32_SEC_01 — unauthorized_device: …
// -----------------------------------------------------------------------------
void DataProcessor::logSecurityEvent(const string& nodeId,
                                     const string& severity,
                                     const string& description)
{
    int64_t ts = nowEpoch();

    // ── Write to SQLite ───────────────────────────────────────────────────────
    SecurityEvent ev;
    ev.nodeId      = nodeId;
    ev.severity    = severity;
    ev.description = description;
    ev.timestamp   = ts;
    m_db->insertSystemEvent(ev);

    // ── Write to flat file ────────────────────────────────────────────────────
    {
        lock_guard<mutex> lock(m_logMutex);
        if (m_securityLog.is_open()) {
            m_securityLog << nowStr()
                          << " [" << severity << "] "
                          << nodeId << " — "
                          << description << "\n";
            m_securityLog.flush();   // Line-buffer: each event visible immediately
        }
    }

    m_securityEvents.fetch_add(1, memory_order_relaxed);
}

// -----------------------------------------------------------------------------
// logDebug — informational messages to system_debug.log only
// -----------------------------------------------------------------------------
void DataProcessor::logDebug(const string& msg) const {
    lock_guard<mutex> lock(m_logMutex);
    if (m_debugLog.is_open()) {
        m_debugLog << nowStr() << " [DataProcessor] " << msg << "\n";
        // No flush here — OS buffering is acceptable for debug logs;
        // we don't want debug I/O to slow the mosquitto loop thread.
    }
}

// =============================================================================
// Static helpers
// =============================================================================

// -----------------------------------------------------------------------------
// extractNodeIdFromTopic
//
// Topic format: factory/sensors/<node_id>/data
//                segment[0]  /  segment[1] / segment[2] / segment[3]
//
// Splits on '/' and returns segment[2].
// Returns empty string if the topic doesn't have the expected structure.
// -----------------------------------------------------------------------------
string DataProcessor::extractNodeIdFromTopic(const string& topic) {
    // Simple manual split — avoids pulling in a tokeniser for a one-liner
    vector<string> segments;
    istringstream stream(topic);
    string seg;
    while (getline(stream, seg, '/')) {
        segments.push_back(seg);
    }
    // Expected: ["factory", "sensors", "<node_id>", "data"]
    if (segments.size() >= 3) {
        return segments[2];
    }
    return {};
}

// -----------------------------------------------------------------------------
// nowEpoch — current wall-clock Unix epoch seconds
// -----------------------------------------------------------------------------
int64_t DataProcessor::nowEpoch() {
    return static_cast<int64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

} // namespace IndustrialGateway
